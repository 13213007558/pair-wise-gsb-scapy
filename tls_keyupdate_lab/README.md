# TLS 1.3 KeyUpdate 行为核查报告

所有 traffic secret 均由 `TLS13_HKDF` 在本地随机生成，本目录任何脚本和报告
都不打印 secret 字节。复现实验台：`keyupdate_harness.py`（从仓库根目录或任意
目录均可运行），UTScapy 回归用例位于
`test/scapy/layers/tls/tls13.uts` 的 `KeyUpdate traffic secret handling` 测试集。

## 覆盖的记录序列

1. 基线：双向 ApplicationData，确认装配的会话密钥可正常加解密。
2. 单方更新：一端发 `KeyUpdate(request_update=0)`，仅该方向写密钥换代，
   对端写方向不受影响。
3. 请求对端更新：`KeyUpdate(request_update=1)` 认证通过后，对端回自己的
   `KeyUpdate(0)`，两端各自进入新一代密钥。
4. 两端相继更新：同一方向连续换代与对端换代互不干扰，代际独立。
5. 异常序列：更新记录被截断（长度字段同步改小）、认证标签被翻转。

判定原则：只有通过 AEAD 认证的明文才算成功；`Raw` 层或未认证解密字节一律
记为失败；同时检查 `rcs/prcs`、`triggered_prcs_commit` 和
`tls13_derived_secrets` 列表，证明会话状态未被异常记录推动。

## 结论：实现缺陷与使用方式问题并存

### 缺陷 1（已修复）：未认证的 KeyUpdate 会推动读状态换代

- 位置：`scapy/layers/tls/record_tls13.py` 的 `TLS13._tls_auth_decrypt`
  捕获 `AEADTagError` 后仅记录日志并返回未认证明文字节；随后
  `TLS13KeyUpdate.post_dissection_tls_session_update`
  （`scapy/layers/tls/handshake.py:1744`）照常派生下一代 traffic secret、
  创建 `prcs` 并置位 `triggered_prcs_commit`，下一条记录的 `pre_dissect`
  即提交该状态。
- 后果（lenient 默认模式，`strict_integrity=False`）：一条标签错误的
  KeyUpdate 会被解析成真实握手消息，读连接状态被替换、
  `client/server_traffic_secrets` 列表追加一代，之后所有合法记录均无法
  通过认证（状态被永久带偏）。这违反 RFC 8446 4.6.3：密钥换代只能由
  认证通过的记录触发。
- 严格模式（`strict_integrity=True`）下异常会直接抛出，状态不换代，但
  失败记录已消耗一个 `seq_num`，调用方不能简单复用同一会话继续逐条解析。
- 截断记录本身是安全的：片段短于 tag 长度时 `inner=None`，或解密字节以
  `Raw` 呈现，不会进入握手消息分支；修复后同样被显式门控。

修复方式（最小改动，仅限 TLS 1.3 记录层）：

- `TLS13` 增加 `integrity_failed` 标记，认证失败时同时在 `tls_session`
  上置 `record_integrity_failed`，每条记录解析开始时清零。
- 新增 `_TLS13MsgListField`：标记存在时跳过正常消息解析与
  `post_dissection_tls_session_update`，未认证字节仅以单个 `Raw` 层保留。
- `_TLSInnerPlaintextField` 对截断等空内层场景做同样门控，避免构造空
  `TLSInnerPlaintext` 崩溃。
- `strict_integrity=True` 的抛异常行为保持不变。

### 缺陷 2（已修复）：服务端对 KeyUpdate 的响应条件缺失

- 位置：`scapy/layers/tls/automaton_srv.py:1149`。原实现对任何
  `TLS13KeyUpdate` 都无条件回 `KeyUpdate(0)`。
- RFC 8446 4.6.3 规定仅当 `request_update=update_requested(1)` 时，
  接收方才必须发送自己的 KeyUpdate；收到 0 时不得响应。
- 修复：仅在 `p.request_update == 1` 时回送，否则回到
  `HANDLED_CLIENTDATA` 等待下一条消息。现有 loopback 测试
  （`tlsclientserver.uts` 的 `key_update=True`）使用的正是值 1，行为不变。

### 使用方式问题（无需改代码，但调用方必须知道）

- 离线逐条解析 pcap 时，方向切换必须使用 `tls_session.mirror()`
  （Scapy 既有测试的标准模式），否则读写连接状态会错位。
- 解析前需把会话置为 `post_handshake=True`，否则
  `TLS13KeyUpdate.post_dissection_tls_session_update` 直接 return，
  密钥不会换代——这是“KeyUpdate 后解不开”最常见的误用原因。
- 推荐默认使用 `strict_integrity=True` 并捕获 `AEADTagError`；lenient
  模式仅用于检视字节，其 `Raw` 内容不可信，也不应驱动任何状态。
- 失败记录会消耗序号，复用会话继续解析前要理解这一点；排查单条记录时
  用独立会话（本实验台的做法）更干净。

## 正确调用示例

```python
from scapy.layers.tls.record_tls13 import TLS13
from scapy.layers.tls.crypto.cipher_aead import AEADTagError

# session 需已载入 application traffic keys，且 post_handshake=True
try:
    rec = TLS13(record_bytes, tls_session=session, strict_integrity=True)
except AEADTagError:
    ...  # 认证失败：不要信任任何解密字节，会话状态保持原样
else:
    for msg in rec.inner.msg:
        ...  # 这里的 msg 已通过认证，KeyUpdate 已安全推动状态换代
```

构造记录（发送侧，状态换代在 `post_build` 末尾自动提交）：

```python
from scapy.layers.tls.handshake import TLS13KeyUpdate
from scapy.layers.tls.record_tls13 import TLS13

rec = TLS13(tls_session=session)
rec.inner.msg.append(TLS13KeyUpdate(request_update=0))
wire = rec.raw_stateful()
```

## 复现证据

- 未补丁代码上 `keyupdate_harness.py` 为 15/17，失败项：
  `bad-tag KU: lenient yields no auth plaintext`（未认证字节被解析成
  `TLS13KeyUpdate`）与 `bad-tag KU: state not rotated`
  （`rcs` 被替换、secret 列表多一代）。
- 补丁后 17/17；`tls13.uts` 新增 4 个用例在未补丁代码上 055/056 失败、
  补丁后全部通过。
- `tls.uts`、修复后的 `tls13.uts` 全部通过。
- `tlsclientserver.uts` 需要 loopback 端口绑定，本沙箱禁止本地绑定
  （EPERM），未能在本环境执行；其 KeyUpdate 用例发送的是
  `request_update=1`，与缺陷 2 的修复条件一致。
