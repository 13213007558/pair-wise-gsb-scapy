# Feedback task starting environment

Upstream: https://github.com/secdev/scapy
Upstream commit: `d2a43b525e145969fae36e42adfb4de8341fbcb8`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m scapy.tools.UTscapy -t test/fields.uts -K tshark -K netaccess -q
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-11): `[34m[1m>>> [0massert [p.x for p in p.plist] == [0x41, 0x42, 0x43, 0x44]`
Whole-command wall time: 1.875 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
