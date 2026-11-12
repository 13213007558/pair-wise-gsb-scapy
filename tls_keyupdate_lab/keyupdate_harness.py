# SPDX-License-Identifier: GPL-2.0-only
"""
Local TLS 1.3 KeyUpdate record-sequence harness.

All traffic secrets are generated locally from a random master secret;
no secret material is ever printed. Two tlsSession endpoints (client and
server) are wired with the application traffic keys and used to build
records on one side and dissect them on the other. Authentication result
is the primary evidence: dissection with strict_integrity=True raises
AEADTagError on a bad tag, and only authenticated plaintext counts as
success.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.crypto.cipher_aead import AEADTagError
from scapy.layers.tls.crypto.suites import TLS_AES_128_GCM_SHA256
from scapy.layers.tls.handshake import TLS13KeyUpdate
from scapy.layers.tls.record import TLSApplicationData
from scapy.layers.tls.record_tls13 import TLS13
from scapy.layers.tls.session import (
    tlsSession, readConnState, writeConnState,
)

HASH_NAME = "sha256"
CS_CLS = TLS_AES_128_GCM_SHA256


def make_endpoint(connection_end, cts0, sts0):
    s = tlsSession(connection_end=connection_end)
    s.tls_version = 0x0304
    s.advertised_tls_version = 0x0304
    s.post_handshake = True
    if connection_end == "client":
        # client writes with client traffic secret, reads with server's
        s.wcs = writeConnState(ciphersuite=CS_CLS, connection_end="client",
                               tls_version=0x0304)
        s.rcs = readConnState(ciphersuite=CS_CLS, connection_end="client",
                              tls_version=0x0304)
        s.wcs.tls13_derive_keys(cts0)
        s.rcs.tls13_derive_keys(sts0)
        s.tls13_derived_secrets["client_traffic_secrets"] = [cts0]
        s.tls13_derived_secrets["server_traffic_secrets"] = [sts0]
    else:
        s.wcs = writeConnState(ciphersuite=CS_CLS, connection_end="server",
                               tls_version=0x0304)
        s.rcs = readConnState(ciphersuite=CS_CLS, connection_end="server",
                              tls_version=0x0304)
        s.wcs.tls13_derive_keys(sts0)
        s.rcs.tls13_derive_keys(cts0)
        s.tls13_derived_secrets["client_traffic_secrets"] = [cts0]
        s.tls13_derived_secrets["server_traffic_secrets"] = [sts0]
    return s


def build_record(session, *msgs):
    pkt = TLS13(tls_session=session)
    for m in msgs:
        pkt.inner.msg.append(m)
    return pkt.raw_stateful()


def dissect_record(session, data, strict=False):
    """Return (TLS13 packet, auth_ok, plaintext_or_None)."""
    try:
        pkt = TLS13(data, tls_session=session, strict_integrity=strict)
    except AEADTagError:
        return None, False, None
    inner = pkt.inner
    if inner is None:
        return pkt, False, None
    from scapy.packet import Raw
    if any(isinstance(m, Raw) for m in inner.msg):
        # unauthenticated decrypted bytes must never count as success
        return pkt, False, [("Raw", None)]
    plain = []
    for m in inner.msg:
        if isinstance(m, TLSApplicationData):
            plain.append(("app", bytes(m.data)))
        elif isinstance(m, TLS13KeyUpdate):
            plain.append(("keyupdate", int(m.request_update)))
        else:
            plain.append((m.name, None))
    return pkt, True, plain


def fresh_secrets():
    hkdf = TLS13_HKDF(HASH_NAME)
    # locally generated, never printed
    master = os.urandom(hkdf.hash.digest_size)
    transcript = os.urandom(hkdf.hash.digest_size)
    cts0 = hkdf.derive_secret(master, b"c ap traffic", transcript)
    sts0 = hkdf.derive_secret(master, b"s ap traffic", transcript)
    return cts0, sts0


def report(name, ok, detail):
    print("%-44s %s  %s" % (name, "PASS" if ok else "FAIL", detail))
    return ok


def main():
    cts0, sts0 = fresh_secrets()
    client = make_endpoint("client", cts0, sts0)
    server = make_endpoint("server", cts0, sts0)
    results = []

    # ---- Scenario 1: baseline app data both directions ------------------
    c_rec = build_record(client, TLSApplicationData(data=b"c-hello-0"))
    pkt, ok, plain = dissect_record(server, c_rec, strict=True)
    results.append(report("baseline client->server appdata", ok and plain == [("app", b"c-hello-0")], str(plain)))
    s_rec = build_record(server, TLSApplicationData(data=b"s-hello-0"))
    pkt, ok, plain = dissect_record(client, s_rec, strict=True)
    results.append(report("baseline server->client appdata", ok and plain == [("app", b"s-hello-0")], str(plain)))

    # ---- Scenario 2: one-sided KeyUpdate (client updates write keys) ----
    ku = build_record(client, TLS13KeyUpdate(request_update=0))
    pkt, ok, plain = dissect_record(server, ku, strict=True)
    results.append(report("one-sided: KeyUpdate authenticates", ok and plain == [("keyupdate", 0)], str(plain)))
    # post-update record must use new client write key
    c_rec1 = build_record(client, TLSApplicationData(data=b"c-after-update-1"))
    pkt, ok, plain = dissect_record(server, c_rec1, strict=True)
    results.append(report("one-sided: post-KU appdata authenticates", ok and plain == [("app", b"c-after-update-1")], str(plain)))
    # server's own write direction must be untouched
    s_rec1 = build_record(server, TLSApplicationData(data=b"s-still-old-1"))
    pkt, ok, plain = dissect_record(client, s_rec1, strict=True)
    results.append(report("one-sided: peer write direction untouched", ok and plain == [("app", b"s-still-old-1")], str(plain)))

    # ---- Scenario 3: request_update=1 semantics -------------------------
    ku_req = build_record(client, TLS13KeyUpdate(request_update=1))
    pkt, ok, plain = dissect_record(server, ku_req, strict=True)
    results.append(report("request: KeyUpdate(1) authenticates", ok and plain == [("keyupdate", 1)], str(plain)))
    # RFC8446 4.6.3: receiver MUST respond with its own KeyUpdate
    resp = build_record(server, TLS13KeyUpdate(request_update=0))
    pkt, ok, plain = dissect_record(client, resp, strict=True)
    results.append(report("request: server response KeyUpdate auth", ok and plain == [("keyupdate", 0)], str(plain)))
    # both sides now on generation 2
    c_rec2 = build_record(client, TLSApplicationData(data=b"c-gen2"))
    pkt, ok, plain = dissect_record(server, c_rec2, strict=True)
    results.append(report("request: client gen2 appdata", ok and plain == [("app", b"c-gen2")], str(plain)))
    s_rec2 = build_record(server, TLSApplicationData(data=b"s-gen2"))
    pkt, ok, plain = dissect_record(client, s_rec2, strict=True)
    results.append(report("request: server gen2 appdata", ok and plain == [("app", b"s-gen2")], str(plain)))

    # ---- Scenario 4: both ends update successively ----------------------
    ku_c = build_record(client, TLS13KeyUpdate(request_update=0))
    dissect_record(server, ku_c, strict=True)
    ku_s = build_record(server, TLS13KeyUpdate(request_update=0))
    dissect_record(client, ku_s, strict=True)
    ku_c2 = build_record(client, TLS13KeyUpdate(request_update=0))
    dissect_record(server, ku_c2, strict=True)
    c3 = build_record(client, TLSApplicationData(data=b"c-gen3"))
    pkt, ok, plain = dissect_record(server, c3, strict=True)
    results.append(report("successive: client gen3 appdata", ok and plain == [("app", b"c-gen3")], str(plain)))
    s3 = build_record(server, TLSApplicationData(data=b"s-gen2-still"))
    pkt, ok, plain = dissect_record(client, s3, strict=True)
    results.append(report("successive: server gen2 unaffected", ok and plain == [("app", b"s-gen2-still")], str(plain)))

    # ---- Scenario 5a: truncated update record (fresh sessions) ----------
    tc = make_endpoint("client", cts0, sts0)
    ts = make_endpoint("server", cts0, sts0)
    ku_trunc = build_record(tc, TLS13KeyUpdate(request_update=0))
    truncated = ku_trunc[:-3]  # strip 3 tag bytes; header length now lies
    # fix the record length field to match the shortened ciphertext
    inner_len = len(truncated) - 5
    truncated = truncated[:3] + struct.pack("!H", inner_len) + truncated[5:]
    pkt, ok, plain = dissect_record(ts, truncated, strict=True)
    results.append(report("truncated KU: strict rejects", not ok, "ok=%r" % ok))
    # non-strict: must NOT be treated as authenticated success
    pkt2, ok2, plain2 = dissect_record(ts, truncated, strict=False)
    results.append(report("truncated KU: lenient flags unauth", ok2 is False, "ok=%r plain=%r" % (ok2, plain2)))
    n_secrets = len(ts.tls13_derived_secrets["client_traffic_secrets"])
    results.append(report("truncated KU: state not rotated",
                          ts.prcs is None and not ts.triggered_prcs_commit
                          and n_secrets == 1,
                          "prcs=%r trig=%r secrets=%d" % (
                              ts.prcs, ts.triggered_prcs_commit, n_secrets)))

    # ---- Scenario 5b: authentication failure (fresh sessions) ------------
    bc = make_endpoint("client", cts0, sts0)
    bs = make_endpoint("server", cts0, sts0)
    rcs_ref = bs.rcs
    ku_bad = bytearray(build_record(bc, TLS13KeyUpdate(request_update=0)))
    ku_bad[-1] ^= 0xFF
    pkt, ok, plain = dissect_record(bs, bytes(ku_bad), strict=True)
    results.append(report("bad-tag KU: strict rejects", not ok, "ok=%r" % ok))
    # lenient dissection of the same forged record (fresh session): this is
    # the path where unauthenticated plaintext used to rotate the state
    bs = make_endpoint("server", cts0, sts0)
    rcs_ref = bs.rcs
    pkt, ok, plain = dissect_record(bs, bytes(ku_bad), strict=False)
    results.append(report("bad-tag KU: lenient yields no auth plaintext",
                          ok is False and plain == [("Raw", None)], str(plain)))
    # critical: after a failed update, the read state must not have rotated
    rcs_kept = bs.rcs is rcs_ref
    n_secrets = len(bs.tls13_derived_secrets["client_traffic_secrets"])
    results.append(report("bad-tag KU: state not rotated",
                          bs.prcs is None and not bs.triggered_prcs_commit
                          and rcs_kept and n_secrets == 1,
                          "prcs=%r trig=%r rcs_kept=%r secrets=%d" % (
                              bs.prcs, bs.triggered_prcs_commit, rcs_kept, n_secrets)))

    print("\n%d/%d passed" % (sum(results), len(results)))
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
