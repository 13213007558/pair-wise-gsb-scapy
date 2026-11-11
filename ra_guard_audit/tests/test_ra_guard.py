"""Assertion tests for the offline RA-guard checker.

The tests run against the synthetic capture produced by
``make_sample_pcap.py`` so the same bytes back the report and the unit checks.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import PcapReader  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402

from raguard.constants import (  # noqa: E402
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
    VERDICT_OUT_OF_SCOPE,
    VERDICT_RA,
    VERDICT_VIOLATION,
)
from raguard.engine import RaGuardInspector  # noqa: E402

PCAP = PROJECT_ROOT / "samples" / "ra_guard_sample.pcap"


def _records():
    inspector = RaGuardInspector()
    return inspector.inspect_file(PCAP), inspector.summary()


def test_capture_exists_and_frame_count():
    frames = list(PcapReader(str(PCAP)))
    assert len(frames) == 23


def test_verdict_counts():
    records, summary = _records()
    assert summary.counts[VERDICT_RA] == 4
    assert summary.counts[VERDICT_VIOLATION] == 7
    assert summary.counts[VERDICT_INCONCLUSIVE] == 4
    assert summary.counts[VERDICT_BENIGN] == 7
    assert summary.counts[VERDICT_OUT_OF_SCOPE] == 1
    assert len(records) == 23


def test_valid_ra_uses_full_criteria_not_type_only():
    records, _ = _records()
    first = records[0]
    assert first.verdict == VERDICT_RA
    assert first.reasons == ["valid_ra"]
    assert first.hop_limit == 255
    assert first.icmpv6_type == 134
    assert first.checksum_declared == first.checksum_computed


def test_hop_limit_attack_is_violation():
    records, _ = _records()
    record = records[1]
    assert record.verdict == VERDICT_VIOLATION
    assert "nd_hop_limit_not_255" in record.reasons
    assert record.hop_limit == 1


def test_non_link_local_source_ra_is_violation():
    records, _ = _records()
    record = records[2]
    assert record.verdict == VERDICT_VIOLATION
    assert "ra_source_not_link_local" in record.reasons


def test_extension_header_chain_is_walked():
    records, _ = _records()
    for index in (3, 4, 5):
        assert records[index].verdict == VERDICT_RA
        assert records[index].extension_headers
        assert records[index].icmpv6_type == 134


def test_malformed_ra_fails_structure_and_checksum():
    records, _ = _records()
    record = records[6]
    assert record.verdict == VERDICT_VIOLATION
    assert "ra_shorter_than_16_octets" in record.reasons
    assert "icmpv6_checksum_bad" in record.reasons


def test_rfc6980_fragmented_ra():
    records, _ = _records()
    first, second = records[7], records[8]
    assert first.verdict == VERDICT_VIOLATION
    assert "fragmented_neighbor_discovery_rfc6980" in first.reasons
    assert second.verdict == VERDICT_VIOLATION
    assert "non_initial_fragment_of_nd_flow_rfc6980" in second.reasons


def test_undersized_initial_fragment_never_passed():
    records, _ = _records()
    for index in (9, 10):
        assert records[index].verdict == VERDICT_VIOLATION
        assert "fragment_0_hides_nd_type_rfc6980" in records[index].reasons


def test_orphan_fragment_is_inconclusive_not_benign():
    records, _ = _records()
    record = records[11]
    assert record.verdict == VERDICT_INCONCLUSIVE
    assert record.reasons == ["fragment_flow_incomplete"]


def test_fragmented_non_nd_udp_is_benign():
    records, _ = _records()
    for index in (12, 13):
        assert records[index].verdict == VERDICT_BENIGN
        assert "fragmented_non_nd_traffic" in records[index].reasons


def test_0x86_in_tcp_and_udp_payload_is_not_an_ra():
    records, _ = _records()
    for index in (14, 15):
        assert records[index].verdict == VERDICT_BENIGN
        assert records[index].reasons == ["not_icmpv6"]
        assert records[index].icmpv6_type is None


def test_non_ra_icmpv6_and_nd_are_benign():
    records, _ = _records()
    # Frame 17 echo request, frames 19-20 neighbor solicitation / advert.
    for index in (16, 18, 19):
        assert records[index].verdict == VERDICT_BENIGN
        assert "non_ra_icmpv6" in records[index].reasons


def test_esp_is_inconclusive_without_keys():
    records, _ = _records()
    record = records[17]
    assert record.verdict == VERDICT_INCONCLUSIVE
    assert record.reasons == ["esp_payload_encrypted"]


def test_truncated_frames_are_inconclusive():
    records, _ = _records()
    truncated = records[20]
    chain = records[21]
    assert truncated.verdict == VERDICT_INCONCLUSIVE
    assert truncated.reasons == ["truncated_icmpv6_header"]
    assert chain.verdict == VERDICT_INCONCLUSIVE
    assert chain.reasons == ["truncated_extension_header"]


def test_non_ipv6_frame_is_out_of_scope():
    records, _ = _records()
    record = records[22]
    assert record.verdict == VERDICT_OUT_OF_SCOPE
    assert record.src is None


def test_records_locate_original_frames():
    records, _ = _records()
    frames = list(PcapReader(str(PCAP)))
    for record, packet in zip(records, frames):
        if IPv6 in packet:
            assert record.src == str(packet[IPv6].src)
        assert record.wire_length == packet.wirelen
        assert record.frame == packet.frame_count if hasattr(
            packet, "frame_count"
        ) else True


def _main():
    failures = 0
    functions = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for function in functions:
        try:
            function()
            print("PASS %s" % function.__name__)
        except AssertionError as exc:
            failures += 1
            print("FAIL %s: %s" % (function.__name__, exc))
    print("%d tests, %d failures" % (len(functions), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_main())
