"""Offline RA-guard inspection engine.

The engine performs two streaming passes over a pcap:

1. Every frame is parsed on its captured octets so truncation, extension
   headers and fragmentation are detected instead of being normalised away.
2. Fragment flows are reassembled per RFC 6980 and their member frames are
   revisited once the flow outcome is known.

Frames that cannot be decided reliably are kept with an explicit reason; they
never default to "pass".
"""

from dataclasses import dataclass, field, asdict
from pathlib import Path

from scapy.all import PcapReader
from scapy.layers.inet6 import IPv6

from .chain import parse_header_chain
from .constants import (
    NH_ESP,
    NH_ICMPV6,
    REASON_ESP_PAYLOAD,
    REASON_FRAGMENT_BENIGN,
    REASON_FRAGMENT_INCOMPLETE,
    REASON_FRAGMENT_OFFSET_ND,
    REASON_FRAGMENT_UNDERSIZED,
    REASON_FRAGMENTED_ND,
    REASON_NON_IPV6,
    REASON_NON_RA_ICMPV6,
    REASON_NOT_ICMPV6,
    REASON_TRUNCATED_ICMPV6,
    REASON_TRUNCATED_IPV6,
    REASON_VALID_RA,
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
    VERDICT_OUT_OF_SCOPE,
    VERDICT_RA,
    VERDICT_VIOLATION,
)
from .fragment import (
    FragmentFlow,
    flow_key,
    initial_fragment_verdict,
    non_initial_fragment_reason,
    reassembled_nd_verdict,
)
from .icmpv6_analysis import inspect_icmpv6


@dataclass
class FrameRecord:
    """Decision and locating evidence for one pcap frame."""

    frame: int
    timestamp: float
    wire_length: int
    captured_length: int
    src: str | None
    dst: str | None
    hop_limit: int | None
    verdict: str
    reasons: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    extension_headers: list[int] = field(default_factory=list)
    fragment_id: int | None = None
    fragment_offset: int | None = None
    fragment_more: int | None = None
    flow_key: str | None = None
    icmpv6_type: int | None = None
    checksum_declared: int | None = None
    checksum_computed: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InspectionSummary:
    total_frames: int = 0
    ipv6_frames: int = 0
    counts: dict = field(
        default_factory=lambda: {
            VERDICT_RA: 0,
            VERDICT_VIOLATION: 0,
            VERDICT_INCONCLUSIVE: 0,
            VERDICT_BENIGN: 0,
            VERDICT_OUT_OF_SCOPE: 0,
        }
    )
    fragment_flows: int = 0
    incomplete_flows: int = 0


class RaGuardInspector:
    """Reusable, stateful inspector for one pcap file."""

    def __init__(self) -> None:
        self.records: list[FrameRecord] = []
        self._flows: dict[tuple[str, str, int], FragmentFlow] = {}
        self._frame_flow: dict[int, tuple[str, str, int]] = {}
        self._pending_fragment_frames: set[int] = set()

    def inspect_file(self, pcap_path: str | Path) -> list[FrameRecord]:
        pcap_path = Path(pcap_path)
        with PcapReader(str(pcap_path)) as reader:
            for frame_index, packet in enumerate(reader, start=1):
                self._inspect_frame(frame_index, packet)
        self._finalize_flows()
        return self.records

    def _record(self, frame_index: int, packet, **kwargs) -> FrameRecord:
        ip6 = packet[IPv6] if IPv6 in packet else None
        record = FrameRecord(
            frame=frame_index,
            timestamp=float(packet.time),
            wire_length=int(packet.wirelen),
            captured_length=len(packet),
            src=str(ip6.src) if ip6 is not None else None,
            dst=str(ip6.dst) if ip6 is not None else None,
            hop_limit=int(ip6.hlim) if ip6 is not None else None,
            **kwargs,
        )
        self.records.append(record)
        return record

    def _inspect_frame(self, frame_index: int, packet) -> None:
        if IPv6 not in packet:
            self._record(
                frame_index,
                packet,
                verdict=VERDICT_OUT_OF_SCOPE,
                reasons=[REASON_NON_IPV6],
                details=["frame does not carry IPv6"],
            )
            return

        chain = parse_header_chain(packet)
        ip6 = packet[IPv6]

        if chain is None or (
            chain.truncated
            and chain.truncation_reason == REASON_TRUNCATED_IPV6
        ):
            self._record(
                frame_index,
                packet,
                verdict=VERDICT_INCONCLUSIVE,
                reasons=[REASON_TRUNCATED_IPV6],
                details=chain.chain_notes if chain else ["no IPv6 header"],
            )
            return

        if chain.fragment is not None:
            self._handle_fragment(frame_index, packet, chain)
            return

        self._handle_terminal(frame_index, packet, chain)

    def _handle_terminal(self, frame_index: int, packet, chain) -> None:
        ip6 = packet[IPv6]
        base_kwargs = {
            "extension_headers": list(chain.extension_headers),
        }

        if chain.truncated:
            if chain.terminal_nh == NH_ICMPV6:
                reason = REASON_TRUNCATED_ICMPV6
            else:
                reason = chain.truncation_reason or "truncated_frame"
            self._record(
                frame_index,
                packet,
                verdict=VERDICT_INCONCLUSIVE,
                reasons=[reason],
                details=list(chain.chain_notes),
                **base_kwargs,
            )
            return

        if chain.terminal_nh == NH_ESP:
            self._record(
                frame_index,
                packet,
                verdict=VERDICT_INCONCLUSIVE,
                reasons=[REASON_ESP_PAYLOAD],
                details=[
                    "ESP payload hides the inner next header; no offline "
                    "decision is possible without keys"
                ],
                **base_kwargs,
            )
            return

        if chain.terminal_nh != NH_ICMPV6:
            self._record(
                frame_index,
                packet,
                verdict=VERDICT_BENIGN,
                reasons=[REASON_NOT_ICMPV6],
                details=[
                    "next header %d is not ICMPv6; a 0x86 octet in the "
                    "payload is application data, not an RA"
                    % chain.terminal_nh
                ],
                **base_kwargs,
            )
            return

        declared_l4 = int(ip6.plen) - chain.extension_octets
        evidence = inspect_icmpv6(
            ip6=ip6,
            icmpv6_bytes=chain.terminal_bytes,
            captured_length=len(chain.terminal_bytes),
            declared_length=declared_l4,
            hop_limit=chain.hop_limit,
        )
        details = list(chain.chain_notes) + list(evidence.notes)
        common = dict(
            reasons=list(evidence.failures),
            details=details,
            icmpv6_type=evidence.icmpv6_type,
            checksum_declared=evidence.declared_checksum,
            checksum_computed=evidence.computed_checksum,
            **base_kwargs,
        )

        if not evidence.is_router_advertisement:
            verdict = (
                VERDICT_VIOLATION
                if evidence.failures
                else VERDICT_BENIGN
            )
            common["reasons"] = evidence.failures or [REASON_NON_RA_ICMPV6]
            common["details"] = details + [
                "ICMPv6 type %s is not a Router Advertisement"
                % evidence.icmpv6_type
            ]
            self._record(
                frame_index,
                packet,
                verdict=verdict,
                **common,
            )
            return

        if evidence.failures:
            self._record(
                frame_index,
                packet,
                verdict=VERDICT_VIOLATION,
                **common,
            )
            return

        common["reasons"] = [REASON_VALID_RA]
        common["details"] = details + [
            "RA with hop limit 255, link-local source, zero code and a "
            "valid ICMPv6 checksum"
        ]
        self._record(
            frame_index,
            packet,
            verdict=VERDICT_RA,
            **common,
        )

    def _handle_fragment(self, frame_index: int, packet, chain) -> None:
        ip6 = packet[IPv6]
        fragment = chain.fragment
        key = flow_key(ip6, fragment.identification)
        flow = self._flows.setdefault(
            key,
            FragmentFlow(src=key[0], dst=key[1], identification=key[2]),
        )
        flow.add_fragment(
            frame_index=frame_index,
            timestamp=float(packet.time),
            next_header=fragment.next_header,
            offset=fragment.offset,
            more_flag=fragment.more_flag,
            data=fragment.fragmentable,
        )
        self._frame_flow[frame_index] = key
        self._pending_fragment_frames.add(frame_index)

        placeholder = self._record(
            frame_index,
            packet,
            verdict=VERDICT_INCONCLUSIVE,
            reasons=[REASON_FRAGMENT_INCOMPLETE],
            details=[
                "fragment frame held pending flow reassembly",
                "fragment offset %d, more flag %d, id 0x%08x"
                % (
                    fragment.offset,
                    fragment.more_flag,
                    fragment.identification,
                ),
            ],
            extension_headers=list(chain.extension_headers),
            fragment_id=fragment.identification,
            fragment_offset=fragment.offset,
            fragment_more=fragment.more_flag,
            flow_key="%s -> %s id=0x%08x" % key,
        )
        if chain.truncated:
            placeholder.details.extend(chain.chain_notes)

    def _finalize_flows(self) -> None:
        records_by_frame = {record.frame: record for record in self.records}
        for flow in self._flows.values():
            initial_reason, initial_note = initial_fragment_verdict(flow)
            final_reason, final_note = reassembled_nd_verdict(flow)
            for frame in flow.member_frames:
                record = records_by_frame[frame]
                if record.fragment_offset == 0:
                    if initial_reason:
                        self._apply_flow_verdict(
                            record, initial_reason, [initial_note], flow
                        )
                    elif flow.complete:
                        self._apply_flow_verdict(
                            record, final_reason, [final_note], flow
                        )
                    else:
                        self._mark_incomplete(record, flow)
                else:
                    reason, note = non_initial_fragment_reason(flow)
                    if (
                        reason == REASON_FRAGMENT_INCOMPLETE
                        and not flow.complete
                    ):
                        self._mark_incomplete(record, flow)
                    else:
                        self._apply_flow_verdict(record, reason, [note], flow)

    def _apply_flow_verdict(
        self, record: FrameRecord, reason: str, notes: list[str], flow: FragmentFlow
    ) -> None:
        if reason in (
            REASON_FRAGMENTED_ND,
            REASON_FRAGMENT_UNDERSIZED,
            REASON_FRAGMENT_OFFSET_ND,
        ):
            record.verdict = VERDICT_VIOLATION
        elif reason == REASON_FRAGMENT_BENIGN:
            record.verdict = VERDICT_BENIGN
        else:
            record.verdict = VERDICT_INCONCLUSIVE
        record.reasons = [reason]
        record.details = notes + [
            "flow members: %s" % ", ".join(map(str, flow.member_frames))
        ]
        if flow.overlaps:
            record.details.append("flow contains overlapping fragments")
        self._pending_fragment_frames.discard(record.frame)

    def _mark_incomplete(self, record: FrameRecord, flow: FragmentFlow) -> None:
        record.verdict = VERDICT_INCONCLUSIVE
        record.reasons = [REASON_FRAGMENT_INCOMPLETE]
        gaps = flow.gap_ranges()
        detail = (
            ["fragment flow never completed within the capture"]
            + (["missing byte ranges: %s" % gaps] if gaps else [])
        )
        record.details = detail + [
            "flow members: %s" % ", ".join(map(str, flow.member_frames))
        ]
        self._pending_fragment_frames.discard(record.frame)

    def summary(self) -> InspectionSummary:
        summary = InspectionSummary(total_frames=len(self.records))
        for record in self.records:
            summary.counts[record.verdict] += 1
            if record.src is not None:
                summary.ipv6_frames += 1
        summary.fragment_flows = len(self._flows)
        summary.incomplete_flows = sum(
            1 for flow in self._flows.values() if not flow.complete
        )
        return summary


def inspect_pcap(pcap_path: str | Path) -> tuple[list[FrameRecord], InspectionSummary]:
    """Convenience entry point returning frame records and a summary."""
    inspector = RaGuardInspector()
    records = inspector.inspect_file(pcap_path)
    return records, inspector.summary()
