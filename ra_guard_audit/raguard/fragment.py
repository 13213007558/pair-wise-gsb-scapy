"""Fragment-flow tracking with RFC 6980 Neighbor Discovery semantics.

RFC 6980 section 4 forbids fragmentation of all Neighbor Discovery messages
and requires that an offset-zero fragment whose fragmentable part is too
short to reveal the ICMPv6 type be dropped.  Scapy's :func:`defragment6` only
handles one flow per call and patches gaps with filler bytes, so the checker
keeps its own per-flow state and records overlaps and missing tail data.
"""

from dataclasses import dataclass, field

from scapy.layers.inet6 import IPv6

from .constants import (
    ICMPV6_RA,
    ND_MESSAGE_TYPES,
    NH_ICMPV6,
    REASON_FRAGMENT_BENIGN,
    REASON_FRAGMENT_INCOMPLETE,
    REASON_FRAGMENT_OFFSET_ND,
    REASON_FRAGMENT_UNDERSIZED,
    REASON_FRAGMENTED_ND,
)

# RFC 4861 section 4.2 fixed header; the ICMPv6 type octet must be visible.
MIN_INITIAL_ICMPV6_BYTES = 1
FRAGMENT_TIMEOUT_SECONDS = 60


@dataclass
class FragmentFlow:
    """Reassembly state for one (src, dst, identification) tuple."""

    src: str
    dst: str
    identification: int
    next_header: int | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    received_total_length: int | None = None
    assembled: bytearray = field(default_factory=bytearray)
    present: list[tuple[int, int]] = field(default_factory=list)
    member_frames: list[int] = field(default_factory=list)
    overlaps: bool = False
    complete: bool = False
    more_last_seen: int = 0

    @property
    def key(self) -> tuple[str, str, int]:
        return self.src, self.dst, self.identification

    def add_fragment(
        self,
        frame_index: int,
        timestamp: float,
        next_header: int,
        offset: int,
        more_flag: int,
        data: bytes,
    ) -> None:
        if self.next_header is None:
            self.next_header = next_header
        elif self.next_header != next_header:
            self.overlaps = True
        if not self.member_frames:
            self.first_seen = timestamp
        self.last_seen = timestamp
        self.member_frames.append(frame_index)
        self.more_last_seen = more_flag

        end = offset + len(data)
        for existing_start, existing_end in self.present:
            if offset < existing_end and existing_start < end:
                self.overlaps = True
        self.present.append((offset, end))

        if end > len(self.assembled):
            self.assembled.extend(b"\x00" * (end - len(self.assembled)))
        self.assembled[offset:end] = data

        if more_flag == 0:
            self.received_total_length = end
            self.complete = self._has_no_gaps(end)

    def _has_no_gaps(self, total_length: int) -> bool:
        covered = bytearray(total_length)
        for start, end in self.present:
            for index in range(min(start, total_length), min(end, total_length)):
                covered[index] = 1
        return all(covered)

    def gap_ranges(self) -> list[tuple[int, int]]:
        if self.received_total_length is None:
            return []
        covered = bytearray(self.received_total_length)
        for start, end in self.present:
            for index in range(min(start, self.received_total_length),
                               min(end, self.received_total_length)):
                covered[index] = 1
        gaps: list[tuple[int, int]] = []
        index = 0
        while index < len(covered):
            if covered[index] == 0:
                start = index
                while index < len(covered) and covered[index] == 0:
                    index += 1
                gaps.append((start, index))
            else:
                index += 1
        return gaps

    @property
    def expired(self) -> bool:
        return self.last_seen - self.first_seen > FRAGMENT_TIMEOUT_SECONDS


def flow_key(ip6: IPv6, identification: int) -> tuple[str, str, int]:
    return str(ip6.src), str(ip6.dst), int(identification)


def initial_fragment_verdict(flow: FragmentFlow) -> tuple[str, str]:
    """Apply RFC 6980 checks to an offset-zero fragment without reassembly.

    Returns a ``(reason_code, human_note)`` pair.  An empty pair means the
    fragment needs full reassembly before a decision is possible.
    """
    if flow.next_header != NH_ICMPV6:
        return (
            REASON_FRAGMENT_BENIGN,
            "fragmented payload next header %d is not ICMPv6"
            % flow.next_header,
        )
    if not flow.present or flow.present[0][0] != 0:
        return ("", "")
    initial_end = flow.present[0][1]
    if initial_end < MIN_INITIAL_ICMPV6_BYTES:
        return (
            REASON_FRAGMENT_UNDERSIZED,
            "offset-zero fragment carries %d fragmentable octet(s), so the "
            "ICMPv6 type is not visible; RFC 6980 section 4 requires "
            "dropping this fragment" % initial_end,
        )
    icmpv6_type = flow.assembled[0]
    if icmpv6_type in ND_MESSAGE_TYPES:
        return (
            REASON_FRAGMENTED_ND,
            "offset-zero fragment reveals ICMPv6 ND type %d; RFC 6980 "
            "section 4 forbids fragmented Neighbor Discovery" % icmpv6_type,
        )
    return ("", "")


def reassembled_nd_verdict(flow: FragmentFlow) -> tuple[str, str]:
    """Classify a fully reassembled fragment flow."""
    if flow.next_header != NH_ICMPV6:
        return (
            REASON_FRAGMENT_BENIGN,
            "reassembled next header %d is not ICMPv6" % flow.next_header,
        )
    if not flow.assembled:
        return (
            REASON_FRAGMENT_INCOMPLETE,
            "reassembled flow has no payload octets",
        )
    icmpv6_type = flow.assembled[0]
    if icmpv6_type in ND_MESSAGE_TYPES:
        label = "RA" if icmpv6_type == ICMPV6_RA else "ND type %d" % icmpv6_type
        return (
            REASON_FRAGMENTED_ND,
            "reassembled payload is a fragmented %s (RFC 6980 section 4)"
            % label,
        )
    return (
        REASON_FRAGMENT_BENIGN,
        "reassembled ICMPv6 type %d is not Neighbor Discovery" % icmpv6_type,
    )


def non_initial_fragment_reason(flow: FragmentFlow) -> tuple[str, str]:
    """Reason recorded on each non-initial fragment frame."""
    has_initial = bool(flow.present) and flow.present[0][0] == 0
    if flow.next_header == NH_ICMPV6 and has_initial and \
            flow.present[0][1] >= MIN_INITIAL_ICMPV6_BYTES and \
            flow.assembled[0] in ND_MESSAGE_TYPES:
        return (
            REASON_FRAGMENT_OFFSET_ND,
            "non-initial fragment of a flow whose offset-zero fragment is an "
            "ICMPv6 Neighbor Discovery message (RFC 6980 section 4)",
        )
    if not has_initial:
        return (
            REASON_FRAGMENT_INCOMPLETE,
            "non-initial fragment without any offset-zero fragment in trace",
        )
    return (
        REASON_FRAGMENT_BENIGN,
        "non-initial fragment of a non-ND fragment flow",
    )
