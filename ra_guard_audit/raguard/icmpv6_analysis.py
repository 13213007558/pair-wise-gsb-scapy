"""ICMPv6 structure checks used by the RA-guard decision logic.

Validation deliberately works on raw octets plus a parsed Scapy IPv6 layer so
that a malformed or truncated message cannot be normalised into a valid one.
Checksums are recomputed from the captured bytes; Scapy's automatic checksum
handling is bypassed because it would hide a deliberately bad checksum.
"""

import socket
from dataclasses import dataclass, field

from scapy.layers.inet6 import IPv6

from .constants import (
    ICMPV6_RA,
    ND_MESSAGE_TYPES,
    ND_REQUIRED_HOP_LIMIT,
    RA_MIN_LENGTH,
    REASON_ICMPV6_CHECKSUM,
    REASON_RA_BAD_CODE,
    REASON_RA_DESTINATION,
    REASON_RA_TOO_SHORT,
    REASON_SOURCE_SCOPE,
)


@dataclass
class Icmpv6Evidence:
    """What could be established about an ICMPv6 message."""

    icmpv6_type: int | None
    code: int | None
    declared_checksum: int | None
    computed_checksum: int | None
    is_neighbor_discovery: bool
    is_router_advertisement: bool
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _ones_complement_sum(data: bytes) -> int:
    total = 0
    if len(data) % 2:
        data += b"\x00"
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def icmpv6_checksum(ip6: IPv6, icmpv6_bytes: bytes) -> int:
    """Compute the ICMPv6 checksum over the IPv6 pseudo-header (RFC 4443 2.3)."""
    pseudo_header = socket.inet_pton(socket.AF_INET6, ip6.src)
    pseudo_header += socket.inet_pton(socket.AF_INET6, ip6.dst)
    pseudo_header += len(icmpv6_bytes).to_bytes(4, "big")
    pseudo_header += b"\x00\x00\x00\x3a"
    zeroed = bytearray(icmpv6_bytes)
    zeroed[2] = 0
    zeroed[3] = 0
    total = _ones_complement_sum(pseudo_header + bytes(zeroed))
    return total ^ 0xFFFF


def is_link_local_unicast(address: str) -> bool:
    """RFC 4291: fe80::/10 is the link-local unicast scope."""
    exploded = address.lower()
    if exploded.startswith("fe8") or exploded.startswith("fe9"):
        return True
    if exploded.startswith("fea") or exploded.startswith("feb"):
        return True
    return False


def inspect_icmpv6(
    ip6: IPv6,
    icmpv6_bytes: bytes,
    captured_length: int,
    declared_length: int,
    hop_limit: int,
) -> Icmpv6Evidence:
    """Validate the ICMPv6 message carried by one fragmentable payload.

    ``captured_length`` / ``declared_length`` describe the L4 bytes actually
    present versus the octets the IPv6 header promised; a mismatch means the
    frame was truncated and the message cannot be fully validated.
    """
    evidence = Icmpv6Evidence(
        icmpv6_type=None,
        code=None,
        declared_checksum=None,
        computed_checksum=None,
        is_neighbor_discovery=False,
        is_router_advertisement=False,
    )

    if len(icmpv6_bytes) < 4:
        evidence.failures.append("truncated_icmpv6_header")
        evidence.notes.append(
            "fewer than four ICMPv6 header octets captured"
        )
        return evidence

    msg_type = icmpv6_bytes[0]
    code = icmpv6_bytes[1]
    declared = int.from_bytes(icmpv6_bytes[2:4], "big")
    evidence.icmpv6_type = msg_type
    evidence.code = code
    evidence.declared_checksum = declared
    evidence.is_neighbor_discovery = msg_type in ND_MESSAGE_TYPES
    evidence.is_router_advertisement = msg_type == ICMPV6_RA

    if captured_length < declared_length:
        evidence.notes.append(
            "snap truncated L4 payload: captured %d of %d declared octets"
            % (captured_length, declared_length)
        )

    if evidence.is_neighbor_discovery and hop_limit != ND_REQUIRED_HOP_LIMIT:
        evidence.failures.append("nd_hop_limit_not_255")
        evidence.notes.append(
            "ND type %d observed with hop limit %d" % (msg_type, hop_limit)
        )

    computed = icmpv6_checksum(ip6, icmpv6_bytes)
    evidence.computed_checksum = computed
    if computed != declared:
        evidence.failures.append(REASON_ICMPV6_CHECKSUM)
        evidence.notes.append(
            "checksum 0x%04x does not match computed 0x%04x"
            % (declared, computed)
        )

    if evidence.is_router_advertisement:
        if code != 0:
            evidence.failures.append(REASON_RA_BAD_CODE)
            evidence.notes.append("RA code field is %d, expected 0" % code)
        if len(icmpv6_bytes) < RA_MIN_LENGTH:
            evidence.failures.append(REASON_RA_TOO_SHORT)
            evidence.notes.append(
                "RA body is %d octets, fixed header requires %d"
                % (len(icmpv6_bytes), RA_MIN_LENGTH)
            )
        if not is_link_local_unicast(ip6.src):
            evidence.failures.append(REASON_SOURCE_SCOPE)
            evidence.notes.append(
                "RA source %s is outside fe80::/10" % ip6.src
            )
        if str(ip6.dst).lower() not in ("ff02::1",):
            # Unicast RAs exist (e.g. re-advertisement to a specific node) but
            # mirrored unsolicited traffic on a guard point is expected on the
            # all-nodes group; record rather than silently accept.
            if is_link_local_unicast(ip6.dst):
                evidence.notes.append(
                    "unicast RA destination %s" % ip6.dst
                )
            else:
                evidence.failures.append(REASON_RA_DESTINATION)
                evidence.notes.append(
                    "RA destination %s is neither ff02::1 nor link-local"
                    % ip6.dst
                )

    return evidence
