"""Byte-level IPv6 header-chain walk with truncation awareness.

Scapy happily turns missing bytes into :class:`Raw` payloads, which hides the
difference between "the next header really is raw bytes" and "the capture was
cut short".  RA-guard review must keep those apart, so the chain is walked on
the captured octets and every step is length checked.
"""

from dataclasses import dataclass, field

from scapy.layers.inet6 import IPv6

from .constants import (
    EXTENSION_HEADERS,
    NH_AH,
    NH_DEST_OPT,
    NH_FRAGMENT,
    NH_HOP_BY_HOP,
    NH_ROUTING,
)

IPV6_FIXED_HEADER_LEN = 40
FRAGMENT_HEADER_LEN = 8


@dataclass
class FragmentInfo:
    """Parsed content of an IPv6 Fragment Header (RFC 8200 section 4.5)."""

    next_header: int
    outer_next_header: int
    offset: int
    more_flag: int
    identification: int
    fragmentable: bytes


@dataclass
class HeaderChain:
    """Result of walking one captured IPv6 packet.

    ``terminal_nh`` is the next-header value that terminates the chain;
    ``terminal_bytes`` are the octets left for that terminal protocol.  When a
    fragment header is present ``fragment`` describes it and the terminal
    protocol is only observable on the offset-zero fragment.
    """

    terminal_nh: int
    terminal_bytes: bytes
    hop_limit: int
    extension_octets: int = 0
    fragment: FragmentInfo | None = None
    extension_headers: list[int] = field(default_factory=list)
    truncated: bool = False
    truncation_reason: str | None = None
    chain_notes: list[str] = field(default_factory=list)


def _extension_length(next_header: int, data: bytes, offset: int) -> int:
    """Return the total length in octets of the extension header at offset."""
    if next_header == NH_FRAGMENT:
        return FRAGMENT_HEADER_LEN
    if next_header == NH_AH:
        # RFC 4302: payload length field counts 32-bit words minus 2.
        if offset + 2 > len(data):
            return -1
        return int(data[offset + 1]) * 4 + 8
    # Hop-by-Hop, Destination Options, Routing (type 0) and Mobility all use
    # the RFC 8200 generic TLV framing: one length octet in 8-octet units,
    # not counting the first eight octets.
    if next_header in (NH_HOP_BY_HOP, NH_DEST_OPT, NH_ROUTING):
        if offset + 2 > len(data):
            return -1
        return int(data[offset + 1]) * 8 + 8
    return -1


def parse_header_chain(packet) -> HeaderChain | None:
    """Walk the extension header chain of a frame containing an IPv6 layer.

    Returns ``None`` for frames that do not carry IPv6.  Truncated captures
    produce a chain flagged :attr:`HeaderChain.truncated` rather than raising.
    """
    if IPv6 not in packet:
        return None

    ip6 = packet[IPv6]
    captured = bytes(ip6)
    hop_limit = int(ip6.hlim)

    if len(captured) < IPV6_FIXED_HEADER_LEN:
        return HeaderChain(
            terminal_nh=int(captured[6]) if len(captured) > 6 else -1,
            terminal_bytes=b"",
            hop_limit=hop_limit,
            truncated=True,
            truncation_reason="truncated_ipv6_header",
        )

    next_header = int(captured[6])
    declared_payload = int(ip6.plen)
    actual_payload = len(captured) - IPV6_FIXED_HEADER_LEN
    if actual_payload < declared_payload:
        # The snap length cut the packet inside its declared payload.
        payload = captured[IPV6_FIXED_HEADER_LEN:]
        snap_truncated = True
    else:
        payload = captured[IPV6_FIXED_HEADER_LEN:]
        snap_truncated = False

    offset = 0
    seen: list[int] = []
    fragment_info: FragmentInfo | None = None

    while next_header in EXTENSION_HEADERS:
        seen.append(next_header)
        if next_header == NH_FRAGMENT:
            if offset + FRAGMENT_HEADER_LEN > len(payload):
                return HeaderChain(
                    terminal_nh=next_header,
                    terminal_bytes=b"",
                    hop_limit=hop_limit,
                    fragment=fragment_info,
                    extension_headers=seen,
                    truncated=True,
                    truncation_reason="truncated_extension_header",
                    chain_notes=["fragment header truncated by snap length"],
                )
            frag_offset = offset
            outer_nh = next_header
            fragmentable_nh = payload[frag_offset]
            field16 = int.from_bytes(
                payload[frag_offset + 2:frag_offset + 4], "big"
            )
            frag_offset_blocks = field16 >> 3
            more_flag = field16 & 0x1
            identification = int.from_bytes(
                payload[frag_offset + 4:frag_offset + 8], "big"
            )
            fragment_info = FragmentInfo(
                next_header=fragmentable_nh,
                outer_next_header=outer_nh,
                offset=frag_offset_blocks * 8,
                more_flag=more_flag,
                identification=identification,
                fragmentable=payload[frag_offset + FRAGMENT_HEADER_LEN:],
            )
            # The fragment header is always the last extension header on the
            # wire; everything after it belongs to the fragmentable part.
            next_header = fragmentable_nh
            offset += FRAGMENT_HEADER_LEN
            break

        ext_len = _extension_length(next_header, payload, offset)
        if ext_len < 0 or offset + ext_len > len(payload):
            return HeaderChain(
                terminal_nh=next_header,
                terminal_bytes=payload[offset:],
                hop_limit=hop_limit,
                fragment=fragment_info,
                extension_headers=seen,
                truncated=True,
                truncation_reason="truncated_extension_header",
                chain_notes=[
                    "extension header %d extends past captured bytes"
                    % next_header
                ],
            )
        next_header = payload[offset]
        offset += ext_len

    terminal_bytes = payload[offset:]
    chain = HeaderChain(
        terminal_nh=next_header,
        terminal_bytes=terminal_bytes,
        hop_limit=hop_limit,
        extension_octets=offset,
        fragment=fragment_info,
        extension_headers=seen,
    )
    if snap_truncated:
        chain.truncated = True
        chain.truncation_reason = (
            "truncated_extension_header"
            if fragment_info is not None and not terminal_bytes
            else "truncated_icmpv6_header"
        )
        chain.chain_notes.append(
            "captured %d payload octets, IPv6 payload length declares %d"
            % (actual_payload, declared_payload)
        )
    return chain
