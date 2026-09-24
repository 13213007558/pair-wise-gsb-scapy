# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
TCP stream editor for offline captures.

This module rewrites the packets of a fully captured, bidirectional TCP
connection so that an interval of one reassembled application stream is
replaced by new (possibly longer or shorter) content.  Every sequence
related field (SEQ, ACK, SACK blocks, and the sequence number consumed
by FIN) is translated to the new sequence space, and IP/TCP lengths and
checksums are recomputed.  The input packets are left unmodified.

Boundary mapping rule
---------------------

Replacing the stream interval [start, end) by N new bytes shifts every
position after the interval by delta = N - (end - start).  Positions
inside the replaced interval no longer exist in the new stream, so they
are mapped to a boundary of the replacement:

- floor(pos) collapses an interior position to the BEGINNING of the
  replacement.  It is used for SEQ and ACK numbers and for the left
  edge of SACK blocks: an acknowledgment may only confirm data up to
  the beginning of the modified region.
- ceil(pos) expands an interior position to the END of the replacement.
  It is used for segment ends and for the right edge of SACK blocks, so
  that a segment overlapping the edited region carries the whole
  replacement.

Retransmissions of the same old segment map to the same new segment and
therefore carry the exact same replacement bytes.

The edit is refused (TCPStreamEditError) when the capture is incomplete
(missing SYN, gaps in either reassembled stream) or when retransmitted
fragments conflict.
"""

from typing import Dict, List, Optional, Tuple

from scapy.compat import bytes_encode
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet, Raw

__all__ = ["TCPStreamEditError", "tcp_stream_edit"]

_TCP_MOD = 1 << 32
_TCP_HALF = 1 << 31

_TCP_SYN = 0x02
_TCP_ACK = 0x10


class TCPStreamEditError(Exception):
    """Raised when a TCP stream edit cannot be performed."""


class _SeqMap(object):
    """Maps positions of the old stream to positions of the new stream."""

    def __init__(self, start=None, end=None, replen=0):
        # type: (Optional[int], Optional[int], int) -> None
        self.start = start
        self.end = end
        self.delta = 0 if start is None else replen - (end - start)

    def floor(self, pos):
        # type: (int) -> int
        """Map a position, collapsing the edited interval to its start."""
        if self.start is None or pos < self.start:
            return pos
        if pos < self.end:
            return self.start
        return pos + self.delta

    def ceil(self, pos):
        # type: (int) -> int
        """Map a position, expanding the edited interval to its end."""
        if self.start is None or pos < self.start:
            return pos
        if pos == self.start:
            # The left edge of a non-empty interval belongs to the
            # preceding segment.  For a pure insertion (start == end)
            # it belongs to the following one.
            return pos if self.start < self.end else pos + self.delta
        if pos < self.end:
            return self.end + self.delta
        return pos + self.delta


class _Direction(object):
    """Reassembled state of one direction of the connection."""

    def __init__(self):
        # type: () -> None
        self.isn = None  # type: Optional[int]
        self.segments = []  # type: List[Tuple[int, bytes]]
        self.stream = b""
        self.seqmap = _SeqMap()

    @property
    def base(self):
        # type: () -> int
        """Sequence number of the first data byte."""
        return (self.isn + 1) % _TCP_MOD  # type: ignore

    def offset(self, seq):
        # type: (int) -> int
        """Stream offset of a sequence number (handles wraparound)."""
        off = (seq - self.base) % _TCP_MOD
        if off >= _TCP_HALF:
            raise TCPStreamEditError(
                "sequence number %d does not belong to this capture" % seq)
        return off

    def build(self):
        # type: () -> None
        """Reassemble the stream, refusing incomplete or conflicting data."""
        if self.isn is None:
            raise TCPStreamEditError(
                "connection is not fully captured: missing SYN")
        stream = bytearray()
        for offset, data in sorted(self.segments, key=lambda seg: seg[0]):
            if offset > len(stream):
                raise TCPStreamEditError(
                    "capture has a gap at stream offset %d" % len(stream))
            overlap = len(stream) - offset
            if data[:overlap] != bytes(stream[offset:]):
                raise TCPStreamEditError(
                    "conflicting retransmission at stream offset %d" % offset)
            stream += data[overlap:]
        self.stream = bytes(stream)


def tcp_stream_edit(packets, src, sport, dst, dport, start, end, replacement):
    # type: (List[Packet], str, int, str, int, int, int, bytes) -> List[Packet]
    """Rewrite a TCP connection with a replaced stream interval.

    :param packets: packets of an offline capture (e.g. from rdpcap())
    :param src, sport, dst, dport: 4-tuple of the connection; the edit
        applies to the stream flowing from (src, sport) to (dst, dport)
    :param start, end: byte interval of the reassembled src->dst stream
        to be replaced
    :param replacement: bytes inserted in place of the interval
    :return: a new list of packets with recomputed lengths and checksums;
        the input packets are not modified
    :raises TCPStreamEditError: if the connection is not fully captured
        or contains conflicting fragments
    """
    replacement = bytes(bytes_encode(replacement))
    if not 0 <= start <= end:
        raise TCPStreamEditError(
            "invalid edit interval [%d, %d)" % (start, end))

    directions = {"fwd": _Direction(), "rev": _Direction()}
    conn = {}  # type: Dict[int, str]
    for i, pkt in enumerate(packets):
        tcp = pkt.getlayer(TCP)
        if tcp is None:
            continue
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            continue
        if (ip.src, ip.dst, tcp.sport, tcp.dport) == (src, dst, sport, dport):
            way = "fwd"
        elif (ip.src, ip.dst, tcp.sport, tcp.dport) == (
                dst, src, dport, sport):
            way = "rev"
        else:
            continue
        direc = directions[way]
        flags = int(tcp.flags)
        payload = bytes(tcp.payload)
        if flags & _TCP_SYN:
            if payload:
                raise TCPStreamEditError(
                    "SYN with data is not supported")
            if direc.isn is None:
                direc.isn = tcp.seq
            elif direc.isn != tcp.seq:
                raise TCPStreamEditError(
                    "conflicting SYN sequence numbers")
        elif payload:
            if direc.isn is None:
                raise TCPStreamEditError(
                    "data before SYN: capture is incomplete")
            direc.segments.append((direc.offset(tcp.seq), payload))
        conn[i] = way

    if not conn:
        raise TCPStreamEditError("no packets match the given connection")
    fwd = directions["fwd"]
    rev = directions["rev"]
    fwd.build()
    rev.build()
    if end > len(fwd.stream):
        raise TCPStreamEditError(
            "edit interval exceeds the reassembled stream (%d bytes)"
            % len(fwd.stream))
    fwd.seqmap = _SeqMap(start, end, len(replacement))
    newstream = fwd.stream[:start] + replacement + fwd.stream[end:]
    streams = {"fwd": newstream, "rev": rev.stream}

    out = []
    for i, pkt in enumerate(packets):
        way = conn.get(i)
        pkt = pkt.copy()
        if way is None:
            out.append(pkt)
            continue
        tcp = pkt.getlayer(TCP)
        direc = directions[way]
        peer = directions["rev" if way == "fwd" else "fwd"]
        flags = int(tcp.flags)
        payload = bytes(tcp.payload)
        if flags & _TCP_SYN:
            newdata = b""
        else:
            oldoff = direc.offset(tcp.seq)
            begin = direc.seqmap.floor(oldoff)
            tcp.seq = (direc.base + begin) % _TCP_MOD
            if payload:
                stop = direc.seqmap.ceil(oldoff + len(payload))
                newdata = streams[way][begin:stop]
            else:
                newdata = b""
        if flags & _TCP_ACK:
            tcp.ack = (peer.base +
                       peer.seqmap.floor(peer.offset(tcp.ack))) % _TCP_MOD
        options = []
        for oname, oval in tcp.options:
            if oname != "SAck":
                options.append((oname, oval))
                continue
            blocks = []
            for j in range(0, len(oval) - 1, 2):
                left = peer.seqmap.floor(peer.offset(oval[j]))
                right = peer.seqmap.ceil(peer.offset(oval[j + 1]))
                if left < right:
                    blocks.append((peer.base + left) % _TCP_MOD)
                    blocks.append((peer.base + right) % _TCP_MOD)
            if blocks:
                options.append(("SAck", tuple(blocks)))
        tcp.options = options
        tcp.remove_payload()
        if newdata:
            pkt = pkt / Raw(newdata)
        # Recompute lengths and checksums
        tcp = pkt.getlayer(TCP)
        del tcp.chksum
        del tcp.dataofs
        ip = pkt.getlayer(IP)
        if ip is not None:
            del ip.len
            del ip.chksum
        else:
            del pkt.getlayer(IPv6).plen
        out.append(pkt.__class__(bytes(pkt)))
    return out
