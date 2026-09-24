# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Offline TCP stream editor.

Rewrite the application payload of a fully captured, bidirectional TCP
connection (e.g. packets read from a pcap file) and fix up every sequence
and acknowledgment number, including SACK blocks and FIN, so that the
resulting packet sequence stays consistent with the edited stream.

Only connections captured from their very beginning (SYN seen in both
directions) and without any missing segment are supported.  Anything
else is rejected.

Boundary mapping rules
----------------------

An edit replaces the old stream interval [start, end) with new bytes.
Old stream offsets are translated to new stream offsets as follows:

- an offset located before the edited interval is unchanged;
- an offset located after the edited interval is shifted by the
  cumulative length delta of all the edits located before it;
- an offset located strictly inside the edited interval is mapped to one
  of the boundaries of the replacement, depending on what it delimits:

  - map_lo (segment start, SACK block left edge) maps to the start
    of the replacement;
  - map_hi (segment end, cumulative ACK, SACK block right edge,
    FIN) maps to the end of the replacement.

Retransmissions of a same old interval map to the same new interval and
therefore carry the same replacement bytes.
"""

from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
)

from scapy.config import conf
from scapy.error import log_runtime
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import NoPayload, Packet, Raw

_SEQ_MODULO = 1 << 32


class TCPStreamEditError(ValueError):
    """A TCP stream edit cannot be performed."""


class StreamEdit(object):
    """Replacement of an interval of a reassembled TCP stream.

    :param sender: (ip, port) tuple of the endpoint that sends the
        edited stream, e.g. ("10.0.0.1", 1234).
    :param start: offset, in the reassembled stream, of the first
        replaced byte.
    :param end: offset, in the reassembled stream, of the first byte
        after the replaced interval.
    :param data: replacement bytes.
    """

    def __init__(self,
                 sender: Tuple[str, int],
                 start: int,
                 end: int,
                 data: bytes) -> None:
        self.sender = sender
        self.start = start
        self.end = end
        self.data = bytes(data)

    def __repr__(self) -> str:
        return "<StreamEdit %s:%d [%d, %d) -> %d bytes>" % (
            self.sender + (self.start, self.end, len(self.data)))


def _offset(seq: int, isn: int) -> int:
    """Stream offset of a sequence number (the SYN consumes one)."""
    return (seq - isn - 1) % _SEQ_MODULO


def _tcp_data(pkt: Packet) -> bytes:
    payload = pkt[TCP].payload
    if isinstance(payload, (NoPayload, conf.padding_layer)):
        return b""
    return bytes(payload)


class _Direction(object):
    """Reassembly state of one direction of a connection."""

    def __init__(self, endpoint: Tuple[str, int]) -> None:
        self.endpoint = endpoint
        self.isn: Optional[int] = None
        self.stream = bytearray()
        self.filled = bytearray()
        self.conflicts: List[Tuple[int, int]] = []

    def add_segment(self, offset: int, data: bytes) -> None:
        end = offset + len(data)
        if end > len(self.stream):
            grow = end - len(self.stream)
            self.stream += b"\x00" * grow
            self.filled += b"\x00" * grow
        conflict_start: Optional[int] = None
        for i, byte in enumerate(data):
            pos = offset + i
            if self.filled[pos]:
                if self.stream[pos] != byte:
                    if conflict_start is None:
                        conflict_start = pos
                    continue
            else:
                self.stream[pos] = byte
                self.filled[pos] = 1
            if conflict_start is not None:
                self.conflicts.append((conflict_start, pos))
                conflict_start = None
        if conflict_start is not None:
            self.conflicts.append((conflict_start, end))

    def check_complete(self) -> None:
        if 0 in self.filled:
            start = self.filled.index(0)
            end = self.filled.find(b"\x01", start)
            if end < 0:
                end = len(self.filled)
            raise TCPStreamEditError(
                "missing stream bytes [%d, %d) from %s:%d" % (
                    (start, end) + self.endpoint))


class _SeqMap(object):
    """Translate stream offsets between the old and the new stream of
    one direction, following the boundary mapping rules described in
    the module docstring.
    """

    def __init__(self, edits: List[StreamEdit]) -> None:
        self.edits = edits

    def map_lo(self, offset: int) -> int:
        shift = 0
        for edit in self.edits:
            if edit.start < offset < edit.end:
                return edit.start + shift
            if offset <= edit.start:
                break
            shift += len(edit.data) - (edit.end - edit.start)
        return offset + shift

    def map_hi(self, offset: int) -> int:
        shift = 0
        for edit in self.edits:
            if edit.start < offset < edit.end:
                return edit.start + shift + len(edit.data)
            if offset <= edit.start:
                break
            shift += len(edit.data) - (edit.end - edit.start)
        return offset + shift


def tcp_stream_edit(
        packets: Iterable[Packet],
        edits: Union[StreamEdit, Iterable[StreamEdit]],
) -> List[Packet]:
    """Edit the reassembled TCP streams of a captured connection.

    :param packets: the packets of a single, fully captured
        bidirectional TCP connection (SYN seen in both directions, no
        missing segment).
    :param edits: a StreamEdit or an iterable of StreamEdit.
    :return: a new list of packets with the edits applied.  Sequence
        and acknowledgment numbers (including SACK blocks and FIN) are
        translated, and lengths and checksums are recomputed.  The
        input packets are left unmodified.
    :raises TCPStreamEditError: if the capture is incomplete, if an
        edited interval conflicts with retransmitted data, or if an
        edit is invalid.
    """
    packets = list(packets)
    if isinstance(edits, StreamEdit):
        edits = [edits]
    edits = list(edits)
    if not packets:
        raise TCPStreamEditError("no packet provided")
    for pkt in packets:
        if TCP not in pkt or (IP not in pkt and IPv6 not in pkt):
            raise TCPStreamEditError(
                "only TCP packets over IP or IPv6 are supported")

    def endpoints(pkt: Packet) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        tcp = pkt[TCP]
        return (ip.src, tcp.sport), (ip.dst, tcp.dport)

    src0, dst0 = endpoints(packets[0])
    directions: Dict[Tuple[str, int], _Direction] = {
        src0: _Direction(src0),
        dst0: _Direction(dst0),
    }

    # First pass: reassemble both streams in capture order.
    for pkt in packets:
        src, dst = endpoints(pkt)
        if src not in directions or dst not in directions or src == dst:
            raise TCPStreamEditError(
                "packet does not belong to the connection: %r" % pkt)
        direction = directions[src]
        tcp = pkt[TCP]
        data = _tcp_data(pkt)
        if tcp.flags.S:
            if data:
                raise TCPStreamEditError(
                    "data on SYN is not supported: %r" % pkt)
            if direction.isn is not None and direction.isn != tcp.seq:
                raise TCPStreamEditError(
                    "inconsistent ISN from %s:%d" % src)
            direction.isn = tcp.seq
        if data:
            if direction.isn is None:
                raise TCPStreamEditError(
                    "data seen before SYN from %s:%d" % src)
            offset = _offset(tcp.seq, direction.isn)
            if offset >= _SEQ_MODULO // 2:
                raise TCPStreamEditError(
                    "cannot unwrap sequence number of %r" % pkt)
            direction.add_segment(offset, data)

    if any(direction.isn is None for direction in directions.values()):
        raise TCPStreamEditError(
            "not a fully captured bidirectional connection")

    # Assign the edits to their direction and build the new streams.
    dir_edits: Dict[Tuple[str, int], List[StreamEdit]] = {
        endpoint: [] for endpoint in directions
    }
    for edit in edits:
        if edit.sender not in directions:
            raise TCPStreamEditError("unknown sender %r" % (edit.sender,))
        if not 0 <= edit.start <= edit.end:
            raise TCPStreamEditError("invalid interval in %r" % edit)
        dir_edits[edit.sender].append(edit)

    new_streams: Dict[Tuple[str, int], bytes] = {}
    seqmaps: Dict[Tuple[str, int], _SeqMap] = {}
    for endpoint, direction in directions.items():
        direction.check_complete()
        stream_len = len(direction.stream)
        sorted_edits = sorted(dir_edits[endpoint],
                              key=lambda edit: edit.start)
        prev_end = 0
        for edit in sorted_edits:
            if edit.start < prev_end:
                raise TCPStreamEditError("overlapping edits: %r" % edit)
            if edit.end > stream_len:
                raise TCPStreamEditError(
                    "edit %r beyond end of stream (%d bytes)" % (
                        edit, stream_len))
            for cstart, cend in direction.conflicts:
                if cstart < edit.end and edit.start < cend:
                    raise TCPStreamEditError(
                        "unresolved retransmission conflict in edited "
                        "interval [%d, %d)" % (cstart, cend))
            prev_end = edit.end
        if direction.conflicts:
            log_runtime.debug(
                "tcpedit: keeping first seen bytes for %d conflicting "
                "retransmission(s) from %s:%d",
                len(direction.conflicts), endpoint[0], endpoint[1])
        new = bytearray()
        pos = 0
        for edit in sorted_edits:
            new += direction.stream[pos:edit.start]
            new += edit.data
            pos = edit.end
        new += direction.stream[pos:]
        new_streams[endpoint] = bytes(new)
        seqmaps[endpoint] = _SeqMap(sorted_edits)

    # Second pass: rewrite every packet.
    out = []
    for pkt in packets:
        src, dst = endpoints(pkt)
        direction = directions[src]
        peer = directions[dst]
        seqmap = seqmaps[src]
        peermap = seqmaps[dst]
        isn = direction.isn
        peer_isn = peer.isn
        npkt = pkt.copy()
        tcp = npkt[TCP]
        data = _tcp_data(npkt)
        if tcp.flags.S:
            # The sequence number of a SYN is the ISN: unchanged.
            pass
        elif data:
            start = _offset(tcp.seq, isn)
            nstart = seqmap.map_lo(start)
            nend = seqmap.map_hi(start + len(data))
            tcp.seq = (isn + 1 + nstart) % _SEQ_MODULO
            tcp.remove_payload()
            new_data = new_streams[src][nstart:nend]
            if new_data:
                tcp.add_payload(Raw(new_data))
        else:
            offset = _offset(tcp.seq, isn)
            if offset >= _SEQ_MODULO // 2:
                raise TCPStreamEditError(
                    "cannot unwrap sequence number of %r" % pkt)
            tcp.seq = (isn + 1 + seqmap.map_hi(offset)) % _SEQ_MODULO
        if tcp.flags.A:
            ack_offset = _offset(tcp.ack, peer_isn)
            if ack_offset >= _SEQ_MODULO // 2:
                raise TCPStreamEditError(
                    "cannot unwrap acknowledgment number of %r" % pkt)
            tcp.ack = (peer_isn + 1 + peermap.map_hi(ack_offset)
                       ) % _SEQ_MODULO
        options = []
        for oname, oval in tcp.options:
            if oname == "SAck":
                mapped = []
                for i in range(0, len(oval), 2):
                    left = _offset(oval[i], peer_isn)
                    right = _offset(oval[i + 1], peer_isn)
                    mapped.append((peer_isn + 1 + peermap.map_lo(left)
                                   ) % _SEQ_MODULO)
                    mapped.append((peer_isn + 1 + peermap.map_hi(right)
                                   ) % _SEQ_MODULO)
                options.append(("SAck", tuple(mapped)))
            else:
                options.append((oname, oval))
        tcp.options = options
        # Invalidate cached lengths and checksums.
        if IP in npkt:
            npkt[IP].len = None
            npkt[IP].chksum = None
        else:
            npkt[IPv6].plen = None
        tcp.chksum = None
        out.append(npkt)
    return out
