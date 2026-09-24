# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Sessions: decode flow of packets when sniffing
"""

from collections import defaultdict
import socket
import struct

from scapy.config import conf
from scapy.data import MTU
from scapy.error import log_runtime
from scapy.packet import Packet
from scapy.pton_ntop import inet_pton

# Typing imports
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    cast,
    TYPE_CHECKING,
)
from scapy.compat import Self
if TYPE_CHECKING:
    from scapy.supersocket import SuperSocket


class DefaultSession(object):
    """Default session: no stream decoding"""

    def __init__(self, supersession: Optional[Self] = None):
        if supersession and not isinstance(supersession, DefaultSession):
            supersession = supersession()
        self.supersession = supersession

    def process(self, pkt: Packet) -> Optional[Packet]:
        """
        Called to pre-process the packet
        """
        # Optionally handle supersession
        if self.supersession:
            return self.supersession.process(pkt)
        return pkt

    def recv(self, sock: 'SuperSocket') -> Iterator[Packet]:
        """
        Will be called by sniff() to ask for a packet
        """
        pkt = sock.recv()
        if not pkt:
            return
        try:
            pkt = self.process(pkt)
        except Exception as ex:
            log_runtime.warning(
                "%s processing failed with '%s'. Skipping." % (
                    type(self),
                    ex,
                )
            )
            if conf.debug_dissector:
                raise
            if pkt is not None:
                yield pkt
            return
        if pkt:
            yield pkt


class IPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.

    Usage:
    >>> sniff(session=IPSession)
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        DefaultSession.__init__(self, *args, **kwargs)
        self.fragments = defaultdict(list)  # type: DefaultDict[Tuple[Any, ...], List[Packet]]  # noqa: E501

    def process(self, packet: Packet) -> Optional[Packet]:
        from scapy.layers.inet import BadFragments, IP, _defrag_ip_pkt
        if not packet:
            return None
        if IP not in packet:
            return packet
        try:
            return _defrag_ip_pkt(packet, self.fragments)[1]  # type: ignore
        except BadFragments:
            return None


class StringBuffer(object):
    """StringBuffer is an object used to re-order data received during
    a TCP transmission.

    Each TCP fragment contains a sequence number, which marks
    (relatively to the first sequence number) the index of the data contained
    in the fragment.

    If a TCP fragment is missed, this class will fill the missing space with
    zeros, but keeps track of the missing ranges so that consumers can
    avoid treating zero-filled holes as valid data (see `full`).

    :param max_gap: the largest missing range that will be zero-filled, in bytes.
        A sequence number far from the data already buffered would otherwise
        allocate the whole distance. Defaults to MTU.
    """

    def __init__(self, max_gap: int = MTU) -> None:
        self.content = bytearray(b"")
        self.content_len = 0
        self.noff = 0  # negative offset
        # Missing ranges (holes), as sorted non-overlapping (start, end)
        # offsets relative to the current buffer.
        self.incomplete = []  # type: List[Tuple[int, int]]
        # Contributor ranges, as [start, end, info] offsets relative to the
        # current buffer, describing where each buffered byte came from.
        self.contributors = []  # type: List[List[Any]]
        self.max_gap = max_gap

    def _add_hole(self, start: int, end: int) -> None:
        """Mark the [start, end) range as missing."""
        if start >= end:
            return
        holes = []  # type: List[Tuple[int, int]]
        inserted = False
        for hstart, hend in self.incomplete:
            if not inserted and end < hstart:
                holes.append((start, end))
                inserted = True
            if inserted or hend < start:
                holes.append((hstart, hend))
            else:
                # Overlapping or adjacent: merge
                start = min(start, hstart)
                end = max(end, hend)
        if not inserted:
            holes.append((start, end))
        self.incomplete = holes

    def _fill_holes(self, start: int, end: int) -> None:
        """Mark the [start, end) range as received."""
        holes = []  # type: List[Tuple[int, int]]
        for hstart, hend in self.incomplete:
            if hend <= start or end <= hstart:
                holes.append((hstart, hend))
                continue
            if hstart < start:
                holes.append((hstart, start))
            if end < hend:
                holes.append((end, hend))
        self.incomplete = holes

    def covered(self, offset: int, length: int) -> List[Tuple[int, int]]:
        """Return the sorted (start, end) offsets of the buffered (non-hole)
        ranges that overlap [offset, offset + length).
        """
        end = offset + length
        ranges = []  # type: List[Tuple[int, int]]
        start = 0
        for hstart, hend in self.incomplete:
            if start < hstart:
                ranges.append((start, hstart))
            start = max(start, hend)
        if start < self.content_len:
            ranges.append((start, self.content_len))
        return [
            (max(start, offset), min(stop, end))
            for start, stop in ranges
            if max(start, offset) < min(stop, end)
        ]

    def note_contributor(self, offset: int, length: int, info: Any) -> None:
        """Record that the [offset, offset + length) range was written by
        `info`, replacing any previous contributor on this range.
        """
        end = offset + length
        contributors = []  # type: List[List[Any]]
        for cstart, cend, cinfo in self.contributors:
            if cend <= offset or end <= cstart:
                contributors.append([cstart, cend, cinfo])
                continue
            if cstart < offset:
                contributors.append([cstart, offset, cinfo])
            if end < cend:
                contributors.append([end, cend, cinfo])
        contributors.append([offset, end, info])
        contributors.sort(key=lambda x: x[0])
        self.contributors = contributors

    def contributor_at(self, offset: int) -> Optional[Any]:
        """Return the contributor info covering `offset`, if any."""
        for cstart, cend, cinfo in self.contributors:
            if cstart <= offset < cend:
                return cinfo
        return None

    def append(self, data: bytes, seq: Optional[int] = None) -> bool:
        if not data:
            return True
        data_len = len(data)
        if seq is None:
            seq = self.content_len
        seq = seq - 1 - self.noff
        if seq < 0:
            # Data is located before the start of the current buffer
            # (e.g. the first fragment was missing)
            if -seq - data_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return False
            shift = -seq
            self.content = bytearray(b"\x00" * shift) + self.content
            self.content_len += shift
            self.noff += seq
            self.incomplete = [
                (start + shift, end + shift)
                for start, end in self.incomplete
            ]
            self.contributors = [
                [start + shift, end + shift, info]
                for start, end, info in self.contributors
            ]
            # The prepended zeroes not covered by the new data are missing.
            self._add_hole(data_len, shift)
            seq = 0
        if seq + data_len > self.content_len:
            # Data is located after the end of the current buffer
            if seq - self.content_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return False
            # As data was missing, mark it.
            self._add_hole(self.content_len, seq)
            self.content += b"\x00" * (seq - self.content_len + data_len)
            self.content_len = seq + data_len
            assert len(self.content) == self.content_len
        self._fill_holes(seq, seq + data_len)
        memoryview(self.content)[seq:seq + data_len] = data
        return True

    def shiftleft(self, i: int) -> None:
        self.content = self.content[i:]
        self.content_len -= i
        self.incomplete = [
            (max(start - i, 0), end - i)
            for start, end in self.incomplete
            if end > i
        ]
        self.contributors = [
            [max(start - i, 0), end - i, info]
            for start, end, info in self.contributors
            if end > i
        ]

    def full(self):
        # type: () -> bool
        # Should only be true when all missing data was filled up,
        # (or there never was missing data)
        return bool(self.content_len) and not self.incomplete

    def clear(self):
        # type: () -> None
        self.__init__()  # type: ignore

    def __bool__(self):
        # type: () -> bool
        return bool(self.content_len)
    __nonzero__ = __bool__

    def __len__(self):
        # type: () -> int
        return self.content_len

    def __bytes__(self):
        # type: () -> bytes
        return bytes(self.content)

    def __str__(self):
        # type: () -> str
        return cast(str, self.__bytes__())


def streamcls(cls: Type[Packet]) -> Callable[
    [bytes, Dict[str, Any], Dict[str, Any]],
    Optional[Packet],
]:
    """
    Wraps a class for use when dissecting streams.
    """
    if hasattr(cls, "tcp_reassemble"):
        return cls.tcp_reassemble  # type: ignore
    else:
        # There is no tcp_reassemble. Just dissect the packet
        return lambda data, *_: data and cls(data)


def _seq_diff(a, b):
    # type: (int, int) -> int
    """Signed difference a - b in TCP sequence number space (RFC 793),
    handling the 2**32 wrap-around.
    """
    return ((a - b + 2**31) % 2**32) - 2**31


class TCPOverlapConflict(object):
    """Report of an overlap between two TCP segments of the same stream
    whose bytes differ.

    :param flow: description of the stream direction
    :param old: description of the packet that provided the buffered bytes
    :param new: description of the packet that provided the conflicting bytes
    :param seq_start: TCP sequence number of the first conflicting byte
    :param seq_end: TCP sequence number past the last conflicting byte
    :param old_data: the conflicting bytes that were buffered
    :param new_data: the conflicting bytes from the new packet
    """

    def __init__(self, flow, old, new, seq_start, seq_end, old_data, new_data):
        # type: (str, Optional[str], str, int, int, bytes, bytes) -> None
        self.flow = flow
        self.old = old
        self.new = new
        self.seq_start = seq_start
        self.seq_end = seq_end
        self.old_data = old_data
        self.new_data = new_data

    def __repr__(self):
        # type: () -> str
        return (
            "<TCPOverlapConflict %s seq=[%#x, %#x) old=%r new=%r>"
            % (self.flow, self.seq_start, self.seq_end, self.old, self.new)
        )


class TCPSession(IPSession):
    """A Session that reconstructs TCP streams.

    NOTE: this has the same effect as wrapping a real socket.socket into StreamSocket,
    but for all concurrent TCP streams (can be used on pcaps or sniffed sessions).

    NOTE: only protocols that implement a ``tcp_reassemble`` function will be processed
    by this session. Other protocols will not be reconstructed.

    DEV: implement a class-function `tcp_reassemble` in your Packet class::

        @classmethod
        def tcp_reassemble(cls, data, metadata, session):
            # data = the reassembled data from the same request/flow
            # metadata = empty dictionary, that can be used to store data
            #            during TCP reassembly
            # session = a dictionary proper to the bidirectional TCP session,
            #           that can be used to store anything
            [...]
            # If the packet is available, return it. Otherwise don't.
            # Whenever you return a packet, the buffer will be discarded.
            return pkt
            # Otherwise, maybe store stuff in metadata, and return None,
            # as you need additional data.
            return None

    For more details and a real example, see:
    https://scapy.readthedocs.io/en/latest/usage.html#how-to-use-tcpsession-to-defragment-tcp-packets

    :param app: Whether the socket is on application layer = has no TCP
                layer. This is identical to StreamSocket so only use this if your
                underlying source of data isn't a socket.socket.
    :param overlap_policy: how to handle TCP segments whose sequence ranges
        overlap. One of:

        - "first-seen": keep the bytes that were received first and drop the
          overlapping part of later segments.
        - "last-seen" (default): the most recently received segment
          overwrites the overlapping bytes.
        - "reject-conflict": overlapping bytes that differ are reported as a
          TCPOverlapConflict (stored in `conflicts` and logged) and the
          reassembly of the affected direction is terminated. Overlaps with
          identical bytes (e.g. retransmissions) are silently accepted.

        Note that holes (missing segments) are never zero-filled into the
        stream: reassembly waits until every hole is filled.
    :param max_gap: the largest missing sequence range, in bytes, that the
        reassembly cache will buffer across. If a segment exceeds this bound,
        the reassembly of the affected direction is explicitly terminated
        (the direction is added to `terminated`).

    Reassembly is tracked independently for each direction of each
    connection. A SYN without ACK is treated as a new connection reusing the
    4-tuple, and restarts the reassembly state of that direction.
    """

    OVERLAP_POLICIES = ("first-seen", "last-seen", "reject-conflict")

    def __init__(self, app=False, overlap_policy="last-seen", max_gap=MTU,
                 *args, **kwargs):
        # type: (bool, str, int, *Any, **Any) -> None
        super(TCPSession, self).__init__(*args, **kwargs)
        if overlap_policy not in self.OVERLAP_POLICIES:
            raise ValueError(
                "overlap_policy must be one of %r" % (self.OVERLAP_POLICIES,)
            )
        self.app = app
        self.overlap_policy = overlap_policy
        self.max_gap = max_gap
        # TCPOverlapConflict entries reported in "reject-conflict" mode
        self.conflicts = []  # type: List[TCPOverlapConflict]
        # Uni-directional idents whose reassembly was explicitly terminated
        self.terminated = set()  # type: Set[bytes]
        if app:
            self.data = StringBuffer()
            self.metadata = {}  # type: Dict[str, Any]
            self.session = {}  # type: Dict[str, Any]
        else:
            # The StringBuffer() is used to build a global
            # string from fragments and their seq nulber
            self.tcp_frags = defaultdict(
                lambda: (StringBuffer(max_gap=self.max_gap), {})
            )  # type: DefaultDict[bytes, Tuple[StringBuffer, Dict[str, Any]]]
            self.tcp_sessions = defaultdict(
                dict
            )  # type: DefaultDict[bytes, Dict[str, Any]]
        # Setup stopping dissection condition
        from scapy.layers.inet import TCP
        self.stop_dissection_after = TCP

    def _get_ident(self, pkt, session=False):
        # type: (Packet, bool) -> bytes
        underlayer = pkt["TCP"].underlayer
        af = socket.AF_INET6 if "IPv6" in pkt else socket.AF_INET
        src = underlayer and inet_pton(af, underlayer.src) or b""
        dst = underlayer and inet_pton(af, underlayer.dst) or b""
        if session:
            # Bidirectional
            def xor(x, y):
                # type: (bytes, bytes) -> bytes
                return bytes(a ^ b for a, b in zip(x, y))
            return struct.pack("!4sH", xor(src, dst), pkt.dport ^ pkt.sport)
        else:
            # Uni-directional
            return src + dst + struct.pack("!HH", pkt.dport, pkt.sport)

    def _strip_padding(self, pkt: Packet) -> Optional[bytes]:
        """Strip the packet of any padding, and return the padding.
        """
        if isinstance(pkt, conf.padding_layer):
            return cast(bytes, pkt.load)
        pad = pkt.getlayer(conf.padding_layer)
        if pad is not None and pad.underlayer is not None:
            # strip padding
            del pad.underlayer.payload
            return cast(bytes, pad.load)
        return None

    @staticmethod
    def _desc(pkt: Packet) -> str:
        """Short description of the source of a TCP packet."""
        underlayer = pkt["TCP"].underlayer
        src = underlayer.src if underlayer is not None else "?"
        dst = underlayer.dst if underlayer is not None else "?"
        return "%s:%s > %s:%s" % (src, pkt["TCP"].sport, dst, pkt["TCP"].dport)

    def _terminate(self, ident: bytes, pkt: Packet) -> None:
        """Explicitly terminate the reassembly of a stream direction."""
        self.tcp_frags.pop(ident, None)
        self.terminated.add(ident)
        log_runtime.warning(
            "TCP reassembly of %s terminated", self._desc(pkt)
        )

    def _report_conflict(self,
                         pkt: Packet,
                         data: StringBuffer,
                         metadata: Dict[str, Any],
                         ostart: int,
                         oend: int,
                         new_data: bytes) -> None:
        """Report a content conflict on the [ostart, oend) buffer range."""
        relative_seq = metadata.get("relative_seq", 0)
        seq_start = (relative_seq + ostart + 1 + data.noff) & 0xFFFFFFFF
        seq_end = (relative_seq + oend + 1 + data.noff) & 0xFFFFFFFF
        conflict = TCPOverlapConflict(
            flow=self._desc(pkt),
            old=data.contributor_at(ostart),
            new=self._desc(pkt),
            seq_start=seq_start,
            seq_end=seq_end,
            old_data=bytes(data.content[ostart:oend]),
            new_data=new_data,
        )
        self.conflicts.append(conflict)
        log_runtime.warning("TCP overlap conflict: %r", conflict)

    def _overlap_filter(
        self,
        ident: bytes,
        pkt: Packet,
        data: StringBuffer,
        metadata: Dict[str, Any],
        new_data: bytes,
        seq: int,
    ) -> Optional[List[Tuple[int, bytes]]]:
        """Apply the overlap policy to new_data (starting at relative
        sequence `seq`). Returns the (seq, data) pieces to append, or
        None if the reassembly of this direction was terminated.
        """
        if self.overlap_policy == "last-seen":
            return [(seq, new_data)]
        offset = seq - 1 - data.noff
        covered = data.covered(offset, len(new_data))
        if self.overlap_policy == "first-seen":
            # Drop the parts of new_data that are already buffered.
            pieces = []  # type: List[Tuple[int, bytes]]
            pos = 0
            for cstart, cend in covered:
                if pos < cstart - offset:
                    pieces.append((seq + pos, new_data[pos:cstart - offset]))
                pos = max(pos, cend - offset)
            if pos < len(new_data):
                pieces.append((seq + pos, new_data[pos:]))
            return pieces
        # reject-conflict: only report overlaps whose bytes differ.
        conflicts = []  # type: List[Tuple[int, int]]
        for cstart, cend in covered:
            old = bytes(data.content[cstart:cend])
            new = new_data[cstart - offset:cend - offset]
            run_start = None  # type: Optional[int]
            for i in range(len(old)):
                if old[i] != new[i]:
                    if run_start is None:
                        run_start = i
                elif run_start is not None:
                    conflicts.append((cstart + run_start, cstart + i))
                    run_start = None
            if run_start is not None:
                conflicts.append((cstart + run_start, cend))
        if conflicts:
            for ostart, oend in conflicts:
                self._report_conflict(
                    pkt, data, metadata, ostart, oend,
                    new_data[ostart - offset:oend - offset],
                )
            self._terminate(ident, pkt)
            return None
        return [(seq, new_data)]

    def process(self,
                pkt: Packet,
                cls: Optional[Type[Packet]] = None) -> Optional[Packet]:
        """Process each packet: matches the TCP seq/ack numbers
        to follow the TCP streams, and orders the fragments.
        """
        packet = None  # type: Optional[Packet]
        if self.app:
            # Special mode: Application layer. Use on top of TCP
            self.data.append(bytes(pkt))
            if cls is None and not isinstance(pkt, bytes):
                cls = pkt.__class__
            if "tcp_reassemble" in self.metadata:
                tcp_reassemble = self.metadata["tcp_reassemble"]
            elif cls is not None:
                self.metadata["tcp_reassemble"] = tcp_reassemble = streamcls(cls)
            else:
                return None
            if self.data.full():
                min_len = self.metadata.get("tcp_min_len")
                if min_len is None or len(self.data) >= min_len:
                    self.metadata.pop("tcp_min_len", None)
                    packet = tcp_reassemble(
                        bytes(self.data),
                        self.metadata,
                        self.session,
                    )
            if packet:
                padding = self._strip_padding(packet)
                if padding:
                    # There is remaining data for the next payload.
                    self.data.shiftleft(len(self.data) - len(padding))
                    # Skip full-padding
                    if isinstance(packet, conf.padding_layer):
                        return None
                else:
                    # No padding (data) left. Clear
                    self.data.clear()
                self.metadata.clear()
                return packet
            return None

        _pkt = super(TCPSession, self).process(pkt)
        if _pkt is None:
            return None
        else:  # Python 3.8 := would be nice
            pkt = _pkt

        from scapy.layers.inet import IP, TCP
        if not pkt:
            return None
        if TCP not in pkt:
            return pkt
        pay = pkt[TCP].payload
        new_data = pay.original
        # Match packets by a unique TCP identifier
        ident = self._get_ident(pkt)
        if pkt[TCP].flags.S and not pkt[TCP].flags.A and not pay:
            # A new connection is reusing this 4-tuple: restart the
            # reassembly state of this direction.
            self.tcp_frags.pop(ident, None)
            self.terminated.discard(ident)
            self.tcp_sessions.pop(self._get_ident(pkt, True), None)
        if ident in self.terminated:
            # The reassembly of this direction was explicitly terminated
            # (overlap conflict or cache bound exceeded).
            return None
        data, metadata = self.tcp_frags[ident]
        tcp_session = self.tcp_sessions[self._get_ident(pkt, True)]
        # Handle TCP sequence numbers
        seq = pkt[TCP].seq
        if "seq" not in metadata:
            metadata["seq"] = seq
        if "next_seq" in metadata and _seq_diff(seq, metadata["next_seq"]) < 0:
            # Retransmitted data (that we already returned)
            new_data = new_data[_seq_diff(metadata["next_seq"], seq):]
            if not new_data:
                return None
            seq = metadata["next_seq"]
        # Let's guess which class is going to be used
        if "pay_class" not in metadata:
            metadata["pay_class"] = pay_class = pkt[TCP].guess_payload_class(new_data)
            metadata["tcp_reassemble"] = tcp_reassemble = streamcls(pay_class)
        else:
            tcp_reassemble = metadata["tcp_reassemble"]

        if pay:
            # Get a relative sequence number for a storage purpose
            relative_seq = metadata.get("relative_seq", None)
            if relative_seq is None:
                relative_seq = metadata["relative_seq"] = (seq - 1) & 0xFFFFFFFF
            seq = _seq_diff(seq, relative_seq)
            # Add the data to the buffer
            noff = data.noff
            pieces = self._overlap_filter(
                ident, pkt, data, metadata, new_data, seq
            )
            if pieces is None:
                # The reassembly of this direction was terminated.
                return None
            for pseq, pdata in pieces:
                if not data.append(pdata, pseq):
                    # The cache bound (max_gap) was exceeded: explicitly
                    # terminate the reassembly of this direction.
                    self._terminate(ident, pkt)
                    return None
                data.note_contributor(
                    pseq - 1 - data.noff, len(pdata), self._desc(pkt)
                )
            if data.noff != noff:
                # The negative offset has changed => data was prepended.
                # this means that our estimate min length may be wrong.
                metadata.pop("tcp_min_len", None)

        # Check TCP FIN or TCP RESET
        if pkt[TCP].flags.F or pkt[TCP].flags.R:
            metadata["tcp_end"] = True
        elif not pay:
            # If there's no payload and the stream isn't ending, ignore.
            return pkt

        # In case any app layer protocol requires it,
        # allow the parser to inspect TCP PSH flag
        if pkt[TCP].flags.P:
            metadata["tcp_psh"] = True
        # Note: data.full() is only true when no hole (missing fragment)
        # remains in the buffer, so zero-filled holes are never passed
        # to the dissector as if they were valid stream content.
        if data.full():
            min_len = metadata.get("tcp_min_len")
            if min_len is None or len(data) >= min_len:
                # Reassemble using all previous packets
                metadata["original"] = pkt
                metadata["ident"] = ident
                metadata.pop("tcp_min_len", None)
                packet = tcp_reassemble(
                    bytes(data),
                    metadata,
                    tcp_session
                )
        # Stack the result on top of the previous frames
        if packet:
            if "seq" in metadata:
                pkt[TCP].seq = metadata["seq"]
            # Clear TCP reassembly metadata
            metadata.clear()
            # Check for padding
            padding = self._strip_padding(packet)
            while padding:
                # There is remaining data for the next payload.
                full_length = data.content_len - len(padding)
                metadata["relative_seq"] = (
                    relative_seq + full_length
                ) & 0xFFFFFFFF
                data.shiftleft(full_length)
                # There might be a sub-payload hidden in the padding
                sub_packet = tcp_reassemble(
                    bytes(data),
                    metadata,
                    tcp_session
                )
                if sub_packet:
                    packet.add_payload(sub_packet)
                    padding = self._strip_padding(sub_packet)
                else:
                    break
            else:
                # No padding (data) left. Clear
                data.clear()
                del self.tcp_frags[ident]
            # Minimum next seq
            metadata["next_seq"] = (pkt[TCP].seq + len(new_data)) & 0xFFFFFFFF
            # Skip full-padding
            if isinstance(packet, conf.padding_layer):
                return None
            # Rebuild resulting packet
            if pay:
                pay.underlayer.remove_payload()
            if IP in pkt:
                pkt[IP].len = None
                pkt[IP].chksum = None
            pkt = pkt / packet
            pkt.wirelen = None
            return pkt
        return None

    def recv(self, sock: 'SuperSocket') -> Iterator[Packet]:
        """
        Will be called by sniff() to ask for a packet
        """
        pkt = sock.recv(stop_dissection_after=self.stop_dissection_after)
        _orig = pkt
        # Now handle TCP reassembly
        if self.app:
            while pkt is not None:
                try:
                    pkt = self.process(pkt)
                except Exception as ex:
                    log_runtime.warning(
                        "%s processing failed with '%s'. Aborting." % (
                            type(self),
                            ex,
                        )
                    )
                    if conf.debug_dissector:
                        raise
                    return None
                if pkt:
                    yield pkt
                    # keep calling process as there might be more
                    pkt = b""  # type: ignore
        else:
            try:
                pkt = self.process(pkt)  # type: ignore
            except Exception as ex:
                log_runtime.warning(
                    "%s processing failed with '%s'. Skipping." % (
                        type(self),
                        ex,
                    )
                )
                if conf.debug_dissector:
                    raise
                if _orig is not None:
                    yield _orig
                return None
            if pkt:
                yield pkt
        return None
