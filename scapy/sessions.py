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
    NamedTuple,
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


def _seq_diff(a, b):
    # type: (int, int) -> int
    """Signed difference ``a - b`` in the 32-bit TCP sequence number
    space (RFC 1982)."""
    return (a - b + (1 << 31)) % (1 << 32) - (1 << 31)


# A conflict detected while merging a fragment into a StringBuffer, as
# (start, end, old_source, new_source) where start and end are buffer
# offsets.
_BufferConflict = Tuple[int, int, Optional[str], Optional[str]]


class TCPReassemblyError(Exception):
    """Raised when the reassembly of a TCP stream must be aborted: the
    reassembly buffer exceeded its bounds, or an overlapping fragment
    with a different content was received under the ``reject-conflict``
    policy."""

    def __init__(self, reason, conflicts=None):
        # type: (str, Optional[List[_BufferConflict]]) -> None
        super(TCPReassemblyError, self).__init__(reason)
        self.conflicts = conflicts or []


class TCPConflict(NamedTuple):
    """Description of an overlap between two TCP segments whose content
    differs.

    :param start: absolute TCP sequence number of the first conflicting
        byte
    :param end: absolute TCP sequence number one past the last
        conflicting byte
    :param old_source: origin of the segment that was already buffered
    :param new_source: origin of the segment that was received last
    :param resolution: how the conflict was resolved: the policy that
        was applied (``first-seen`` or ``last-seen``), or ``rejected``
    """
    start: int
    end: int
    old_source: Optional[str]
    new_source: Optional[str]
    resolution: str


class StringBuffer(object):
    """StringBuffer is an object used to re-order data received during
    a TCP transmission.

    Each TCP fragment contains a sequence number, which marks
    (relatively to the first sequence number) the index of the data contained
    in the fragment.

    If a TCP fragment is missed, the missing range is zero-filled in
    ``content`` and tracked in ``incomplete``: ``contiguous()`` only
    returns the valid prefix of the buffer, so that missing data is
    never mistaken for valid stream content.

    :param max_gap: the largest missing range that will be zero-filled, in bytes.
        A sequence number far from the data already buffered would otherwise
        allocate the whole distance. Defaults to MTU.
    :param policy: how to resolve overlaps between fragments whose
        content differs: ``first-seen`` keeps the bytes that were
        received first, ``last-seen`` (default) overwrites them with
        the most recent ones and ``reject-conflict`` raises
        :class:`TCPReassemblyError`.
    :param max_size: the maximum size in bytes of the buffered content.
        A :class:`TCPReassemblyError` is raised when appending more
        data would exceed it. Defaults to no limit.
    """

    OVERLAP_POLICIES = ("first-seen", "last-seen", "reject-conflict")

    def __init__(self,
                 max_gap: int = MTU,
                 policy: str = "last-seen",
                 max_size: Optional[int] = None) -> None:
        if policy not in self.OVERLAP_POLICIES:
            raise ValueError(
                "policy must be one of %s" % (self.OVERLAP_POLICIES,)
            )
        self.content = bytearray(b"")
        self.content_len = 0
        self.noff = 0  # negative offset
        self.incomplete = []  # type: List[List[int]]
        self.sources = []  # type: List[List[Any]]
        self.max_gap = max_gap
        self.policy = policy
        self.max_size = max_size
        #: Conflicts detected by the last append(), as
        #: (start, end, old_source, new_source) tuples
        self.conflicts = []  # type: List[_BufferConflict]

    def append(self,
               data: bytes,
               seq: Optional[int] = None,
               source: Optional[str] = None) -> None:
        """Add a fragment to the buffer.
        :param data: the content of the fragment
        :param seq: the 1-based position of the fragment in the stream
        :param source: a description of the origin of the fragment,
            used when reporting conflicts
        The conflicts detected while merging the fragment are stored
        in the ``conflicts`` attribute, as (start, end, old_source,
        new_source) tuples where start and end are buffer offsets.
        Only overlaps whose content differs are reported.
        """
        self.conflicts = []
        if not data:
            return
        data_len = len(data)
        if seq is None:
            seq = self.content_len
        seq = seq - 1 - self.noff
        shift = -seq if seq < 0 else 0
        start = seq + shift
        end = start + data_len
        if self.max_size is not None and \
                max(self.content_len + shift, end) > self.max_size:
            raise TCPReassemblyError(
                "StringBuffer content would exceed max_size (%d)" %
                self.max_size
            )
        if shift:
            # Data is located before the start of the current buffer
            # (e.g. the first fragment was missing)
            if shift - data_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return
            self.content = bytearray(b"\x00" * shift) + self.content
            self.content_len += shift
            self.noff -= shift
            for hole in self.incomplete:
                hole[0] += shift
                hole[1] += shift
            for src in self.sources:
                src[0] += shift
                src[1] += shift
            if data_len < shift:
                # The prepended space past the new data is missing
                self.incomplete.insert(0, [data_len, shift])
        if end > self.content_len:
            # Data is located after the end of the current buffer
            if start - self.content_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return
            if start > self.content_len:
                # As data was missing, mark it.
                self.incomplete.append([self.content_len, start])
            self.content += b"\x00" * (end - self.content_len)
            self.content_len = end
            assert len(self.content) == self.content_len
        self.conflicts = self._merge(data, start, source)

    def _merge(self,
               data: bytes,
               start: int,
               source: Optional[str]) -> List[_BufferConflict]:
        """Write data at start, resolving overlaps with the data
        already buffered according to the overlap policy."""
        end = start + len(data)
        conflicts = []  # type: List[_BufferConflict]
        diffs = []  # type: List[Tuple[int, int, bytes]]
        for src_start, src_end, src in self.sources:
            ov_start = max(start, src_start)
            ov_end = min(end, src_end)
            if ov_start >= ov_end:
                continue
            old = bytes(self.content[ov_start:ov_end])
            new = data[ov_start - start:ov_end - start]
            if old == new:
                # Retransmitted or identical data: not a conflict
                continue
            # Locate the exact bytes that differ
            i = 0
            while i < len(old):
                if old[i] == new[i]:
                    i += 1
                    continue
                j = i + 1
                while j < len(old) and old[j] != new[j]:
                    j += 1
                conflicts.append((ov_start + i, ov_start + j, src, source))
                diffs.append((ov_start + i, ov_start + j, old[i:j]))
                i = j
        if conflicts and self.policy == "reject-conflict":
            raise TCPReassemblyError(
                "conflicting overlap rejected", conflicts=conflicts
            )
        memoryview(self.content)[start:end] = data
        if self.policy == "first-seen":
            # Restore the bytes that were received first
            for diff_start, diff_end, old in diffs:
                self.content[diff_start:diff_end] = old
            # Only the non-conflicting ranges are attributed to the
            # new fragment
            new_ranges = []  # type: List[Tuple[int, int]]
            pos = start
            for diff_start, diff_end, _old in diffs:
                if pos < diff_start:
                    new_ranges.append((pos, diff_start))
                pos = diff_end
            if pos < end:
                new_ranges.append((pos, end))
        else:
            new_ranges = [(start, end)]
        # The written range does not contain holes anymore
        incomplete = []  # type: List[List[int]]
        for hole_start, hole_end in self.incomplete:
            if hole_end <= start or hole_start >= end:
                incomplete.append([hole_start, hole_end])
                continue
            if hole_start < start:
                incomplete.append([hole_start, start])
            if hole_end > end:
                incomplete.append([end, hole_end])
        self.incomplete = incomplete
        # Attribute the written ranges to their source
        for range_start, range_end in new_ranges:
            self._set_source(range_start, range_end, source)
        return conflicts

    def _set_source(self,
                    start: int,
                    end: int,
                    source: Optional[str]) -> None:
        """Attribute the buffered [start, end) range to source."""
        sources = []  # type: List[List[Any]]
        for src_start, src_end, src in self.sources:
            if src_end <= start or src_start >= end:
                sources.append([src_start, src_end, src])
                continue
            if src_start < start:
                sources.append([src_start, start, src])
            if src_end > end:
                sources.append([end, src_end, src])
        sources.append([start, end, source])
        sources.sort(key=lambda x: x[0])
        # Merge adjacent ranges sharing the same source
        merged = []  # type: List[List[Any]]
        for entry in sources:
            if merged and merged[-1][1] == entry[0] and \
                    merged[-1][2] == entry[2]:
                merged[-1][1] = entry[1]
            else:
                merged.append(entry)
        self.sources = merged

    def contiguous_len(self) -> int:
        """The length of the valid prefix of the buffer, i.e. up to
        the first hole (missing data)."""
        if self.incomplete:
            return self.incomplete[0][0]
        return self.content_len

    def contiguous(self) -> bytes:
        """The valid prefix of the buffer. Missing data is never
        zero-filled here."""
        return bytes(self.content[:self.contiguous_len()])

    def shiftleft(self, i: int) -> None:
        self.content = self.content[i:]
        self.content_len -= i
        incomplete = []  # type: List[List[int]]
        for hole_start, hole_end in self.incomplete:
            if hole_end > i:
                incomplete.append([max(hole_start - i, 0), hole_end - i])
        self.incomplete = incomplete
        sources = []  # type: List[List[Any]]
        for src_start, src_end, src in self.sources:
            if src_end > i:
                sources.append([max(src_start - i, 0), src_end - i, src])
        self.sources = sources

    def full(self):
        # type: () -> bool
        # Should only be true when all missing data was filled up,
        # (or there never was missing data)
        return bool(self)

    def clear(self):
        # type: () -> None
        self.__init__(  # type: ignore
            max_gap=self.max_gap,
            policy=self.policy,
            max_size=self.max_size,
        )

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
    :param policy: how to resolve overlaps between TCP segments whose
                content differs: ``first-seen`` keeps the bytes received
                first, ``last-seen`` (default) keeps the most recent ones
                and ``reject-conflict`` stops reassembling the direction.
                Detected conflicts are reported in the ``conflicts``
                attribute, as TCPConflict tuples.
    :param max_buffer: the maximum size in bytes of the reassembly
                buffer of each direction. The reassembly of a direction
                is explicitly terminated when its buffer would exceed
                this size. Defaults to no limit.

    .. note:: Missing TCP fragments (holes) are never zero-filled:
              only the contiguous data of a stream is passed to
              ``tcp_reassemble``.
    """

    def __init__(self, app=False, policy="last-seen", max_buffer=None,
                 *args, **kwargs):
        # type: (bool, str, Optional[int], *Any, **Any) -> None
        super(TCPSession, self).__init__(*args, **kwargs)
        self.app = app
        if policy not in StringBuffer.OVERLAP_POLICIES:
            raise ValueError(
                "policy must be one of %s" % (StringBuffer.OVERLAP_POLICIES,)
            )
        self.policy = policy
        self.max_buffer = max_buffer
        #: Conflicts detected while reassembling, as TCPConflict tuples
        self.conflicts = []  # type: List[TCPConflict]
        if app:
            self.data = StringBuffer()
            self.metadata = {}  # type: Dict[str, Any]
            self.session = {}  # type: Dict[str, Any]
        else:
            # The StringBuffer() is used to build a global
            # string from fragments and their seq nulber
            self.tcp_frags = defaultdict(
                lambda: (
                    StringBuffer(policy=self.policy,
                                 max_size=self.max_buffer),
                    {}
                )
            )  # type: DefaultDict[bytes, Tuple[StringBuffer, Dict[str, Any]]]
            self.tcp_sessions = defaultdict(
                dict
            )  # type: DefaultDict[bytes, Dict[str, Any]]
            # Directions whose reassembly was explicitly terminated
            self.tcp_terminated = set()  # type: Set[bytes]
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

    def _get_source(self, pkt):
        # type: (Packet) -> str
        """A description of the origin of a TCP packet, used when
        reporting conflicts."""
        tcp = pkt["TCP"]
        underlayer = tcp.underlayer
        if underlayer is None:
            return ":%s > :%s (seq %d)" % (tcp.sport, tcp.dport, tcp.seq)
        return "%s:%s > %s:%s (seq %d)" % (
            underlayer.src, tcp.sport,
            underlayer.dst, tcp.dport,
            tcp.seq,
        )

    def _register_conflicts(self, metadata, data, conflicts, resolution):
        # type: (Dict[str, Any], StringBuffer, List[_BufferConflict], str) -> None  # noqa: E501
        """Record and report the conflicts detected while buffering
        a fragment."""
        relative_seq = metadata.get("relative_seq", 0)
        for start, end, old_source, new_source in conflicts:
            conflict = TCPConflict(
                start=(relative_seq + start + 1 + data.noff) % (1 << 32),
                end=(relative_seq + end + 1 + data.noff) % (1 << 32),
                old_source=old_source,
                new_source=new_source,
                resolution=resolution,
            )
            self.conflicts.append(conflict)
            log_runtime.warning(
                "TCPSession: conflicting TCP overlap on sequence "
                "numbers [%d, %d): '%s' vs '%s' (%s)",
                conflict.start, conflict.end,
                old_source, new_source, resolution,
            )

    def _terminate(self, ident, reason):
        # type: (bytes, str) -> None
        """Explicitly terminate the reassembly of a direction: its
        buffer is dropped and its packets are no longer reassembled."""
        log_runtime.warning(
            "TCPSession: reassembly of flow %r terminated: %s",
            ident, reason,
        )
        self.tcp_terminated.add(ident)
        self.tcp_frags.pop(ident, None)

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
        if pkt[TCP].flags.S and not pay:
            # A SYN starts a new connection: if this 4-tuple was already
            # in use (connection reuse), reset the reassembly state of
            # this direction. SYN retransmissions are ignored.
            old_metadata = self.tcp_frags.get(ident, (None, {}))[1]
            if old_metadata.get("syn_seq") != pkt[TCP].seq:
                self.tcp_frags.pop(ident, None)
                self.tcp_terminated.discard(ident)
        if ident in self.tcp_terminated:
            # The reassembly of this direction was explicitly terminated.
            return pkt
        data, metadata = self.tcp_frags[ident]
        if pkt[TCP].flags.S and not pay:
            metadata["syn_seq"] = pkt[TCP].seq
        tcp_session = self.tcp_sessions[self._get_ident(pkt, True)]
        # Handle TCP sequence numbers
        seq = pkt[TCP].seq
        if "seq" not in metadata:
            metadata["seq"] = seq
        if "next_seq" in metadata:
            retransmission = _seq_diff(metadata["next_seq"], seq)
            if retransmission > 0:
                # Retransmitted data (that we already returned)
                new_data = new_data[retransmission:]
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
            # Get a relative sequence number for a storage purpose.
            # Comparisons happen in the 32-bit TCP sequence number
            # space, so that sequence number wrap-around is handled.
            relative_seq = metadata.get("relative_seq", None)
            if relative_seq is None:
                relative_seq = metadata["relative_seq"] = (seq - 1) % (1 << 32)
            seq = _seq_diff(seq, relative_seq)
            # Add the data to the buffer
            noff = data.noff
            try:
                data.append(new_data, seq, source=self._get_source(pkt))
            except TCPReassemblyError as ex:
                # The buffer exceeded its bounds or a conflict was
                # rejected: explicitly terminate this direction.
                self._register_conflicts(
                    metadata, data, ex.conflicts, "rejected"
                )
                self._terminate(ident, "%s" % (ex,))
                return pkt
            self._register_conflicts(metadata, data, data.conflicts, self.policy)
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
        # Only the contiguous part of the buffer is valid: data past a
        # hole (a missing fragment) is held until the hole is filled,
        # rather than zero-filled and passed to the dissector.
        contiguous = data.contiguous()
        if contiguous:
            min_len = metadata.get("tcp_min_len")
            if min_len is None or len(contiguous) >= min_len:
                # Reassemble using all previous packets
                metadata["original"] = pkt
                metadata["ident"] = ident
                metadata.pop("tcp_min_len", None)
                packet = tcp_reassemble(
                    contiguous,
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
                full_length = data.contiguous_len() - len(padding)
                metadata["relative_seq"] = relative_seq + full_length
                data.shiftleft(full_length)
                contiguous = data.contiguous()
                if not contiguous:
                    # The remaining data starts with a hole.
                    break
                # There might be a sub-payload hidden in the padding
                sub_packet = tcp_reassemble(
                    contiguous,
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
            metadata["next_seq"] = (pkt[TCP].seq + len(new_data)) % (1 << 32)
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
