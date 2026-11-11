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
    zeros.

    :param max_gap: the largest missing range that will be zero-filled, in bytes.
        A sequence number far from the data already buffered would otherwise
        allocate the whole distance. Defaults to MTU.
    """

    def __init__(self, max_gap: int = MTU) -> None:
        self.content = bytearray(b"")
        self.content_len = 0
        self.noff = 0  # negative offset
        self.incomplete = []  # type: List[Tuple[int, int]]
        self.max_gap = max_gap

    def append(self, data: bytes, seq: Optional[int] = None) -> bool:
        """
        Store data at the position indicated by seq.

        :returns: False if the data was dropped (further than allowed per
            'max_gap'), True otherwise.
        """
        if not data:
            return False
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
            self.content = bytearray(b"\x00" * (-seq)) + self.content
            self.content_len += (-seq)
            self.noff += seq
            seq = 0
        if seq + data_len > self.content_len:
            # Data is located after the end of the current buffer
            if seq - self.content_len > self.max_gap:
                log_runtime.warning(
                    "Dropped data further than allowed per 'max_gap'."
                )
                return False
            self.content += b"\x00" * (seq - self.content_len + data_len)
            # As data was missing, mark it.
            # self.incomplete.append((self.content_len, seq))
            self.content_len = seq + data_len
            assert len(self.content) == self.content_len
        # XXX removes empty space marker.
        # for ifrag in self.incomplete:
        #     if [???]:
        #         self.incomplete.remove([???])
        memoryview(self.content)[seq:seq + data_len] = data
        return True

    def shiftleft(self, i: int) -> None:
        self.content = self.content[i:]
        self.content_len -= i

    def full(self):
        # type: () -> bool
        # Should only be true when all missing data was filled up,
        # (or there never was missing data)
        return bool(self)

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


class TCPAmbiguity(object):
    """A single overlap between TCP segments, recorded by TCPSession when
    its ``ambiguity`` mode is enabled.

    Two segments covering the same sequence numbers may carry identical
    bytes (a regular retransmission) or conflicting ones (which endpoints
    may interpret differently). Each record holds both byte strings and
    the packets they come from, so that an analyst can reconstruct which
    two inputs diverged.

    :ivar kind: "retransmit" (identical bytes), "conflict" (different
        bytes) or "delivered" (the range overlaps data that was already
        reassembled and discarded: the previous bytes are unrecoverable
        and the overlap cannot be verified).
    :ivar src: source address of the incoming packet
    :ivar dst: destination address of the incoming packet
    :ivar sport: TCP source port of the incoming packet
    :ivar dport: TCP destination port of the incoming packet
    :ivar seq: first sequence number of the overlapping range
    :ivar end: end of the overlapping range (exclusive). ``seq`` and
        ``end`` are unwrapped: reduce them mod 2**32 to get wire values.
    :ivar incoming: bytes of the incoming packet over this range
    :ivar buffered: bytes previously buffered over this range
        (None for "delivered" records)
    :ivar packet: the incoming packet
    :ivar sources: packets that contributed the buffered bytes over this
        range (empty for "delivered" records)
    """

    def __init__(self,
                 kind,  # type: str
                 pkt,  # type: Packet
                 seq,  # type: int
                 end,  # type: int
                 incoming,  # type: bytes
                 buffered,  # type: Optional[bytes]
                 sources,  # type: List[Packet]
                 ):
        # type: (...) -> None
        tcp = pkt["TCP"]
        underlayer = tcp.underlayer
        self.kind = kind
        self.src = underlayer and underlayer.src or None
        self.dst = underlayer and underlayer.dst or None
        self.sport = tcp.sport
        self.dport = tcp.dport
        self.seq = seq
        self.end = end
        self.incoming = incoming
        self.buffered = buffered
        self.packet = pkt
        self.sources = sources

    def __repr__(self):
        # type: () -> str
        return "<TCPAmbiguity %s %s:%s -> %s:%s seq=[%r,%r)>" % (
            self.kind,
            self.src,
            self.sport,
            self.dst,
            self.dport,
            self.seq,
            self.end,
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
    :param ambiguity: Whether to report overlapping TCP segments (not
                supported with app=True). When enabled, each overlap is
                classified and appended to ``self.tcp_ambiguities`` as a
                TCPAmbiguity: "retransmit" when both segments carry the
                same bytes, "conflict" when they differ, and "delivered"
                when the range overlaps data that was already reassembled
                and can no longer be verified. Reassembly itself is
                unchanged.
    """

    def __init__(self, app=False, ambiguity=False, *args, **kwargs):
        # type: (bool, bool, *Any, **Any) -> None
        super(TCPSession, self).__init__(*args, **kwargs)
        self.app = app
        self.ambiguity = ambiguity
        self.tcp_ambiguities = []  # type: List[TCPAmbiguity]
        if app:
            if ambiguity:
                log_runtime.warning(
                    "TCPSession: 'ambiguity' is not supported with app=True."
                )
            self.data = StringBuffer()
            self.metadata = {}  # type: Dict[str, Any]
            self.session = {}  # type: Dict[str, Any]
        else:
            # The StringBuffer() is used to build a global
            # string from fragments and their seq nulber
            self.tcp_frags = defaultdict(
                lambda: (StringBuffer(), {})
            )  # type: DefaultDict[bytes, Tuple[StringBuffer, Dict[str, Any]]]
            self.tcp_sessions = defaultdict(
                dict
            )  # type: DefaultDict[bytes, Dict[str, Any]]
            # Packets that contributed bytes to each buffer, as
            # (unwrapped seq start, unwrapped seq end, packet)
            self.tcp_ambig_sources = defaultdict(
                list
            )  # type: DefaultDict[bytes, List[Tuple[int, int, Packet]]]
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

    def _tcp_check_ambiguity(self,
                             ident,  # type: bytes
                             pkt,  # type: Packet
                             data,  # type: StringBuffer
                             relative_seq,  # type: int
                             seq,  # type: int
                             new_data,  # type: bytes
                             ):
        # type: (...) -> int
        """ambiguity mode: compare incoming data against the bytes already
        buffered for this direction, and record any overlap as a
        TCPAmbiguity ("retransmit" or "conflict").

        :returns: the unwrapped absolute sequence number of new_data.
        """
        sources = self.tcp_ambig_sources[ident]
        # Absolute sequence number of the first buffered byte
        buf_base = relative_seq + 1 + data.noff
        # Unwrap seq around the buffer to handle sequence number wraparound
        start = buf_base + (
            (seq - buf_base + 0x80000000) % 0x100000000
        ) - 0x80000000
        end = start + len(new_data)
        ov_start = max(start, buf_base)
        ov_end = min(end, buf_base + data.content_len)
        if ov_start >= ov_end:
            return start
        # Drop the ranges that the buffer has already moved past
        sources[:] = [source for source in sources if source[1] > buf_base]
        # Only compare against bytes that were really received: where
        # fragments are still missing, the buffer is zero-filled and
        # holds no evidence.
        holes = [(ov_start, ov_end)]
        for src_start, src_end, _ in sources:
            holes = [
                part
                for hole_start, hole_end in holes
                for part in (
                    (hole_start, min(hole_end, src_start)),
                    (max(hole_start, src_end), hole_end),
                )
                if part[0] < part[1]
            ]
        known = []  # type: List[Tuple[int, int]]
        cursor = ov_start
        for hole_start, hole_end in sorted(holes):
            if cursor < hole_start:
                known.append((cursor, hole_start))
            cursor = max(cursor, hole_end)
        if cursor < ov_end:
            known.append((cursor, ov_end))
        for rg_start, rg_end in known:
            buffered = bytes(data.content[rg_start - buf_base:
                                          rg_end - buf_base])
            incoming = new_data[rg_start - start:rg_end - start]
            self.tcp_ambiguities.append(TCPAmbiguity(
                "conflict" if buffered != incoming else "retransmit",
                pkt,
                rg_start,
                rg_end,
                incoming,
                buffered,
                [src_pkt
                 for src_start, src_end, src_pkt in sources
                 if src_start < rg_end and rg_start < src_end],
            ))
        return start

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
        data, metadata = self.tcp_frags[ident]
        tcp_session = self.tcp_sessions[self._get_ident(pkt, True)]
        # Handle TCP sequence numbers
        seq = pkt[TCP].seq
        if "seq" not in metadata:
            metadata["seq"] = seq
        if "next_seq" in metadata and seq < metadata["next_seq"]:
            # Retransmitted data (that we already returned)
            if self.ambiguity:
                delivered = new_data[:metadata["next_seq"] - seq]
                if delivered:
                    # Those bytes were already reassembled and discarded:
                    # the overlap cannot be verified anymore.
                    self.tcp_ambiguities.append(TCPAmbiguity(
                        "delivered",
                        pkt,
                        seq,
                        seq + len(delivered),
                        delivered,
                        None,
                        [],
                    ))
            new_data = new_data[metadata["next_seq"] - seq:]
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
                relative_seq = metadata["relative_seq"] = seq - 1
            if self.ambiguity:
                abs_seq = self._tcp_check_ambiguity(
                    ident, pkt, data, relative_seq, seq, new_data
                )
            seq = seq - relative_seq
            # Add the data to the buffer
            noff = data.noff
            if data.append(new_data, seq):
                if self.ambiguity:
                    # Remember which packet provided those bytes
                    self.tcp_ambig_sources[ident].append(
                        (abs_seq, abs_seq + len(new_data), pkt)
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
        # XXX TODO: check that no empty space is missing in the buffer.
        # XXX Currently, if a TCP fragment was missing, we won't notice it.
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
                metadata["relative_seq"] = relative_seq + full_length
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
                if self.ambiguity:
                    self.tcp_ambig_sources.pop(ident, None)
            # Minimum next seq
            metadata["next_seq"] = pkt[TCP].seq + len(new_data)
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
