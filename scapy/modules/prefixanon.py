# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Offline prefix-preserving IP address anonymization for pcap files.

This module rewrites the IP addresses found in a capture file with a
keyed, prefix-preserving pseudonym (a Crypto-PAn style construction):
two addresses that share a common prefix of a given length are mapped
to addresses that share a common prefix of the same length, so that
anonymized captures remain usable for topology analysis.  IPv4 and
IPv6 addresses are mapped in two independent domains.

The same address is always mapped to the same value, wherever it
appears: outer IP headers, the packets quoted by ICMP errors and the
address fields of the supported protocols (ARP, ICMP redirect gateway,
ICMPv6 Neighbor Discovery).  Lengths and checksums affected by the
mapping are recomputed.  MAC addresses and application payloads are
left untouched.

Packets that cannot be fully processed (truncated captures, fragments
whose transport payload is incomplete) are still anonymized at the IP
level, but the checksums that cannot be recomputed are left unchanged
and an explicit record is added to the returned report instead of
silently emitting a checksum that would look valid.

The mapping only depends on the caller-provided key, is repeatable for
a fixed key, and the key is never written to the output file nor to
any log.

Typical usage::

    from scapy.modules.prefixanon import anonymize_pcap
    report = anonymize_pcap("in.pcap", "out.pcap", key=b"secret")
    for issue in report.issues:
        print(issue)
"""

import hashlib
import hmac
import socket

from collections import namedtuple

from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror
from scapy.layers.inet6 import (
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_Redirect,
    ICMPv6NDOptPrefixInfo,
    IPerror6,
    IPv6,
    IPv6ExtHdrFragment,
    _ICMPv6,
)
from scapy.layers.l2 import ARP
from scapy.packet import NoPayload, Packet
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils import PcapReader, PcapWriter

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)

__all__ = [
    "AnonymizationIssue",
    "AnonymizationReport",
    "PrefixPreservingAnonymizer",
    "anonymize_pcap",
]


#: Record describing a packet that could not be fully anonymized.
AnonymizationIssue = namedtuple(
    "AnonymizationIssue", ["packet", "reason", "detail"]
)


class _PrefixPreservingMap(object):
    """Keyed prefix-preserving pseudonym for one address family.

    For each bit position, the output bit is the input bit XORed with
    one pseudorandom bit derived from the key and the address prefix
    seen so far (Crypto-PAn).  Addresses sharing a prefix therefore
    keep a prefix of the same length after mapping.
    """

    def __init__(self, key, bits, domain):
        # type: (bytes, int, bytes) -> None
        self._key = hmac.new(key, domain, hashlib.sha256).digest()
        self._bits = bits
        self._cache = {}  # type: Dict[int, int]

    def map_int(self, value):
        # type: (int) -> int
        cached = self._cache.get(value)
        if cached is not None:
            return cached
        bits = self._bits
        size = bits // 8
        result = 0
        for pos in range(bits):
            if pos:
                prefix = (value >> (bits - pos)) << (bits - pos)
            else:
                prefix = 0
            digest = hmac.new(
                self._key, prefix.to_bytes(size, "big"), hashlib.sha256
            ).digest()
            bit = (value >> (bits - 1 - pos)) & 1
            result = (result << 1) | (bit ^ (digest[0] & 1))
        self._cache[value] = result
        return result

    def map_str(self, addr, family):
        # type: (str, int) -> str
        packed = inet_pton(family, addr)
        value = int.from_bytes(packed, "big")
        mapped = self.map_int(value)
        return inet_ntop(family, mapped.to_bytes(len(packed), "big"))


class PrefixPreservingAnonymizer(object):
    """Apply a keyed, prefix-preserving mapping to packet addresses.

    :param key: caller-provided secret (bytes or str) determining the
        mapping.  The same key always produces the same mapping; it is
        never stored in output files or logs.

    IPv4 and IPv6 addresses are mapped independently.  Records about
    packets that could not be fully processed are appended to
    :attr:`issues`.
    """

    def __init__(self, key):
        # type: (Union[bytes, str]) -> None
        if isinstance(key, str):
            key = key.encode("utf8")
        if not key:
            raise ValueError("the anonymization key must not be empty")
        self._map4 = _PrefixPreservingMap(key, 32, b"scapy.prefixanon/ipv4")
        self._map6 = _PrefixPreservingMap(key, 128, b"scapy.prefixanon/ipv6")
        self.issues = []  # type: List[AnonymizationIssue]

    def map_ipv4(self, addr):
        # type: (str) -> str
        """Map an IPv4 address to its prefix-preserving pseudonym."""
        return self._map4.map_str(addr, socket.AF_INET)

    def map_ipv6(self, addr):
        # type: (str) -> str
        """Map an IPv6 address to its prefix-preserving pseudonym."""
        return self._map6.map_str(addr, socket.AF_INET6)

    def _find_limitations(self, pkt):
        # type: (Packet) -> List[Tuple[str, str]]
        """Detect packets whose checksums cannot be fully recomputed."""
        limitations = []  # type: List[Tuple[str, str]]
        ip = pkt.getlayer(IP)
        if ip is not None:
            if (ip.original is not None and ip.len is not None and
                    len(ip.original) < ip.len):
                limitations.append((
                    "truncated",
                    "captured %d bytes but IPv4 total length is %d; "
                    "checksums of incomplete layers were left unchanged"
                    % (len(ip.original), ip.len),
                ))
            elif ip.frag:
                # Non-first fragment: no transport header is present,
                # the IP header checksum can be recomputed.
                pass
            elif ip.flags.MF:
                limitations.append((
                    "fragmented",
                    "first fragment of a fragmented IPv4 datagram; "
                    "the transport checksum was left unchanged",
                ))
        ip6 = pkt.getlayer(IPv6)
        if ip6 is not None:
            if (ip6.original is not None and ip6.plen is not None and
                    len(ip6.original) < 40 + ip6.plen):
                limitations.append((
                    "truncated",
                    "captured %d bytes but IPv6 packet is %d bytes; "
                    "checksums of incomplete layers were left unchanged"
                    % (len(ip6.original), 40 + ip6.plen),
                ))
            frag = pkt.getlayer(IPv6ExtHdrFragment)
            if frag is not None and not frag.offset and frag.m:
                limitations.append((
                    "fragmented",
                    "first fragment of a fragmented IPv6 datagram; "
                    "the transport checksum was left unchanged",
                ))
        return limitations

    def _transform_stack(self, pkt, complete):
        # type: (Packet, bool) -> None
        quoted = False
        current = pkt  # type: Optional[Packet]
        while current is not None and not isinstance(current, NoPayload):
            if isinstance(current, (IPerror, IPerror6)):
                # Packet quoted by an ICMP error: its addresses are
                # mapped for consistency and its IP header checksum is
                # recomputed, but the quoted transport checksum covers
                # data that is not present and is preserved verbatim.
                quoted = True
            if isinstance(current, IP):
                current.src = self.map_ipv4(current.src)
                current.dst = self.map_ipv4(current.dst)
                del current.chksum
            elif isinstance(current, IPv6):
                current.src = self.map_ipv6(current.src)
                current.dst = self.map_ipv6(current.dst)
            if isinstance(current, ARP):
                current.psrc = self.map_ipv4(current.psrc)
                current.pdst = self.map_ipv4(current.pdst)
            if isinstance(current, ICMP) and current.type == 5:
                current.gw = self.map_ipv4(current.gw)
            if isinstance(current, (ICMPv6ND_NS, ICMPv6ND_NA)):
                current.tgt = self.map_ipv6(current.tgt)
            elif isinstance(current, ICMPv6ND_Redirect):
                current.tgt = self.map_ipv6(current.tgt)
                current.dst = self.map_ipv6(current.dst)
            if isinstance(current, ICMPv6NDOptPrefixInfo):
                current.prefix = self.map_ipv6(current.prefix)
            if complete and not quoted:
                if isinstance(current, (TCP, ICMP)):
                    del current.chksum
                elif isinstance(current, UDP):
                    if current.chksum:
                        del current.chksum
                elif isinstance(current, _ICMPv6):
                    del current.cksum
            current = current.payload

    def transform_packet(self, pkt, number=None):
        # type: (Packet, Optional[int]) -> Packet
        """Anonymize the addresses of one packet, in place.

        Affected lengths and checksums are recomputed when the packet
        is rebuilt (e.g. with ``bytes(pkt)``).  When truncation or
        fragmentation prevents a checksum from being recomputed, the
        original value is kept and a record is appended to
        :attr:`issues`.
        """
        limitations = self._find_limitations(pkt)
        for reason, detail in limitations:
            self.issues.append(AnonymizationIssue(number, reason, detail))
        self._transform_stack(pkt, complete=not limitations)
        return pkt


class AnonymizationReport(object):
    """Result of :func:`anonymize_pcap`.

    :attr:`packets` is the number of processed packets and
    :attr:`issues` lists the packets that could not be fully
    anonymized (see :class:`AnonymizationIssue`).
    """

    def __init__(self):
        # type: () -> None
        self.packets = 0
        self.issues = []  # type: List[AnonymizationIssue]

    def __repr__(self):
        # type: () -> str
        return "<AnonymizationReport packets=%d issues=%d>" % (
            self.packets, len(self.issues))


def anonymize_pcap(input, output, key):
    # type: (Union[str, Any], Union[str, Any], Union[bytes, str]) -> AnonymizationReport  # noqa: E501
    """Rewrite a capture file with prefix-preserving anonymized addresses.

    :param input: path of the pcap/pcapng file to read (or file-like).
    :param output: path of the pcap file to write (or file-like).
    :param key: caller-provided secret determining the mapping.
    :return: an :class:`AnonymizationReport`.

    Only files are processed; no traffic is captured or sent.  MAC
    addresses and application payloads are left untouched, and the key
    is never written to the output file.
    """
    anonymizer = PrefixPreservingAnonymizer(key)
    report = AnonymizationReport()
    with PcapReader(input) as reader:
        with PcapWriter(output,
                        linktype=reader.linktype,
                        nano=reader.nano,
                        snaplen=reader.snaplen) as writer:
            for number, pkt in enumerate(reader, 1):
                anonymizer.transform_packet(pkt, number)
                writer.write(pkt)
                report.packets += 1
    report.issues = anonymizer.issues
    return report
