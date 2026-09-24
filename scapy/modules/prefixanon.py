# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Offline pcap anonymization with prefix-preserving IP address mapping.

This module rewrites the IP addresses found in a capture file using a
keyed, prefix-preserving mapping (in the spirit of Crypto-PAn): two
addresses that share a common prefix of length k are mapped to
addresses that share a common prefix of the same length k, so that
prefix relationships usable for topology analysis are preserved while
the addresses themselves are pseudonymized. IPv4 and IPv6 use
independent mappings derived from the same caller-provided key.

The mapping is deterministic for a fixed key. The key is never
written to the output file, to pcap comments or to the logs.

The same address is mapped identically everywhere it appears: outer
IP headers, inner packets quoted by ICMP/ICMPv6 errors, the ICMP
redirect gateway address and ARP protocol addresses. Lengths and
checksums affected by the transformation are recomputed. When a
packet is truncated or fragmented so that a checksum cannot be fully
recomputed, that checksum is zeroed and an explicit record is added to
the returned report: the output never silently contains a checksum
that claims to be valid.

MAC addresses and application payloads are left untouched.

Only files are processed: this module never captures or sends
traffic.

Usage::

    from scapy.modules.prefixanon import anonymize_pcap
    report = anonymize_pcap("in.pcap", "out.pcap", key=b"secret")
    if not report.ok:
        for record in report.records:
            print(record)
"""

import hashlib
import ipaddress
import struct

from collections import namedtuple
from typing import Dict, Iterator, List, Set, Tuple, Union

from scapy.config import conf
from scapy.error import Scapy_Exception, log_runtime
from scapy.layers.inet import (
    ICMP,
    ICMPerror,
    IP,
    IPerror,
    TCP,
    TCPerror,
    UDP,
    UDPerror,
)
from scapy.layers.inet6 import (
    IPerror6,
    IPv6,
    IPv6ExtHdrFragment,
    _ICMPv6,
)
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from scapy.utils import RawPcapNgReader, RawPcapReader, RawPcapWriter

__all__ = [
    "AnonymizationRecord",
    "PcapAnonymizationReport",
    "PrefixPreservingMapping",
    "anonymize_pcap",
]


class _PrefixCipher(object):
    """Keyed prefix-preserving permutation of {0, 1}^addrlen.

    Bit i of the output is bit i of the input XORed with a
    pseudo-random bit derived from the key and the first i bits of
    the input. Two inputs that share a k-bit prefix are therefore
    mapped to outputs that share a k-bit prefix, and differ at bit
    k + 1.
    """

    def __init__(self, key, addrlen, domain):
        # type: (bytes, int, bytes) -> None
        # Derive a per-family sub-key so that the IPv4 and IPv6
        # mappings are fully independent.
        self._key = hashlib.sha256(domain + key).digest()
        self._addrlen = addrlen
        self._cache = {}  # type: Dict[Tuple[int, int], int]

    def _pad_bit(self, prefix, plen):
        # type: (int, int) -> int
        """Pseudo-random bit for a plen-long prefix of the input."""
        try:
            return self._cache[(plen, prefix)]
        except KeyError:
            digest = hashlib.sha256(
                self._key +
                struct.pack("!B", plen) +
                prefix.to_bytes((plen + 7) // 8, "big")
            ).digest()
            bit = digest[0] & 1
            self._cache[(plen, prefix)] = bit
            return bit

    def anonymize(self, value):
        # type: (int) -> int
        result = 0
        prefix = 0
        for i in range(self._addrlen):
            bit = (value >> (self._addrlen - 1 - i)) & 1
            result = (result << 1) | (bit ^ self._pad_bit(prefix, i))
            prefix = (prefix << 1) | bit
        return result


class PrefixPreservingMapping(object):
    """Deterministic, keyed, prefix-preserving IP address mapping.

    A fixed key always yields the same mapping. IPv4 and IPv6
    addresses are mapped through independent permutations. The key is
    only kept as derived digests and is never logged.
    """

    def __init__(self, key):
        # type: (Union[str, bytes]) -> None
        if isinstance(key, str):
            key = key.encode("utf8")
        if not key:
            raise ValueError("key must not be empty")
        self._v4 = _PrefixCipher(key, 32, b"scapy.prefixanon.v4")
        self._v6 = _PrefixCipher(key, 128, b"scapy.prefixanon.v6")

    def anonymize_ipv4(self, addr):
        # type: (str) -> str
        return str(ipaddress.IPv4Address(
            self._v4.anonymize(int(ipaddress.IPv4Address(addr)))
        ))

    def anonymize_ipv6(self, addr):
        # type: (str) -> str
        return str(ipaddress.IPv6Address(
            self._v6.anonymize(int(ipaddress.IPv6Address(addr)))
        ))


#: Processing record for a packet that could not be fully anonymized.
#: reason is one of "truncated", "fragmented" or "unparsed".
AnonymizationRecord = namedtuple("AnonymizationRecord",
                                 ["packet", "reason", "detail"])


class PcapAnonymizationReport(object):
    """Outcome of an anonymize_pcap() run.

    Attributes:
      - packets_total: packets read from the input file
      - packets_anonymized: packets whose addresses were rewritten
      - packets_copied: packets copied unchanged (non-IP or
        undecodable)
      - mapped_addresses: original addresses that were mapped
      - records: explicit AnonymizationRecord entries for every
        packet whose checksums could not all be recomputed
    """

    def __init__(self):
        # type: () -> None
        self.packets_total = 0
        self.packets_anonymized = 0
        self.packets_copied = 0
        self.mapped_addresses = set()  # type: Set[str]
        self.records = []  # type: List[AnonymizationRecord]

    @property
    def ok(self):
        # type: () -> bool
        """True when no packet required an explicit record."""
        return not self.records

    def __repr__(self):
        # type: () -> str
        return ("<PcapAnonymizationReport total=%d anonymized=%d copied=%d "
                "issues=%d>" % (self.packets_total,
                                self.packets_anonymized,
                                self.packets_copied,
                                len(self.records)))


def _iter_layers(pkt):
    # type: (Packet) -> Iterator[Packet]
    idx = 0
    while True:
        layer = pkt.getlayer(idx)
        if layer is None:
            return
        yield layer
        idx += 1


def _anonymize_packet(data, llcls, mapping, meta, index, report):
    # type: (bytes, type, PrefixPreservingMapping, RawPcapReader.PacketMetadata, int, PcapAnonymizationReport) -> bytes  # noqa: E501
    """Anonymize a single captured packet. Returns the output bytes."""
    try:
        pkt = llcls(data)
    except Exception as exc:
        log_runtime.debug(
            "prefixanon: packet %d: dissection failed: %s", index, exc)
        report.packets_copied += 1
        report.records.append(AnonymizationRecord(
            index, "unparsed",
            "packet could not be dissected; copied unchanged"))
        return data
    layers = list(_iter_layers(pkt))
    if not any(isinstance(layer, (IP, IPv6, ARP)) for layer in layers):
        report.packets_copied += 1
        return data

    def map4(addr):
        # type: (str) -> str
        report.mapped_addresses.add(addr)
        return mapping.anonymize_ipv4(addr)

    def map6(addr):
        # type: (str) -> str
        report.mapped_addresses.add(addr)
        return mapping.anonymize_ipv6(addr)

    # Detect captures that are too short to recompute checksums over,
    # and fragmented datagrams whose transport checksum covers bytes
    # that are not all present in this packet.
    truncated = bool(meta.wirelen and meta.caplen < meta.wirelen)
    fragmented = False
    for layer in layers:
        if isinstance(layer, (IPerror, IPerror6)):
            # Quoted header: its length fields describe the original
            # datagram, not the quote.
            continue
        if isinstance(layer, IP):
            if layer.len is not None and layer.len > len(bytes(layer)):
                truncated = True
            if layer.frag > 0 or int(layer.flags) & 1:  # MF
                fragmented = True
        elif isinstance(layer, IPv6):
            if (layer.plen is not None and
                    40 + layer.plen > len(bytes(layer))):
                truncated = True
        elif isinstance(layer, IPv6ExtHdrFragment):
            if layer.offset > 0 or layer.m:
                fragmented = True
    full_recompute = not (truncated or fragmented)

    for layer in layers:
        if isinstance(layer, IPerror6):
            layer.src = map6(layer.src)
            layer.dst = map6(layer.dst)
        elif isinstance(layer, IPerror):
            layer.src = map4(layer.src)
            layer.dst = map4(layer.dst)
            del layer.chksum
        elif isinstance(layer, (TCPerror, UDPerror, ICMPerror)):
            # Transport header quoted inside an ICMP error: the
            # original datagram is unavailable, its checksum cannot be
            # recomputed and is left as quoted data.
            continue
        elif isinstance(layer, IP):
            layer.src = map4(layer.src)
            layer.dst = map4(layer.dst)
            del layer.chksum
            if not truncated:
                del layer.len
        elif isinstance(layer, IPv6):
            layer.src = map6(layer.src)
            layer.dst = map6(layer.dst)
            if not truncated:
                del layer.plen
        elif isinstance(layer, TCP):
            if full_recompute:
                del layer.chksum
            else:
                layer.chksum = 0
        elif isinstance(layer, UDP):
            if full_recompute:
                del layer.chksum
                del layer.len
            else:
                layer.chksum = 0
        elif isinstance(layer, ICMP):
            gw = getattr(layer, "gw", None)
            if gw:
                layer.gw = map4(gw)
            if full_recompute:
                del layer.chksum
            else:
                layer.chksum = 0
        elif isinstance(layer, _ICMPv6):
            if full_recompute:
                del layer.cksum
            else:
                layer.cksum = 0
        elif isinstance(layer, ARP):
            if layer.ptype == 0x0800:  # IPv4
                layer.psrc = map4(layer.psrc)
                layer.pdst = map4(layer.pdst)

    if truncated:
        report.records.append(AnonymizationRecord(
            index, "truncated",
            "packet is truncated; checksums that could not be "
            "recomputed were zeroed"))
    if fragmented:
        report.records.append(AnonymizationRecord(
            index, "fragmented",
            "packet is fragmented; the transport checksum cannot be "
            "recomputed from a fragment and was zeroed"))
    report.packets_anonymized += 1
    return bytes(pkt)


def anonymize_pcap(input_filename, output_filename, key):
    # type: (str, str, Union[str, bytes]) -> PcapAnonymizationReport
    """Anonymize a pcap file offline and return a processing report.

    Reads the classic pcap file "input_filename", rewrites IP
    addresses with the keyed prefix-preserving mapping derived from
    "key" and writes the result to "output_filename". Packets keep
    their original timestamps; MAC addresses and application payloads
    are untouched.

    :param input_filename: path of the input pcap file
    :param output_filename: path of the pcap file to write
    :param key: caller-provided secret (bytes or str) selecting the
        mapping. It is never written to the output file or logged.
    :return: a PcapAnonymizationReport; check "report.ok" and
        "report.records" for packets whose checksums could not be
        recomputed (truncated, fragmented or undecodable).
    """
    mapping = PrefixPreservingMapping(key)
    report = PcapAnonymizationReport()
    reader = RawPcapReader(input_filename)
    if isinstance(reader, RawPcapNgReader):
        reader.close()
        raise Scapy_Exception("pcapng input is not supported")
    try:
        linktype = reader.linktype
        try:
            llcls = conf.l2types.num2layer[linktype]
        except KeyError:
            raise Scapy_Exception(
                "prefixanon: unsupported linktype %i" % linktype)
        writer = RawPcapWriter(output_filename,
                               linktype=linktype,
                               snaplen=reader.snaplen,
                               nano=reader.nano,
                               endianness=reader.endian)
        try:
            writer.write_header(None)
            for index, (data, meta) in enumerate(reader):
                report.packets_total += 1
                out = _anonymize_packet(data, llcls, mapping, meta,
                                        index, report)
                writer._write_packet(out,
                                     linktype=linktype,
                                     sec=meta.sec,
                                     usec=meta.usec,
                                     caplen=len(out),
                                     wirelen=meta.wirelen)
        finally:
            writer.close()
    finally:
        reader.close()
    return report
