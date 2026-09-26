# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Pure-Python packet filter expressions.

This module compiles a small tcpdump-like filter language into a
reusable predicate that can be applied to any number of Scapy packets.
It is meant for environments where libpcap is not available (e.g. data
analysis containers) and only works on local Packet objects; it never
touches libpcap.

Supported syntax::

    expr      := or_expr
    or_expr   := and_expr ("or" and_expr)*
    and_expr  := unary (("and" | <nothing>) unary)*
    unary     := "not" unary | "(" expr ")" | primitive
    primitive := ["ip" | "ip6" | "tcp" | "udp"] ["src" | "dst"]
                 ("host" ADDR | "net" CIDR | "port" PORT |
                  "portrange" LOW-HIGH)
               | "ip" | "ip6" | "tcp" | "udp"

Two primitives separated only by whitespace are combined with an
implicit "and", like in tcpdump expressions ("tcp dst port 443").

Notes:

- Addresses and networks must be numeric (IPv4 or IPv6); name
  resolution is not performed. Ports must be numeric; service names
  are not supported.
- Anything outside the grammar above raises PacketFilterError at
  compile time instead of being silently interpreted.
- "tcp"/"udp" match on the IP protocol / IPv6 next-header chain, so
  they also match non-first fragments (like libpcap). "port" and
  "portrange" require a real TCP/UDP layer: non-first fragments never
  match them, and their payload is never interpreted as ports.
- Transport layers are located through VLAN (including QinQ) and IPv6
  extension headers, because matching is done on the packet layers
  rather than on fixed offsets.
- Applying a compiled filter to a malformed packet returns False
  (and logs a debug message) instead of raising.

Example::

    from scapy.modules.packetfilter import compile_filter

    filt = compile_filter("ip and tcp and dst port 80")
    matched = [pkt for pkt in packets if filt.match(pkt)]
"""

import ipaddress
import re

from typing import Callable, Optional, Union

from scapy.error import log_runtime
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, _IPv6ExtHdr
from scapy.packet import Packet  # noqa: F401  (used in type comments)

__all__ = ["PacketFilter", "PacketFilterError", "compile_filter"]


class PacketFilterError(ValueError):
    """Raised when a filter expression cannot be compiled."""


_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_PROTO_PRIMITIVES = ("ip", "ip6", "tcp", "udp")
_VALUE_PRIMITIVES = ("host", "net", "port", "portrange")
_DIRECTIONS = ("src", "dst")
_PRIMITIVE_STARTS = _PROTO_PRIMITIVES + _VALUE_PRIMITIVES + _DIRECTIONS


# Packet inspection helpers

def _transport_protocol(pkt):
    # type: (Packet) -> Optional[int]
    """Return the transport protocol number of a packet.

    This walks the IPv6 extension header chain, so a transport layer
    hidden behind extension headers is still recognized.
    """
    ip = pkt.getlayer(IP)
    if ip is not None:
        return ip.proto
    ip6 = pkt.getlayer(IPv6)
    if ip6 is None:
        return None
    nh = ip6.nh
    layer = ip6.payload
    while isinstance(layer, _IPv6ExtHdr):
        nh = layer.nh
        layer = layer.payload
    return nh


def _nonfirst_fragment(pkt):
    # type: (Packet) -> bool
    """Return True for non-first fragments, which carry no ports."""
    ip = pkt.getlayer(IP)
    if ip is not None:
        return ip.frag != 0
    frag = pkt.getlayer(IPv6ExtHdrFragment)
    return frag is not None and frag.offset != 0


def _to_address(value):
    # type: (str) -> Optional[_IPAddress]
    try:
        # Scoped IPv6 addresses ("fe80::1%eth0") compare on the address
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


# Predicate builders

def _protocol_predicate(name):
    if name == "ip":
        return lambda pkt: pkt.getlayer(IP) is not None
    if name == "ip6":
        return lambda pkt: pkt.getlayer(IPv6) is not None
    number = 6 if name == "tcp" else 17
    return lambda pkt: _transport_protocol(pkt) == number


def _check_family(proto, version, value):
    # type: (Optional[str], int, str) -> None
    if proto == "ip" and version != 4:
        raise PacketFilterError(
            "'ip' qualifier used with non-IPv4 address %r" % value)
    if proto == "ip6" and version != 6:
        raise PacketFilterError(
            "'ip6' qualifier used with non-IPv6 address %r" % value)


def _host_predicate(value, direction, proto):
    addr = _to_address(value)
    if addr is None:
        raise PacketFilterError(
            "invalid address %r in 'host' primitive (name resolution "
            "is not supported)" % value)
    _check_family(proto, addr.version, value)
    layer = IP if addr.version == 4 else IPv6

    def pred(pkt):
        l3 = pkt.getlayer(layer)
        if l3 is None:
            return False
        if direction != "dst" and _to_address(l3.src) == addr:
            return True
        return direction != "src" and _to_address(l3.dst) == addr
    return pred


def _net_predicate(value, direction, proto):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise PacketFilterError(
            "invalid network %r in 'net' primitive, expected CIDR "
            "notation (e.g. '10.0.0.0/8')" % value)
    _check_family(proto, network.version, value)
    layer = IP if network.version == 4 else IPv6

    def pred(pkt):
        l3 = pkt.getlayer(layer)
        if l3 is None:
            return False
        if direction != "dst":
            src = _to_address(l3.src)
            if src is not None and src in network:
                return True
        if direction != "src":
            dst = _to_address(l3.dst)
            if dst is not None and dst in network:
                return True
        return False
    return pred


def _parse_port(value):
    # type: (str) -> int
    try:
        port = int(value, 10)
    except ValueError:
        raise PacketFilterError(
            "invalid port %r (service names are not supported)" % value)
    if not 0 <= port <= 65535:
        raise PacketFilterError("port %d out of range 0-65535" % port)
    return port


def _port_predicate(test, direction, proto):
    # type: (Callable[[int], bool], Optional[str], Optional[str]) -> Callable[[Packet], bool]  # noqa: E501
    layers = []
    if proto != "udp":
        layers.append(TCP)
    if proto != "tcp":
        layers.append(UDP)

    def pred(pkt):
        if _nonfirst_fragment(pkt):
            # A non-first fragment has no transport header: never guess
            # ports from its payload.
            return False
        for layer in layers:
            l4 = pkt.getlayer(layer)
            if l4 is None:
                continue
            if direction != "dst" and test(l4.sport):
                return True
            if direction != "src" and test(l4.dport):
                return True
        return False
    return pred


# Parser

class _Parser:
    def __init__(self, expression):
        # type: (str) -> None
        self.tokens = _TOKEN_RE.findall(expression)
        self.pos = 0

    def peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def expect(self):
        # type: () -> str
        token = self.peek()
        if token is None:
            raise PacketFilterError("unexpected end of filter expression")
        self.pos += 1
        return token

    def parse(self):
        if not self.tokens:
            raise PacketFilterError("empty filter expression")
        pred = self.parse_or()
        token = self.peek()
        if token is not None:
            raise PacketFilterError(
                "unexpected token %r in filter expression" % token)
        return pred

    def parse_or(self):
        pred = self.parse_and()
        while self.peek() is not None and self.peek().lower() == "or":
            self.pos += 1
            left, right = pred, self.parse_and()
            pred = lambda pkt, lhs=left, rhs=right: lhs(pkt) or rhs(pkt)
        return pred

    def parse_and(self):
        pred = self.parse_unary()
        while True:
            token = self.peek()
            if token is not None and token.lower() == "and":
                self.pos += 1
            elif token is not None and token.lower() in _PRIMITIVE_STARTS:
                # tcpdump-style implicit "and" between primitives
                pass
            else:
                break
            left, right = pred, self.parse_unary()
            pred = lambda pkt, lhs=left, rhs=right: lhs(pkt) and rhs(pkt)
        return pred

    def parse_unary(self):
        token = self.peek()
        if token is None:
            raise PacketFilterError("unexpected end of filter expression")
        low = token.lower()
        if low == "not":
            self.pos += 1
            pred = self.parse_unary()
            return lambda pkt: not pred(pkt)
        if token == "(":
            self.pos += 1
            pred = self.parse_or()
            if self.peek() != ")":
                raise PacketFilterError("missing ')' in filter expression")
            self.pos += 1
            return pred
        return self.parse_primitive()

    def parse_primitive(self):
        token = self.expect()
        low = token.lower()
        if low not in _PRIMITIVE_STARTS:
            raise PacketFilterError(
                "unsupported syntax %r in filter expression" % token)
        proto = None
        if low in _PROTO_PRIMITIVES:
            token = self.peek()
            nxt = token.lower() if token is not None else None
            if nxt in _VALUE_PRIMITIVES or nxt in _DIRECTIONS:
                # protocol qualifier, e.g. "tcp dst port 443"
                proto = low
                low = self.expect().lower()
            else:
                return _protocol_predicate(low)
        direction = None
        if low in _DIRECTIONS:
            direction = low
            low = self.expect().lower()
        if low == "host":
            pred = _host_predicate(self.expect(), direction, proto)
        elif low == "net":
            pred = _net_predicate(self.expect(), direction, proto)
        elif low == "port":
            pred = _port_predicate(
                lambda port, p=_parse_port(self.expect()): port == p,
                direction, proto)
        elif low == "portrange":
            pred = _port_predicate(
                self._parse_portrange(self.expect()), direction, proto)
        else:
            raise PacketFilterError(
                "expected 'host', 'net', 'port' or 'portrange' "
                "after %r" % low)
        if proto in ("tcp", "udp"):
            base = _protocol_predicate(proto)
            return lambda pkt: base(pkt) and pred(pkt)
        return pred

    @staticmethod
    def _parse_portrange(value):
        # type: (str) -> Callable[[int], bool]
        parts = value.split("-")
        if len(parts) != 2:
            raise PacketFilterError(
                "invalid portrange %r, expected 'low-high'" % value)
        low, high = _parse_port(parts[0]), _parse_port(parts[1])
        if low > high:
            raise PacketFilterError(
                "invalid portrange %r, low is greater than high" % value)
        return lambda port: low <= port <= high


# Public API

class PacketFilter:
    """A compiled filter expression, reusable on any number of packets."""

    def __init__(self, expression, predicate):
        self.expression = expression
        self._predicate = predicate

    def match(self, pkt):
        # type: (Packet) -> bool
        """Return True if the packet matches the compiled expression.

        Malformed packets never raise: they deterministically do not
        match, and the error is logged at debug level.
        """
        try:
            return bool(self._predicate(pkt))
        except Exception as exc:
            log_runtime.debug(
                "filter %r failed on packet: %s", self.expression, exc)
            return False

    def __call__(self, pkt):
        # type: (Packet) -> bool
        return self.match(pkt)

    def __repr__(self):
        return "<PacketFilter %r>" % self.expression


def compile_filter(expression):
    # type: (str) -> PacketFilter
    """Compile a filter expression into a reusable PacketFilter.

    Raises PacketFilterError on any unsupported or invalid syntax.
    """
    if not isinstance(expression, str):
        raise PacketFilterError(
            "filter expression must be a string, got %r"
            % type(expression).__name__)
    return PacketFilter(expression, _Parser(expression).parse())
