# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""Pure Python packet filter expressions."""

import ipaddress
import re
import socket

from typing import Any, Iterator, NamedTuple, Optional, Tuple

from scapy.error import Scapy_Exception, log_runtime


class PacketFilterSyntaxError(Scapy_Exception, ValueError):
    pass


class _Token(NamedTuple):
    value: str
    pos: int


class _Node(NamedTuple):
    kind: str
    value: Any = None
    direction: str = "both"
    left: Optional["_Node"] = None
    right: Optional["_Node"] = None


class _PacketContext(object):
    def __init__(self):
        self.ipv4 = None
        self.ipv6 = None
        self.tcp = None
        self.udp = None
        self.transport_proto = None
        self.ports_visible = True

    def network_layers(self):
        return tuple(layer for layer in (self.ipv4, self.ipv6) if layer)

    def transport_layers(self):
        return tuple(layer for layer in (self.tcp, self.udp) if layer)


class CompiledPacketFilter(object):
    """A packet filter expression compiled independently from libpcap."""

    def __init__(self, expression, tree):
        self.expression = expression
        self._tree = tree

    def __call__(self, packet, diagnose=False):
        if diagnose:
            return self.diagnose(packet)
        try:
            context = _build_packet_context(packet)
            return self._match(context, self._tree)
        except Exception:
            log_runtime.debug("packet filter evaluation failed", exc_info=True)
            return False

    def diagnose(self, packet):
        # type: (Any) -> Tuple[bool, Optional[str]]
        try:
            context = _build_packet_context(packet)
            return self._match(context, self._tree), None
        except Exception as exc:
            return False, str(exc)

    def _match(self, context, node):
        if node.kind == "and":
            return (self._match(context, node.left) and
                    self._match(context, node.right))
        if node.kind == "or":
            return (self._match(context, node.left) or
                    self._match(context, node.right))
        if node.kind == "not":
            return not self._match(context, node.left)
        if node.kind == "proto":
            return self._match_proto(context, node.value)
        if node.kind == "host":
            return self._match_address(context, node.value, node.direction)
        if node.kind == "net":
            return self._match_network(context, node.value, node.direction)
        if node.kind == "port":
            return self._match_port(context, node.value, node.direction)
        if node.kind == "portrange":
            return self._match_portrange(context, node.value, node.direction)
        raise RuntimeError("unknown filter node %r" % node.kind)

    @staticmethod
    def _match_proto(context, proto):
        if proto == "ip":
            return context.ipv4 is not None
        if proto == "ip6":
            return context.ipv6 is not None
        if proto == "tcp":
            return (context.tcp is not None or
                    context.transport_proto == socket.IPPROTO_TCP)
        if proto == "udp":
            return (context.udp is not None or
                    context.transport_proto == socket.IPPROTO_UDP)
        raise RuntimeError("unknown protocol %r" % proto)

    @staticmethod
    def _match_address(context, address, direction):
        for layer in context.network_layers():
            for field in _direction_fields(direction):
                try:
                    candidate = _parse_ip_address(getattr(layer, field))
                except ValueError:
                    continue
                if candidate == address:
                    return True
        return False

    @staticmethod
    def _match_network(context, network, direction):
        for layer in context.network_layers():
            for field in _direction_fields(direction):
                try:
                    address = _parse_ip_address(getattr(layer, field))
                except ValueError:
                    continue
                if address.version == network.version and address in network:
                    return True
        return False

    @staticmethod
    def _match_port(context, port, direction):
        if not context.ports_visible:
            return False
        for layer in context.transport_layers():
            for field in _direction_fields(direction):
                if getattr(layer, field) == port:
                    return True
        return False

    @staticmethod
    def _match_portrange(context, ports, direction):
        low, high = ports
        if not context.ports_visible:
            return False
        for layer in context.transport_layers():
            for field in _direction_fields(direction):
                port = getattr(layer, field)
                if low <= port <= high:
                    return True
        return False


def compile_packet_filter(expression):
    # type: (str) -> CompiledPacketFilter
    """Compile a BPF-like expression without using libpcap."""
    if not isinstance(expression, str):
        raise TypeError("filter expression must be a string")
    tokens = list(_tokenize(expression))
    parser = _Parser(tokens, expression)
    tree = parser.parse_or()
    if parser.current is not None:
        raise parser.error("unexpected token %r" % parser.current.value)
    return CompiledPacketFilter(expression, tree)


class _Parser(object):
    qualifiers = frozenset(("host", "net", "port", "portrange"))
    protocols = frozenset(("ip", "ip6", "tcp", "udp"))
    directions = frozenset(("src", "dst"))

    def __init__(self, tokens, expression):
        self.tokens = tokens
        self.expression = expression
        self.pos = 0

    @property
    def current(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self):
        token = self.current
        if token is None:
            raise self.error("unexpected end of expression")
        self.pos += 1
        return token

    def error(self, message):
        token = self.current
        pos = token.pos if token is not None else len(self.expression)
        return PacketFilterSyntaxError("%s at position %d" % (message, pos))

    def parse_or(self):
        node = self.parse_and()
        while self.current is not None and self.current.value == "or":
            self.consume()
            node = _Node("or", left=node, right=self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.current is not None and self.current.value == "and":
            self.consume()
            node = _Node("and", left=node, right=self.parse_not())
        return node

    def parse_not(self):
        if self.current is not None and self.current.value == "not":
            self.consume()
            return _Node("not", left=self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        if self.current is None:
            raise self.error("unexpected end of expression")
        if self.current.value == "(":
            self.consume()
            node = self.parse_or()
            if self.current is None or self.current.value != ")":
                raise self.error("missing closing parenthesis")
            self.consume()
            return node

        direction = "both"
        protocol = None
        qualifier = None
        for _ in range(3):
            token = self.current
            if token is None:
                break
            if token.value in self.directions and direction == "both":
                direction = self.consume().value
            elif token.value in self.protocols and protocol is None:
                protocol = self.consume().value
            elif token.value in self.qualifiers and qualifier is None:
                qualifier = self.consume().value
            else:
                break

        if protocol is not None and qualifier is None:
            if self.current is not None and self.current.value in self.qualifiers:
                qualifier = self.consume().value
            else:
                return _Node("proto", protocol)

        if qualifier is None:
            token = self.current
            if token is None:
                raise self.error("unexpected end of expression")
            if token.value in ("and", "or", ")"):
                raise self.error("unexpected token %r" % token.value)
            raise PacketFilterSyntaxError(
                "unsupported syntax %r at position %d" % (token.value, token.pos)
            )

        value_token = self.current
        if value_token is None:
            raise self.error("missing %s value" % qualifier)
        reserved = self.qualifiers | self.protocols | self.directions | frozenset(
            ("and", "or", ")")
        )
        if value_token.value in reserved:
            raise self.error("missing %s value" % qualifier)
        self.consume()

        if qualifier in ("host", "net"):
            value = _parse_host_or_network(qualifier, value_token.value)
        else:
            value = _parse_port_value(qualifier, value_token.value)
        _validate_protocol_primitive(protocol, qualifier, value_token.pos)
        return _Node(qualifier, value, direction)


def _validate_protocol_primitive(protocol, qualifier, pos):
    if protocol in ("tcp", "udp") and qualifier in ("host", "net"):
        raise PacketFilterSyntaxError(
            "%s cannot be combined with %s at position %d" % (
                protocol, qualifier, pos)
        )


_token_re = re.compile(r"[A-Za-z0-9_.:/-]+|[()]")


def _tokenize(expression):
    # type: (str) -> Iterator[_Token]
    pos = 0
    while pos < len(expression):
        if expression[pos].isspace():
            pos += 1
            continue
        match = _token_re.match(expression, pos)
        if match is None:
            raise PacketFilterSyntaxError(
                "unsupported syntax %r at position %d" % (
                    expression[pos], pos)
            )
        yield _Token(match.group(0).lower(), match.start())
        pos = match.end()


def _parse_host_or_network(kind, value):
    try:
        if kind == "host":
            return _parse_ip_address(value)
        if "/" not in value:
            raise ValueError
        return ipaddress.ip_interface(value).network
    except ValueError:
        raise PacketFilterSyntaxError("unsupported %s %r" % (kind, value))


def _parse_port_value(kind, value):
    if kind == "port":
        port = _parse_port(value)
        if port is None:
            raise PacketFilterSyntaxError("unsupported port %r" % value)
        return port
    parts = value.split("-")
    if len(parts) != 2:
        raise PacketFilterSyntaxError("unsupported portrange %r" % value)
    low = _parse_port(parts[0])
    high = _parse_port(parts[1])
    if low is None or high is None or low > high:
        raise PacketFilterSyntaxError("unsupported portrange %r" % value)
    return low, high


def _parse_port(value):
    if not value.isdigit():
        return None
    port = int(value)
    if 0 <= port <= 65535:
        return port
    return None


def _parse_ip_address(value):
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if "%" in value:
        value = value.split("%", 1)[0]
    return ipaddress.ip_address(value)


def _direction_fields(direction):
    if direction == "src":
        return ("src", "sport")
    if direction == "dst":
        return ("dst", "dport")
    return "src", "dst", "sport", "dport"


def _build_packet_context(packet):
    from scapy.layers.inet import IP, TCP as TCPv4, UDP as UDPv4
    from scapy.layers.inet6 import (
        IPv6,
        IPv6ExtHdrFragment,
        TCP as TCPv6,
        UDP as UDPv6,
        _IPv6ExtHdr,
    )

    context = _PacketContext()
    layer = packet
    seen = set()

    while layer is not None and id(layer) not in seen:
        seen.add(id(layer))
        if isinstance(layer, IP):
            context.ipv4 = layer
            context.transport_proto = layer.proto
            if layer.frag > 0:
                context.ports_visible = False
                break
            layer = layer.payload
            continue
        if isinstance(layer, IPv6):
            context.ipv6 = layer
            context.transport_proto = layer.nh
            layer = layer.payload
            continue
        if context.ipv6 is not None and isinstance(layer, _IPv6ExtHdr):
            if isinstance(layer, IPv6ExtHdrFragment):
                context.transport_proto = layer.nh
                if layer.offset > 0:
                    context.ports_visible = False
                    break
            layer = layer.payload
            continue
        if isinstance(layer, (TCPv4, TCPv6)):
            context.tcp = layer
            if context.transport_proto is None:
                context.transport_proto = socket.IPPROTO_TCP
            break
        if isinstance(layer, (UDPv4, UDPv6)):
            context.udp = layer
            if context.transport_proto is None:
                context.transport_proto = socket.IPPROTO_UDP
            break
        layer = getattr(layer, "payload", None)

    return context
    if protocol in ("ip", "ip6") and qualifier in ("port", "portrange"):
        raise PacketFilterSyntaxError(
            "%s cannot be combined with %s at position %d" % (
                protocol, qualifier, pos)
        )
