"""Generate a small synthetic pcap exercising the RA-guard checker.

All addresses are taken from RFC 3849 documentation space (2001:db8::/32),
RFC 4291 link-local / multicast space, or RFC 5737 IPv4 documentation space.
MAC addresses use the locally administered bit.  No real network data appears
in the capture.
"""

from pathlib import Path

from scapy.all import ARP, Ether, ESP, UDP, TCP, Raw, wrpcap
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    HBHOptUnknown,
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
)

from raguard.constants import ICMPV6_RA

SRC_LL = "fe80::1"
ATTACKER_LL = "fe80::bad"
DOC_SRC = "2001:db8::1"
DOC_DST = "2001:db8::2"
ALL_NODES = "ff02::1"
SOLICITED = "ff02::1:ff00:2"
TEST_MAC = "02:00:00:00:00:01"
ATTACKER_MAC = "02:00:00:00:be:ef"


def eth(src=TEST_MAC, dst="33:33:00:00:00:01"):
    return Ether(src=src, dst=dst)


def valid_ra():
    return (
        eth()
        / IPv6(src=SRC_LL, dst=ALL_NODES, hlim=255)
        / ICMPv6ND_RA(routerlifetime=1800, reachabletime=0, retranstimer=0)
        / ICMPv6NDOptSrcLLAddr(lladdr=TEST_MAC)
        / ICMPv6NDOptPrefixInfo(
            prefix="2001:db8:1::", prefixlen=64, L=1, A=1, validlifetime=86400
        )
    )


def hlim_attack_ra():
    # RFC 4861 requires hlim 255; a forwarder may reset hop limit, so an
    # off-link attacker sends hlim 1 to survive naive type-only matching.
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=1)
        / ICMPv6ND_RA(routerlifetime=9000)
        / ICMPv6NDOptPrefixInfo(
            prefix="2001:db8:66::", prefixlen=64, L=1, A=1
        )
    )


def source_scope_attack_ra():
    # RA sourced from a routable documentation address instead of fe80::/10.
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=DOC_SRC, dst=ALL_NODES, hlim=255)
        / ICMPv6ND_RA(routerlifetime=9000)
    )


def hbh_hidden_ra():
    # Extension header inserted before the RA; a type-134 byte search that
    # only looks at fixed offsets misses this.
    options = [HBHOptUnknown(otype=0x1F, optdata=b"\x00" * 6)]
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / IPv6ExtHdrHopByHop(options=options)
        / ICMPv6ND_RA(routerlifetime=3600)
    )


def destopt_hidden_ra():
    options = [HBHOptUnknown(otype=0x1F, optdata=b"\x01" * 6)]
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / IPv6ExtHdrDestOpt(options=options)
        / ICMPv6ND_RA(routerlifetime=3600)
    )


def double_ext_ra():
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / IPv6ExtHdrHopByHop(options=[HBHOptUnknown(otype=0x1E, optdata=b"")])
        / IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=0x1E, optdata=b"")])
        / ICMPv6ND_RA(routerlifetime=120)
    )


def malformed_ra():
    # Type 134 but only six octets: shorter than the fixed RA header.  The
    # checksum field is deliberately left zero so both structural failures
    # are observable.
    body = bytes([ICMPV6_RA, 0, 0, 0, 64, 0x08])
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255, nh=58)
        / Raw(load=body)
    )


def _split_fragments(inner_packet, flow_id, first_data_octets):
    """Split a fragmentable packet into two aligned fragment frames.

    The split point is expressed in fragmentable-part octets and is rounded
    down to an 8-octet boundary so the second fragment offset is legal and the
    two ranges stay contiguous.
    """
    fragmentable = bytes(inner_packet.payload)
    split = (first_data_octets // 8) * 8
    outer = inner_packet[IPv6]
    f1 = (
        eth()
        / IPv6(src=outer.src, dst=outer.dst, hlim=outer.hlim)
        / IPv6ExtHdrFragment(id=flow_id, offset=0, m=1, nh=outer.nh)
        / Raw(load=fragmentable[:split])
    )
    f2 = (
        eth()
        / IPv6(src=outer.src, dst=outer.dst, hlim=outer.hlim)
        / IPv6ExtHdrFragment(
            id=flow_id, offset=split // 8, m=0, nh=outer.nh
        )
        / Raw(load=fragmentable[split:])
    )
    return f1, f2


def fragmented_ra_two_parts():
    inner = (
        IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / ICMPv6ND_RA(routerlifetime=1800)
        / ICMPv6NDOptPrefixInfo(
            prefix="2001:db8:f0::", prefixlen=64, L=1, A=1
        )
    )
    f1, f2 = _split_fragments(inner, 0x1111, first_data_octets=24)
    f1[Ether].src = ATTACKER_MAC
    f2[Ether].src = ATTACKER_MAC
    return f1, f2


def undersized_initial_fragment():
    # The inner next header is ICMPv6 but the offset-zero fragment carries
    # zero fragmentable octets, so the ICMPv6 type cannot be examined.
    # RFC 6980 section 4 requires dropping such an undersized fragment.
    ra_packet = (
        IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / ICMPv6ND_RA(routerlifetime=60)
        / ICMPv6NDOptPrefixInfo(
            prefix="2001:db8:f1::", prefixlen=64, L=1, A=1
        )
    )
    tail = bytes(ra_packet.payload)
    f1 = (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / IPv6ExtHdrFragment(id=0x2222, offset=0, m=1, nh=58)
    )
    f2 = (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / IPv6ExtHdrFragment(id=0x2222, offset=0, m=0, nh=58)
        / Raw(load=tail)
    )
    return f1, f2


def orphan_fragment():
    # Non-initial fragment with no offset zero anywhere in the capture.
    return (
        eth(src=ATTACKER_MAC)
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64)
        / IPv6ExtHdrFragment(id=0x3333, offset=16, m=0)
        / Raw(load=b"\x86" * 24)
    )


def fragmented_udp_flow():
    # Ordinary large UDP datagram; fragmentation is legal for non-ND traffic.
    payload = b"\x86" * 60
    inner = IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64) / UDP(
        sport=5353, dport=5353
    ) / Raw(load=payload)
    wire = bytes(inner)
    split = 40 + 24
    f1 = (
        eth()
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64)
        / IPv6ExtHdrFragment(id=0x4444, offset=0, m=1)
        / Raw(load=wire[40:split])
    )
    f2 = (
        eth()
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64)
        / IPv6ExtHdrFragment(id=0x4444, offset=split // 8, m=0)
        / Raw(load=wire[split:])
    )
    return f1, f2


def benign_tcp_with_134_byte():
    # Application payload contains 0x86 but the next header is TCP.
    return (
        eth()
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64)
        / TCP(sport=44300, dport=443, flags="PA", seq=100)
        / Raw(load=b"GET /index HTTP/1.1\r\n\x86\x00padding")
    )


def benign_udp_ra_like_payload():
    # UDP payload starts with 0x86; not ICMPv6 so it is not an RA.
    return (
        eth()
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64)
        / UDP(sport=60000, dport=5353)
        / Raw(load=bytes([ICMPV6_RA, 0]) + b"\x00" * 20)
    )


def benign_echo():
    return (
        eth()
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64)
        / ICMPv6EchoRequest(id=1, seq=1, data=b"diagnostic ping")
    )


def benign_ns_na():
    ns = (
        eth()
        / IPv6(src=SRC_LL, dst=SOLICITED, hlim=255)
        / ICMPv6ND_NS(tgt="fe80::2")
    )
    na = (
        eth(dst=TEST_MAC)
        / IPv6(src="fe80::2", dst=SRC_LL, hlim=255)
        / ICMPv6ND_NA(tgt="fe80::2", R=1, S=1)
        / ICMPv6NDOptSrcLLAddr(lladdr="02:00:00:00:00:02")
    )
    return ns, na


def truncated_ra():
    full = (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / ICMPv6ND_RA(routerlifetime=1800)
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8:c0::", prefixlen=64)
    )
    raw_frame = bytes(full)
    # Keep Ethernet + IPv6 + ten ICMPv6 octets, cutting the fixed RA header.
    return Ether(raw_frame[: 14 + 40 + 10])


def esp_hidden_payload():
    # ESP encrypts the inner next header, so an offline tool cannot tell
    # whether an RA is hidden inside without decryption keys.
    return (
        eth()
        / IPv6(src=DOC_SRC, dst=DOC_DST, hlim=64, nh=50)
        / ESP(spi=0x00001234, seq=1)
        / Raw(load=b"\x86" * 24 + b"\x00" * 12)
    )


def arp_frame():
    # Legacy ARP is not IPv6 and must be ignored rather than flagged.
    return (
        Ether(src="02:00:00:00:00:03", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc="02:00:00:00:00:03",
            psrc="192.0.2.10",
            hwdst="00:00:00:00:00:00",
            pdst="192.0.2.1",
        )
    )


def truncated_chain():
    full = (
        eth(src=ATTACKER_MAC)
        / IPv6(src=ATTACKER_LL, dst=ALL_NODES, hlim=255)
        / IPv6ExtHdrHopByHop(
            options=[HBHOptUnknown(otype=0x1F, optdata=b"\x00" * 10)]
        )
        / ICMPv6ND_RA()
    )
    raw_frame = bytes(full)
    # Cut inside the hop-by-hop header.
    return Ether(raw_frame[: 14 + 40 + 6])


def build_frames():
    frames = []
    frames.append(("valid_ra", valid_ra()))
    frames.append(("ra_hlim_1", hlim_attack_ra()))
    frames.append(("ra_non_link_local_source", source_scope_attack_ra()))
    frames.append(("ra_after_hop_by_hop", hbh_hidden_ra()))
    frames.append(("ra_after_dest_options", destopt_hidden_ra()))
    frames.append(("ra_after_two_extension_headers", double_ext_ra()))
    frames.append(("malformed_short_ra", malformed_ra()))
    for name, frame in zip(
        ("fragmented_ra_part_1", "fragmented_ra_part_2"),
        fragmented_ra_two_parts(),
    ):
        frames.append((name, frame))
    for name, frame in zip(
        ("undersized_initial_fragment", "hidden_ra_second_fragment"),
        undersized_initial_fragment(),
    ):
        frames.append((name, frame))
    frames.append(("orphan_non_initial_fragment", orphan_fragment()))
    for name, frame in zip(
        ("fragmented_udp_part_1", "fragmented_udp_part_2"),
        fragmented_udp_flow(),
    ):
        frames.append((name, frame))
    frames.append(("tcp_with_0x86_payload", benign_tcp_with_134_byte()))
    frames.append(("udp_with_0x86_first_byte", benign_udp_ra_like_payload()))
    frames.append(("icmpv6_echo_request", benign_echo()))
    frames.append(("esp_encrypted_payload", esp_hidden_payload()))
    for name, frame in zip(("neighbor_solicit", "neighbor_advert"), benign_ns_na()):
        frames.append((name, frame))
    frames.append(("truncated_ra", truncated_ra()))
    frames.append(("truncated_extension_header", truncated_chain()))
    frames.append(("legacy_arp_request", arp_frame()))
    return frames


def main(output: Path) -> None:
    labeled = build_frames()
    wrpcap(str(output), [frame for _, frame in labeled])
    print("wrote %d frames to %s" % (len(labeled), output))
    for index, (name, frame) in enumerate(labeled, start=1):
        print("  frame %2d  %s" % (index, name))


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        __file__).resolve().parents[1] / "samples" / "ra_guard_sample.pcap"
    main(target)
