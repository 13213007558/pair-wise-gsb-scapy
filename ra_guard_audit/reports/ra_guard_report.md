# Offline RA-Guard Inspection Report

- Capture: `samples/ra_guard_sample.pcap`
- Generated (UTC): 2026-11-11T02:13:40Z

## Summary

| Metric | Value |
| --- | --- |
| Total frames | 23 |
| IPv6 frames | 22 |
| Validated Router Advertisement | 4 |
| Violation | 7 |
| Inconclusive (not passed by default) | 4 |
| Benign non-RA traffic | 7 |
| Out of scope (non-IPv6) | 1 |
| Fragment flows | 4 |
| Incomplete fragment flows | 2 |

## Violation (7)

### Frame 2 — fe80::bad -> ff02::1 (hlim 1)

- Wire length: 102, captured: 102
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0xdb4f, computed 0xdb4f
- Reason codes: `nd_hop_limit_not_255`
  - ND type 134 observed with hop limit 1

### Frame 3 — 2001:db8::1 -> ff02::1 (hlim 255)

- Wire length: 70, captured: 70
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0x29c7, computed 0x29c7
- Reason codes: `ra_source_not_link_local`
  - RA source 2001:db8::1 is outside fe80::/10

### Frame 7 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 60, captured: 60
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0x0000, computed 0x3085
- Reason codes: `icmpv6_checksum_bad`, `ra_shorter_than_16_octets`
  - checksum 0x0000 does not match computed 0x3085
  - RA body is 6 octets, fixed header requires 16

### Frame 8 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 86, captured: 86
- Extension header chain (next-header values): 44
- Fragment: fe80::bad -> ff02::1 id=0x00001111, offset 0, M 1
- Reason codes: `fragmented_neighbor_discovery_rfc6980`
  - offset-zero fragment reveals ICMPv6 ND type 134; RFC 6980 section 4 forbids fragmented Neighbor Discovery
  - flow members: 8, 9

### Frame 9 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 86, captured: 86
- Extension header chain (next-header values): 44
- Fragment: fe80::bad -> ff02::1 id=0x00001111, offset 24, M 0
- Reason codes: `non_initial_fragment_of_nd_flow_rfc6980`
  - non-initial fragment of a flow whose offset-zero fragment is an ICMPv6 Neighbor Discovery message (RFC 6980 section 4)
  - flow members: 8, 9

### Frame 10 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 62, captured: 62
- Extension header chain (next-header values): 44
- Fragment: fe80::bad -> ff02::1 id=0x00002222, offset 0, M 1
- Reason codes: `fragment_0_hides_nd_type_rfc6980`
  - offset-zero fragment carries 0 fragmentable octet(s), so the ICMPv6 type is not visible; RFC 6980 section 4 requires dropping this fragment
  - flow members: 10, 11

### Frame 11 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 110, captured: 110
- Extension header chain (next-header values): 44
- Fragment: fe80::bad -> ff02::1 id=0x00002222, offset 0, M 0
- Reason codes: `fragment_0_hides_nd_type_rfc6980`
  - offset-zero fragment carries 0 fragmentable octet(s), so the ICMPv6 type is not visible; RFC 6980 section 4 requires dropping this fragment
  - flow members: 10, 11

## Inconclusive (not passed by default) (4)

### Frame 12 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 86, captured: 86
- Extension header chain (next-header values): 44
- Fragment: 2001:db8::1 -> 2001:db8::2 id=0x00003333, offset 128, M 0
- Reason codes: `fragment_flow_incomplete`
  - fragment flow never completed within the capture
  - missing byte ranges: [(0, 128)]
  - flow members: 12

### Frame 18 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 98, captured: 98
- Reason codes: `esp_payload_encrypted`
  - ESP payload hides the inner next header; no offline decision is possible without keys

### Frame 21 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 64, captured: 64
- Reason codes: `truncated_icmpv6_header`
  - captured 10 payload octets, IPv6 payload length declares 48

### Frame 22 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 60, captured: 60
- Extension header chain (next-header values): 0
- Reason codes: `truncated_extension_header`
  - extension header 0 extends past captured bytes

## Validated Router Advertisement (4)

### Frame 1 — fe80::1 -> ff02::1 (hlim 255)

- Wire length: 110, captured: 110
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0xaef5, computed 0xaef5
- Reason codes: `valid_ra`
  - RA with hop limit 255, link-local source, zero code and a valid ICMPv6 checksum

### Frame 4 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 86, captured: 86
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0x626b, computed 0x626b
- Extension header chain (next-header values): 0
- Reason codes: `valid_ra`
  - RA with hop limit 255, link-local source, zero code and a valid ICMPv6 checksum

### Frame 5 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 86, captured: 86
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0x626b, computed 0x626b
- Extension header chain (next-header values): 60
- Reason codes: `valid_ra`
  - RA with hop limit 255, link-local source, zero code and a valid ICMPv6 checksum

### Frame 6 — fe80::bad -> ff02::1 (hlim 255)

- Wire length: 86, captured: 86
- ICMPv6 type: 134
- ICMPv6 checksum: declared 0x7003, computed 0x7003
- Extension header chain (next-header values): 0, 60
- Reason codes: `valid_ra`
  - RA with hop limit 255, link-local source, zero code and a valid ICMPv6 checksum

## Benign non-RA traffic (7)

### Frame 13 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 86, captured: 86
- Extension header chain (next-header values): 44
- Fragment: 2001:db8::1 -> 2001:db8::2 id=0x00004444, offset 0, M 1
- Reason codes: `fragmented_non_nd_traffic`
  - fragmented payload next header 59 is not ICMPv6
  - flow members: 13, 14

### Frame 14 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 106, captured: 106
- Extension header chain (next-header values): 44
- Fragment: 2001:db8::1 -> 2001:db8::2 id=0x00004444, offset 64, M 0
- Reason codes: `fragmented_non_nd_traffic`
  - non-initial fragment of a non-ND fragment flow
  - flow members: 13, 14

### Frame 15 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 104, captured: 104
- Reason codes: `not_icmpv6`
  - next header 6 is not ICMPv6; a 0x86 octet in the payload is application data, not an RA

### Frame 16 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 84, captured: 84
- Reason codes: `not_icmpv6`
  - next header 17 is not ICMPv6; a 0x86 octet in the payload is application data, not an RA

### Frame 17 — 2001:db8::1 -> 2001:db8::2 (hlim 64)

- Wire length: 77, captured: 77
- ICMPv6 type: 128
- ICMPv6 checksum: declared 0x2240, computed 0x2240
- Reason codes: `non_ra_icmpv6`
  - ICMPv6 type 128 is not a Router Advertisement

### Frame 19 — fe80::1 -> ff02::1:ff00:2 (hlim 255)

- Wire length: 78, captured: 78
- ICMPv6 type: 135
- ICMPv6 checksum: declared 0x7da1, computed 0x7da1
- Reason codes: `non_ra_icmpv6`
  - ICMPv6 type 135 is not a Router Advertisement

### Frame 20 — fe80::2 -> fe80::1 (hlim 255)

- Wire length: 86, captured: 86
- ICMPv6 type: 136
- ICMPv6 checksum: declared 0x9919, computed 0x9919
- Reason codes: `non_ra_icmpv6`
  - ICMPv6 type 136 is not a Router Advertisement

## Out of scope (non-IPv6) (1)

### Frame 23 — - -> - (hlim -)

- Wire length: 42, captured: 42
- Reason codes: `non_ipv6_frame`
  - frame does not carry IPv6
