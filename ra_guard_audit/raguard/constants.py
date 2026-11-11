"""Protocol constants and verdict taxonomy for the offline RA-guard checker.

All numeric values come from the IANA registries referenced by RFC 8200,
RFC 4443, RFC 4861 and RFC 6980; they are duplicated here so the checker does
not depend on platform ``IPPROTO_*`` availability.
"""

# IPv6 next-header values (RFC 8200 section 4.3 / IANA).
NH_HOP_BY_HOP = 0
NH_TCP = 6
NH_UDP = 17
NH_IPV6 = 41
NH_ROUTING = 43
NH_FRAGMENT = 44
NH_ESP = 50
NH_AH = 51
NH_ICMPV6 = 58
NH_DEST_OPT = 60
NH_MOBILITY = 135
NH_SHIM6 = 140

# Extension headers that are walked as part of the header chain.
EXTENSION_HEADERS = frozenset(
    {
        NH_HOP_BY_HOP,
        NH_ROUTING,
        NH_FRAGMENT,
        NH_DEST_OPT,
        NH_AH,
        NH_MOBILITY,
        NH_SHIM6,
    }
)

# ICMPv6 types (RFC 4443 / RFC 4861).
ICMPV6_DST_UNREACH = 1
ICMPV6_PACKET_TOO_BIG = 2
ICMPV6_TIME_EXCEEDED = 3
ICMPV6_PARAM_PROBLEM = 4
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
ICMPV6_MLD_QUERY = 130
ICMPV6_MLD_REPORT = 131
ICMPV6_MLD_DONE = 132
ICMPV6_RS = 133
ICMPV6_RA = 134
ICMPV6_NS = 135
ICMPV6_NA = 136
ICMPV6_REDIRECT = 137
ICMPV6_RPL = 155

# Neighbor Discovery message types whose hop limit must be 255.  RFC 4861
# section 3.1 and RFC 6980 section 4.
ND_MESSAGE_TYPES = frozenset(
    {ICMPV6_RS, ICMPV6_RA, ICMPV6_NS, ICMPV6_NA, ICMPV6_REDIRECT}
)

# Minimum on-wire size of an ICMPv6 ND Router Advertisement fixed header
# (RFC 4861 section 4.2: type, code, cksum, hop limit, flags, lifetime,
# reachable timer, retrans timer).
RA_MIN_LENGTH = 16

# ND messages require an exactly-on-link hop limit of 255 (RFC 4861 3.1).
ND_REQUIRED_HOP_LIMIT = 255

# All-nodes link-local multicast group used by unsolicited RAs.
ALL_NODES_MULTICAST = "ff02::1"

# Final dispositions for an inspected frame or fragment.
VERDICT_RA = "ra"              # fully validated Router Advertisement
VERDICT_VIOLATION = "violation"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_BENIGN = "benign"
VERDICT_OUT_OF_SCOPE = "out_of_scope"

VERDICT_ORDER = (
    VERDICT_VIOLATION,
    VERDICT_INCONCLUSIVE,
    VERDICT_RA,
    VERDICT_BENIGN,
    VERDICT_OUT_OF_SCOPE,
)

# Machine-readable reason codes.
REASON_VALID_RA = "valid_ra"
REASON_NOT_ICMPV6 = "not_icmpv6"
REASON_NON_RA_ICMPV6 = "non_ra_icmpv6"
REASON_NON_IPV6 = "non_ipv6_frame"
REASON_TRUNCATED_IPV6 = "truncated_ipv6_header"
REASON_TRUNCATED_EXT = "truncated_extension_header"
REASON_TRUNCATED_ICMPV6 = "truncated_icmpv6_header"
REASON_UNKNOWN_NH = "unknown_next_header"
REASON_ESP_PAYLOAD = "esp_payload_encrypted"
REASON_HOP_LIMIT = "nd_hop_limit_not_255"
REASON_SOURCE_SCOPE = "ra_source_not_link_local"
REASON_RA_TOO_SHORT = "ra_shorter_than_16_octets"
REASON_RA_BAD_CODE = "ra_code_not_zero"
REASON_ICMPV6_CHECKSUM = "icmpv6_checksum_bad"
REASON_RA_DESTINATION = "ra_destination_not_all_nodes"
REASON_FRAGMENTED_ND = "fragmented_neighbor_discovery_rfc6980"
REASON_FRAGMENT_OFFSET_ND = "non_initial_fragment_of_nd_flow_rfc6980"
REASON_FRAGMENT_UNDERSIZED = "fragment_0_hides_nd_type_rfc6980"
REASON_FRAGMENT_INCOMPLETE = "fragment_flow_incomplete"
REASON_FRAGMENT_BENIGN = "fragmented_non_nd_traffic"
