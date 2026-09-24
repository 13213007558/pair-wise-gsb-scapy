# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) 6WIND <olivier.matz@6wind.com>

"""
SCTP (Stream Control Transmission Protocol).
"""

import struct
import hashlib
import hmac

from scapy.compat import raw
from scapy.volatile import RandBin
from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField,
    ByteEnumField,
    Field,
    FieldLenField,
    FieldListField,
    IPField,
    IntEnumField,
    IntField,
    MultipleTypeField,
    PacketLenField,
    PacketListField,
    PadField,
    ShortEnumField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    XByteField,
    XIntField,
    XShortField,
)
from scapy.data import SCTP_SERVICES
from scapy.layers.inet import IP, IPerror
from scapy.layers.inet6 import IP6Field, IPv6, IPerror6, nh_clserror

IPPROTO_SCTP = 132

# crc32-c (Castagnoli) (crc32c_poly=0x1EDC6F41)
crc32c_table = [
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
    0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
    0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
    0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
    0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
    0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
    0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
    0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
    0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
    0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
    0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
    0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
    0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
    0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
    0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
    0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
    0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
    0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
    0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
    0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
    0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
    0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
    0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
    0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
    0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
    0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
    0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
    0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
    0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
    0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
    0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
    0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
]


def crc32c(buf):
    crc = 0xffffffff
    for c in buf:
        crc = (crc >> 8) ^ crc32c_table[(crc ^ (c)) & 0xFF]
    crc = (~crc) & 0xffffffff
    # reverse endianness
    return struct.unpack(">I", struct.pack("<I", crc))[0]


# old checksum (RFC2960)
"""
BASE = 65521 # largest prime smaller than 65536
def update_adler32(adler, buf):
    s1 = adler & 0xffff
    s2 = (adler >> 16) & 0xffff
    print(s1, s2)

    for c in buf:
        print(c)
        s1 = (s1 + c) % BASE
        s2 = (s2 + s1) % BASE
        print(s1, s2)
    return (s2 << 16) + s1

def sctp_checksum(buf):
    return update_adler32(1, buf)
"""

hmactypes = {
    0: "Reserved1",
    1: "SHA-1",
    2: "Reserved2",
    3: "SHA-256",
}

sctpchunktypescls = {
    0: "SCTPChunkData",
    1: "SCTPChunkInit",
    2: "SCTPChunkInitAck",
    3: "SCTPChunkSACK",
    4: "SCTPChunkHeartbeatReq",
    5: "SCTPChunkHeartbeatAck",
    6: "SCTPChunkAbort",
    7: "SCTPChunkShutdown",
    8: "SCTPChunkShutdownAck",
    9: "SCTPChunkError",
    10: "SCTPChunkCookieEcho",
    11: "SCTPChunkCookieAck",
    14: "SCTPChunkShutdownComplete",
    15: "SCTPChunkAuthentication",
    64: "SCTPChunkIData",
    130: "SCTPChunkReConfig",
    132: "SCTPChunkPad",
    0x80: "SCTPChunkAddressConfAck",
    192: "SCTPChunkForwardTSN",
    0xc1: "SCTPChunkAddressConf",
    194: "SCTPChunkIForwardTSN",
}

sctpchunktypes = {
    0: "data",
    1: "init",
    2: "init-ack",
    3: "sack",
    4: "heartbeat-req",
    5: "heartbeat-ack",
    6: "abort",
    7: "shutdown",
    8: "shutdown-ack",
    9: "error",
    10: "cookie-echo",
    11: "cookie-ack",
    14: "shutdown-complete",
    15: "authentication",
    64: "i-data",
    130: "re-config",
    132: "pad",
    0x80: "address-configuration-ack",
    192: "forward-tsn",
    0xc1: "address-configuration",
    194: "i-forward-tsn",
}

sctpchunkparamtypescls = {
    1: "SCTPChunkParamHeartbeatInfo",
    5: "SCTPChunkParamIPv4Addr",
    6: "SCTPChunkParamIPv6Addr",
    7: "SCTPChunkParamStateCookie",
    8: "SCTPChunkParamUnrocognizedParam",
    9: "SCTPChunkParamCookiePreservative",
    11: "SCTPChunkParamHostname",
    12: "SCTPChunkParamSupportedAddrTypes",
    13: "SCTPChunkParamOutgoingSSNResetRequest",
    14: "SCTPChunkParamIncomingSSNResetRequest",
    15: "SCTPChunkParamSSNTSNResetRequest",
    16: "SCTPChunkParamReConfigurationResponse",
    17: "SCTPChunkParamAddOutgoingStreamRequest",
    18: "SCTPChunkParamAddIncomingStreamRequest",
    0x8000: "SCTPChunkParamECNCapable",
    0x8002: "SCTPChunkParamRandom",
    0x8003: "SCTPChunkParamChunkList",
    0x8004: "SCTPChunkParamRequestedHMACFunctions",
    0x8008: "SCTPChunkParamSupportedExtensions",
    0xc000: "SCTPChunkParamFwdTSN",
    0xc001: "SCTPChunkParamAddIPAddr",
    0xc002: "SCTPChunkParamDelIPAddr",
    0xc003: "SCTPChunkParamErrorIndication",
    0xc004: "SCTPChunkParamSetPrimaryAddr",
    0xc005: "SCTPChunkParamSuccessIndication",
    0xc006: "SCTPChunkParamAdaptationLayer",
}

sctpchunkparamtypes = {
    1: "heartbeat-info",
    5: "IPv4",
    6: "IPv6",
    7: "state-cookie",
    8: "unrecognized-param",
    9: "cookie-preservative",
    11: "hostname",
    12: "addrtypes",
    13: "out-ssn-reset-req",
    14: "in-ssn-reset-req",
    15: "ssn-tsn-reset-req",
    16: "re-configuration-response",
    17: "add-outgoing-stream-req",
    18: "add-incoming-stream-req",
    0x8000: "ecn-capable",
    0x8002: "random",
    0x8003: "chunk-list",
    0x8004: "requested-HMAC-functions",
    0x8008: "supported-extensions",
    0xc000: "fwd-tsn-supported",
    0xc001: "add-IP",
    0xc002: "del-IP",
    0xc003: "error-indication",
    0xc004: "set-primary-addr",
    0xc005: "success-indication",
    0xc006: "adaptation-layer",
}

# SCTP header

# Dummy class to guess payload type (variable parameters)


class _SCTPChunkGuessPayload:
    def default_payload_class(self, p):
        if len(p) < 4:
            return conf.padding_layer
        else:
            t = p[0]
            return globals().get(sctpchunktypescls.get(t, "Raw"), conf.raw_layer)  # noqa: E501


class SCTP(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ShortEnumField("sport", 0, SCTP_SERVICES),
                   ShortEnumField("dport", 0, SCTP_SERVICES),
                   XIntField("tag", 0),
                   XIntField("chksum", None), ]

    def answers(self, other):
        if not isinstance(other, SCTP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        return 1

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            crc = crc32c(raw(p))
            p = p[:8] + struct.pack(">I", crc) + p[12:]
        return p


class SCTPerror(SCTP):
    name = "SCTP in ICMP"

    def answers(self, other):
        if not isinstance(other, SCTP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        return 1

    def mysummary(self):
        return Packet.mysummary(self)


nh_clserror[IPPROTO_SCTP] = SCTPerror

# SCTP Chunk variable params


resultcode = {
    0: "Success - Nothing to do",
    1: "Success - Performed",
    2: "Denied",
    3: "Error - Wrong SSN",
    4: "Error - Request already in progress",
    5: "Error - Bad Sequence Number",
    6: "In Progress"
}


class ChunkParamField(PacketListField):
    def __init__(self, name, default, count_from=None, length_from=None):
        PacketListField.__init__(self, name, default, conf.raw_layer, count_from=count_from, length_from=length_from)  # noqa: E501

    def m2i(self, p, m):
        cls = conf.raw_layer
        if len(m) >= 4:
            t = m[0] * 256 + m[1]
            cls = globals().get(sctpchunkparamtypescls.get(t, "Raw"), conf.raw_layer)  # noqa: E501
        return cls(m)

# dummy class to avoid Raw() after Chunk params


class _SCTPChunkParam:
    def extract_padding(self, s):
        return b"", s[:]


class SCTPChunkParamHeartbeatInfo(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 1, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="data",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(StrLenField("data", "",
                                        length_from=lambda pkt: pkt.len - 4),
                            4, padwith=b"\x00"), ]


class SCTPChunkParamIPv4Addr(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 5, sctpchunkparamtypes),
                   ShortField("len", 8),
                   IPField("addr", "127.0.0.1"), ]


class SCTPChunkParamIPv6Addr(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 6, sctpchunkparamtypes),
                   ShortField("len", 20),
                   IP6Field("addr", "::1"), ]


class SCTPChunkParamStateCookie(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 7, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="cookie",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(StrLenField("cookie", "",
                                        length_from=lambda pkt: pkt.len - 4),
                            4, padwith=b"\x00"), ]


class SCTPChunkParamUnrocognizedParam(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 8, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="param",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(StrLenField("param", "",
                                        length_from=lambda pkt: pkt.len - 4),
                            4, padwith=b"\x00"), ]


class SCTPChunkParamCookiePreservative(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 9, sctpchunkparamtypes),
                   ShortField("len", 8),
                   XIntField("sug_cookie_inc", None), ]


class SCTPChunkParamHostname(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 11, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="hostname",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(StrLenField("hostname", "",
                                        length_from=lambda pkt: pkt.len - 4),
                            4, padwith=b"\x00"), ]


class SCTPChunkParamSupportedAddrTypes(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 12, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="addr_type_list",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(FieldListField("addr_type_list", ["IPv4"],
                                           ShortEnumField("addr_type", 5, sctpchunkparamtypes),  # noqa: E501
                                           length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"), ]


class SCTPChunkParamOutSSNResetReq(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 13, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="stream_num_list",
                                 adjust=lambda pkt, x:x + 16),
                   XIntField("re_conf_req_seq_num", None),
                   XIntField("re_conf_res_seq_num", None),
                   XIntField("tsn", None),
                   PadField(FieldListField("stream_num_list", [],
                                           XShortField("stream_num", None),
                                           length_from=lambda pkt: pkt.len - 16),
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkParamInSSNResetReq(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 14, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="stream_num_list",
                                 adjust=lambda pkt, x:x + 8),
                   XIntField("re_conf_req_seq_num", None),
                   PadField(FieldListField("stream_num_list", [],
                                           XShortField("stream_num", None),
                                           length_from=lambda pkt: pkt.len - 8),
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkParamSSNTSNResetReq(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 15, sctpchunkparamtypes),
                   XShortField("len", 8),
                   XIntField("re_conf_req_seq_num", None),
                   ]


class SCTPChunkParamReConfigRes(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 16, sctpchunkparamtypes),
                   XShortField("len", 12),
                   XIntField("re_conf_res_seq_num", None),
                   IntEnumField("result", None, resultcode),
                   XIntField("sender_next_tsn", None),
                   XIntField("receiver_next_tsn", None),
                   ]


class SCTPChunkParamAddOutgoingStreamReq(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 17, sctpchunkparamtypes),
                   XShortField("len", 12),
                   XIntField("re_conf_req_seq_num", None),
                   XShortField("num_new_stream", None),
                   XShortField("reserved", None),
                   ]


class SCTPChunkParamAddIncomingStreamReq(SCTPChunkParamAddOutgoingStreamReq):
    type = 18


class SCTPChunkParamECNCapable(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0x8000, sctpchunkparamtypes),
                   ShortField("len", 4), ]


class SCTPChunkParamRandom(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0x8002, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="random",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(StrLenField("random", RandBin(32),
                                        length_from=lambda pkt: pkt.len - 4),
                            4, padwith=b"\x00"), ]


class SCTPChunkParamChunkList(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0x8003, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="chunk_list",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(FieldListField("chunk_list", None,
                                           ByteEnumField("chunk", None, sctpchunktypes),  # noqa: E501
                                           length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"), ]


class SCTPChunkParamRequestedHMACFunctions(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0x8004, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="HMAC_functions_list",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(FieldListField("HMAC_functions_list", ["SHA-1"],
                                           ShortEnumField("HMAC_function", 1, hmactypes),  # noqa: E501
                                           length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"), ]


class SCTPChunkParamSupportedExtensions(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0x8008, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="supported_extensions",
                                 adjust=lambda pkt, x:x + 4),
                   PadField(FieldListField("supported_extensions",
                                           ["authentication",
                                            "address-configuration",
                                            "address-configuration-ack"],
                                           ByteEnumField("supported_extensions",  # noqa: E501
                                                         None, sctpchunktypes),
                                           length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"), ]


class SCTPChunkParamFwdTSN(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0xc000, sctpchunkparamtypes),
                   ShortField("len", 4), ]


class SCTPChunkParamAddIPAddr(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0xc001, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="addr",
                                 adjust=lambda pkt, x:x + 12),
                   XIntField("correlation_id", None),
                   ShortEnumField("addr_type", 5, sctpchunkparamtypes),
                   FieldLenField("addr_len", None, length_of="addr",
                                 adjust=lambda pkt, x:x + 4),
                   MultipleTypeField(
                       [
                           (IPField("addr", "127.0.0.1"),
                            lambda p: p.addr_type == 5),
                           (IP6Field("addr", "::1"),
                            lambda p: p.addr_type == 6),
                       ],
                       StrFixedLenField("addr", "",
                                        length_from=lambda pkt: pkt.addr_len))
                   ]


class SCTPChunkParamDelIPAddr(SCTPChunkParamAddIPAddr):
    type = 0xc002


class SCTPChunkParamErrorIndication(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0xc003, sctpchunkparamtypes),
                   FieldLenField("len", None, length_of="error_causes",
                                 adjust=lambda pkt, x:x + 8),
                   XIntField("correlation_id", None),
                   PadField(StrLenField("error_causes", "",
                                        length_from=lambda pkt: pkt.len - 4),
                            4, padwith=b"\x00"), ]


class SCTPChunkParamSetPrimaryAddr(SCTPChunkParamAddIPAddr):
    type = 0xc004


class SCTPChunkParamSuccessIndication(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0xc005, sctpchunkparamtypes),
                   ShortField("len", 8),
                   XIntField("correlation_id", None), ]


class SCTPChunkParamAdaptationLayer(_SCTPChunkParam, Packet):
    fields_desc = [ShortEnumField("type", 0xc006, sctpchunkparamtypes),
                   ShortField("len", 8),
                   XIntField("indication", None), ]

# SCTP Chunks


# Dictionary taken from: http://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml  # noqa: E501
SCTP_PAYLOAD_PROTOCOL_INDENTIFIERS = {
    0: 'Reserved',
    1: 'IUA',
    2: 'M2UA',
    3: 'M3UA',
    4: 'SUA',
    5: 'M2PA',
    6: 'V5UA',
    7: 'H.248',
    8: 'BICC/Q.2150.3',
    9: 'TALI',
    10: 'DUA',
    11: 'ASAP',
    12: 'ENRP',
    13: 'H.323',
    14: 'Q.IPC/Q.2150.3',
    15: 'SIMCO',
    16: 'DDP Segment Chunk',
    17: 'DDP Stream Session Control',
    18: 'S1AP',
    19: 'RUA',
    20: 'HNBAP',
    21: 'ForCES-HP',
    22: 'ForCES-MP',
    23: 'ForCES-LP',
    24: 'SBc-AP',
    25: 'NBAP',
    26: 'Unassigned',
    27: 'X2AP',
    28: 'IRCP',
    29: 'LCS-AP',
    30: 'MPICH2',
    31: 'SABP',
    32: 'FGP',
    33: 'PPP',
    34: 'CALCAPP',
    35: 'SSP',
    36: 'NPMP-CONTROL',
    37: 'NPMP-DATA',
    38: 'ECHO',
    39: 'DISCARD',
    40: 'DAYTIME',
    41: 'CHARGEN',
    42: '3GPP RNA',
    43: '3GPP M2AP',
    44: '3GPP M3AP',
    45: 'SSH/SCTP',
    46: 'Diameter/SCTP',
    47: 'Diameter/DTLS/SCTP',
    48: 'R14P',
    49: 'Unassigned',
    50: 'WebRTC DCEP',
    51: 'WebRTC String',
    52: 'WebRTC Binary Partial',
    53: 'WebRTC Binary',
    54: 'WebRTC String Partial',
    55: '3GPP PUA',
    56: 'WebRTC String Empty',
    57: 'WebRTC Binary Empty'
}


class _SCTPChunkDataField(PacketLenField):
    """PacketLenField that dispatches using bind_layers bindings."""

    def m2i(self, pkt, m):
        # Only dissect complete messages
        if pkt.beginning != 1 or pkt.ending != 1:
            return conf.raw_layer(load=m)
        # Check bind_layers bindings
        for fval, cls in pkt.payload_guess:
            if all(
                hasattr(pkt, k) and v == pkt.getfieldval(k)
                for k, v in fval.items()
            ):
                return cls(m)
        return conf.raw_layer(load=m)


class SCTPChunkData(_SCTPChunkGuessPayload, Packet):
    # TODO : add a padding function in post build if this layer is used to generate SCTP chunk data  # noqa: E501
    fields_desc = [ByteEnumField("type", 0, sctpchunktypes),
                   BitField("reserved", None, 4),
                   BitField("delay_sack", 0, 1),
                   BitField("unordered", 0, 1),
                   BitField("beginning", 0, 1),
                   BitField("ending", 0, 1),
                   FieldLenField("len", None, length_of="data", adjust=lambda pkt, x:x + 16),  # noqa: E501
                   XIntField("tsn", None),
                   XShortField("stream_id", None),
                   XShortField("stream_seq", None),
                   IntEnumField("proto_id", None, SCTP_PAYLOAD_PROTOCOL_INDENTIFIERS),  # noqa: E501
                   PadField(_SCTPChunkDataField("data", None, conf.raw_layer,
                                                length_from=lambda pkt: pkt.len - 16),  # noqa: E501
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkIData(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 64, sctpchunktypes),
                   BitField("reserved", None, 4),
                   BitField("delay_sack", 0, 1),    # immediate bit
                   BitField("unordered", 0, 1),
                   BitField("beginning", 0, 1),
                   BitField("ending", 0, 1),
                   FieldLenField("len", None, length_of="data",
                                 adjust=lambda pkt, x:x + 20),
                   XIntField("tsn", None),
                   XShortField("stream_id", None),
                   XShortField("reserved_16", None),
                   XIntField("message_id", None),
                   MultipleTypeField(
                       [
                           (IntEnumField("ppid_fsn", None,
                                         SCTP_PAYLOAD_PROTOCOL_INDENTIFIERS),
                            lambda pkt: pkt.beginning == 1),
                           (XIntField("ppid_fsn", None),
                            lambda pkt: pkt.beginning == 0),
                       ],
                       XIntField("ppid_fsn", None)),
                   PadField(StrLenField("data", None,
                                        length_from=lambda pkt: pkt.len - 20),
                            4, padwith=b"\x00"),
                   ]


class SCTPForwardSkip(_SCTPChunkParam, Packet):
    fields_desc = [ShortField("stream_id", None),
                   ShortField("stream_seq", None)
                   ]


class SCTPChunkForwardTSN(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 192, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="skips",
                                 adjust=lambda pkt, x:x + 8),
                   IntField("new_tsn", None),
                   ChunkParamField("skips", None,
                                   length_from=lambda pkt: pkt.len - 8)
                   ]


class SCTPIForwardSkip(_SCTPChunkParam, Packet):
    fields_desc = [ShortField("stream_id", None),
                   BitField("reserved", None, 15),
                   BitField("unordered", None, 1),
                   IntField("message_id", None)
                   ]


class SCTPChunkIForwardTSN(SCTPChunkForwardTSN):
    type = 194


class SCTPChunkInit(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 1, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="params", adjust=lambda pkt, x:x + 20),  # noqa: E501
                   XIntField("init_tag", None),
                   IntField("a_rwnd", None),
                   ShortField("n_out_streams", None),
                   ShortField("n_in_streams", None),
                   XIntField("init_tsn", None),
                   ChunkParamField("params", None, length_from=lambda pkt:pkt.len - 20),  # noqa: E501
                   ]


class SCTPChunkInitAck(SCTPChunkInit):
    type = 2


class GapAckField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")

    def i2m(self, pkt, x):
        if x is None:
            return b"\0\0\0\0"
        sta, end = [int(e) for e in x.split(':')]
        args = tuple([">HH", sta, end])
        return struct.pack(*args)

    def m2i(self, pkt, x):
        return "%d:%d" % (struct.unpack(">HH", x))

    def any2i(self, pkt, x):
        if isinstance(x, tuple) and len(x) == 2:
            return "%d:%d" % (x)
        return x


class SCTPChunkSACK(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 3, sctpchunktypes),
                   XByteField("flags", None),
                   ShortField("len", None),
                   XIntField("cumul_tsn_ack", None),
                   IntField("a_rwnd", None),
                   FieldLenField("n_gap_ack", None, count_of="gap_ack_list"),
                   FieldLenField("n_dup_tsn", None, count_of="dup_tsn_list"),
                   FieldListField("gap_ack_list", [], GapAckField("gap_ack", None), count_from=lambda pkt:pkt.n_gap_ack),  # noqa: E501
                   FieldListField("dup_tsn_list", [], XIntField("dup_tsn", None), count_from=lambda pkt:pkt.n_dup_tsn),  # noqa: E501
                   ]

    def post_build(self, p, pay):
        if self.len is None:
            p = p[:2] + struct.pack(">H", len(p)) + p[4:]
        return p + pay


class SCTPChunkHeartbeatReq(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 4, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="params", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   ChunkParamField("params", None, length_from=lambda pkt:pkt.len - 4),  # noqa: E501
                   ]


class SCTPChunkHeartbeatAck(SCTPChunkHeartbeatReq):
    type = 5


class SCTPChunkAbort(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 6, sctpchunktypes),
                   BitField("reserved", None, 7),
                   BitField("TCB", 0, 1),
                   FieldLenField("len", None, length_of="error_causes", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   PadField(StrLenField("error_causes", "", length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkShutdown(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 7, sctpchunktypes),
                   XByteField("flags", None),
                   ShortField("len", 8),
                   XIntField("cumul_tsn_ack", None),
                   ]


class SCTPChunkShutdownAck(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 8, sctpchunktypes),
                   XByteField("flags", None),
                   ShortField("len", 4),
                   ]


class SCTPChunkError(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 9, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="error_causes", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   PadField(StrLenField("error_causes", "", length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkCookieEcho(SCTPChunkError):
    fields_desc = [ByteEnumField("type", 10, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="cookie", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   PadField(StrLenField("cookie", "", length_from=lambda pkt: pkt.len - 4),  # noqa: E501
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkCookieAck(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 11, sctpchunktypes),
                   XByteField("flags", None),
                   ShortField("len", 4),
                   ]


class SCTPChunkShutdownComplete(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 14, sctpchunktypes),
                   BitField("reserved", None, 7),
                   BitField("TCB", 0, 1),
                   ShortField("len", 4),
                   ]


class SCTPChunkAuthentication(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 15, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="HMAC",
                                 adjust=lambda pkt, x:x + 8),
                   ShortField("shared_key_id", None),
                   ShortField("HMAC_function", None),
                   PadField(StrLenField("HMAC", "", length_from=lambda pkt: pkt.len - 8),  # noqa: E501
                            4, padwith=b"\x00"),
                   ]


class SCTPChunkAddressConf(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 0xc1, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="params",
                                 adjust=lambda pkt, x:x + 8),
                   IntField("seq", 0),
                   ChunkParamField("params", None, length_from=lambda pkt:pkt.len - 8),  # noqa: E501
                   ]


class SCTPChunkReConfig(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 130, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="params",
                                 adjust=lambda pkt, x:x + 4),
                   ChunkParamField("params", None, length_from=lambda pkt: pkt.len - 4),
                   ]


class SCTPChunkPad(_SCTPChunkGuessPayload, Packet):
    fields_desc = [ByteEnumField("type", 132, sctpchunktypes),
                   XByteField("flags", None),
                   FieldLenField("len", None, length_of="padding",
                                 adjust=lambda pkt, x:x + 8),
                   PadField(StrLenField("padding", None,
                                        length_from=lambda pkt: pkt.len - 8),
                            4, padwith=b"\x00")
                   ]


class SCTPChunkAddressConfAck(SCTPChunkAddressConf):
    type = 0x80


# SCTP authentication (RFC 4895)

# HMAC identifiers usable in the AUTH chunk, mapped to their hash
# constructor.
sctp_hmac_identifiers = {
    1: ("SHA-1", hashlib.sha1),
    3: ("SHA-256", hashlib.sha256),
}


class SCTPAuthError(Exception):
    """Raised when an SCTP packet cannot be signed (RFC 4895)."""


def _sctp_auth_param_bytes(param):
    """
    Return the bytes of a RANDOM, CHUNKS or HMAC-ALGO parameter as
    exchanged in INIT and INIT-ACK chunks, padding included.
    """
    if param is None:
        return b""
    if isinstance(param, Packet):
        return raw(param)
    return bytes(param)


def _sctp_auth_concat(vector1, vector2):
    """Concatenate two byte vectors, the smallest one first."""
    if vector2 < vector1:
        vector1, vector2 = vector2, vector1
    return vector1 + vector2


def _sctp_auth_hmac_ids(param):
    """Return the HMAC identifiers listed in a HMAC-ALGO parameter."""
    if len(param) < 4:
        return []
    length = min(struct.unpack(">H", param[2:4])[0], len(param))
    return [struct.unpack(">H", param[i:i + 2])[0]
            for i in range(4, length - 1, 2)]


def _sctp_auth_chunk_types(param):
    """Return the chunk types listed in a CHUNKS parameter."""
    if len(param) < 4:
        return []
    length = min(struct.unpack(">H", param[2:4])[0], len(param))
    return list(param[4:length])


def _sctp_chunk_spans(data):
    """
    Iterate over the chunks of a serialized SCTP packet.

    Yield (offset, type, length) tuples, where length is the chunk
    length without its padding.
    """
    offset = 12  # size of the SCTP common header
    while offset + 4 <= len(data):
        length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        if length < 4 or offset + length > len(data):
            break
        yield offset, data[offset], length
        offset += (length + 3) & ~3


def _sctp_auth_check_positions(data, protected_types):
    """
    Check that all chunks of protected_types are located after the
    AUTH chunk.  Return None on success, an error message otherwise.
    """
    auth_seen = False
    for _, chunk_type, _ in _sctp_chunk_spans(data):
        if chunk_type == 15:  # authentication
            auth_seen = True
        elif chunk_type in protected_types and not auth_seen:
            return ("the %s chunk requires authentication and MUST be "
                    "sent after the AUTH chunk"
                    % sctpchunktypes.get(chunk_type, str(chunk_type)))
    return None


def _sctp_auth_hmac_hashfn(hmac_id, negotiated_ids):
    """
    Return the hash constructor of a negotiated HMAC identifier.
    """
    if hmac_id not in negotiated_ids:
        raise SCTPAuthError(
            "HMAC identifier %d was not negotiated for this association"
            % hmac_id)
    try:
        return sctp_hmac_identifiers[hmac_id][1]
    except KeyError:
        raise SCTPAuthError("unsupported HMAC identifier %d" % hmac_id)


class SCTPAuthAssociation:
    r"""
    Offline authentication state of an SCTP association (RFC 4895).

    The association shared key is derived from the shared keys of both
    endpoints and from the RANDOM, CHUNKS and HMAC-ALGO parameters
    exchanged in the INIT and INIT-ACK chunks (RFC 4895, Section 6.1):

    - the endpoint pair shared key is the concatenation of the local
      and remote shared keys, the key with the smaller shared key
      identifier first,
    - the association shared key is the concatenation of the endpoint
      pair shared key, both RANDOM parameters, both CHUNKS parameters
      and both HMAC-ALGO parameters, the two vectors of each pair
      being concatenated smallest first.  The parameters include
      their padding.

    The parameters are provided by the caller, either as bytes or as
    SCTPChunkParamRandom, SCTPChunkParamChunkList and
    SCTPChunkParamRequestedHMACFunctions packets.  This class only
    performs byte-level authentication of packets: it does not take
    part in any handshake and does not exchange packets with a peer.
    """

    def __init__(self, local_key_id=0, local_key=b"",
                 remote_key_id=0, remote_key=b"",
                 local_random=None, remote_random=None,
                 local_chunks=None, remote_chunks=None,
                 local_hmacs=None, remote_hmacs=None):
        self.local_key_id = local_key_id
        self.remote_key_id = remote_key_id
        local_key = local_key or b""
        remote_key = remote_key or b""
        local_random = _sctp_auth_param_bytes(local_random)
        remote_random = _sctp_auth_param_bytes(remote_random)
        local_chunks = _sctp_auth_param_bytes(local_chunks)
        remote_chunks = _sctp_auth_param_bytes(remote_chunks)
        local_hmacs = _sctp_auth_param_bytes(local_hmacs)
        remote_hmacs = _sctp_auth_param_bytes(remote_hmacs)
        if local_key_id <= remote_key_id:
            pair_key = local_key + remote_key
        else:
            pair_key = remote_key + local_key
        self.assoc_key = (
            pair_key +
            _sctp_auth_concat(local_random, remote_random) +
            _sctp_auth_concat(local_chunks, remote_chunks) +
            _sctp_auth_concat(local_hmacs, remote_hmacs)
        )
        self.local_hmac_ids = _sctp_auth_hmac_ids(local_hmacs)
        self.remote_hmac_ids = _sctp_auth_hmac_ids(remote_hmacs)
        self.local_chunk_types = _sctp_auth_chunk_types(local_chunks)
        self.remote_chunk_types = _sctp_auth_chunk_types(remote_chunks)

    def sign(self, pkt, shared_key_id=None, hmac_id=None):
        """
        Sign the SCTP packet pkt, which contains an
        SCTPChunkAuthentication chunk, and return its bytes.

        The HMAC is computed over the SCTP common header (with the
        checksum field set to zero) and all the chunks, the HMAC field
        of the AUTH chunk being set to zero (RFC 4895, Section 6.3).
        The CRC32c checksum is computed afterwards, over the
        authenticated packet, and does not alter the authentication.

        shared_key_id and hmac_id override the corresponding fields of
        the AUTH chunk when provided.
        """
        if not isinstance(pkt, Packet):
            pkt = SCTP(bytes(pkt))
        pkt = pkt.copy()
        auth = pkt.getlayer(SCTPChunkAuthentication)
        if auth is None:
            raise SCTPAuthError(
                "the packet contains no SCTPChunkAuthentication chunk")
        if shared_key_id is not None:
            auth.shared_key_id = shared_key_id
        if hmac_id is not None:
            auth.HMAC_function = hmac_id
        if auth.shared_key_id != self.local_key_id:
            raise SCTPAuthError(
                "no shared key with identifier %d for this association"
                % auth.shared_key_id)
        hashfn = _sctp_auth_hmac_hashfn(auth.HMAC_function,
                                        self.remote_hmac_ids)
        auth.HMAC = b"\x00" * hashfn().digest_size
        pkt.chksum = 0
        data = bytearray(raw(pkt))
        error = _sctp_auth_check_positions(data, self.remote_chunk_types)
        if error:
            raise SCTPAuthError(error)
        offset = next(off for off, ctype, _ in _sctp_chunk_spans(data)
                      if ctype == 15)
        signature = hmac.new(self.assoc_key, bytes(data), hashfn)
        data[offset + 8:offset + 8 + signature.digest_size] = \
            signature.digest()
        data[8:12] = struct.pack(">I", crc32c(bytes(data)))
        return bytes(data)

    def verify(self, pkt):
        """
        Verify the SCTP packet pkt against its AUTH chunk.

        Return (True, None) if the packet is authentic, (False,
        reason) otherwise.  The CRC32c checksum is not part of the
        authentication and is not verified.
        """
        if isinstance(pkt, Packet):
            data = raw(pkt)
        else:
            data = bytes(pkt)
        auth_span = None
        for span in _sctp_chunk_spans(data):
            if span[1] == 15:  # authentication
                auth_span = span
                break
        if auth_span is None:
            return False, "the packet contains no AUTH chunk"
        error = _sctp_auth_check_positions(data, self.local_chunk_types)
        if error:
            return False, error
        offset, _, length = auth_span
        shared_key_id, hmac_id = struct.unpack(
            ">HH", data[offset + 4:offset + 8])
        if shared_key_id != self.remote_key_id:
            return (False,
                    "no shared key with identifier %d for this "
                    "association" % shared_key_id)
        if hmac_id not in self.local_hmac_ids:
            return (False, "HMAC identifier %d was not negotiated for "
                    "this association" % hmac_id)
        if hmac_id not in sctp_hmac_identifiers:
            return False, "unsupported HMAC identifier %d" % hmac_id
        name, hashfn = sctp_hmac_identifiers[hmac_id]
        hmac_length = length - 8
        if hmac_length != hashfn().digest_size:
            return (False, "invalid HMAC length %d for %s"
                    % (hmac_length, name))
        data = bytearray(data)
        received = bytes(data[offset + 8:offset + 8 + hmac_length])
        data[8:12] = b"\x00" * 4
        data[offset + 8:offset + 8 + hmac_length] = b"\x00" * hmac_length
        expected = hmac.new(self.assoc_key, bytes(data), hashfn)
        if hmac.compare_digest(received, expected.digest()):
            return True, None
        return False, "HMAC verification failed"


bind_layers(IP, SCTP, proto=IPPROTO_SCTP)
bind_layers(IPerror, SCTPerror, proto=IPPROTO_SCTP)
bind_layers(IPv6, SCTP, nh=IPPROTO_SCTP)
bind_layers(IPerror6, SCTPerror, proto=IPPROTO_SCTP)
