//! The field registry: the one place that knows what each `abbrev` means.
//!
//! The detail tree formats labels from it; the display filter (Phase 3)
//! type-checks against it. Dissectors emit `abbrev`s that must exist here —
//! `tests/registry_coverage.rs` walks every fixture tree to enforce that.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{OnceLock, RwLock};

use super::node::{NodeRef, Value};

/// Numeric display base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Dec,
    Hex,
    /// `0x1f (31)`
    HexDec,
    /// For enums: show the symbolic name only, with no numeric value.
    Name,
}

/// Value type of a field. Determines both the label format and, later, the
/// operators the filter language allows on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A top-level protocol layer.
    Protocol,
    /// A subtree container without a value of its own.
    Group,
    Bool,
    Unsigned(Base),
    Signed,
    Str,
    Bytes,
    Ipv4,
    Ipv6,
    Mac,
    /// An unsigned value with symbolic names.
    Enum(&'static [(u64, &'static str)], Base),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDef {
    pub abbrev: &'static str,
    pub name: &'static str,
    pub kind: Kind,
    /// Fields this one stands for in a display filter. `ip.addr` matches
    /// either `ip.src` or `ip.dst`; the field itself is never emitted as a
    /// tree row.
    pub members: &'static [&'static str],
}

const fn f(abbrev: &'static str, name: &'static str, kind: Kind) -> FieldDef {
    FieldDef {
        abbrev,
        name,
        kind,
        members: &[],
    }
}

/// An alias: a filter-only name matching any of several real fields.
const fn alias(
    abbrev: &'static str,
    name: &'static str,
    kind: Kind,
    members: &'static [&'static str],
) -> FieldDef {
    FieldDef {
        abbrev,
        name,
        kind,
        members,
    }
}

// ---- value name tables ---------------------------------------------------

/// libpcap DLT_* values the dissector chain understands, plus common others.
pub static LINK_TYPES: &[(u64, &str)] = &[
    (0, "NULL/Loopback"),
    (1, "Ethernet"),
    (12, "Raw IP"),
    (101, "Raw IP"),
    (105, "IEEE 802.11 wireless LAN"),
    (108, "OpenBSD loopback"),
    (113, "Linux cooked capture v1"),
    (127, "IEEE 802.11 plus radiotap"),
    (228, "Raw IPv4"),
    (229, "Raw IPv6"),
    (276, "Linux cooked capture v2"),
];

pub static ETHERTYPES: &[(u64, &str)] = &[
    (0x0800, "IPv4"),
    (0x0806, "ARP"),
    (0x8035, "RARP"),
    (0x809B, "AppleTalk"),
    (0x8100, "802.1Q Virtual LAN"),
    (0x86DD, "IPv6"),
    (0x8808, "Ethernet flow control"),
    (0x8847, "MPLS unicast"),
    (0x8848, "MPLS multicast"),
    (0x8863, "PPPoE Discovery"),
    (0x8864, "PPPoE Session"),
    (0x888E, "802.1X Authentication"),
    (0x88A8, "802.1ad Provider Bridge"),
    (0x88CC, "LLDP"),
    (0x88E5, "MACsec"),
    (0x8906, "FCoE"),
    (0x9000, "Loopback"),
];

pub static IPPROTOS: &[(u64, &str)] = &[
    (0, "IPv6 Hop-by-Hop Option"),
    (1, "ICMP"),
    (2, "IGMP"),
    (4, "IPv4"),
    (6, "TCP"),
    (17, "UDP"),
    (41, "IPv6"),
    (43, "IPv6 Routing"),
    (44, "IPv6 Fragment"),
    (47, "GRE"),
    (50, "ESP"),
    (51, "AH"),
    (58, "ICMPv6"),
    (59, "IPv6 No Next Header"),
    (60, "IPv6 Destination Option"),
    (89, "OSPF"),
    (132, "SCTP"),
    (136, "UDPLite"),
];

/// Checksum verification result, matching Wireshark numbering.
pub static CHECKSUM_STATUS: &[(u64, &str)] = &[
    (0, "Bad"),
    (1, "Good"),
    (2, "Unverified"),
    (3, "Not present"),
];

pub static ARP_HWTYPES: &[(u64, &str)] = &[(1, "Ethernet"), (6, "IEEE 802"), (15, "Frame Relay")];

pub static ARP_OPCODES: &[(u64, &str)] = &[
    (1, "request"),
    (2, "reply"),
    (3, "reverse request"),
    (4, "reverse reply"),
];

pub static IP_OPTS: &[(u64, &str)] = &[
    (0, "End of Options List (EOL)"),
    (1, "No-Operation (NOP)"),
    (7, "Record Route"),
    (68, "Time Stamp"),
    (130, "Security"),
    (131, "Loose Source Route"),
    (137, "Strict Source Route"),
    (148, "Router Alert"),
];

pub static IPV6_OPTS: &[(u64, &str)] = &[
    (0, "Pad1"),
    (1, "PadN"),
    (5, "Router Alert"),
    (194, "Jumbo Payload"),
];

pub static IPV6_ROUTING_TYPES: &[(u64, &str)] = &[
    (0, "Source Route"),
    (2, "Type 2 Routing"),
    (3, "RPL Source Route"),
    (4, "Segment Routing"),
];

pub static ICMP_TYPES: &[(u64, &str)] = &[
    (0, "Echo (ping) reply"),
    (3, "Destination Unreachable"),
    (4, "Source Quench"),
    (5, "Redirect"),
    (8, "Echo (ping) request"),
    (9, "Router Advertisement"),
    (10, "Router Solicitation"),
    (11, "Time-to-live exceeded"),
    (12, "Parameter Problem"),
    (13, "Timestamp"),
    (14, "Timestamp Reply"),
];

pub static ICMPV6_TYPES: &[(u64, &str)] = &[
    (1, "Destination Unreachable"),
    (2, "Packet Too Big"),
    (3, "Time Exceeded"),
    (4, "Parameter Problem"),
    (128, "Echo (ping) request"),
    (129, "Echo (ping) reply"),
    (130, "Multicast Listener Query"),
    (131, "Multicast Listener Report"),
    (132, "Multicast Listener Done"),
    (133, "Router Solicitation"),
    (134, "Router Advertisement"),
    (135, "Neighbor Solicitation"),
    (136, "Neighbor Advertisement"),
    (137, "Redirect"),
    (143, "Multicast Listener Report Message v2"),
];

pub static ICMPV6_OPT_TYPES: &[(u64, &str)] = &[
    (1, "Source link-layer address"),
    (2, "Target link-layer address"),
    (3, "Prefix information"),
    (4, "Redirected header"),
    (5, "MTU"),
    (25, "Recursive DNS Server"),
];

pub static TCP_OPT_KINDS: &[(u64, &str)] = &[
    (0, "End of Option List (EOL)"),
    (1, "No-Operation (NOP)"),
    (2, "Maximum segment size"),
    (3, "Window scale"),
    (4, "SACK permitted"),
    (5, "SACK"),
    (8, "Time Stamp Option"),
    (30, "Multipath TCP"),
    (34, "TCP Fast Open Cookie"),
];

pub static DNS_TYPES: &[(u64, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (15, "MX"),
    (16, "TXT"),
    (28, "AAAA"),
    (33, "SRV"),
    (41, "OPT"),
    (43, "DS"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (65, "HTTPS"),
    (255, "ANY"),
];

pub static DNS_CLASSES: &[(u64, &str)] = &[(1, "IN"), (3, "CH"), (4, "HS"), (255, "ANY")];

pub static DNS_OPCODES: &[(u64, &str)] = &[
    (0, "Standard query"),
    (1, "Inverse query"),
    (2, "Server status request"),
    (4, "Notify"),
    (5, "Update"),
];

pub static DNS_RCODES: &[(u64, &str)] = &[
    (0, "No error"),
    (1, "Format error"),
    (2, "Server failure"),
    (3, "No such name"),
    (4, "Not implemented"),
    (5, "Refused"),
];

pub static DHCP_OPS: &[(u64, &str)] = &[(1, "Boot Request"), (2, "Boot Reply")];

pub static DHCP_MSG_TYPES: &[(u64, &str)] = &[
    (1, "Discover"),
    (2, "Offer"),
    (3, "Request"),
    (4, "Decline"),
    (5, "ACK"),
    (6, "NAK"),
    (7, "Release"),
    (8, "Inform"),
];

pub static DHCP_OPTIONS: &[(u64, &str)] = &[
    (0, "Pad"),
    (1, "Subnet Mask"),
    (3, "Router"),
    (6, "Domain Name Server"),
    (12, "Host Name"),
    (15, "Domain Name"),
    (28, "Broadcast Address"),
    (42, "NTP Servers"),
    (50, "Requested IP Address"),
    (51, "IP Address Lease Time"),
    (53, "DHCP Message Type"),
    (54, "DHCP Server Identifier"),
    (55, "Parameter Request List"),
    (57, "Maximum DHCP Message Size"),
    (58, "Renewal Time Value"),
    (59, "Rebinding Time Value"),
    (60, "Vendor class identifier"),
    (61, "Client identifier"),
    (255, "End"),
];

pub static TLS_CONTENT_TYPES: &[(u64, &str)] = &[
    (20, "Change Cipher Spec"),
    (21, "Alert"),
    (22, "Handshake"),
    (23, "Application Data"),
    (24, "Heartbeat"),
];

pub static TLS_VERSIONS: &[(u64, &str)] = &[
    (0x0300, "SSL 3.0"),
    (0x0301, "TLS 1.0"),
    (0x0302, "TLS 1.1"),
    (0x0303, "TLS 1.2"),
    (0x0304, "TLS 1.3"),
];

pub static TLS_HANDSHAKE_TYPES: &[(u64, &str)] = &[
    (0, "Hello Request"),
    (1, "Client Hello"),
    (2, "Server Hello"),
    (4, "New Session Ticket"),
    (8, "Encrypted Extensions"),
    (11, "Certificate"),
    (12, "Server Key Exchange"),
    (13, "Certificate Request"),
    (14, "Server Hello Done"),
    (15, "Certificate Verify"),
    (16, "Client Key Exchange"),
    (20, "Finished"),
];

pub static TLS_ALERT_LEVELS: &[(u64, &str)] = &[(1, "Warning"), (2, "Fatal")];

pub static TLS_ALERT_DESCS: &[(u64, &str)] = &[
    (0, "Close Notify"),
    (10, "Unexpected Message"),
    (20, "Bad Record MAC"),
    (40, "Handshake Failure"),
    (42, "Bad Certificate"),
    (46, "Certificate Unknown"),
    (48, "Unknown CA"),
    (70, "Protocol Version"),
    (80, "Internal Error"),
    (112, "Unrecognized Name"),
];

pub static TLS_EXTENSIONS: &[(u64, &str)] = &[
    (0, "server_name"),
    (1, "max_fragment_length"),
    (5, "status_request"),
    (10, "supported_groups"),
    (11, "ec_point_formats"),
    (13, "signature_algorithms"),
    (16, "application_layer_protocol_negotiation"),
    (18, "signed_certificate_timestamp"),
    (21, "padding"),
    (23, "extended_master_secret"),
    (27, "compress_certificate"),
    (35, "session_ticket"),
    (41, "pre_shared_key"),
    (42, "early_data"),
    (43, "supported_versions"),
    (44, "cookie"),
    (45, "psk_key_exchange_modes"),
    (49, "post_handshake_auth"),
    (50, "signature_algorithms_cert"),
    (51, "key_share"),
    (65281, "renegotiation_info"),
];

pub static TLS_CIPHER_SUITES: &[(u64, &str)] = &[
    (0x0000, "TLS_NULL_WITH_NULL_NULL"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    (0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    (0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
];

// ---- the registry --------------------------------------------------------

use Base::{Dec, Hex, HexDec};
use Kind::*;

pub static FIELDS: &[FieldDef] = &[
    // frame
    f("frame", "Frame", Protocol),
    f("frame.number", "Frame Number", Unsigned(Dec)),
    f("frame.time_epoch", "Epoch Time", Str),
    f("frame.len", "Frame Length", Unsigned(Dec)),
    f("frame.cap_len", "Capture Length", Unsigned(Dec)),
    f(
        "frame.encap_type",
        "Encapsulation type",
        Enum(LINK_TYPES, Dec),
    ),
    f("frame.protocols", "Protocols in frame", Str),
    // malformed / data
    f("_ws.malformed", "Malformed Packet", Protocol),
    f("data", "Data", Protocol),
    f("data.data", "Data", Bytes),
    f("data.len", "Length", Unsigned(Dec)),
    // null / loopback
    f("null", "Null/Loopback", Protocol),
    f("null.family", "Family", Unsigned(Dec)),
    // ethernet
    f("eth", "Ethernet II", Protocol),
    alias(
        "eth.addr",
        "Source or Destination",
        Mac,
        &["eth.src", "eth.dst"],
    ),
    f("eth.dst", "Destination", Mac),
    f("eth.src", "Source", Mac),
    f("eth.type", "Type", Enum(ETHERTYPES, Hex)),
    f("eth.len", "Length", Unsigned(Dec)),
    f("eth.padding", "Padding", Bytes),
    f("eth.trailer", "Trailer", Bytes),
    // 802.1Q
    f("vlan", "802.1Q Virtual LAN", Protocol),
    f("vlan.priority", "Priority", Unsigned(Dec)),
    f("vlan.dei", "DEI", Bool),
    f("vlan.id", "ID", Unsigned(Dec)),
    f("vlan.etype", "Type", Enum(ETHERTYPES, Hex)),
    // LLC / SNAP
    f("llc", "Logical-Link Control", Protocol),
    f("llc.dsap", "DSAP", Unsigned(Hex)),
    f("llc.ssap", "SSAP", Unsigned(Hex)),
    f("llc.control", "Control field", Unsigned(Hex)),
    f("llc.oui", "Organization Code", Unsigned(Hex)),
    f("llc.type", "Type", Enum(ETHERTYPES, Hex)),
    f("llc.pid", "Protocol ID", Unsigned(Hex)),
    // ARP
    f("arp", "Address Resolution Protocol", Protocol),
    f("arp.hw.type", "Hardware type", Enum(ARP_HWTYPES, Dec)),
    f("arp.proto.type", "Protocol type", Enum(ETHERTYPES, Hex)),
    f("arp.hw.size", "Hardware size", Unsigned(Dec)),
    f("arp.proto.size", "Protocol size", Unsigned(Dec)),
    f("arp.opcode", "Opcode", Enum(ARP_OPCODES, Dec)),
    f("arp.src.hw_mac", "Sender MAC address", Mac),
    alias(
        "arp.addr",
        "Sender or Target IP address",
        Ipv4,
        &["arp.src.proto_ipv4", "arp.dst.proto_ipv4"],
    ),
    f("arp.src.proto_ipv4", "Sender IP address", Ipv4),
    f("arp.dst.hw_mac", "Target MAC address", Mac),
    f("arp.dst.proto_ipv4", "Target IP address", Ipv4),
    f("arp.src.hw", "Sender hardware address", Bytes),
    f("arp.src.proto", "Sender protocol address", Bytes),
    f("arp.dst.hw", "Target hardware address", Bytes),
    f("arp.dst.proto", "Target protocol address", Bytes),
    // IPv4
    f("ip", "Internet Protocol Version 4", Protocol),
    f("ip.version", "Version", Unsigned(Dec)),
    f("ip.hdr_len", "Header Length", Unsigned(Dec)),
    f("ip.dsfield", "Differentiated Services Field", Unsigned(Hex)),
    f(
        "ip.dsfield.dscp",
        "Differentiated Services Codepoint",
        Unsigned(Dec),
    ),
    f(
        "ip.dsfield.ecn",
        "Explicit Congestion Notification",
        Unsigned(Dec),
    ),
    f("ip.len", "Total Length", Unsigned(Dec)),
    f("ip.len_tso", "Segmentation offload", Bool),
    f("ip.id", "Identification", Unsigned(HexDec)),
    f("ip.flags", "Flags", Unsigned(Hex)),
    f("ip.flags.rb", "Reserved bit", Bool),
    f("ip.flags.df", "Don't fragment", Bool),
    f("ip.flags.mf", "More fragments", Bool),
    f("ip.frag_offset", "Fragment Offset", Unsigned(Dec)),
    f("ip.ttl", "Time to Live", Unsigned(Dec)),
    f("ip.proto", "Protocol", Enum(IPPROTOS, Dec)),
    f("ip.checksum", "Header Checksum", Unsigned(Hex)),
    f(
        "ip.checksum.status",
        "Header checksum status",
        Enum(CHECKSUM_STATUS, Base::Name),
    ),
    alias(
        "ip.addr",
        "Source or Destination Address",
        Ipv4,
        &["ip.src", "ip.dst"],
    ),
    f("ip.src", "Source Address", Ipv4),
    f("ip.dst", "Destination Address", Ipv4),
    f("ip.options", "Options", Group),
    f("ip.opt", "Option", Group),
    f("ip.opt.type", "Type", Enum(IP_OPTS, Dec)),
    f("ip.opt.len", "Length", Unsigned(Dec)),
    f("ip.opt.data", "Option data", Bytes),
    f("ip.opt.ra", "Router Alert", Unsigned(Dec)),
    f("ip.opt.padding", "Padding", Bytes),
    f("ip.opt.ptr", "Pointer", Unsigned(Dec)),
    f("ip.opt.route", "Route address", Ipv4),
    f("ip.fragment", "IPv4 Fragment", Group),
    f("ip.fragments", "IPv4 Fragments", Group),
    f("ip.fragment.count", "Fragment count", Unsigned(Dec)),
    f(
        "ip.reassembled.length",
        "Reassembled IPv4 length",
        Unsigned(Dec),
    ),
    f("ip.reassembled.data", "Reassembled IPv4 data", Bytes),
    // IPv6
    f("ipv6", "Internet Protocol Version 6", Protocol),
    f("ipv6.version", "Version", Unsigned(Dec)),
    f("ipv6.tclass", "Traffic Class", Unsigned(Hex)),
    f("ipv6.flow", "Flow Label", Unsigned(Hex)),
    f("ipv6.plen", "Payload Length", Unsigned(Dec)),
    f("ipv6.nxt", "Next Header", Enum(IPPROTOS, Dec)),
    f("ipv6.hlim", "Hop Limit", Unsigned(Dec)),
    alias(
        "ipv6.addr",
        "Source or Destination Address",
        Ipv6,
        &["ipv6.src", "ipv6.dst"],
    ),
    f("ipv6.src", "Source Address", Ipv6),
    f("ipv6.dst", "Destination Address", Ipv6),
    f("ipv6.hopopts", "Hop-by-Hop Options", Group),
    f("ipv6.hopopts.nxt", "Next Header", Enum(IPPROTOS, Dec)),
    f("ipv6.hopopts.len", "Length", Unsigned(Dec)),
    f("ipv6.dstopts", "Destination Options", Group),
    f("ipv6.dstopts.nxt", "Next Header", Enum(IPPROTOS, Dec)),
    f("ipv6.dstopts.len", "Length", Unsigned(Dec)),
    f("ipv6.opt", "Option", Group),
    f("ipv6.opt.type", "Type", Enum(IPV6_OPTS, Dec)),
    f("ipv6.opt.length", "Length", Unsigned(Dec)),
    f("ipv6.opt.data", "Data", Bytes),
    f("ipv6.opt.router_alert", "Router Alert", Unsigned(Dec)),
    f("ipv6.routing", "Routing Header", Group),
    f("ipv6.routing.nxt", "Next Header", Enum(IPPROTOS, Dec)),
    f("ipv6.routing.len", "Length", Unsigned(Dec)),
    f("ipv6.routing.type", "Type", Enum(IPV6_ROUTING_TYPES, Dec)),
    f("ipv6.routing.segleft", "Segments Left", Unsigned(Dec)),
    f("ipv6.routing.data", "Type-specific data", Bytes),
    f("ipv6.routing.addr", "Address", Ipv6),
    f("ipv6.fraghdr", "Fragment Header", Group),
    f("ipv6.fraghdr.nxt", "Next header", Enum(IPPROTOS, Dec)),
    f(
        "ipv6.fraghdr.reserved_octet",
        "Reserved octet",
        Unsigned(Hex),
    ),
    f("ipv6.fraghdr.offset", "Offset", Unsigned(Dec)),
    f("ipv6.fraghdr.reserved_bits", "Reserved bits", Unsigned(Dec)),
    f("ipv6.fraghdr.more", "More Fragments", Bool),
    f("ipv6.fraghdr.ident", "Identification", Unsigned(Hex)),
    // ICMP
    f("icmp", "Internet Control Message Protocol", Protocol),
    f("icmp.type", "Type", Enum(ICMP_TYPES, Dec)),
    f("icmp.code", "Code", Unsigned(Dec)),
    f("icmp.checksum", "Checksum", Unsigned(Hex)),
    f(
        "icmp.checksum.status",
        "Checksum Status",
        Enum(CHECKSUM_STATUS, Base::Name),
    ),
    f("icmp.ident", "Identifier", Unsigned(Dec)),
    f("icmp.seq", "Sequence Number", Unsigned(Dec)),
    f("icmp.unused", "Unused", Unsigned(Hex)),
    f("icmp.mtu", "MTU of next hop", Unsigned(Dec)),
    f("icmp.gateway", "Gateway Address", Ipv4),
    f("icmp.pointer", "Pointer", Unsigned(Dec)),
    f("icmp.data", "Data", Bytes),
    // ICMPv6
    f("icmpv6", "Internet Control Message Protocol v6", Protocol),
    f("icmpv6.type", "Type", Enum(ICMPV6_TYPES, Dec)),
    f("icmpv6.code", "Code", Unsigned(Dec)),
    f("icmpv6.checksum", "Checksum", Unsigned(Hex)),
    f(
        "icmpv6.checksum.status",
        "Checksum Status",
        Enum(CHECKSUM_STATUS, Base::Name),
    ),
    f("icmpv6.reserved", "Reserved", Unsigned(Hex)),
    f("icmpv6.echo.identifier", "Identifier", Unsigned(Dec)),
    f("icmpv6.echo.sequence_number", "Sequence", Unsigned(Dec)),
    f("icmpv6.mtu", "MTU", Unsigned(Dec)),
    f("icmpv6.pointer", "Pointer", Unsigned(Dec)),
    f("icmpv6.nd.ns.target_address", "Target Address", Ipv6),
    f("icmpv6.nd.na.target_address", "Target Address", Ipv6),
    f("icmpv6.nd.na.flag", "Flags", Unsigned(Hex)),
    f("icmpv6.nd.na.flag.r", "Router", Bool),
    f("icmpv6.nd.na.flag.s", "Solicited", Bool),
    f("icmpv6.nd.na.flag.o", "Override", Bool),
    f("icmpv6.nd.ra.cur_hop_limit", "Cur hop limit", Unsigned(Dec)),
    f("icmpv6.nd.ra.flag", "Flags", Unsigned(Hex)),
    f("icmpv6.nd.ra.flag.m", "Managed address configuration", Bool),
    f("icmpv6.nd.ra.flag.o", "Other configuration", Bool),
    f(
        "icmpv6.nd.ra.router_lifetime",
        "Router lifetime (s)",
        Unsigned(Dec),
    ),
    f(
        "icmpv6.nd.ra.reachable_time",
        "Reachable time (ms)",
        Unsigned(Dec),
    ),
    f(
        "icmpv6.nd.ra.retrans_timer",
        "Retrans timer (ms)",
        Unsigned(Dec),
    ),
    f("icmpv6.nd.rd.target_address", "Target Address", Ipv6),
    f(
        "icmpv6.nd.rd.destination_address",
        "Destination Address",
        Ipv6,
    ),
    f("icmpv6.opt", "ICMPv6 Option", Group),
    f("icmpv6.opt.type", "Type", Enum(ICMPV6_OPT_TYPES, Dec)),
    f("icmpv6.opt.length", "Length", Unsigned(Dec)),
    f("icmpv6.opt.linkaddr", "Link-layer address", Mac),
    f("icmpv6.opt.mtu", "MTU", Unsigned(Dec)),
    f("icmpv6.opt.prefix.length", "Prefix Length", Unsigned(Dec)),
    f(
        "icmpv6.opt.prefix.valid_lifetime",
        "Valid Lifetime",
        Unsigned(Dec),
    ),
    f(
        "icmpv6.opt.prefix.preferred_lifetime",
        "Preferred Lifetime",
        Unsigned(Dec),
    ),
    f("icmpv6.opt.prefix", "Prefix", Ipv6),
    f("icmpv6.opt.data", "Data", Bytes),
    f("icmpv6.data", "Data", Bytes),
    // UDP
    f("udp", "User Datagram Protocol", Protocol),
    f("udp.srcport", "Source Port", Unsigned(Dec)),
    f("udp.dstport", "Destination Port", Unsigned(Dec)),
    alias(
        "udp.port",
        "Port",
        Unsigned(Dec),
        &["udp.srcport", "udp.dstport"],
    ),
    f("udp.length", "Length", Unsigned(Dec)),
    f("udp.checksum", "Checksum", Unsigned(Hex)),
    f(
        "udp.checksum.status",
        "Checksum Status",
        Enum(CHECKSUM_STATUS, Base::Name),
    ),
    f("udp.payload", "UDP payload", Bytes),
    // TCP
    f("tcp", "Transmission Control Protocol", Protocol),
    f("tcp.srcport", "Source Port", Unsigned(Dec)),
    f("tcp.dstport", "Destination Port", Unsigned(Dec)),
    alias(
        "tcp.port",
        "Port",
        Unsigned(Dec),
        &["tcp.srcport", "tcp.dstport"],
    ),
    f("tcp.len", "TCP Segment Len", Unsigned(Dec)),
    f("tcp.seq", "Sequence Number (raw)", Unsigned(Dec)),
    f("tcp.ack", "Acknowledgment Number (raw)", Unsigned(Dec)),
    f("tcp.hdr_len", "Header Length", Unsigned(Dec)),
    f("tcp.flags", "Flags", Unsigned(Hex)),
    f("tcp.flags.res", "Reserved", Bool),
    f("tcp.flags.ae", "Accurate ECN", Bool),
    f("tcp.flags.cwr", "Congestion Window Reduced", Bool),
    f("tcp.flags.ece", "ECN-Echo", Bool),
    f("tcp.flags.urg", "Urgent", Bool),
    f("tcp.flags.ack", "Acknowledgment", Bool),
    f("tcp.flags.push", "Push", Bool),
    f("tcp.flags.reset", "Reset", Bool),
    f("tcp.flags.syn", "Syn", Bool),
    f("tcp.flags.fin", "Fin", Bool),
    f("tcp.window_size_value", "Window", Unsigned(Dec)),
    f("tcp.checksum", "Checksum", Unsigned(Hex)),
    f(
        "tcp.checksum.status",
        "Checksum Status",
        Enum(CHECKSUM_STATUS, Base::Name),
    ),
    f("tcp.urgent_pointer", "Urgent Pointer", Unsigned(Dec)),
    f("tcp.options", "Options", Group),
    f("tcp.option_kind", "Kind", Enum(TCP_OPT_KINDS, Dec)),
    f("tcp.option_len", "Length", Unsigned(Dec)),
    f("tcp.options.eol", "End of Option List (EOL)", Group),
    f("tcp.options.nop", "No-Operation (NOP)", Group),
    f("tcp.options.mss", "Maximum segment size", Group),
    f("tcp.options.mss_val", "MSS Value", Unsigned(Dec)),
    f("tcp.options.wscale", "Window scale", Group),
    f("tcp.options.wscale.shift", "Shift count", Unsigned(Dec)),
    f("tcp.options.wscale.multiplier", "Multiplier", Unsigned(Dec)),
    f("tcp.options.sack_perm", "SACK permitted", Group),
    f("tcp.options.sack", "SACK", Group),
    f("tcp.options.sack_le", "SACK Left Edge", Unsigned(Dec)),
    f("tcp.options.sack_re", "SACK Right Edge", Unsigned(Dec)),
    f("tcp.options.timestamp", "Timestamps", Group),
    f(
        "tcp.options.timestamp.tsval",
        "Timestamp value",
        Unsigned(Dec),
    ),
    f(
        "tcp.options.timestamp.tsecr",
        "Timestamp echo reply",
        Unsigned(Dec),
    ),
    f("tcp.options.unknown", "Unknown option", Group),
    f("tcp.options.data", "Option data", Bytes),
    f("tcp.payload", "TCP payload", Bytes),
    // DNS
    f("dns", "Domain Name System", Protocol),
    f("dns.id", "Transaction ID", Unsigned(Hex)),
    f("dns.flags", "Flags", Unsigned(Hex)),
    f("dns.flags.response", "Response", Bool),
    f("dns.flags.opcode", "Opcode", Enum(DNS_OPCODES, Dec)),
    f("dns.flags.authoritative", "Authoritative", Bool),
    f("dns.flags.truncated", "Truncated", Bool),
    f("dns.flags.recdesired", "Recursion desired", Bool),
    f("dns.flags.recavail", "Recursion available", Bool),
    f("dns.flags.z", "Z", Bool),
    f("dns.flags.authenticated", "Answer authenticated", Bool),
    f("dns.flags.checkdisable", "Non-authenticated data", Bool),
    f("dns.flags.rcode", "Reply code", Enum(DNS_RCODES, Dec)),
    f("dns.count.queries", "Questions", Unsigned(Dec)),
    f("dns.count.answers", "Answer RRs", Unsigned(Dec)),
    f("dns.count.auth_rr", "Authority RRs", Unsigned(Dec)),
    f("dns.count.add_rr", "Additional RRs", Unsigned(Dec)),
    f("dns.queries", "Queries", Group),
    f("dns.answers", "Answers", Group),
    f("dns.authority", "Authoritative nameservers", Group),
    f("dns.additional", "Additional records", Group),
    f("dns.qry", "Query", Group),
    f("dns.qry.name", "Name", Str),
    f("dns.qry.type", "Type", Enum(DNS_TYPES, Dec)),
    f("dns.qry.class", "Class", Enum(DNS_CLASSES, Hex)),
    f("dns.resp", "Resource record", Group),
    f("dns.resp.name", "Name", Str),
    f("dns.resp.type", "Type", Enum(DNS_TYPES, Dec)),
    f("dns.resp.class", "Class", Enum(DNS_CLASSES, Hex)),
    f("dns.resp.ttl", "Time to live", Unsigned(Dec)),
    f("dns.resp.len", "Data length", Unsigned(Dec)),
    f("dns.a", "Address", Ipv4),
    f("dns.aaaa", "AAAA Address", Ipv6),
    f("dns.cname", "CNAME", Str),
    f("dns.ns", "Name Server", Str),
    f("dns.ptr.domain_name", "Domain Name", Str),
    f("dns.mx.preference", "Preference", Unsigned(Dec)),
    f("dns.mx.mail_exchange", "Mail Exchange", Str),
    f("dns.txt", "TXT", Str),
    f("dns.soa.mname", "Primary name server", Str),
    f("dns.soa.rname", "Responsible authority's mailbox", Str),
    f("dns.soa.serial_number", "Serial Number", Unsigned(Dec)),
    f(
        "dns.soa.refresh_interval",
        "Refresh Interval",
        Unsigned(Dec),
    ),
    f("dns.soa.retry_interval", "Retry Interval", Unsigned(Dec)),
    f("dns.soa.expire_limit", "Expire limit", Unsigned(Dec)),
    f("dns.soa.minimum_ttl", "Minimum TTL", Unsigned(Dec)),
    f("dns.srv.priority", "Priority", Unsigned(Dec)),
    f("dns.srv.weight", "Weight", Unsigned(Dec)),
    f("dns.srv.port", "Port", Unsigned(Dec)),
    f("dns.srv.target", "Target", Str),
    f("dns.resp.data", "Data", Bytes),
    // DHCP
    f("dhcp", "Dynamic Host Configuration Protocol", Protocol),
    f("dhcp.type", "Message type", Enum(DHCP_OPS, Dec)),
    f("dhcp.hw.type", "Hardware type", Enum(ARP_HWTYPES, Hex)),
    f("dhcp.hw.len", "Hardware address length", Unsigned(Dec)),
    f("dhcp.hops", "Hops", Unsigned(Dec)),
    f("dhcp.id", "Transaction ID", Unsigned(Hex)),
    f("dhcp.secs", "Seconds elapsed", Unsigned(Dec)),
    f("dhcp.flags", "Bootp flags", Unsigned(Hex)),
    f("dhcp.flags.bc", "Broadcast flag", Bool),
    f("dhcp.ip.client", "Client IP address", Ipv4),
    f("dhcp.ip.your", "Your (client) IP address", Ipv4),
    f("dhcp.ip.server", "Next server IP address", Ipv4),
    f("dhcp.ip.relay", "Relay agent IP address", Ipv4),
    f("dhcp.hw.mac_addr", "Client MAC address", Mac),
    f(
        "dhcp.hw.addr_padding",
        "Client hardware address padding",
        Bytes,
    ),
    f("dhcp.server", "Server host name", Str),
    f("dhcp.file", "Boot file name", Str),
    f("dhcp.cookie", "Magic cookie", Unsigned(Hex)),
    f("dhcp.option", "Option", Group),
    f("dhcp.option.type", "Option", Enum(DHCP_OPTIONS, Dec)),
    f("dhcp.option.length", "Length", Unsigned(Dec)),
    f("dhcp.option.value", "Value", Bytes),
    f("dhcp.option.dhcp", "DHCP", Enum(DHCP_MSG_TYPES, Dec)),
    f("dhcp.option.subnet_mask", "Subnet Mask", Ipv4),
    f("dhcp.option.router", "Router", Ipv4),
    f("dhcp.option.domain_name_server", "Domain Name Server", Ipv4),
    f("dhcp.option.broadcast_address", "Broadcast Address", Ipv4),
    f("dhcp.option.ntp_server", "NTP Server", Ipv4),
    f(
        "dhcp.option.requested_ip_address",
        "Requested IP Address",
        Ipv4,
    ),
    f(
        "dhcp.option.ip_address_lease_time",
        "IP Address Lease Time",
        Unsigned(Dec),
    ),
    f(
        "dhcp.option.renewal_time_value",
        "Renewal Time Value",
        Unsigned(Dec),
    ),
    f(
        "dhcp.option.rebinding_time_value",
        "Rebinding Time Value",
        Unsigned(Dec),
    ),
    f("dhcp.option.dhcp_server_id", "DHCP Server Identifier", Ipv4),
    f(
        "dhcp.option.dhcp_max_message_size",
        "Maximum DHCP Message Size",
        Unsigned(Dec),
    ),
    f("dhcp.option.hostname", "Host Name", Str),
    f("dhcp.option.domain_name", "Domain Name", Str),
    f(
        "dhcp.option.vendor_class_id",
        "Vendor class identifier",
        Str,
    ),
    f("dhcp.option.client_id", "Client identifier", Bytes),
    f(
        "dhcp.option.request_list_item",
        "Parameter Request List Item",
        Enum(DHCP_OPTIONS, Dec),
    ),
    f("dhcp.option.end", "Option End", Group),
    f("dhcp.option.padding", "Padding", Bytes),
    // HTTP
    f("http", "Hypertext Transfer Protocol", Protocol),
    f("http.request", "Request", Group),
    f("http.request.method", "Request Method", Str),
    f("http.request.uri", "Request URI", Str),
    f("http.request.version", "Request Version", Str),
    f("http.request.line", "Request line", Str),
    f("http.response", "Response", Group),
    f("http.response.version", "Response Version", Str),
    f("http.response.code", "Status Code", Unsigned(Dec)),
    f("http.response.phrase", "Response Phrase", Str),
    f("http.response.line", "Response line", Str),
    f("http.host", "Host", Str),
    f("http.user_agent", "User-Agent", Str),
    f("http.content_type", "Content-Type", Str),
    f("http.content_length", "Content-Length", Unsigned(Dec)),
    f("http.server", "Server", Str),
    f("http.connection", "Connection", Str),
    f("http.file_data", "File Data", Bytes),
    // TLS
    f("tls", "Transport Layer Security", Protocol),
    f("tls.record", "TLS Record Layer", Group),
    f(
        "tls.record.content_type",
        "Content Type",
        Enum(TLS_CONTENT_TYPES, Dec),
    ),
    f("tls.record.version", "Version", Enum(TLS_VERSIONS, Hex)),
    f("tls.record.length", "Length", Unsigned(Dec)),
    f(
        "tls.record.opaque_type",
        "Opaque Type",
        Enum(TLS_CONTENT_TYPES, Dec),
    ),
    f(
        "tls.change_cipher_spec",
        "Change Cipher Spec Message",
        Group,
    ),
    f("tls.alert_message", "Alert Message", Group),
    f(
        "tls.alert_message.level",
        "Level",
        Enum(TLS_ALERT_LEVELS, Dec),
    ),
    f(
        "tls.alert_message.desc",
        "Description",
        Enum(TLS_ALERT_DESCS, Dec),
    ),
    f("tls.handshake", "Handshake Protocol", Group),
    f(
        "tls.handshake.type",
        "Handshake Type",
        Enum(TLS_HANDSHAKE_TYPES, Dec),
    ),
    f("tls.handshake.length", "Length", Unsigned(Dec)),
    f("tls.handshake.version", "Version", Enum(TLS_VERSIONS, Hex)),
    f("tls.handshake.random", "Random", Bytes),
    f(
        "tls.handshake.session_id_length",
        "Session ID Length",
        Unsigned(Dec),
    ),
    f("tls.handshake.session_id", "Session ID", Bytes),
    f(
        "tls.handshake.cipher_suites_length",
        "Cipher Suites Length",
        Unsigned(Dec),
    ),
    f("tls.handshake.ciphersuites", "Cipher Suites", Group),
    f(
        "tls.handshake.ciphersuite",
        "Cipher Suite",
        Enum(TLS_CIPHER_SUITES, Hex),
    ),
    f(
        "tls.handshake.comp_methods_length",
        "Compression Methods Length",
        Unsigned(Dec),
    ),
    f("tls.handshake.comp_methods", "Compression Methods", Group),
    f(
        "tls.handshake.comp_method",
        "Compression Method",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.extensions_length",
        "Extensions Length",
        Unsigned(Dec),
    ),
    f("tls.handshake.extension", "Extension", Group),
    f(
        "tls.handshake.extension.type",
        "Type",
        Enum(TLS_EXTENSIONS, Dec),
    ),
    f("tls.handshake.extension.len", "Length", Unsigned(Dec)),
    f("tls.handshake.extension.data", "Data", Bytes),
    f(
        "tls.handshake.extensions_server_name_list_len",
        "Server Name list length",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.extensions_server_name_type",
        "Server Name Type",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.extensions_server_name_len",
        "Server Name length",
        Unsigned(Dec),
    ),
    f("tls.handshake.extensions_server_name", "Server Name", Str),
    f(
        "tls.handshake.extensions.supported_versions_len",
        "Supported Versions length",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.extensions.supported_version",
        "Supported Version",
        Enum(TLS_VERSIONS, Hex),
    ),
    f(
        "tls.handshake.extensions_alpn_len",
        "ALPN Extension Length",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.extensions_alpn_str_len",
        "ALPN string length",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.extensions_alpn_str",
        "ALPN Next Protocol",
        Str,
    ),
    f(
        "tls.handshake.certificates_length",
        "Certificates Length",
        Unsigned(Dec),
    ),
    f(
        "tls.handshake.certificate_length",
        "Certificate Length",
        Unsigned(Dec),
    ),
    f("tls.handshake.certificate", "Certificate", Bytes),
    f("tls.app_data", "Encrypted Application Data", Bytes),
    f("tls.handshake.encrypted", "Encrypted handshake data", Bytes),
    f("tls.continuation_data", "Continuation Data", Bytes),
];

// ---- lookup ----------------------------------------------------------------

/// FNV-1a. Field lookup happens once per node built, so the default
/// SipHash costs more than the whole rest of a node; these keys are short,
/// fixed, and not attacker-controlled (they are `&'static str` literals).
#[derive(Default)]
pub struct FnvHasher(u64);

impl Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        self.0 = h;
    }
}

type FnvMap<K, V> = HashMap<K, V, BuildHasherDefault<FnvHasher>>;

fn index() -> &'static FnvMap<&'static str, u16> {
    static INDEX: OnceLock<FnvMap<&'static str, u16>> = OnceLock::new();
    INDEX.get_or_init(|| {
        FIELDS
            .iter()
            .enumerate()
            .map(|(i, d)| (d.abbrev, i as u16))
            .collect()
    })
}

/// Abbrevs seen at run time that are not in `FIELDS`. Should stay empty (a
/// test walks every fixture tree to enforce it) but keeps unknown fields
/// addressable rather than silently renaming them.
struct Extra {
    names: Vec<&'static str>,
    ids: FnvMap<&'static str, u16>,
}

fn extra() -> &'static RwLock<Extra> {
    static EXTRA: OnceLock<RwLock<Extra>> = OnceLock::new();
    EXTRA.get_or_init(|| {
        RwLock::new(Extra {
            names: Vec::new(),
            ids: FnvMap::default(),
        })
    })
}

/// A direct-mapped memo of pointer -> id. Dissectors pass `&'static str`
/// literals, so the same field is almost always the same pointer; a hit costs
/// a shift and a compare instead of hashing the string. Verified by pointer
/// equality, so a collision or a distinct-but-equal literal is simply a miss
/// that falls through to the map.
const MEMO_SLOTS: usize = 512;

thread_local! {
    static FIELD_MEMO: std::cell::RefCell<[(usize, u16); MEMO_SLOTS]> =
        const { std::cell::RefCell::new([(0, 0); MEMO_SLOTS]) };
}

fn memo_slot(abbrev: &'static str) -> usize {
    (abbrev.as_ptr() as usize >> 3) & (MEMO_SLOTS - 1)
}

/// Stable numeric id for a field abbrev.
pub fn field_id(abbrev: &'static str) -> u16 {
    let key = abbrev.as_ptr() as usize;
    let slot = memo_slot(abbrev);
    if let Some(hit) = FIELD_MEMO.with(|m| {
        let m = m.borrow();
        let (k, id) = m[slot];
        (k == key).then_some(id)
    }) {
        return hit;
    }
    let id = field_id_uncached(abbrev);
    FIELD_MEMO.with(|m| m.borrow_mut()[slot] = (key, id));
    id
}

fn field_id_uncached(abbrev: &'static str) -> u16 {
    if let Some(id) = index().get(abbrev) {
        return *id;
    }
    if let Ok(e) = extra().read() {
        if let Some(id) = e.ids.get(abbrev) {
            return *id;
        }
    }
    let Ok(mut e) = extra().write() else {
        return u16::MAX;
    };
    if let Some(id) = e.ids.get(abbrev) {
        return *id;
    }
    let id = (FIELDS.len() + e.names.len()).min(usize::from(u16::MAX)) as u16;
    e.names.push(abbrev);
    e.ids.insert(abbrev, id);
    id
}

/// Id for an abbrev only if it is registered or already interned.
pub fn field_id_if_known(abbrev: &str) -> Option<u16> {
    if let Some(id) = index().get(abbrev) {
        return Some(*id);
    }
    extra().read().ok()?.ids.get(abbrev).copied()
}

pub fn field_abbrev(id: u16) -> &'static str {
    if let Some(d) = FIELDS.get(usize::from(id)) {
        return d.abbrev;
    }
    extra()
        .read()
        .ok()
        .and_then(|e| e.names.get(usize::from(id) - FIELDS.len()).copied())
        .unwrap_or("?")
}

pub fn field(id: u16) -> Option<&'static FieldDef> {
    FIELDS.get(usize::from(id))
}

pub fn lookup(abbrev: &str) -> Option<&'static FieldDef> {
    index().get(abbrev).and_then(|id| field(*id))
}

/// All field definitions, for completion.
pub fn all() -> &'static [FieldDef] {
    FIELDS
}

/// The registered field name closest to `name`, for "did you mean" hints.
/// Uses edit distance capped at a third of the name length, so a typo is
/// suggested but an unrelated name is not.
pub fn closest(name: &str) -> Option<&'static str> {
    let budget = (name.len() / 3).clamp(1, 4);
    let mut best: Option<(usize, &'static str)> = None;
    for d in FIELDS {
        let dist = edit_distance(name, d.abbrev, budget);
        if let Some(dist) = dist {
            if best.is_none_or(|(b, _)| dist < b) {
                best = Some((dist, d.abbrev));
            }
        }
    }
    best.map(|(_, name)| name)
}

/// Levenshtein distance, abandoning once it exceeds `budget`.
fn edit_distance(a: &str, b: &str, budget: usize) -> Option<usize> {
    if a.len().abs_diff(b.len()) > budget {
        return None;
    }
    let a: Vec<u8> = a.bytes().collect();
    let b: Vec<u8> = b.bytes().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        let mut row_best = cur[0];
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            row_best = row_best.min(cur[j + 1]);
        }
        if row_best > budget {
            return None;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    let dist = prev[b.len()];
    (dist <= budget).then_some(dist)
}

/// Symbolic name for `value` in `table`.
pub fn enum_name(table: &[(u64, &'static str)], value: u64) -> Option<&'static str> {
    table.iter().find(|(v, _)| *v == value).map(|(_, n)| *n)
}

// ---- labels ----------------------------------------------------------------

/// Protocol-layer labels derived from child fields, so dissectors need not
/// format a string per layer. `{abbrev}` is replaced by the display of the
/// first direct child with that field (enum children show their name only).
static LAYER_TEMPLATES: &[(&str, &str)] = &[
    (
        "frame",
        "Frame {frame.number}: {frame.len} bytes on wire, {frame.cap_len} bytes captured",
    ),
    ("eth", "Ethernet II, Src: {eth.src}, Dst: {eth.dst}"),
    ("ip", "Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}"),
    ("ipv6", "Internet Protocol Version 6, Src: {ipv6.src}, Dst: {ipv6.dst}"),
    ("arp", "Address Resolution Protocol ({arp.opcode})"),
    (
        "udp",
        "User Datagram Protocol, Src Port: {udp.srcport}, Dst Port: {udp.dstport}",
    ),
    (
        "tcp",
        "Transmission Control Protocol, Src Port: {tcp.srcport}, Dst Port: {tcp.dstport}, Seq: {tcp.seq}, Ack: {tcp.ack}, Len: {tcp.len}",
    ),
    ("icmp", "Internet Control Message Protocol"),
    ("icmpv6", "Internet Control Message Protocol v6"),
    ("data", "Data ({data.len} bytes)"),
];

fn hex_of(bytes: &[u8]) -> String {
    const MAX: usize = 48;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(MAX * 2 + 1);
    for b in bytes.iter().take(MAX) {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0xf)] as char);
    }
    if bytes.len() > MAX {
        s.push('…');
    }
    s
}

fn format_unsigned(v: u64, base: Base, width_bytes: usize) -> String {
    let w = width_bytes.clamp(1, 8) * 2;
    match base {
        Base::Dec => v.to_string(),
        Base::Hex => format!("0x{v:0w$x}"),
        Base::HexDec => format!("0x{v:0w$x} ({v})"),
        Base::Name => v.to_string(),
    }
}

/// Just the value part of a label (no field name).
pub fn value_text(node: &NodeRef<'_>, data: &[u8]) -> String {
    let def = field(node.field_id());
    let value = node.value();
    match (def.map(|d| d.kind), &value) {
        (Some(Kind::Bool), Value::Bool(b)) => (if *b { "Set" } else { "Not set" }).to_string(),
        (Some(Kind::Unsigned(base)), Value::Unsigned(v)) => {
            format_unsigned(*v, base, node.range().len())
        }
        (Some(Kind::Enum(table, Base::Name)), Value::Unsigned(v)) => {
            enum_name(table, *v).unwrap_or("Unknown").to_string()
        }
        (Some(Kind::Enum(table, base)), Value::Unsigned(v)) => {
            let sym = enum_name(table, *v).unwrap_or("Unknown");
            format!("{sym} ({})", format_unsigned(*v, base, node.range().len()))
        }
        (_, Value::Bytes) => hex_of(data.get(node.range()).unwrap_or(&[])),
        (_, Value::None) => String::new(),
        (_, v) => v.to_string(),
    }
}

fn render_template(template: &str, node: &NodeRef<'_>, data: &[u8]) -> String {
    let mut out = String::with_capacity(template.len() + 32);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let key = &rest[open + 1..open + close];
        match node.child(key) {
            Some(child) => match (field(child.field_id()).map(|d| d.kind), child.value()) {
                (Some(Kind::Enum(table, _)), Value::Unsigned(v)) => {
                    out.push_str(enum_name(table, v).unwrap_or("unknown"));
                }
                _ => out.push_str(&value_text(&child, data)),
            },
            None => out.push('?'),
        }
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

/// The display label for `node`. `data` is the bytes of the node's data
/// source, used only for `Bytes` fields.
pub fn label(node: &NodeRef<'_>, data: &[u8]) -> String {
    if let Some(t) = node.text() {
        return t.to_string();
    }
    let abbrev = node.abbrev();
    let Some(def) = field(node.field_id()) else {
        return match node.value() {
            Value::None | Value::Bytes => abbrev.to_string(),
            v => format!("{abbrev}: {v}"),
        };
    };
    match def.kind {
        Kind::Protocol | Kind::Group => {
            if let Some((_, template)) = LAYER_TEMPLATES.iter().find(|(a, _)| *a == abbrev) {
                return render_template(template, node, data);
            }
            def.name.to_string()
        }
        _ => {
            let v = value_text(node, data);
            if v.is_empty() {
                def.name.to_string()
            } else {
                format!("{}: {v}", def.name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::node::Tree;

    #[test]
    fn abbrevs_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for d in FIELDS {
            assert!(seen.insert(d.abbrev), "duplicate abbrev {}", d.abbrev);
        }
    }

    #[test]
    fn ids_round_trip_and_unknowns_are_interned() {
        assert_eq!(field_abbrev(field_id("tcp.srcport")), "tcp.srcport");
        let id = field_id("zz.unknown.field");
        assert!(usize::from(id) >= FIELDS.len());
        assert_eq!(field_abbrev(id), "zz.unknown.field");
        // The pointer memo must return the same id on a second lookup.
        assert_eq!(field_id("zz.unknown.field"), id);
        assert_eq!(field_id_if_known("zz.never"), None);
        // A distinct allocation with the same content resolves identically.
        let same: &'static str = Box::leak("tcp.srcport".to_string().into_boxed_str());
        assert_eq!(field_id(same), field_id("tcp.srcport"));
    }

    fn leaf(abbrev: &'static str, range: std::ops::Range<usize>, value: Value) -> Tree {
        Tree::build(|b| {
            b.leaf(abbrev, 0, range, value);
        })
    }

    #[test]
    fn labels_follow_kind() {
        let t = leaf("tcp.srcport", 34..36, Value::Unsigned(443));
        assert_eq!(label(&t.get(0).unwrap(), &[]), "Source Port: 443");
        let t = leaf("eth.type", 12..14, Value::Unsigned(0x0800));
        assert_eq!(label(&t.get(0).unwrap(), &[]), "Type: IPv4 (0x0800)");
        let t = leaf("ip.id", 18..20, Value::Unsigned(0x1c46));
        assert_eq!(
            label(&t.get(0).unwrap(), &[]),
            "Identification: 0x1c46 (7238)"
        );
        let t = leaf("tcp.flags.syn", 47..48, Value::Bool(true));
        assert_eq!(label(&t.get(0).unwrap(), &[]), "Syn: Set");
        let t = leaf("data.data", 1..3, Value::Bytes);
        assert_eq!(label(&t.get(0).unwrap(), &[0, 0xab, 0xcd]), "Data: abcd");
        let t = leaf("ip.checksum.status", 24..26, Value::Unsigned(1));
        assert_eq!(
            label(&t.get(0).unwrap(), &[]),
            "Header checksum status: Good"
        );
        let t = Tree::build(|b| {
            let id = b.leaf("tcp", 0, 0..0, Value::None);
            b.set_text(id, "TCP, Src Port: 1");
        });
        assert_eq!(label(&t.get(0).unwrap(), &[]), "TCP, Src Port: 1");
        let t = leaf("nope.field", 0..0, Value::Unsigned(1));
        assert_eq!(label(&t.get(0).unwrap(), &[]), "nope.field: 1");
    }

    #[test]
    fn layer_labels_come_from_children() {
        let t = Tree::build(|b| {
            b.begin("eth", 0, 0..14);
            b.leaf("eth.dst", 0, 0..6, Value::Mac([0xff; 6]));
            b.leaf("eth.src", 0, 6..12, Value::Mac([1, 2, 3, 4, 5, 6]));
            b.end();
        });
        assert_eq!(
            label(&t.get(0).unwrap(), &[]),
            "Ethernet II, Src: 01:02:03:04:05:06, Dst: ff:ff:ff:ff:ff:ff"
        );
        let t = Tree::build(|b| {
            b.begin("arp", 0, 0..28);
            b.leaf("arp.opcode", 0, 6..8, Value::Unsigned(2));
            b.end();
        });
        assert_eq!(
            label(&t.get(0).unwrap(), &[]),
            "Address Resolution Protocol (reply)"
        );
    }
}
