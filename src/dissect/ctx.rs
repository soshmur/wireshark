//! Per-frame dissection context. Dissectors are pure functions of their input
//! slice plus this context; the context carries what crosses layer
//! boundaries: the summary columns, the protocol chain, the next-layer
//! handoff, extra data sources (reassembly) and shared reassembly state.

use std::sync::Arc;

use netscope_ffi::LinkType;

use super::node::SourceId;
use super::reassembly::Reassembly;
use super::Summary;
use crate::capture::Timestamp;

/// Every dissector the driver knows how to call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Ethernet,
    Null,
    Vlan,
    Llc,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Udp,
    Tcp,
    Dns,
    Dhcp,
    Http,
    Tls,
    Data,
}

impl Proto {
    /// Name used in `[Malformed Packet: X]` and `frame.protocols`.
    pub fn name(self) -> &'static str {
        match self {
            Proto::Ethernet => "eth",
            Proto::Null => "null",
            Proto::Vlan => "vlan",
            Proto::Llc => "llc",
            Proto::Arp => "arp",
            Proto::Ipv4 => "ip",
            Proto::Ipv6 => "ipv6",
            Proto::Icmp => "icmp",
            Proto::Icmpv6 => "icmpv6",
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Dns => "dns",
            Proto::Dhcp => "dhcp",
            Proto::Http => "http",
            Proto::Tls => "tls",
            Proto::Data => "data",
        }
    }
}

/// Network-layer addresses, needed for transport pseudo-header checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetAddrs {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handoff {
    pub proto: Proto,
    pub source: SourceId,
    /// Absolute offset within `source`.
    pub offset: usize,
    /// Number of bytes to expose, when the current layer knows its payload
    /// length (IP total length clips Ethernet padding).
    pub len: Option<usize>,
}

pub struct Ctx<'a> {
    pub link_type: LinkType,
    pub frame_number: u32,
    pub ts: Timestamp,
    pub reassembly: &'a mut Reassembly,
    pub summary: Summary,
    /// Protocol chain, e.g. `["eth", "ip", "tcp"]`.
    pub protocols: Vec<&'static str>,
    /// Addresses of the innermost network layer seen so far.
    pub net_addrs: Option<NetAddrs>,
    /// Extra data sources created during this frame (index 1..).
    pub extra_sources: Vec<Arc<[u8]>>,
    /// Data source of the slice the current dissector is looking at.
    pub source: SourceId,
    /// Absolute offset of that slice within its source.
    pub base: usize,
    next: Option<Handoff>,
    /// Nesting depth of encapsulated dissection (ICMP error payloads).
    pub nesting: u8,
}

impl<'a> Ctx<'a> {
    pub fn new(
        link_type: LinkType,
        frame_number: u32,
        ts: Timestamp,
        reassembly: &'a mut Reassembly,
    ) -> Ctx<'a> {
        Ctx {
            link_type,
            frame_number,
            ts,
            reassembly,
            summary: Summary::default(),
            protocols: Vec::with_capacity(6),
            net_addrs: None,
            extra_sources: Vec::new(),
            source: 0,
            base: 0,
            next: None,
            nesting: 0,
        }
    }

    /// Hand the bytes from `offset` (relative to the current dissector's
    /// slice) to `proto` once the current dissector returns.
    pub fn call_next(&mut self, proto: Proto, offset: usize) {
        self.next = Some(Handoff {
            proto,
            source: self.source,
            offset: self.base + offset,
            len: None,
        });
    }

    /// Like `call_next` but exposes only `len` bytes from `offset`.
    pub fn call_next_bounded(&mut self, proto: Proto, offset: usize, len: usize) {
        self.next = Some(Handoff {
            proto,
            source: self.source,
            offset: self.base + offset,
            len: Some(len),
        });
    }

    /// Hand a whole extra data source to `proto`.
    pub fn call_next_in_source(&mut self, proto: Proto, source: SourceId) {
        self.next = Some(Handoff {
            proto,
            source,
            offset: 0,
            len: None,
        });
    }

    pub fn take_next(&mut self) -> Option<Handoff> {
        self.next.take()
    }

    /// Register a reassembled buffer; returns its source id.
    pub fn add_source(&mut self, bytes: Arc<[u8]>) -> SourceId {
        self.extra_sources.push(bytes);
        self.extra_sources.len() as SourceId
    }

    pub fn set_protocol(&mut self, name: &'static str) {
        self.protocols.push(name);
        self.summary.protocol = name;
    }

    pub fn set_info(&mut self, info: impl Into<String>) {
        self.summary.info = info.into();
    }
}
