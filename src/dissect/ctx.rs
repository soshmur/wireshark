//! Per-frame dissection context. Dissectors are pure functions of their input
//! slice plus this context; the context owns the tree being built and carries
//! what crosses layer boundaries: the summary columns, the protocol chain, the
//! next-layer handoff, extra data sources (reassembly) and reassembly state.

use std::ops::Range;
use std::sync::Arc;

use netscope_ffi::LinkType;

use super::node::{NodeId, SourceId, Tree, TreeBuilder, Value};
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
    /// The tree being built, in depth-first order.
    pub tree: TreeBuilder,
    /// Protocol chain, e.g. `["eth", "ip", "tcp"]`. A fixed array so a frame
    /// costs no allocation for it; deeper stacks than this do not exist.
    protocols: [&'static str; 12],
    protocol_count: usize,
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
            tree: TreeBuilder::new(),
            protocols: [""; 12],
            protocol_count: 0,
            net_addrs: None,
            extra_sources: Vec::new(),
            source: 0,
            base: 0,
            next: None,
            nesting: 0,
        }
    }

    // ---- tree building ----------------------------------------------------

    /// A field at the current depth, in the data source being dissected.
    pub fn leaf(&mut self, abbrev: &'static str, range: Range<usize>, value: Value) -> NodeId {
        self.tree.leaf(abbrev, self.source, range, value)
    }

    /// A field with a free-text label.
    pub fn leaf_text(
        &mut self,
        abbrev: &'static str,
        range: Range<usize>,
        value: Value,
        text: &str,
    ) -> NodeId {
        let id = self.tree.leaf(abbrev, self.source, range, value);
        self.tree.set_text(id, text);
        id
    }

    /// Open a container; nodes added until `end` are its children.
    pub fn begin(&mut self, abbrev: &'static str, range: Range<usize>) -> NodeId {
        self.tree.begin(abbrev, self.source, range)
    }

    /// Open a container that carries a value of its own (a flags byte).
    pub fn begin_value(
        &mut self,
        abbrev: &'static str,
        range: Range<usize>,
        value: Value,
    ) -> NodeId {
        self.tree.begin_value(abbrev, self.source, range, value)
    }

    /// Open a container with a free-text label.
    pub fn begin_text(&mut self, abbrev: &'static str, range: Range<usize>, text: &str) -> NodeId {
        let id = self.tree.begin(abbrev, self.source, range);
        self.tree.set_text(id, text);
        id
    }

    /// Open a container with both a value and a free-text label.
    pub fn begin_value_text(
        &mut self,
        abbrev: &'static str,
        range: Range<usize>,
        value: Value,
        text: &str,
    ) -> NodeId {
        let id = self.tree.begin_value(abbrev, self.source, range, value);
        self.tree.set_text(id, text);
        id
    }

    pub fn end(&mut self) {
        self.tree.end();
    }

    /// The current nesting depth, to restore after a fallible sub-dissection
    /// that may return from inside open containers.
    pub fn depth(&self) -> u8 {
        self.tree.depth()
    }

    pub fn restore_depth(&mut self, depth: u8) {
        self.tree.set_depth(depth);
    }

    /// Close a container and set the range end it actually covered.
    pub fn end_at(&mut self, id: NodeId, end: usize) {
        self.tree.end_at(id, end);
    }

    pub fn set_text(&mut self, id: NodeId, text: &str) {
        self.tree.set_text(id, text);
    }

    /// Set a label by formatting straight into the tree's arena.
    pub fn set_textf(&mut self, id: NodeId, args: std::fmt::Arguments<'_>) {
        self.tree.set_text_args(id, args);
    }

    /// Open a container whose label is formatted into the arena.
    pub fn begin_textf(
        &mut self,
        abbrev: &'static str,
        range: Range<usize>,
        args: std::fmt::Arguments<'_>,
    ) -> NodeId {
        let id = self.tree.begin(abbrev, self.source, range);
        self.tree.set_text_args(id, args);
        id
    }

    /// A field whose label is formatted into the arena.
    pub fn leaf_textf(
        &mut self,
        abbrev: &'static str,
        range: Range<usize>,
        value: Value,
        args: std::fmt::Arguments<'_>,
    ) -> NodeId {
        let id = self.tree.leaf(abbrev, self.source, range, value);
        self.tree.set_text_args(id, args);
        id
    }

    pub fn set_end(&mut self, id: NodeId, end: usize) {
        self.tree.set_end(id, end);
    }

    /// Run `f` with nodes attributed to another data source (reassembly).
    pub fn in_source<T>(&mut self, source: SourceId, f: impl FnOnce(&mut Ctx<'a>) -> T) -> T {
        let saved = self.source;
        self.source = source;
        let out = f(self);
        self.source = saved;
        out
    }

    pub fn finish_tree(self) -> (Tree, Summary, Vec<Arc<[u8]>>) {
        (self.tree.finish(), self.summary, self.extra_sources)
    }

    // ---- layer handoff ----------------------------------------------------

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

    /// Record a layer in the chain and make it the Protocol column.
    pub fn set_protocol(&mut self, name: &'static str) {
        self.push_protocol(name);
        self.summary.protocol = name;
    }

    /// Record a layer in the chain only. `data` uses this so the Protocol
    /// column keeps naming the last protocol that was actually recognised.
    pub fn push_protocol(&mut self, name: &'static str) {
        if let Some(slot) = self.protocols.get_mut(self.protocol_count) {
            *slot = name;
            self.protocol_count += 1;
        }
    }

    /// The protocol chain recorded so far.
    pub fn protocols(&self) -> &[&'static str] {
        &self.protocols[..self.protocol_count]
    }

    /// Number of protocols recorded, to roll back nested dissection.
    pub fn protocol_count(&self) -> usize {
        self.protocol_count
    }

    pub fn truncate_protocols(&mut self, n: usize) {
        self.protocol_count = self.protocol_count.min(n);
    }

    pub fn set_info(&mut self, info: impl Into<String>) {
        self.summary.info = info.into();
    }
}
