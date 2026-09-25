//! Per-frame dissection context. Dissectors are pure functions of their input
//! slice plus this context; the context owns the tree being built and carries
//! what crosses layer boundaries: the summary columns, the protocol chain, the
//! next-layer handoff, extra data sources (reassembly) and the per-worker
//! state carried between frames.

use std::ops::Range;
use std::sync::Arc;

use netscope_ffi::LinkType;

use super::expert::{Expert, Group, Severity};
use super::node::{NodeId, SourceId, Tree, TreeBuilder, Value};
use super::state::State;
use super::stream::desegment::Origin;
use super::stream::Direction;
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

/// Dissection settings. These change what a dissector *reports*, never what
/// it parses, so a frame dissected under either setting has the same shape.
///
/// The default is to verify, because a caller that has not thought about
/// checksum offload is better served by being told a packet looks wrong than
/// by silence. The application overrides it: `netscope` ships with both off,
/// as Wireshark does, because on a real capture a NIC computes the transport
/// checksums after libpcap has already seen the packet and 20-40% of frames
/// would be flagged for no reason. See DECISIONS.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Verify the IPv4 header checksum and the ICMPv4 checksum. Both are
    /// computed in software, so they are rarely wrong for a benign reason.
    pub validate_ip_checksums: bool,
    /// Verify the TCP, UDP and ICMPv6 checksums. These cover a pseudo-header
    /// and are the ones NICs offload.
    pub validate_transport_checksums: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            validate_ip_checksums: true,
            validate_transport_checksums: true,
        }
    }
}

impl Options {
    /// Nothing verified: every checksum status reports `Unverified`.
    pub fn no_checksums() -> Options {
        Options {
            validate_ip_checksums: false,
            validate_transport_checksums: false,
        }
    }
}

pub struct Ctx<'a> {
    /// Settings in force for this frame.
    options: Options,
    pub link_type: LinkType,
    pub frame_number: u32,
    pub ts: Timestamp,
    /// Per-worker state carried across frames.
    pub state: &'a mut State,
    /// Conversation this frame belongs to, once the transport layer has
    /// looked it up. A sub-dissector needs it to hold bytes for the rest of
    /// its message.
    pub stream: Option<(u32, Direction)>,
    /// Where the bytes the current sub-dissector is looking at came from,
    /// when they are a desegmented buffer rather than one segment.
    pub origin: Option<Origin>,
    /// Set when a sub-dissector kept bytes for later: this frame ends in the
    /// middle of a message.
    pub held_bytes: bool,
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
        state: &'a mut State,
    ) -> Ctx<'a> {
        Ctx::with_options(link_type, frame_number, ts, state, Options::default())
    }

    pub fn with_options(
        link_type: LinkType,
        frame_number: u32,
        ts: Timestamp,
        state: &'a mut State,
        options: Options,
    ) -> Ctx<'a> {
        Ctx {
            options,
            link_type,
            frame_number,
            ts,
            state,
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
            stream: None,
            origin: None,
            held_bytes: false,
        }
    }

    /// Keep `bytes` until the rest of the message arrives, and report whether
    /// they were kept. A refusal (no conversation, over a cap) means the
    /// caller must dissect what it has.
    ///
    /// Bytes are held per stream *and direction*, so a request and the
    /// response to it never run into one another.
    pub fn hold(&mut self, bytes: &[u8]) -> bool {
        let (Some((stream, dir)), Some(origin)) = (self.stream, self.origin) else {
            return false;
        };
        let ts = self.ts;
        let kept = self.state.desegment.keep(stream, dir, bytes, origin, ts);
        self.held_bytes |= kept;
        kept
    }

    /// Discard any bytes held for this direction: the message they belonged
    /// to will never be completed.
    pub fn drop_held(&mut self) {
        if let Some((stream, dir)) = self.stream {
            self.state.desegment.forget(stream, dir);
        }
    }

    /// The dissection settings in force.
    pub fn options(&self) -> Options {
        self.options
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
        let id = self.tree.leaf(abbrev, self.source, range.clone(), value);
        self.tree.set_text(id, text);
        self.note_malformed(abbrev, range);
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
        let id = self.tree.begin(abbrev, self.source, range.clone());
        self.tree.set_text(id, text);
        self.note_malformed(abbrev, range);
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
        let id = self.tree.leaf(abbrev, self.source, range.clone(), value);
        self.tree.set_text_args(id, args);
        self.note_malformed(abbrev, range);
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

    /// Every `_ws.malformed` node is an expert Error, without each of the
    /// nine places that emit one having to remember. Enforcing it here rather
    /// than at the call sites is the difference between an invariant and a
    /// convention that drifts - which it had, before this existed.
    ///
    /// The specific reason stays in the node's own text; the expert record
    /// carries a fixed summary so the packet list needs no per-frame string.
    fn note_malformed(&mut self, abbrev: &'static str, range: Range<usize>) {
        if abbrev == "_ws.malformed" {
            self.expert_record(
                range,
                Severity::Error,
                Group::Malformed,
                "Malformed packet: this layer could not be parsed",
            );
        }
    }

    /// The `_ws.expert` subtree and the frame-level record, with no field of
    /// its own. Used where the finding *is* the node, such as a malformed
    /// layer.
    pub fn expert_record(
        &mut self,
        range: Range<usize>,
        severity: Severity,
        group: Group,
        summary: &'static str,
    ) {
        let node = self.begin_text("_ws.expert", range, summary);
        self.leaf(
            "_ws.expert.severity",
            0..0,
            Value::Unsigned(severity as u64),
        );
        self.leaf("_ws.expert.group", 0..0, Value::Unsigned(group as u64));
        self.end();
        let _ = node;
        // Keep the worst; ties keep the first, which is the one the dissector
        // reached earliest and so the most specific to the outer layer.
        let better = match &self.summary.expert {
            Some(e) => severity > e.severity,
            None => true,
        };
        if better {
            self.summary.expert = Some(Expert {
                severity,
                group,
                summary,
            });
        }
    }

    /// Raise an expert finding: a node in the tree, plus the frame-level
    /// record the packet list reads.
    ///
    /// `abbrev` is the finding's own field, so a filter can name the specific
    /// problem (`tcp.analysis.retransmission`) as well as the generic one
    /// (`_ws.expert.severity >= "Warning"`).
    pub fn expert(
        &mut self,
        abbrev: &'static str,
        range: Range<usize>,
        severity: Severity,
        group: Group,
        summary: &'static str,
    ) {
        self.leaf_text(abbrev, range.clone(), Value::None, summary);
        self.expert_record(range, severity, group, summary);
    }

    pub fn set_info(&mut self, info: impl Into<String>) {
        self.summary.info = info.into();
    }
}
