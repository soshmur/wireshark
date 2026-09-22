//! Stage 2: turning raw frames into dissected `Frame`s.
//!
//! `dissect` runs the chain of protocol dissectors for one frame. Each
//! dissector returns its own top-level node and tells the context which
//! dissector gets the payload; a failure becomes a `[Malformed Packet]` node
//! covering the rest of the layer and dissection stops there for that data
//! source. One bad packet never aborts the frame, let alone the capture.

pub mod ctx;
pub mod cursor;
pub mod node;
pub mod proto;
pub mod reassembly;
pub mod registry;
pub mod worker;

use std::sync::Arc;

use netscope_ffi::LinkType;

use crate::capture::{RawFrame, Timestamp};
pub use ctx::{Ctx, Proto};
pub use cursor::DissectError;
pub use node::{Node, NodeRef, SourceId, Tree, Value};
pub use reassembly::Reassembly;

/// Packet-list columns, computed once at dissection time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    pub source: String,
    pub destination: String,
    pub protocol: &'static str,
    pub info: String,
}

impl Summary {
    /// Column text for the protocol: Wireshark-style capitalisation.
    pub fn protocol_display(&self) -> &'static str {
        match self.protocol {
            "eth" => "ETH",
            "null" => "NULL",
            "vlan" => "VLAN",
            "llc" => "LLC",
            "arp" => "ARP",
            "ip" => "IPv4",
            "ipv6" => "IPv6",
            "icmp" => "ICMP",
            "icmpv6" => "ICMPv6",
            "udp" => "UDP",
            "tcp" => "TCP",
            "dns" => "DNS",
            "dhcp" => "DHCP",
            "http" => "HTTP",
            "tls" => "TLS",
            "data" => "DATA",
            "" => "RAW",
            other => other,
        }
    }
}

/// A fully dissected frame as stored and rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub number: u32,
    pub ts: Timestamp,
    /// Data source 0: the captured bytes.
    pub bytes: Arc<[u8]>,
    pub orig_len: u32,
    /// Flattened dissection tree; its roots are the layers, `frame` first.
    pub tree: Tree,
    pub summary: Summary,
    /// Data sources 1..: reassembled buffers referenced by node ranges.
    pub extra_sources: Vec<Arc<[u8]>>,
}

impl Frame {
    pub fn caplen(&self) -> usize {
        self.bytes.len()
    }

    /// Bytes of data source `id`, if it exists.
    pub fn source(&self, id: SourceId) -> Option<&[u8]> {
        if id == 0 {
            Some(&self.bytes)
        } else {
            self.extra_sources
                .get(usize::from(id) - 1)
                .map(|b| b.as_ref())
        }
    }

    /// Approximate memory held by this frame, for ring-buffer accounting.
    pub fn approx_size(&self) -> usize {
        std::mem::size_of::<Frame>()
            + self.bytes.len()
            + self.tree.approx_size()
            + self.summary.source.len()
            + self.summary.destination.len()
            + self.summary.info.len()
            + self.extra_sources.iter().map(|b| b.len()).sum::<usize>()
    }

    /// Top-level protocol layers, `frame` first.
    pub fn layers(&self) -> impl Iterator<Item = NodeRef<'_>> + '_ {
        self.tree.roots()
    }
}

/// Largest `range.end` anywhere in a builder subtree, for source 0.
fn max_end(n: &Node) -> usize {
    let own = if n.source == 0 { n.range.end } else { 0 };
    n.children.iter().map(max_end).fold(own, usize::max)
}

/// Upper bound on chained layers in one frame; guards against a dispatch
/// cycle ever being introduced.
const MAX_LAYERS: usize = 32;

fn run(proto: Proto, data: &[u8], ctx: &mut Ctx) -> cursor::Result<Node> {
    match proto {
        Proto::Ethernet => proto::eth::dissect(data, ctx),
        Proto::Null => proto::null::dissect(data, ctx),
        Proto::Vlan => proto::vlan::dissect(data, ctx),
        Proto::Llc => proto::llc::dissect(data, ctx),
        Proto::Arp => proto::arp::dissect(data, ctx),
        Proto::Ipv4 => proto::ipv4::dissect(data, ctx),
        Proto::Ipv6 => proto::ipv6::dissect(data, ctx),
        Proto::Icmp => proto::icmp::dissect(data, ctx),
        Proto::Icmpv6 => proto::icmpv6::dissect(data, ctx),
        Proto::Udp => proto::udp::dissect(data, ctx),
        Proto::Tcp => proto::tcp::dissect(data, ctx),
        Proto::Dns => proto::dns::dissect(data, ctx),
        Proto::Dhcp => proto::dhcp::dissect(data, ctx),
        Proto::Http => proto::http::dissect(data, ctx),
        Proto::Tls => proto::tls::dissect(data, ctx),
        Proto::Data => proto::data(data, ctx),
    }
}

/// The first dissector for a link type.
pub fn link_dissector(link_type: LinkType) -> Proto {
    match link_type {
        LinkType::ETHERNET => Proto::Ethernet,
        LinkType::NULL | LinkType(108) => Proto::Null,
        LinkType::RAW | LinkType(228) => Proto::Ipv4,
        LinkType(229) => Proto::Ipv6,
        _ => Proto::Data,
    }
}

/// Dissect one raw frame. Never panics on any input.
pub fn dissect(
    link_type: LinkType,
    number: u32,
    raw: RawFrame,
    reassembly: &mut Reassembly,
) -> Frame {
    let bytes = raw.bytes;
    let mut ctx = Ctx::new(link_type, number, raw.ts, reassembly);
    let mut layers: Vec<Node> = Vec::with_capacity(6);

    let mut proto = link_dissector(link_type);
    let mut source: SourceId = 0;
    let mut offset = 0usize;
    let mut len: Option<usize> = None;
    for _ in 0..MAX_LAYERS {
        // Clone the Arc so the dissector can borrow `ctx` mutably.
        let owned: Arc<[u8]> = if source == 0 {
            Arc::clone(&bytes)
        } else {
            match ctx.extra_sources.get(usize::from(source) - 1) {
                Some(b) => Arc::clone(b),
                None => break,
            }
        };
        let end = len.map_or(owned.len(), |l| (offset + l).min(owned.len()));
        let slice = owned.get(offset..end).unwrap_or(&[]);
        ctx.source = source;
        ctx.base = offset;
        match run(proto, slice, &mut ctx) {
            Ok(node) => layers.push(node),
            Err(e) => {
                // The layer could not be parsed. Show what it covers as a
                // malformed node, and the bytes it could not consume as data
                // beneath it, so the frame is still fully accounted for.
                let mut bad = Node::new("_ws.malformed", offset..owned.len(), Value::None)
                    .with_source(source)
                    .with_text(format!("[Malformed Packet: {}] {e}", proto.name()));
                if offset < owned.len() {
                    ctx.base = offset;
                    if let Ok(rest) = proto::data(slice, &mut ctx) {
                        bad.push(rest);
                    }
                }
                layers.push(bad);
                ctx.set_info(format!("[Malformed Packet: {}] {e}", proto.name()));
                ctx.summary.protocol = proto.name();
                ctx.take_next();
                break;
            }
        }
        match ctx.take_next() {
            Some(h) => {
                proto = h.proto;
                source = h.source;
                offset = h.offset;
                len = h.len;
            }
            None => break,
        }
    }

    // Bytes of the frame that no layer claimed are Ethernet padding or a
    // trailer; account for them once here, where the whole frame is visible,
    // rather than hanging them off a layer whose range does not cover them.
    let covered = layers
        .iter()
        .filter(|n| n.source == 0)
        .map(max_end)
        .max()
        .unwrap_or(0);
    if covered < bytes.len() && !layers.is_empty() {
        let range = covered..bytes.len();
        let tail = bytes.get(range.clone()).unwrap_or(&[]);
        let (abbrev, text) = if link_type == LinkType::ETHERNET {
            if tail.iter().all(|b| *b == 0) {
                ("eth.padding", format!("Padding: {} bytes", tail.len()))
            } else {
                ("eth.trailer", format!("Trailer: {} bytes", tail.len()))
            }
        } else {
            ("data.data", format!("Trailing data: {} bytes", tail.len()))
        };
        layers.push(Node::new(abbrev, range, Value::Bytes).with_text(text));
    }

    let protocols = ctx.protocols.join(":");
    layers.insert(
        0,
        frame_node(
            number,
            raw.ts,
            bytes.len(),
            raw.orig_len,
            link_type,
            &protocols,
        ),
    );
    let tree = Tree::from_layers(&layers);
    let mut summary = ctx.summary;
    if summary.protocol.is_empty() {
        summary.protocol = "RAW";
    }
    Frame {
        number,
        ts: raw.ts,
        bytes,
        orig_len: raw.orig_len,
        tree,
        summary,
        extra_sources: ctx.extra_sources,
    }
}

fn frame_node(
    number: u32,
    ts: Timestamp,
    caplen: usize,
    orig_len: u32,
    link_type: LinkType,
    protocols: &str,
) -> Node {
    let mut root = Node::new("frame", 0..caplen, Value::None).reserve(6);
    root.push(Node::new(
        "frame.number",
        0..0,
        Value::Unsigned(u64::from(number)),
    ));
    root.push(Node::new(
        "frame.time_epoch",
        0..0,
        Value::Str(format!("{}.{:09}", ts.secs, ts.nanos)),
    ));
    root.push(Node::new(
        "frame.len",
        0..0,
        Value::Unsigned(u64::from(orig_len)),
    ));
    root.push(Node::new(
        "frame.cap_len",
        0..0,
        Value::Unsigned(caplen as u64),
    ));
    root.push(Node::new(
        "frame.encap_type",
        0..0,
        Value::Unsigned(u64::from(link_type.0.max(0) as u32)),
    ));
    root.push(Node::new(
        "frame.protocols",
        0..0,
        Value::Str(protocols.to_string()),
    ));
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(bytes: &[u8]) -> RawFrame {
        RawFrame {
            ts: Timestamp { secs: 1, nanos: 2 },
            caplen: bytes.len() as u32,
            orig_len: bytes.len() as u32,
            bytes: Arc::from(bytes),
        }
    }

    #[test]
    fn ethernet_ipv4_tcp_chain() {
        let mut b = vec![0xffu8; 6];
        b.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        b.extend_from_slice(&[0x08, 0x00]);
        // IPv4 header, total length 40, proto TCP.
        b.extend_from_slice(&[
            0x45, 0, 0, 40, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        // TCP header: ports 1234 -> 80, SYN.
        b.extend_from_slice(&[
            0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        let mut r = Reassembly::new();
        let f = dissect(LinkType::ETHERNET, 7, raw(&b), &mut r);
        assert_eq!(f.summary.source, "10.0.0.1");
        assert_eq!(f.summary.destination, "10.0.0.2");
        assert_eq!(f.summary.protocol, "tcp");
        assert!(f.summary.info.contains("[SYN]"), "{}", f.summary.info);
        let names: Vec<&str> = f.layers().map(|n| n.abbrev()).collect();
        assert_eq!(names, ["frame", "eth", "ip", "tcp"]);
    }

    #[test]
    fn truncated_frames_become_malformed_and_do_not_panic() {
        let mut r = Reassembly::new();
        let full: Vec<u8> = (0..60u8).collect();
        for n in 0..=full.len() {
            let f = dissect(LinkType::ETHERNET, 1, raw(&full[..n]), &mut r);
            assert_eq!(f.tree.get(0).map(|n| n.range()), Some(0..n));
        }
        // 14-byte Ethernet header claiming IPv4 with nothing after it.
        let mut b = vec![0u8; 12];
        b.extend_from_slice(&[0x08, 0x00]);
        let f = dissect(LinkType::ETHERNET, 1, raw(&b), &mut r);
        let names: Vec<&str> = f.layers().map(|n| n.abbrev()).collect();
        assert_eq!(names, ["frame", "eth", "_ws.malformed"]);
        assert!(f.summary.info.starts_with("[Malformed Packet: ip]"));
    }
}
