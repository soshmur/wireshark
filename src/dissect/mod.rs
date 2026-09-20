//! Stage 2: turning raw frames into dissected `Frame`s.
//!
//! Phase 1 ships only the `frame` pseudo-protocol node and a best-effort
//! summary read at fixed Ethernet offsets. Real dissectors arrive in Phase 2
//! and replace `summarise`.

pub mod node;
pub mod worker;

use std::sync::Arc;

use netscope_ffi::LinkType;

use crate::capture::{RawFrame, Timestamp};
pub use node::{Node, Value};

/// Packet-list columns, computed once at dissection time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    pub source: String,
    pub destination: String,
    pub protocol: &'static str,
    pub info: String,
}

/// A fully dissected frame as stored and rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub number: u32,
    pub ts: Timestamp,
    pub bytes: Arc<[u8]>,
    pub orig_len: u32,
    pub tree: Node,
    pub summary: Summary,
}

impl Frame {
    pub fn caplen(&self) -> usize {
        self.bytes.len()
    }

    /// Approximate memory held by this frame, for ring-buffer accounting.
    pub fn approx_size(&self) -> usize {
        std::mem::size_of::<Frame>()
            + self.bytes.len()
            + self.tree.approx_size()
            + self.summary.source.len()
            + self.summary.destination.len()
            + self.summary.info.len()
    }
}

/// Dissect one raw frame. Never panics on any input.
pub fn dissect(link_type: LinkType, number: u32, raw: RawFrame) -> Frame {
    let bytes = raw.bytes;
    let tree = frame_node(number, raw.ts, bytes.len(), raw.orig_len, link_type);
    let summary = summarise(link_type, &bytes);
    Frame {
        number,
        ts: raw.ts,
        bytes,
        orig_len: raw.orig_len,
        tree,
        summary,
    }
}

fn frame_node(
    number: u32,
    ts: Timestamp,
    caplen: usize,
    orig_len: u32,
    link_type: LinkType,
) -> Node {
    let label = format!(
        "Frame {number}: {orig_len} bytes on wire ({} bits), {caplen} bytes captured ({} bits)",
        u64::from(orig_len) * 8,
        caplen * 8
    );
    Node::new("frame", label, 0..caplen, Value::None).with_children(vec![
        Node::new(
            "frame.number",
            format!("Frame Number: {number}"),
            0..0,
            Value::Unsigned(u64::from(number)),
        ),
        Node::new(
            "frame.time_epoch",
            format!("Epoch Time: {}.{:09} seconds", ts.secs, ts.nanos),
            0..0,
            Value::Signed(ts.secs),
        ),
        Node::new(
            "frame.len",
            format!("Frame Length: {orig_len} bytes"),
            0..0,
            Value::Unsigned(u64::from(orig_len)),
        ),
        Node::new(
            "frame.cap_len",
            format!("Capture Length: {caplen} bytes"),
            0..0,
            Value::Unsigned(caplen as u64),
        ),
        Node::new(
            "frame.encap_type",
            format!(
                "Encapsulation type: {} ({})",
                link_type.description(),
                link_type.0
            ),
            0..0,
            Value::Signed(i64::from(link_type.0)),
        ),
    ])
}

fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Phase 1 "source-so-far": MACs and EtherType read at fixed offsets when the
/// link type is Ethernet. Every read is bounds-checked; short frames get blanks.
fn summarise(link_type: LinkType, bytes: &[u8]) -> Summary {
    if link_type != LinkType::ETHERNET {
        return Summary {
            protocol: "RAW",
            ..Summary::default()
        };
    }
    let (Some(dst), Some(src)) = (bytes.get(0..6), bytes.get(6..12)) else {
        return Summary {
            protocol: "ETH",
            info: "short frame".into(),
            ..Summary::default()
        };
    };
    let ethertype = bytes.get(12..14).map(|t| u16::from_be_bytes([t[0], t[1]]));
    let (protocol, info) = match ethertype {
        Some(0x0800) => ("IPv4", String::new()),
        Some(0x86DD) => ("IPv6", String::new()),
        Some(0x0806) => ("ARP", String::new()),
        Some(0x8100) => ("802.1Q", String::new()),
        Some(0x88CC) => ("LLDP", String::new()),
        Some(t) if t <= 1500 => ("802.3", format!("length {t}")),
        Some(t) => ("ETH", format!("type 0x{t:04x}")),
        None => ("ETH", "no type".into()),
    };
    Summary {
        source: mac(src),
        destination: mac(dst),
        protocol,
        info,
    }
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
    fn ethernet_summary_reads_fixed_offsets() {
        let mut b = vec![0xffu8; 6];
        b.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        b.extend_from_slice(&[0x08, 0x00]);
        b.extend_from_slice(&[0; 20]);
        let f = dissect(LinkType::ETHERNET, 7, raw(&b));
        assert_eq!(f.summary.source, "00:01:02:03:04:05");
        assert_eq!(f.summary.destination, "ff:ff:ff:ff:ff:ff");
        assert_eq!(f.summary.protocol, "IPv4");
        assert_eq!(f.number, 7);
        assert_eq!(f.tree.range, 0..b.len());
    }

    #[test]
    fn short_and_empty_frames_do_not_panic() {
        for n in 0..16 {
            let b = vec![0u8; n];
            let f = dissect(LinkType::ETHERNET, 1, raw(&b));
            assert_eq!(f.tree.range, 0..n);
        }
    }
}
