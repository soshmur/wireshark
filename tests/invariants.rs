//! Structural invariants that must hold for every dissected frame, checked
//! over every fixture frame and over truncations of each of them.
//!
//! These are the properties the hex pane and (in Phase 3) the filter engine
//! rely on: a node's range is inside its data source, a child's range is
//! inside its parent's, and every byte range is well formed.

mod common;

use std::sync::Arc;

use netscope::capture::{RawFrame, Timestamp};
use netscope::dissect::{dissect, registry, Frame, Reassembly};
use netscope_ffi::LinkType;

fn check(frame: &Frame, context: &str) {
    // Depth 0 nodes must start with `frame`.
    let roots: Vec<&str> = frame.tree.roots().map(|n| n.abbrev()).collect();
    assert_eq!(roots.first(), Some(&"frame"), "{context}: first layer");

    let mut stack: Vec<(u8, std::ops::Range<usize>, &str, u8)> = Vec::new();
    for node in frame.tree.iter() {
        let r = node.range();
        let abbrev = node.abbrev();
        assert!(r.start <= r.end, "{context}: {abbrev} inverted range {r:?}");

        let source = frame.source(node.source());
        assert!(
            source.is_some(),
            "{context}: {abbrev} references missing source {}",
            node.source()
        );
        let len = source.map_or(0, <[u8]>::len);
        assert!(
            r.end <= len,
            "{context}: {abbrev} range {r:?} past source {} length {len}",
            node.source()
        );

        // Every label renders without panicking and is non-empty.
        let label = registry::label(&node, source.unwrap_or(&[]));
        assert!(!label.is_empty(), "{context}: {abbrev} empty label");

        while stack.last().is_some_and(|(d, _, _, _)| *d >= node.depth()) {
            stack.pop();
        }
        if let Some((_, parent_range, parent, parent_source)) = stack.last() {
            // Zero-length nodes are generated fields with no bytes of their
            // own; a child in another data source (reassembly) is unrelated
            // to its parent's range.
            if !r.is_empty() && !parent_range.is_empty() && *parent_source == node.source() {
                assert!(
                    r.start >= parent_range.start && r.end <= parent_range.end,
                    "{context}: {abbrev} {r:?} escapes parent {parent} {parent_range:?}"
                );
            }
        }
        stack.push((node.depth(), r, abbrev, node.source()));
    }
}

fn raw(bytes: &[u8]) -> RawFrame {
    RawFrame {
        ts: Timestamp {
            secs: 1_700_000_000,
            nanos: 0,
        },
        caplen: bytes.len() as u32,
        orig_len: bytes.len() as u32,
        bytes: Arc::from(bytes),
    }
}

#[test]
fn fixture_frames_satisfy_tree_invariants() {
    for fx in common::fixtures::all() {
        let link = LinkType(i32::from(fx.link_type));
        let mut reassembly = Reassembly::new();
        for (i, bytes) in fx.frames.iter().enumerate() {
            let frame = dissect(link, i as u32 + 1, raw(bytes), &mut reassembly);
            check(&frame, &format!("{} frame {}", fx.name, i + 1));
        }
    }
}

#[test]
fn every_truncation_of_every_fixture_frame_holds() {
    for fx in common::fixtures::all() {
        let link = LinkType(i32::from(fx.link_type));
        for (i, bytes) in fx.frames.iter().enumerate() {
            // A fresh reassembly per truncation so fragments do not interact.
            for cut in 0..=bytes.len() {
                let mut reassembly = Reassembly::new();
                let frame = dissect(link, 1, raw(&bytes[..cut]), &mut reassembly);
                check(&frame, &format!("{} frame {} cut to {cut}", fx.name, i + 1));
            }
        }
    }
}

#[test]
fn single_byte_corruptions_hold() {
    // Flip bytes in the largest frames: length fields, type fields, offsets.
    for fx in common::fixtures::all() {
        let link = LinkType(i32::from(fx.link_type));
        for (i, bytes) in fx.frames.iter().enumerate().take(4) {
            for pos in 0..bytes.len().min(80) {
                for value in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                    let mut corrupt = bytes.clone();
                    corrupt[pos] = value;
                    let mut reassembly = Reassembly::new();
                    let frame = dissect(link, 1, raw(&corrupt), &mut reassembly);
                    check(
                        &frame,
                        &format!("{} frame {} byte {pos}={value:#04x}", fx.name, i + 1),
                    );
                }
            }
        }
    }
}

/// Checksum validation is a reporting setting, not a parsing one: turning it
/// off must change only the `*.checksum.status` values, never the shape of
/// the tree. `netscope` ships with it off, matching Wireshark, because a NIC
/// computes the transport checksums after libpcap has seen the packet.
#[test]
fn checksum_validation_changes_reporting_and_nothing_else() {
    use netscope::dissect::{dissect_with, Options};

    const STATUS_FIELDS: &[&str] = &[
        "ip.checksum.status",
        "icmp.checksum.status",
        "icmpv6.checksum.status",
        "tcp.checksum.status",
        "udp.checksum.status",
    ];
    // CK_UNVERIFIED, from src/dissect/proto/mod.rs.
    const UNVERIFIED: u64 = 2;
    const NOT_PRESENT: u64 = 3;

    let mut verified_any = false;
    for fx in common::fixtures::all() {
        let link = LinkType(i32::from(fx.link_type));
        let mut on = Reassembly::new();
        let mut off = Reassembly::new();
        for (i, bytes) in fx.frames.iter().enumerate() {
            let n = i as u32 + 1;
            let a = dissect_with(link, n, raw(bytes), &mut on, Options::default());
            let b = dissect_with(link, n, raw(bytes), &mut off, Options::no_checksums());

            // Same shape: same nodes, same ranges, same sources.
            assert_eq!(
                a.tree.len(),
                b.tree.len(),
                "{}#{n}: node count changed",
                fx.name
            );
            for (x, y) in a.tree.iter().zip(b.tree.iter()) {
                assert_eq!(x.abbrev(), y.abbrev(), "{}#{n}", fx.name);
                assert_eq!(x.range(), y.range(), "{}#{n}: {}", fx.name, x.abbrev());
                assert_eq!(x.source(), y.source(), "{}#{n}: {}", fx.name, x.abbrev());
                assert_eq!(x.depth(), y.depth(), "{}#{n}: {}", fx.name, x.abbrev());
            }

            // With validation off, no status is ever Good or Bad.
            for node in b.tree.iter() {
                if STATUS_FIELDS.contains(&node.abbrev()) {
                    let v = node.unsigned().unwrap_or(UNVERIFIED);
                    assert!(
                        v == UNVERIFIED || v == NOT_PRESENT,
                        "{}#{n}: {} reported {v} with validation off",
                        fx.name,
                        node.abbrev()
                    );
                }
            }
            // With it on, the fixtures do produce verdicts - otherwise this
            // test would pass against a dissector that never verifies.
            for node in a.tree.iter() {
                if STATUS_FIELDS.contains(&node.abbrev())
                    && node.unsigned().is_some_and(|v| v < UNVERIFIED)
                {
                    verified_any = true;
                }
            }
        }
    }
    assert!(
        verified_any,
        "no fixture produced a checksum verdict with validation on"
    );
    let _ = registry::all();
}
