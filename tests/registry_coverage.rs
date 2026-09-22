//! The field registry is the single source of field knowledge. This test
//! walks every fixture tree and fails on any emitted abbrev that is not
//! registered, and on any registered field that no fixture exercises
//! (dead registry entries drift from the dissectors that should emit them).

mod common;

use std::collections::BTreeSet;

use netscope::dissect::{dissect, registry, Reassembly};
use netscope_ffi::LinkType;

/// Registered fields that are legitimately never emitted as tree rows:
/// filter-only aliases and payload fields the filter engine derives from a
/// layer's extent, plus formats the fixtures do not exercise.
const ALLOWED_UNUSED: &[&str] = &[
    "udp.port",
    "tcp.port",
    "udp.payload",
    "tcp.payload",
    "arp.dst.proto",
    "arp.src.proto",
    "ipv6.routing.addr",
    "icmp.pointer",
    "icmpv6.pointer",
    "ip.opt.ptr",
    "ip.opt.route",
    "tls.record.opaque_type",
    "tls.handshake.certificate",
    "tls.handshake.certificate_length",
    "tls.handshake.certificates_length",
    "dhcp.hw.addr_padding",
];

#[test]
fn every_emitted_field_is_registered_and_every_field_is_emitted() {
    let mut emitted = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    for fx in common::fixtures::all() {
        let bytes = common::pcapng_with_link(fx.link_type, &fx.frames);
        let section = netscope::pcapng::read(&bytes).expect("parse");
        let link = LinkType(i32::from(fx.link_type));
        let mut reassembly = Reassembly::new();
        for (i, p) in section.packets.into_iter().enumerate() {
            let frame = dissect(link, i as u32 + 1, p.frame, &mut reassembly);
            for n in frame.tree.iter() {
                let abbrev = n.abbrev();
                emitted.insert(abbrev);
                if registry::lookup(abbrev).is_none() {
                    unknown.insert(abbrev);
                }
            }
        }
    }
    assert!(unknown.is_empty(), "emitted but unregistered: {unknown:?}");

    let unused: Vec<&str> = registry::all()
        .iter()
        .map(|d| d.abbrev)
        .filter(|a| !emitted.contains(a) && !ALLOWED_UNUSED.contains(a))
        .collect();
    assert!(
        unused.is_empty(),
        "registered but never emitted by any fixture: {unused:?}"
    );
}
