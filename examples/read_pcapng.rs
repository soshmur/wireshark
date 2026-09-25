//! Read a pcapng file and print one line per frame, through the same store
//! the UI uses. A preview of Phase 5's file support and a way to eyeball the
//! dissectors against a capture.
//!
//!     cargo run --release --example read_pcapng -- tests/fixtures/dns.pcapng

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use netscope::dissect::{dissect, State};
use netscope::store::{Limits, Store};
use netscope_ffi::LinkType;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: read_pcapng <file.pcapng>");
        std::process::exit(2);
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    let section = match netscope::pcapng::read(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    for (i, iface) in section.interfaces.iter().enumerate() {
        let lt = LinkType(i32::from(iface.link_type));
        println!(
            "interface {i}: {} link type {} ({}), snaplen {}, {} ts units/s",
            iface.name.as_deref().unwrap_or("-"),
            lt.name(),
            lt.description(),
            iface.snaplen,
            iface.ts_per_sec
        );
    }

    let store = Store::new(Limits::default());
    let mut state = State::new();
    let mut batch = Vec::with_capacity(1024);
    for (i, p) in section.packets.iter().enumerate() {
        let lt = section
            .interfaces
            .get(p.interface as usize)
            .map_or(LinkType::ETHERNET, |f| LinkType(i32::from(f.link_type)));
        batch.push(Arc::new(dissect(
            lt,
            i as u32 + 1,
            p.frame.clone(),
            &mut state,
        )));
    }
    store.append(batch);

    let snap = store.snapshot();
    let start = snap.start_ts();
    let mut by_proto: BTreeMap<&str, usize> = BTreeMap::new();
    let mut malformed = 0usize;
    for f in snap.iter() {
        let since = start.map_or(0.0, |s| {
            (f.ts.secs - s.secs) as f64 + (f64::from(f.ts.nanos) - f64::from(s.nanos)) * 1e-9
        });
        println!(
            "{:>5}  {:>9.6}  {:<22} -> {:<22} {:<7} {:>5}  {}",
            f.number,
            since,
            f.summary.source,
            f.summary.destination,
            f.summary.protocol_display(),
            f.orig_len,
            f.summary.info
        );
        *by_proto.entry(f.summary.protocol_display()).or_default() += 1;
        if f.tree.iter().any(|n| n.abbrev() == "_ws.malformed") {
            malformed += 1;
        }
    }
    let stats = store.stats();
    println!(
        "\n{} frames, {:.1} KB in the store, {by_proto:?}, {malformed} with a malformed node",
        stats.frames,
        stats.bytes as f64 / 1024.0
    );
}
