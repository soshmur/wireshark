//! Headless check of the capture pipeline: open the best interface (or the one
//! named on the command line), capture for a few seconds, print the counters.
//!
//!     cargo run --release --example capture_smoke -- [device-name] [seconds]

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use netscope::capture::{self, Capture, CaptureConfig, Preflight};
use netscope::dissect::worker::Worker;
use netscope::store::{Limits, Store};

fn main() {
    let mut args = std::env::args().skip(1);
    let wanted = args.next();
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);

    let preflight = capture::preflight::run();
    println!("preflight: {preflight}");
    if matches!(preflight, Preflight::Fail { .. }) {
        std::process::exit(2);
    }

    let devices = match capture::device::enumerate() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("enumerate: {e}");
            std::process::exit(2);
        }
    };
    for d in &devices {
        println!(
            "  {:<45} {:<40} {}",
            d.display_name(),
            d.info.addresses.join(","),
            d.state_tags()
        );
    }
    let Some(dev) = devices.iter().find(|d| {
        wanted
            .as_deref()
            .is_none_or(|w| d.info.name == w || d.display_name().contains(w))
    }) else {
        eprintln!("no matching device");
        std::process::exit(2);
    };
    println!("opening {} ({})", dev.display_name(), dev.info.name);

    let cfg = CaptureConfig {
        device: dev.info.name.clone(),
        ..CaptureConfig::default()
    };
    let (mut cap, rx) = match Capture::start(cfg) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("start: {e}");
            std::process::exit(1);
        }
    };
    let lt = cap.link_type();
    println!(
        "link type: {} ({}, DLT {})",
        lt.name(),
        lt.description(),
        lt.0
    );

    // The real pipeline: worker dissects into the store; we poll like the UI.
    let store = Store::new(Limits::default());
    let mut worker = Worker::spawn(rx, std::sync::Arc::clone(&store), lt);
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    cap.stop();
    worker.join();
    let snap = store.snapshot();
    for f in snap.iter().take(40) {
        println!(
            "  #{:<4} {:<6} {:>5} {:<22} -> {:<22} {}",
            f.number,
            f.summary.protocol_display(),
            f.orig_len,
            f.summary.source,
            f.summary.destination,
            f.summary.info
        );
    }
    let mut by_proto: std::collections::BTreeMap<&str, usize> = Default::default();
    let mut malformed = 0;
    for f in snap.iter() {
        *by_proto.entry(f.summary.protocol_display()).or_default() += 1;
        if f.tree.iter().any(|n| n.abbrev() == "_ws.malformed") {
            malformed += 1;
        }
    }
    println!("by protocol: {by_proto:?}; frames with a malformed node: {malformed}");
    let consumed = snap.len();
    let s = cap.stats();
    println!(
        "captured {} frames / {} bytes in {secs}s; consumed {consumed}; dropped: channel {} driver {} interface {}",
        s.received, s.bytes, s.dropped_channel, s.kernel_dropped, s.kernel_if_dropped
    );
    if let Some(e) = cap.error() {
        println!("capture error: {e}");
    }
}
