//! Headless check of the capture pipeline: open the best interface (or the one
//! named on the command line), capture for a few seconds, print the counters.
//!
//!     cargo run --release --example capture_smoke -- [device-name] [seconds]

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use netscope::capture::{self, Capture, CaptureConfig, Preflight};

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

    // Consume like the UI never would: on this thread, printing the first few.
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut shown = 0;
    let mut consumed = 0u64;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(f) => {
                consumed += 1;
                if shown < 5 {
                    shown += 1;
                    let head: Vec<String> = f
                        .bytes
                        .iter()
                        .take(16)
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    println!(
                        "  frame ts={}.{:09} caplen={} orig_len={} {}",
                        f.ts.secs,
                        f.ts.nanos,
                        f.caplen,
                        f.orig_len,
                        head.join(" ")
                    );
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    cap.stop();
    let s = cap.stats();
    println!(
        "captured {} frames / {} bytes in {secs}s; consumed {consumed}; dropped: channel {} driver {} interface {}",
        s.received, s.bytes, s.dropped_channel, s.kernel_dropped, s.kernel_if_dropped
    );
    if let Some(e) = cap.error() {
        println!("capture error: {e}");
    }
}
