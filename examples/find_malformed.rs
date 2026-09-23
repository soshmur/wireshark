//! Capture live and print the full tree of any frame with a malformed node,
//! plus its hex, so real-world dissector gaps can be triaged.
//!
//!     cargo run --release --example find_malformed -- "Wi-Fi" 20

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use netscope::capture::{Capture, CaptureConfig};
use netscope::dissect::{registry, worker::Worker};
use netscope::store::{Limits, Store};

fn main() {
    let mut args = std::env::args().skip(1);
    let wanted = args.next();
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(15);
    let Ok(devices) = netscope::capture::device::enumerate() else {
        eprintln!("cannot enumerate");
        std::process::exit(2);
    };
    let Some(dev) = devices.iter().find(|d| {
        wanted
            .as_deref()
            .is_none_or(|w| d.info.name == w || d.display_name().contains(w))
    }) else {
        eprintln!("no matching device");
        std::process::exit(2);
    };
    let cfg = CaptureConfig {
        device: dev.info.name.clone(),
        ..CaptureConfig::default()
    };
    let Ok((mut cap, rx)) = Capture::start(cfg) else {
        eprintln!("cannot start capture");
        std::process::exit(1);
    };
    let store = Store::new(Limits::default());
    let mut worker = Worker::spawn(rx, std::sync::Arc::clone(&store), cap.link_type());
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    cap.stop();
    worker.join();

    let snap = store.snapshot();
    let mut found = 0;
    for f in snap.iter() {
        if !f.tree.iter().any(|n| n.abbrev() == "_ws.malformed") {
            continue;
        }
        found += 1;
        println!(
            "\n=== frame #{} {} -> {} {} | {}",
            f.number,
            f.summary.source,
            f.summary.destination,
            f.summary.protocol_display(),
            f.summary.info
        );
        for n in f.tree.iter() {
            let data = f.source(n.source()).unwrap_or(&[]);
            let r = n.range();
            println!(
                "{}{}  [{} {}:{}-{}]",
                "  ".repeat(usize::from(n.depth()) + 1),
                registry::label(&n, data),
                n.abbrev(),
                n.source(),
                r.start,
                r.end
            );
        }
        let hex: String = f.bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!("  bytes: {hex}");
        if found >= 3 {
            break;
        }
    }
    println!(
        "\n{} frames captured, {found} with a malformed node",
        snap.len()
    );
}
