//! Capture live, then run a set of display filters and the default colour
//! rules over what arrived. Fixtures are built from the specification, so
//! this is the only check that the filter engine meets traffic it did not
//! have a hand in shaping.
//!
//!     cargo run --release --example live_filter -- "Wi-Fi" 20

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use netscope::app::colour_rules::{defaults, Rules};
use netscope::capture::{Capture, CaptureConfig};
use netscope::dissect::worker::Worker;
use netscope::filter::{compile, matches};
use netscope::store::{Limits, Store};

const FILTERS: &[&str] = &[
    "eth",
    "ip",
    "ipv6",
    "arp",
    "tcp",
    "udp",
    "icmp || icmpv6",
    "dns",
    "tls",
    "http",
    "ip.addr == 10.0.0.0/8 || ip.addr == 192.168.0.0/16",
    "tcp.flags.syn == true",
    "tcp.port in {80, 443, 8080}",
    "udp.length > 100",
    "eth.dst[0] == 01",
    "frame.protocols matches \"tls$\"",
    "dns.qry.name contains \".\"",
    "tcp contains \"HTTP\"",
    "_ws.malformed",
    // Checksum offload: the NIC fills these in after libpcap has seen the
    // packet, so locally originated frames look wrong. Split by direction to
    // show that is what is happening.
    "ip.checksum.status == \"Bad\" || tcp.checksum.status == \"Bad\" || udp.checksum.status == \"Bad\"",
    "ip.checksum.status == \"Bad\"",
    "tcp.checksum.status == \"Bad\"",
    "udp.checksum.status == \"Bad\"",
    "tcp.checksum == 0x0000",
];

fn main() {
    let mut args = std::env::args().skip(1);
    let device = args.next().unwrap_or_else(|| "Wi-Fi".to_string());
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);

    // The argument is matched against the friendly name as well as the
    // device name, so "Wi-Fi" works the way it does everywhere else.
    let Ok(devices) = netscope::capture::device::enumerate() else {
        eprintln!("cannot enumerate interfaces");
        return;
    };
    let Some(dev) = devices
        .iter()
        .find(|d| d.info.name == device || d.display_name().contains(&device))
    else {
        eprintln!("no interface matching {device:?}");
        return;
    };
    let device = dev.display_name();

    let store = Store::new(Limits::default());
    let cfg = CaptureConfig {
        device: dev.info.name.clone(),
        ..CaptureConfig::default()
    };
    let (cap, rx) = match Capture::start(cfg) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("could not capture on {device}: {e}");
            return;
        }
    };
    let mut worker = Worker::spawn(rx, std::sync::Arc::clone(&store), cap.link_type());
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut cap = cap;
    cap.stop();
    drop(cap);
    worker.join();

    let snapshot = store.snapshot();
    let total = snapshot.len();
    println!("{total} frames captured on {device}\n");
    if total == 0 {
        println!("no traffic; nothing to check");
        return;
    }

    println!("{:<52} {:>8}", "filter", "matched");
    for f in FILTERS {
        match compile(f) {
            Ok(test) => {
                let n = snapshot.iter().filter(|fr| matches(&test, fr)).count();
                println!("{f:<52} {n:>8}");
            }
            Err(e) => println!("{f:<52}  does not compile: {e}"),
        }
    }

    println!("\ncolour rules (first match wins):");
    let rules = Rules::new(defaults());
    let mut counts = vec![0usize; rules.rules().len()];
    let mut uncoloured = 0usize;
    for frame in snapshot.iter() {
        match rules.matching(frame) {
            Some(i) => counts[i] += 1,
            None => uncoloured += 1,
        }
    }
    for (rule, n) in rules.rules().iter().zip(&counts) {
        if *n > 0 {
            println!("  {:<16} {n:>8}", rule.name);
        }
    }
    println!("  {:<16} {uncoloured:>8}", "(no rule)");
}
