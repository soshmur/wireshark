//! Display-filter throughput over stored frames.
//!
//!     cargo run --release --example bench_filter -- [frames]
//!
//! Frames are dissected once up front, exactly as a capture would, and the
//! filters then run over the stored trees. That is the whole point of the
//! design: the number below is the cost of *filtering*, with no re-parsing
//! anywhere in it.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Instant;

use netscope::dissect::{dissect, Frame, State};
use netscope::filter::compile;
use netscope::store::{Limits, Store, View};
use netscope_ffi::LinkType;

/// Chosen so that most of them *match*, because a filter that fails early
/// short-circuits and would flatter the numbers. The synthetic frames are
/// Ethernet `00:1c:42:..` -> IPv4 `10.0.x.y` -> TCP `4xxxx` -> `5001`.
const FILTERS: &[&str] = &[
    "tcp",
    "tcp.dstport == 5001",
    "tcp.srcport == 40000",
    "ip.addr == 10.0.0.0/8",
    "tcp.flags.push == true && tcp.flags.ack == true",
    "eth.src[0:3] == 00:1c:42",
    "ip.proto in {1, 6, 17}",
    "frame.protocols matches \"^eth:ip:tcp\"",
    "tcp || udp || icmp || arp || dns || dhcp || http || tls",
    // Worst case: a byte scan of every payload, matching nothing, so every
    // frame is searched to the end.
    "tcp contains \"netscope\"",
];

fn main() {
    let total: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);

    let store = Store::new(Limits {
        max_frames: u64::MAX,
        max_bytes: u64::MAX,
    });
    let mut state = State::new();
    let mut batch: Vec<Arc<Frame>> = Vec::with_capacity(4096);
    let t = Instant::now();
    for i in 0..total {
        batch.push(Arc::new(dissect(
            LinkType::ETHERNET,
            i as u32 + 1,
            netscope::synthetic::raw_frame(i),
            &mut state,
        )));
        if batch.len() == 4096 {
            store.append(std::mem::replace(&mut batch, Vec::with_capacity(4096)));
        }
    }
    store.append(batch);
    let load = t.elapsed();
    println!(
        "dissected {total} frames in {:.2} s ({:.0} frames/s)\n",
        load.as_secs_f64(),
        total as f64 / load.as_secs_f64()
    );

    let snapshot = store.snapshot();
    println!(
        "{:<52} {:>9} {:>12} {:>10}",
        "filter", "matched", "frames/s", "ns/frame"
    );
    for f in FILTERS {
        let test = match compile(f) {
            Ok(t) => t,
            Err(e) => {
                println!("{f:<52} does not compile: {e}");
                continue;
            }
        };
        let t = Instant::now();
        let view = View::filtered(snapshot.clone(), &test);
        let dt = t.elapsed().as_secs_f64();
        println!(
            "{:<52} {:>9} {:>12.0} {:>10.1}",
            f,
            view.len(),
            total as f64 / dt,
            dt * 1e9 / total as f64
        );
    }
}
