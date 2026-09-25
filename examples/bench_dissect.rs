//! Dissection-only throughput on the synthetic Ethernet/IPv4/TCP path.
//!
//!     cargo run --release --example bench_dissect -- [frames]

#![forbid(unsafe_code)]

use std::time::Instant;

use netscope::dissect::{dissect, State};
use netscope_ffi::LinkType;

fn main() {
    let total: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let raws: Vec<_> = (0..total).map(netscope::synthetic::raw_frame).collect();
    let bytes: usize = raws.iter().map(|r| r.bytes.len()).sum();
    let mut state = State::new();
    let t = Instant::now();
    let mut nodes = 0usize;
    let mut size = 0usize;
    for (i, raw) in raws.into_iter().enumerate() {
        let f = dissect(LinkType::ETHERNET, i as u32 + 1, raw, &mut state);
        nodes += f.tree.len();
        size += f.approx_size();
    }
    let dt = t.elapsed();
    println!(
        "dissect {total} frames ({:.1} MB) in {dt:.2?} = {:.0} frames/s, {:.2} us/frame, {:.1} nodes/frame, {:.0} B/frame accounted",
        bytes as f64 / 1e6,
        total as f64 / dt.as_secs_f64(),
        dt.as_secs_f64() * 1e6 / total as f64,
        nodes as f64 / total as f64,
        size as f64 / total as f64
    );
}
