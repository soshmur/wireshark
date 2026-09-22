//! Throughput of the dissect + store path on a synthetic 1e6-frame feed, plus
//! the cost of taking a snapshot at full occupancy (what the UI pays per
//! repaint while capturing).
//!
//!     cargo run --release --example bench_store -- [frames]

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Instant;

use netscope::capture::RawFrame;
use netscope::dissect::{dissect, Reassembly};
use netscope::store::{Limits, Store, CHUNK};
use netscope_ffi::LinkType;

fn main() {
    let total: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let store = Store::new(Limits {
        max_frames: total + CHUNK as u64,
        max_bytes: u64::MAX,
    });

    // Pre-generate raw frames so capture-side allocation is not measured.
    let t0 = Instant::now();
    let raws: Vec<RawFrame> = (0..total).map(netscope::synthetic::raw_frame).collect();
    println!("generated {total} raw frames in {:.2?}", t0.elapsed());

    let t1 = Instant::now();
    let mut batch = Vec::with_capacity(1024);
    let mut number = 1u32;
    let mut reassembly = Reassembly::new();
    for raw in raws {
        batch.push(Arc::new(dissect(
            LinkType::ETHERNET,
            number,
            raw,
            &mut reassembly,
        )));
        number = number.wrapping_add(1);
        if batch.len() == 1024 {
            store.append(std::mem::replace(&mut batch, Vec::with_capacity(1024)));
        }
    }
    store.append(batch);
    let dt = t1.elapsed();
    println!(
        "dissect+append {total} frames in {dt:.2?} = {:.0} frames/s (one thread)",
        total as f64 / dt.as_secs_f64()
    );

    let st = store.stats();
    println!(
        "store: {} frames, {:.1} MB accounted",
        st.frames,
        st.bytes as f64 / (1024.0 * 1024.0)
    );

    let t2 = Instant::now();
    let iters = 1000;
    let mut len = 0;
    for _ in 0..iters {
        let s = store.snapshot();
        len = s.len();
    }
    let per = t2.elapsed() / iters;
    println!("snapshot() of {len} frames: {per:.2?} each");

    let t3 = Instant::now();
    let s = store.snapshot();
    let mut sum = 0u64;
    for row in (0..s.len()).step_by(997) {
        if let Some(f) = s.get(row) {
            sum += u64::from(f.number);
        }
    }
    println!(
        "random-ish row access: {:.2?} for {} lookups (checksum {sum})",
        t3.elapsed(),
        s.len() / 997 + 1
    );
}
