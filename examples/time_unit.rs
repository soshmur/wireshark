//! Time a single dissector call on a file of raw bytes (fuzz artifact triage).
//!     cargo run --release --example time_unit -- ipv4 path/to/unit
#![forbid(unsafe_code)]
use netscope::capture::Timestamp;
use netscope::dissect::{ctx::Ctx, proto, Reassembly};
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next().unwrap_or_default();
    let path = args.next().unwrap_or_default();
    let data = std::fs::read(&path).expect("read unit");
    let mut reassembly = Reassembly::new();
    // Warm the registry's lazy index so it is not attributed to the dissector.
    let _ = netscope::dissect::registry::lookup("ip.src");
    let iters = 200;
    let t = Instant::now();
    for _ in 0..iters {
        let mut ctx = Ctx::new(
            netscope_ffi::LinkType::ETHERNET,
            1,
            Timestamp::default(),
            &mut reassembly,
        );
        let r = match which.as_str() {
            "ipv4" => proto::ipv4::dissect(&data, &mut ctx),
            "ipv6" => proto::ipv6::dissect(&data, &mut ctx),
            "dns" => proto::dns::dissect(&data, &mut ctx),
            "tcp" => proto::tcp::dissect(&data, &mut ctx),
            other => panic!("unknown dissector {other}"),
        };
        std::hint::black_box(&r);
    }
    let per = t.elapsed() / iters;
    println!("{which} on {} bytes: {per:?} per call", data.len());
}
