//! Print which fixture frames a filter selects, for writing expectations.
//!     cargo run --release --example filter_probe -- ipv4 "icmp && !udp"
#![forbid(unsafe_code)]
use netscope::dissect::{dissect, State};
use netscope::filter::{compile, matches};
use netscope_ffi::LinkType;

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap_or_default();
    let fx = common::fixtures::all()
        .into_iter()
        .find(|f| f.name == name)
        .expect("fixture");
    let link = LinkType(i32::from(fx.link_type));
    let mut r = State::new();
    let frames: Vec<_> = fx
        .frames
        .iter()
        .enumerate()
        .map(|(i, b)| {
            dissect(
                link,
                i as u32 + 1,
                netscope::capture::RawFrame {
                    ts: netscope::capture::Timestamp::default(),
                    caplen: b.len() as u32,
                    orig_len: b.len() as u32,
                    bytes: std::sync::Arc::from(b.as_slice()),
                },
                &mut r,
            )
        })
        .collect();
    for filter in args {
        match compile(&filter) {
            Ok(t) => {
                let hits: Vec<u32> = frames
                    .iter()
                    .filter(|f| matches(&t, f))
                    .map(|f| f.number)
                    .collect();
                println!("{filter:<45} {hits:?}");
            }
            Err(e) => println!("{filter:<45} ERROR {e}"),
        }
    }
}
