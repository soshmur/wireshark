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
    // Go through the fixture writer and reader so the frames carry the
    // fixture's real timestamps. Dissecting the raw bytes with a default
    // timestamp makes every frame simultaneous, which silently changes what
    // the TCP analyser concludes: a retransmission reads as out-of-order.
    let bytes = common::pcapng_fixture(&fx);
    let section = netscope::pcapng::read(&bytes).expect("read fixture");
    let frames: Vec<_> = section
        .packets
        .into_iter()
        .enumerate()
        .map(|(i, p)| dissect(link, i as u32 + 1, p.frame, &mut r))
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
