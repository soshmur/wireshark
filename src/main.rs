#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    // Developer flag: `netscope --synthetic N` preloads N generated frames so the
    // list can be exercised at scale without a network.
    let mut args = std::env::args().skip(1);
    let mut synthetic = 0u64;
    while let Some(a) = args.next() {
        if a == "--synthetic" {
            synthetic = args
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(1_000_000);
        }
    }
    netscope::app::run(netscope::app::Options { synthetic })
}
