//! Write a capture to a file and read it back, reporting what survived.
//!
//!     cargo run --release --example file_roundtrip -- [frames] [out.pcapng]
//!
//! The same code paths File > Save As and File > Open use, exercised without
//! the UI so a round trip can be checked from a terminal.

#![forbid(unsafe_code)]

use std::sync::Arc;

use netscope::capture::file::{self, SaveFormat};
use netscope::dissect::{dissect, Frame, Options, State};
use netscope_ffi::LinkType;

fn main() {
    let mut args = std::env::args().skip(1);
    let count: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5000);
    let path = args
        .next()
        .unwrap_or_else(|| "roundtrip.pcapng".to_string());

    let mut state = State::new();
    let original: Vec<Arc<Frame>> = (0..count)
        .map(|i| {
            Arc::new(dissect(
                LinkType::ETHERNET,
                i as u32 + 1,
                netscope::synthetic::raw_frame(i),
                &mut state,
            ))
        })
        .collect();

    for format in [SaveFormat::Pcapng, SaveFormat::Pcap] {
        let out = std::path::Path::new(&path).with_extension(format.extension());
        let saved = match file::save_path(&out, &original, format) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: {e}", out.display());
                continue;
            }
        };
        println!(
            "\n{} -> {} packets, {} bytes{}",
            out.display(),
            saved.frames,
            saved.bytes,
            saved
                .precision
                .map(|p| format!(", {} timestamps", p.name()))
                .unwrap_or_default()
        );
        for n in &saved.notes {
            println!("  note: {n}");
        }

        let loaded = match file::load_path(&out) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("  reread failed: {e}");
                continue;
            }
        };
        for w in &loaded.warnings {
            println!("  warning: {w}");
        }
        let again = loaded.dissect_all(Options::default());
        let bytes_match = original
            .iter()
            .zip(&again)
            .filter(|(a, b)| a.bytes == b.bytes)
            .count();
        let times_match = original
            .iter()
            .zip(&again)
            .filter(|(a, b)| a.ts == b.ts)
            .count();
        let trees_match = original
            .iter()
            .zip(&again)
            .filter(|(a, b)| a.tree.len() == b.tree.len() && a.summary.info == b.summary.info)
            .count();
        println!(
            "  reread {} packets: {bytes_match} byte-identical, {times_match} same timestamp, \
             {trees_match} dissect the same",
            again.len()
        );
    }
}
