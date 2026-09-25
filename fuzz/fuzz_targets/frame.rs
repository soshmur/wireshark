#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope::capture::{RawFrame, Timestamp};
use netscope::dissect::{dissect, State};
use std::sync::Arc;

// Whole-frame path: link dissector chain, malformed handling, state.
fuzz_target!(|data: &[u8]| {
    let mut state = State::new();
    let link = match data.first() {
        Some(b) if b % 3 == 1 => netscope_ffi::LinkType::NULL,
        Some(b) if b % 3 == 2 => netscope_ffi::LinkType::RAW,
        _ => netscope_ffi::LinkType::ETHERNET,
    };
    let raw = RawFrame {
        ts: Timestamp::default(),
        caplen: data.len() as u32,
        orig_len: data.len() as u32,
        bytes: Arc::from(data),
    };
    let frame = dissect(link, 1, raw, &mut state);
    for n in frame.tree.iter() {
        let src = frame.source(n.source()).unwrap_or(&[]);
        let _ = netscope::dissect::registry::label(&n, src);
    }
});
