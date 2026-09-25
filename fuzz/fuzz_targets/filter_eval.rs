#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope::capture::{RawFrame, Timestamp};
use netscope::dissect::{dissect, State};
use std::sync::Arc;

// Evaluating a compiled filter against an arbitrary (often malformed) frame.
// Slices, byte comparisons and `contains` all index into packet bytes, so
// this is the path where an out-of-range range would show up.
fuzz_target!(|data: &[u8]| {
    // First line is the filter, the rest is the frame.
    let split = data.iter().position(|b| *b == b'\n').unwrap_or(data.len());
    let (head, tail) = data.split_at(split);
    let Ok(text) = std::str::from_utf8(head) else {
        return;
    };
    let Ok(test) = netscope::filter::compile(text) else {
        return;
    };
    let bytes = tail.strip_prefix(b"\n").unwrap_or(tail);
    let mut state = State::new();
    let raw = RawFrame {
        ts: Timestamp::default(),
        caplen: bytes.len() as u32,
        orig_len: bytes.len() as u32,
        bytes: Arc::from(bytes),
    };
    let frame = dissect(netscope_ffi::LinkType::ETHERNET, 1, raw, &mut state);
    let _ = netscope::filter::matches(&test, &frame);
});
