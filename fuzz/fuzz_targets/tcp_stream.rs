#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope::capture::{RawFrame, Timestamp};
use netscope::dissect::{dissect, State};
use std::sync::Arc;

// A sequence of frames through one State, so conversation tracking, sequence
// analysis and desegmentation all carry state from one frame to the next.
// The single-frame targets cannot reach any of that: every bug in this file's
// surface needs at least two related frames.
fuzz_target!(|data: &[u8]| {
    // The input is a run of length-prefixed frames sharing one worker state.
    let mut state = State::new();
    let mut at = 0usize;
    let mut number = 1u32;
    while at + 2 <= data.len() && number <= 64 {
        let len = usize::from(u16::from_be_bytes([data[at], data[at + 1]]));
        at += 2;
        let end = (at + len).min(data.len());
        let bytes = &data[at..end];
        at = end;
        // Timestamps advance so the analyser's reordering and fast-retransmit
        // windows are actually exercised rather than always collapsing.
        let ts = Timestamp {
            secs: 1_700_000_000 + i64::from(number / 8),
            nanos: (number % 8) * 1_000_000,
        };
        let raw = RawFrame {
            ts,
            caplen: bytes.len() as u32,
            orig_len: bytes.len() as u32,
            bytes: Arc::from(bytes),
        };
        let frame = dissect(netscope_ffi::LinkType::ETHERNET, number, raw, &mut state);
        // Every node must point inside a data source it names - the
        // desegmented buffers are new sources, and a range into the wrong one
        // would be read as the wrong bytes.
        for n in frame.tree.iter() {
            let src = frame.source(n.source()).unwrap_or(&[]);
            assert!(
                n.range().end <= src.len(),
                "frame {number}: {} range {:?} past source {} of {} bytes",
                n.abbrev(),
                n.range(),
                n.source(),
                src.len()
            );
            let _ = netscope::dissect::registry::label(&n, src);
        }
        number += 1;
    }
});
