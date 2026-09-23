#![no_main]
use libfuzzer_sys::fuzz_target;

// The display filter compiler: lexer, parser, type checker. Arbitrary text
// must produce either a Test or a FilterError with an in-range column, never
// a panic and never an index outside the input.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match netscope::filter::compile(text) {
        Ok(_) => {}
        Err(e) => {
            // The column must point inside the text (or one past its end,
            // for "unexpected end of input"), or the caret the UI draws
            // would be nonsense.
            assert!(
                e.column <= text.len(),
                "column {} past end of {:?}",
                e.column,
                text
            );
            assert!(
                e.column + e.len <= text.len() + 1,
                "span {}..{} past end of {:?}",
                e.column,
                e.column + e.len,
                text
            );
            assert!(!e.message.is_empty(), "empty message for {text:?}");
        }
    }
    // Completion runs over the same text at every caret position the UI can
    // put the caret in.
    for caret in text.char_indices().map(|(i, _)| i).chain([text.len()]) {
        let (start, end, _) = netscope::filter::complete::suggest_at(text, caret, 8);
        assert!(start <= end && end <= text.len(), "bad span for {text:?}");
    }
});
