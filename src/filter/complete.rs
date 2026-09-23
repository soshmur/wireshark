//! Completion suggestions for the filter bar, drawn from the field registry
//! so the same source of truth drives the tree, the language and the hints.

use crate::dissect::registry::{self, FieldDef};

/// Where the word being typed starts, and what it is so far.
///
/// Both ends are kept on character boundaries. The caret arrives from the
/// text widget and is clamped down to one; the word start steps back over a
/// separator by that character's own width, because adding one to the byte
/// index of a multi-byte separator such as `\u{e9}` lands inside it and slicing
/// there panics.
pub fn word_at(text: &str, caret: usize) -> (usize, &str) {
    let mut caret = caret.min(text.len());
    while caret > 0 && !text.is_char_boundary(caret) {
        caret -= 1;
    }
    let start = text[..caret]
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '.'))
        .map_or(0, |(i, c)| i + c.len_utf8());
    (start, &text[start..caret])
}

/// Field names that continue `prefix`, best first: exact prefix matches in
/// registry order, then names containing it.
pub fn suggest(prefix: &str, limit: usize) -> Vec<&'static FieldDef> {
    if prefix.is_empty() {
        return Vec::new();
    }
    let lower = prefix.to_ascii_lowercase();
    let mut starts = Vec::new();
    let mut contains = Vec::new();
    for def in registry::all() {
        if def.abbrev.starts_with(&lower) {
            starts.push(def);
        } else if def.abbrev.contains(&lower) {
            contains.push(def);
        }
        if starts.len() >= limit {
            break;
        }
    }
    starts.extend(contains);
    starts.truncate(limit);
    starts
}

/// Suggestions for the word the caret is in, with the span they replace.
pub fn suggest_at(
    text: &str,
    caret: usize,
    limit: usize,
) -> (usize, usize, Vec<&'static FieldDef>) {
    let (start, word) = word_at(text, caret);
    let end = start + word.len();
    // A word that is already exactly a field name needs no suggestions.
    if registry::lookup(word).is_some() {
        return (start, end, Vec::new());
    }
    (start, end, suggest(word, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_word_under_the_caret() {
        assert_eq!(word_at("tcp.po", 6), (0, "tcp.po"));
        assert_eq!(word_at("ip && tcp.po", 12), (6, "tcp.po"));
        assert_eq!(word_at("ip && tcp.po", 2), (0, "ip"));
        assert_eq!(word_at("tcp.port == 443", 15), (12, "443"));
        assert_eq!(word_at("", 0), (0, ""));
        assert_eq!(word_at("(tcp", 4), (1, "tcp"));
    }

    #[test]
    fn non_ascii_text_does_not_panic() {
        // Fuzzing found this: the byte after a multi-byte separator is not a
        // character boundary, and slicing there panicked the whole UI as
        // soon as anyone typed an accented character into the filter bar.
        assert_eq!(word_at("\u{e9}tcp", "\u{e9}tcp".len()), (2, "tcp"));
        assert_eq!(word_at("ip\u{e9}tcp", "ip\u{e9}tcp".len()), (4, "tcp"));
        // An emoji is four bytes; the word starts after all of them.
        let text = "\u{1f600}tcp";
        assert_eq!(word_at(text, text.len()), (4, "tcp"));
        // A caret landing inside a character is clamped back, not panicked.
        assert_eq!(word_at("tcp\u{e9}", 4), (0, "tcp"));
        // Every caret position in a non-ASCII string is safe.
        for text in ["\u{e9}", "a\u{e9}b", "\u{1f600}\u{1f600}", "ip.\u{e9}.addr"] {
            for caret in 0..=text.len() {
                let (start, word) = word_at(text, caret);
                assert!(start <= text.len());
                assert!(text.is_char_boundary(start), "{text:?} at {caret}");
                assert!(text[start..].starts_with(word));
            }
        }
    }

    #[test]
    fn suggests_fields_by_prefix() {
        let s = suggest("tcp.opt", 10);
        assert!(!s.is_empty());
        assert!(
            s.iter().all(|d| d.abbrev.contains("tcp.opt")),
            "{:?}",
            s.iter().map(|d| d.abbrev).collect::<Vec<_>>()
        );
        assert!(suggest("", 10).is_empty());
        assert!(suggest("zzzz", 10).is_empty());
    }

    #[test]
    fn an_exact_field_name_needs_no_suggestions() {
        let (start, end, s) = suggest_at("tcp.srcport", 11, 10);
        assert_eq!((start, end), (0, 11));
        assert!(s.is_empty());
        let (start, end, s) = suggest_at("ip && tcp.srcpo", 15, 10);
        assert_eq!((start, end), (6, 15));
        assert!(s.iter().any(|d| d.abbrev == "tcp.srcport"));
    }
}
