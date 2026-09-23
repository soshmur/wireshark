//! Completion suggestions for the filter bar, drawn from the field registry
//! so the same source of truth drives the tree, the language and the hints.

use crate::dissect::registry::{self, FieldDef};

/// Where the word being typed starts, and what it is so far.
pub fn word_at(text: &str, caret: usize) -> (usize, &str) {
    let caret = caret.min(text.len());
    let head = &text[..caret];
    let start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .map_or(0, |i| i + 1);
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
