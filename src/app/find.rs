//! Find (Ctrl+F): search the displayed rows for a display filter, a string
//! or a byte sequence, forwards or backwards from the selection.
//!
//! Searching is separate from filtering. A filter changes what the list
//! shows; find moves the selection within what it already shows, so a find
//! that hits a frame the current filter hides simply does not hit.

use crate::dissect::{registry, Frame};
use crate::filter::{self, Test};
use crate::store::View;

/// What the search text means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    /// A display filter, evaluated per frame.
    DisplayFilter,
    /// A literal string.
    #[default]
    String,
    /// A byte sequence, written as hex with optional `:`, `-` or space
    /// separators.
    Hex,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::DisplayFilter => "Display filter",
            Kind::String => "String",
            Kind::Hex => "Hex value",
        }
    }
}

/// Where a string or byte search looks. A display filter ignores this: it
/// names its own fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// The packet-list columns: addresses, protocol and info.
    #[default]
    List,
    /// Every label in the detail tree.
    Details,
    /// The raw bytes of every data source.
    Bytes,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::List => "Packet list",
            Scope::Details => "Packet details",
            Scope::Bytes => "Packet bytes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

/// A search query, compiled once and reused for every step.
#[derive(Debug)]
pub enum Query {
    Filter(Box<Test>),
    /// `needle` is already lower-cased when the search is case-insensitive.
    Text {
        needle: String,
        case_sensitive: bool,
        scope: Scope,
    },
    Bytes {
        needle: Vec<u8>,
        scope: Scope,
    },
}

/// Parse hex digits with optional `:`, `-` or space separators. Digits are
/// taken in pairs across separators, so `aabb`, `aa:bb` and `aa bb` are the
/// same two bytes.
fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let mut nibbles = Vec::new();
    for c in text.chars() {
        match c {
            ':' | '-' | ' ' | '\t' => continue,
            _ => match c.to_digit(16) {
                Some(d) => nibbles.push(d as u8),
                None => return Err(format!("`{c}` is not a hex digit")),
            },
        }
    }
    if nibbles.is_empty() {
        return Err("no hex digits".into());
    }
    if nibbles.len() % 2 != 0 {
        return Err("an odd number of hex digits".into());
    }
    Ok(nibbles.chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
}

/// Compile the search text, or say why it cannot be.
pub fn compile(
    kind: Kind,
    text: &str,
    case_sensitive: bool,
    scope: Scope,
) -> Result<Query, String> {
    if text.trim().is_empty() {
        return Err("nothing to find".into());
    }
    match kind {
        Kind::DisplayFilter => filter::compile(text)
            .map(|t| Query::Filter(Box::new(t)))
            .map_err(|e| format!("column {}: {}", e.column + 1, e.message)),
        Kind::String => Ok(Query::Text {
            needle: if case_sensitive {
                text.to_string()
            } else {
                text.to_lowercase()
            },
            case_sensitive,
            scope,
        }),
        Kind::Hex => parse_hex(text).map(|needle| Query::Bytes { needle, scope }),
    }
}

fn contains(haystack: &str, needle: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        haystack.contains(needle)
    } else {
        haystack.to_lowercase().contains(needle)
    }
}

/// Every label the detail tree would render for this frame.
fn detail_hit(frame: &Frame, f: impl Fn(&str) -> bool) -> bool {
    frame.tree.iter().any(|node| {
        let data = frame.source(node.source()).unwrap_or(&[]);
        f(&registry::label(&node, data))
    })
}

fn sources(frame: &Frame) -> impl Iterator<Item = &[u8]> {
    std::iter::once(&*frame.bytes).chain(frame.extra_sources.iter().map(|s| &**s))
}

fn window_search(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Does `frame` satisfy the query?
pub fn hits(query: &Query, frame: &Frame) -> bool {
    match query {
        Query::Filter(test) => filter::matches(test, frame),
        Query::Text {
            needle,
            case_sensitive,
            scope,
        } => match scope {
            Scope::List => {
                let s = &frame.summary;
                contains(&s.source.to_string(), needle, *case_sensitive)
                    || contains(&s.destination.to_string(), needle, *case_sensitive)
                    || contains(s.protocol_display(), needle, *case_sensitive)
                    || contains(&s.info, needle, *case_sensitive)
            }
            Scope::Details => detail_hit(frame, |label| contains(label, needle, *case_sensitive)),
            // A string searched in raw bytes is matched as its own bytes;
            // packet payloads are not text and must not be transcoded.
            Scope::Bytes => sources(frame).any(|s| window_search(s, needle.as_bytes())),
        },
        Query::Bytes { needle, scope } => match scope {
            Scope::List => window_search(frame.summary.info.as_bytes(), needle),
            Scope::Details => detail_hit(frame, |label| window_search(label.as_bytes(), needle)),
            Scope::Bytes => sources(frame).any(|s| window_search(s, needle)),
        },
    }
}

/// The next displayed row satisfying `query`, starting after (or before)
/// `from`. The search wraps around the end of the list, so it always finds a
/// hit if one exists anywhere.
pub fn search(
    view: &View,
    from: Option<usize>,
    direction: Direction,
    query: &Query,
) -> Option<usize> {
    let n = view.len();
    if n == 0 {
        return None;
    }
    // Start one step past the current row, so repeating a find advances.
    // The backward start is biased by `n` so that stepping down towards zero
    // never underflows: `step` is at most `n - 1` and `start` at least that.
    let start = match (from, direction) {
        (Some(r), Direction::Forward) => r + 1,
        (Some(r), Direction::Backward) => r + n - 1,
        (None, Direction::Forward) => 0,
        (None, Direction::Backward) => n - 1,
    };
    for step in 0..n {
        let row = match direction {
            Direction::Forward => (start + step) % n,
            Direction::Backward => (start - step) % n,
        };
        if let Some(frame) = view.get(row) {
            if hits(query, frame) {
                return Some(row);
            }
        }
    }
    None
}

/// The find bar's own state. It is only drawn while `open`.
#[derive(Debug, Default)]
pub struct FindBar {
    pub open: bool,
    pub text: String,
    pub kind: Kind,
    pub scope: Scope,
    pub case_sensitive: bool,
    /// The last compile failure, or the outcome of the last search.
    status: Option<(bool, String)>,
    focus_requested: bool,
}

/// What the bar asks the application to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Find(Direction),
    Close,
}

impl FindBar {
    /// Ctrl+F: open it and take the keyboard.
    pub fn open(&mut self) {
        self.open = true;
        self.focus_requested = true;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.status = None;
    }

    /// Report the outcome of a search the caller ran.
    pub fn report(&mut self, found: bool) {
        self.status = Some(if found {
            (true, String::new())
        } else {
            (false, "no match".to_string())
        });
    }

    pub fn compiled(&self) -> Result<Query, String> {
        compile(self.kind, &self.text, self.case_sensitive, self.scope)
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Action {
        let mut action = Action::None;
        ui.horizontal(|ui| {
            ui.label("Find:");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.text)
                    .hint_text("text, hex bytes, or a display filter")
                    .desired_width(240.0)
                    .id_salt("find-text"),
            );
            if self.focus_requested {
                self.focus_requested = false;
                resp.request_focus();
            }
            if resp.changed() {
                self.status = None;
            }
            if resp.has_focus() {
                let (enter, esc, shift) = ui.input(|i| {
                    (
                        i.key_pressed(egui::Key::Enter),
                        i.key_pressed(egui::Key::Escape),
                        i.modifiers.shift,
                    )
                });
                if enter {
                    action = Action::Find(if shift {
                        Direction::Backward
                    } else {
                        Direction::Forward
                    });
                }
                if esc {
                    action = Action::Close;
                }
            }
            egui::ComboBox::from_id_salt("find-kind")
                .selected_text(self.kind.label())
                .width(110.0)
                .show_ui(ui, |ui| {
                    for k in [Kind::String, Kind::Hex, Kind::DisplayFilter] {
                        ui.selectable_value(&mut self.kind, k, k.label());
                    }
                });
            // A display filter names its own fields, so a scope would be
            // meaningless for it.
            ui.add_enabled_ui(self.kind != Kind::DisplayFilter, |ui| {
                egui::ComboBox::from_id_salt("find-scope")
                    .selected_text(self.scope.label())
                    .width(110.0)
                    .show_ui(ui, |ui| {
                        for s in [Scope::List, Scope::Details, Scope::Bytes] {
                            ui.selectable_value(&mut self.scope, s, s.label());
                        }
                    });
                ui.checkbox(&mut self.case_sensitive, "Case")
                    .on_hover_text("Case-sensitive (string search only)");
            });
            if ui.button("◀ Prev").clicked() {
                action = Action::Find(Direction::Backward);
            }
            if ui.button("Next ▶").clicked() {
                action = Action::Find(Direction::Forward);
            }
            if ui.button("✖").clicked() {
                action = Action::Close;
            }
            // A compile error is shown as soon as it exists, without waiting
            // for the user to press Find.
            if let Err(e) = self.compiled() {
                if !self.text.trim().is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(230, 120, 120), e);
                }
            } else if let Some((ok, text)) = &self.status {
                if !text.is_empty() {
                    let colour = if *ok {
                        egui::Color32::from_rgb(140, 200, 150)
                    } else {
                        egui::Color32::from_rgb(230, 180, 110)
                    };
                    ui.colored_label(colour, text);
                }
            }
        });
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, Reassembly};
    use crate::store::{Limits, Store};
    use netscope_ffi::LinkType;
    use std::sync::Arc;

    fn view(count: u64) -> View {
        let store = Store::new(Limits::default());
        let mut r = Reassembly::new();
        let batch: Vec<Arc<Frame>> = (0..count)
            .map(|i| {
                Arc::new(dissect(
                    LinkType::ETHERNET,
                    i as u32 + 1,
                    crate::synthetic::raw_frame(i),
                    &mut r,
                ))
            })
            .collect();
        store.append(batch);
        View::all(store.snapshot())
    }

    #[test]
    fn hex_accepts_the_usual_separators() {
        assert_eq!(parse_hex("aabbcc"), Ok(vec![0xaa, 0xbb, 0xcc]));
        assert_eq!(parse_hex("aa:bb:cc"), Ok(vec![0xaa, 0xbb, 0xcc]));
        assert_eq!(parse_hex("AA-BB CC"), Ok(vec![0xaa, 0xbb, 0xcc]));
        assert!(parse_hex("aab").is_err(), "odd digit count");
        assert!(parse_hex("zz").is_err(), "not hex");
        assert!(parse_hex("::").is_err(), "no digits");
    }

    #[test]
    fn a_bad_display_filter_reports_its_column() {
        let e = compile(Kind::DisplayFilter, "tcp.port ==", false, Scope::List)
            .expect_err("should not compile");
        assert!(e.starts_with("column "), "{e}");
    }

    #[test]
    fn finds_forwards_backwards_and_wraps() {
        let v = view(10);
        // The source MAC's last byte is the frame index, so this is frame 4.
        let q = compile(Kind::DisplayFilter, "eth.src[5] == 3", false, Scope::List)
            .expect("compile");
        assert_eq!(search(&v, None, Direction::Forward, &q), Some(3));
        // Starting on the hit and searching again wraps right back to it,
        // since it is the only one.
        assert_eq!(search(&v, Some(3), Direction::Forward, &q), Some(3));
        assert_eq!(search(&v, Some(3), Direction::Backward, &q), Some(3));
        assert_eq!(search(&v, Some(9), Direction::Forward, &q), Some(3));
        assert_eq!(search(&v, Some(0), Direction::Backward, &q), Some(3));
    }

    #[test]
    fn repeating_a_find_advances_through_the_hits() {
        let v = view(10);
        let q = compile(Kind::DisplayFilter, "tcp", false, Scope::List).expect("compile");
        let mut row = search(&v, None, Direction::Forward, &q).expect("first");
        assert_eq!(row, 0);
        for expected in 1..10 {
            row = search(&v, Some(row), Direction::Forward, &q).expect("next");
            assert_eq!(row, expected);
        }
        // And past the end, back to the start.
        assert_eq!(search(&v, Some(9), Direction::Forward, &q), Some(0));
        // Backwards from the start goes to the end.
        assert_eq!(search(&v, Some(0), Direction::Backward, &q), Some(9));
    }

    #[test]
    fn a_query_matching_nothing_finds_nothing() {
        let v = view(5);
        let q = compile(Kind::String, "no such text anywhere", false, Scope::List)
            .expect("compile");
        assert_eq!(search(&v, None, Direction::Forward, &q), None);
        assert_eq!(search(&v, Some(2), Direction::Backward, &q), None);
    }

    #[test]
    fn string_search_honours_case_and_scope() {
        let v = view(3);
        let frame = v.get(0).expect("row");
        // The protocol column reads "TCP"; the detail tree says "Transmission
        // Control Protocol".
        let upper = compile(Kind::String, "TCP", true, Scope::List).expect("compile");
        assert!(hits(&upper, frame));
        let lower = compile(Kind::String, "tcp", true, Scope::List).expect("compile");
        assert!(!hits(&lower, frame), "case-sensitive must not fold");
        let folded = compile(Kind::String, "tcp", false, Scope::List).expect("compile");
        assert!(hits(&folded, frame));
        let detail =
            compile(Kind::String, "Transmission Control", false, Scope::Details).expect("compile");
        assert!(hits(&detail, frame));
        assert!(
            !hits(
                &compile(Kind::String, "Transmission Control", false, Scope::List)
                    .expect("compile"),
                frame
            ),
            "a detail label is not in the list columns"
        );
    }

    #[test]
    fn hex_search_finds_bytes_in_the_frame() {
        let v = view(1);
        let frame = v.get(0).expect("row");
        // Every synthetic frame is Ethernet II carrying IPv4.
        let ethertype = compile(Kind::Hex, "08:00", false, Scope::Bytes).expect("compile");
        assert!(hits(&ethertype, frame));
        let absent = compile(Kind::Hex, "de:ad:be:ef:de:ad", false, Scope::Bytes).expect("compile");
        assert!(!hits(&absent, frame));
    }

    #[test]
    fn an_empty_view_finds_nothing_rather_than_panicking() {
        let v = View::all(Store::new(Limits::default()).snapshot());
        let q = compile(Kind::String, "anything", false, Scope::List).expect("compile");
        assert_eq!(search(&v, None, Direction::Forward, &q), None);
        assert_eq!(search(&v, Some(0), Direction::Backward, &q), None);
    }
}
