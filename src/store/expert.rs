//! Expert findings, gathered and grouped across a capture.
//!
//! The per-frame column answers "is there something wrong with this packet".
//! This answers the question you actually open a capture with: "is there
//! anything wrong in here, and where". Scrolling a million rows looking for
//! coloured cells is not an answer.
//!
//! Built on demand from a snapshot, like the other statistics, so it always
//! describes the frames the packet list is showing.

use crate::dissect::{Group, Severity};

use super::Snapshot;

/// One kind of finding, with every frame that raised it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub severity: Severity,
    pub group: Group,
    /// The finding's own field, e.g. `tcp.analysis.retransmission`.
    pub field: &'static str,
    /// The message the dissector attached.
    pub summary: String,
    pub count: u64,
    /// The first few frames, for jumping to one. Not all of them: a capture
    /// with a million retransmissions should not cost a million u32s here.
    pub first_frames: Vec<u32>,
}

impl Entry {
    /// A display filter selecting every frame with this finding.
    pub fn filter(&self) -> String {
        self.field.to_string()
    }
}

/// How many frame numbers to keep per entry.
pub const SAMPLE_FRAMES: usize = 32;

/// Fields that are expert findings rather than ordinary data.
///
/// Recognised by name, which is a convention rather than something the
/// registry records: `tcp.analysis.*` is a finding except for the three
/// fields under it that are measurements. `bytes_in_flight` is on every
/// ordinary segment of a healthy transfer, and counting it would bury the
/// real findings; the two `duplicate_ack` numbers belong to the finding
/// beside them rather than being findings themselves.
///
/// A finding added to a dissector under a new prefix has to be added here
/// too, which the test below exists to make obvious rather than silent.
fn is_finding(abbrev: &str) -> bool {
    abbrev.starts_with("tcp.analysis.")
        && !abbrev.ends_with("bytes_in_flight")
        && !abbrev.ends_with("duplicate_ack_num")
        && !abbrev.ends_with("duplicate_ack_frame")
        || abbrev == "_ws.checksum.bad"
        || abbrev == "_ws.malformed"
}

/// Gather every finding in the snapshot.
pub fn findings(snapshot: &Snapshot) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for frame in snapshot.iter() {
        // A frame's findings sit beside `_ws.expert` nodes carrying the
        // severity and group; walk the tree once and pair them up.
        let mut pending: Option<(&'static str, String)> = None;
        for node in frame.tree.iter() {
            let abbrev = node.abbrev();
            if is_finding(abbrev) {
                let data = frame.source(node.source()).unwrap_or(&[]);
                let text = node
                    .text()
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| crate::dissect::registry::label(&node, data));
                pending = Some((abbrev, text));
                continue;
            }
            if abbrev == "_ws.expert" {
                let severity = node
                    .children()
                    .find(|c| c.abbrev() == "_ws.expert.severity")
                    .and_then(|c| c.unsigned())
                    .map(Severity::from_u64)
                    .unwrap_or_default();
                let group = node
                    .children()
                    .find(|c| c.abbrev() == "_ws.expert.group")
                    .and_then(|c| c.unsigned())
                    .map(Group::from_u64)
                    .unwrap_or_default();
                let (field, summary) = match pending.take() {
                    Some(p) => p,
                    // An expert record with no field beside it: the malformed
                    // case, where the node itself is the finding.
                    None => ("_ws.malformed", node.text().unwrap_or("").to_string()),
                };
                record(&mut entries, severity, group, field, summary, frame.number);
            }
        }
    }
    // Worst first, then most frequent: the order someone triaging wants.
    entries.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.field.cmp(b.field))
    });
    entries
}

fn record(
    entries: &mut Vec<Entry>,
    severity: Severity,
    group: Group,
    field: &'static str,
    summary: String,
    frame: u32,
) {
    if let Some(e) = entries
        .iter_mut()
        .find(|e| e.field == field && e.summary == summary)
    {
        e.count += 1;
        if e.first_frames.len() < SAMPLE_FRAMES {
            e.first_frames.push(frame);
        }
        return;
    }
    entries.push(Entry {
        severity,
        group,
        field,
        summary,
        count: 1,
        first_frames: vec![frame],
    });
}

/// Counts by severity, for the window's header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    pub chats: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.errors + self.warnings + self.notes + self.chats
    }
}

pub fn counts(entries: &[Entry]) -> Counts {
    let mut c = Counts::default();
    for e in entries {
        match e.severity {
            Severity::Error => c.errors += e.count,
            Severity::Warn => c.warnings += e.count,
            Severity::Note => c.notes += e.count,
            Severity::Chat => c.chats += e.count,
            Severity::Comment => {}
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, State};
    use crate::store::{Limits, Store};
    use netscope_ffi::LinkType;
    use std::sync::Arc;

    fn store_of(count: u64) -> Arc<Store> {
        let store = Store::new(Limits::default());
        let mut state = State::new();
        let batch: Vec<Arc<crate::dissect::Frame>> = (0..count)
            .map(|i| {
                Arc::new(dissect(
                    LinkType::ETHERNET,
                    i as u32 + 1,
                    crate::synthetic::raw_frame(i),
                    &mut state,
                ))
            })
            .collect();
        store.append(batch);
        store
    }

    #[test]
    fn a_clean_capture_has_nothing_to_report() {
        let store = store_of(200);
        let entries = findings(&store.snapshot());
        assert!(entries.is_empty(), "{entries:#?}");
        assert_eq!(counts(&entries).total(), 0);
    }

    #[test]
    fn the_bytes_in_flight_measurement_is_not_a_finding() {
        // It is on every ordinary segment of a healthy transfer. Counting it
        // would bury the real findings under it.
        assert!(!is_finding("tcp.analysis.bytes_in_flight"));
        assert!(!is_finding("tcp.analysis.duplicate_ack_num"));
        assert!(!is_finding("tcp.analysis.duplicate_ack_frame"));
        assert!(is_finding("tcp.analysis.retransmission"));
        assert!(is_finding("tcp.analysis.duplicate_ack"));
        assert!(is_finding("_ws.malformed"));
        assert!(is_finding("_ws.checksum.bad"));
        assert!(!is_finding("tcp.seq"));
        assert!(!is_finding("ip.checksum"));
    }

    #[test]
    fn the_frame_sample_is_bounded() {
        // A capture with a million retransmissions must not cost a million
        // frame numbers per entry.
        let mut entries = Vec::new();
        for n in 1..=1000u32 {
            record(
                &mut entries,
                Severity::Note,
                Group::Sequence,
                "tcp.analysis.retransmission",
                "resent".into(),
                n,
            );
        }
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].count, 1000);
        assert_eq!(entries[0].first_frames.len(), SAMPLE_FRAMES);
        assert_eq!(entries[0].first_frames[0], 1, "and they are the first ones");
    }

    #[test]
    fn entries_are_worst_first_then_most_frequent() {
        let mut entries = [
            Entry {
                severity: Severity::Note,
                group: Group::Sequence,
                field: "tcp.analysis.retransmission",
                summary: "a".into(),
                count: 100,
                first_frames: vec![1],
            },
            Entry {
                severity: Severity::Error,
                group: Group::Malformed,
                field: "_ws.malformed",
                summary: "b".into(),
                count: 1,
                first_frames: vec![2],
            },
            Entry {
                severity: Severity::Note,
                group: Group::Sequence,
                field: "tcp.analysis.out_of_order",
                summary: "c".into(),
                count: 500,
                first_frames: vec![3],
            },
        ];
        entries.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.field.cmp(b.field))
        });
        // The single Error outranks 500 Notes: severity first, which is what
        // someone triaging wants.
        assert_eq!(entries[0].summary, "b");
        assert_eq!(entries[1].summary, "c");
        assert_eq!(entries[2].summary, "a");
    }

    #[test]
    fn counts_add_up_by_severity() {
        let entries = vec![
            Entry {
                severity: Severity::Error,
                group: Group::Checksum,
                field: "_ws.checksum.bad",
                summary: "x".into(),
                count: 3,
                first_frames: vec![],
            },
            Entry {
                severity: Severity::Warn,
                group: Group::Sequence,
                field: "tcp.analysis.lost_segment",
                summary: "y".into(),
                count: 7,
                first_frames: vec![],
            },
        ];
        let c = counts(&entries);
        assert_eq!((c.errors, c.warnings, c.notes), (3, 7, 0));
        assert_eq!(c.total(), 10);
    }

    #[test]
    fn every_entry_filter_compiles() {
        // The window's "apply as filter" is only useful if what it produces
        // is something the engine accepts.
        for field in [
            "tcp.analysis.retransmission",
            "tcp.analysis.lost_segment",
            "_ws.malformed",
            "_ws.checksum.bad",
        ] {
            let e = Entry {
                severity: Severity::Note,
                group: Group::Sequence,
                field,
                summary: String::new(),
                count: 1,
                first_frames: vec![],
            };
            assert!(crate::filter::compile(&e.filter()).is_ok(), "{field}");
        }
    }
}
