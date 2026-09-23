//! The displayed subset of a snapshot.
//!
//! A `View` is the list the UI actually renders: every frame when no display
//! filter is set, or the matching rows when one is. Building it walks the
//! snapshot once; the packet list then indexes it in constant time, so a
//! filtered list scrolls as fast as an unfiltered one.

use std::sync::Arc;

use crate::dissect::Frame;
use crate::filter::{matches, Test};

use super::Snapshot;

#[derive(Debug, Clone)]
pub struct View {
    snapshot: Snapshot,
    /// Row indexes into the snapshot, or `None` when unfiltered.
    rows: Option<Arc<Vec<u32>>>,
    /// Version of the snapshot this view was built from.
    version: u64,
    filtered: bool,
}

impl View {
    /// Every frame in the snapshot.
    pub fn all(snapshot: Snapshot) -> View {
        let version = snapshot.version();
        View {
            snapshot,
            rows: None,
            version,
            filtered: false,
        }
    }

    /// The frames matching `test`.
    pub fn filtered(snapshot: Snapshot, test: &Test) -> View {
        let version = snapshot.version();
        let mut rows = Vec::new();
        for row in 0..snapshot.len() {
            let Some(frame) = snapshot.get(row) else {
                continue;
            };
            if matches(test, frame) {
                rows.push(row as u32);
            }
        }
        View {
            snapshot,
            rows: Some(Arc::new(rows)),
            version,
            filtered: true,
        }
    }

    /// Build from a snapshot and an optional filter.
    pub fn build(snapshot: Snapshot, test: Option<&Test>) -> View {
        match test {
            Some(t) => View::filtered(snapshot, t),
            None => View::all(snapshot),
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn is_filtered(&self) -> bool {
        self.filtered
    }

    /// Rows shown.
    pub fn len(&self) -> usize {
        match &self.rows {
            Some(r) => r.len(),
            None => self.snapshot.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Rows in the underlying capture, shown or not.
    pub fn total(&self) -> usize {
        self.snapshot.len()
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn get(&self, row: usize) -> Option<&Arc<Frame>> {
        match &self.rows {
            Some(r) => self.snapshot.get(*r.get(row)? as usize),
            None => self.snapshot.get(row),
        }
    }

    /// Displayed row of the frame with `number`, if it is shown.
    pub fn row_of(&self, number: u32) -> Option<usize> {
        let underlying = self.snapshot.row_of(number)? as u32;
        match &self.rows {
            Some(r) => r.binary_search(&underlying).ok(),
            None => Some(underlying as usize),
        }
    }

    /// The displayed row at or after `number`, for keeping a selection close
    /// to where it was when the filter changes.
    pub fn row_at_or_after(&self, number: u32) -> Option<usize> {
        let underlying = self.snapshot.row_of(number)? as u32;
        match &self.rows {
            Some(r) => match r.binary_search(&underlying) {
                Ok(i) => Some(i),
                Err(i) => (i < r.len()).then_some(i),
            },
            None => Some(underlying as usize),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Frame>> + '_ {
        (0..self.len()).filter_map(move |i| self.get(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dissect::{dissect, Reassembly};
    use crate::filter::compile;
    use crate::store::{Limits, Store};
    use netscope_ffi::LinkType;

    fn store_with(count: u64) -> Arc<Store> {
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
        store
    }

    #[test]
    fn unfiltered_view_is_the_whole_snapshot() {
        let store = store_with(10);
        let v = View::all(store.snapshot());
        assert_eq!(v.len(), 10);
        assert_eq!(v.total(), 10);
        assert!(!v.is_filtered());
        assert_eq!(v.get(3).map(|f| f.number), Some(4));
        assert_eq!(v.row_of(4), Some(3));
    }

    #[test]
    fn filtered_view_selects_and_maps_rows() {
        let store = store_with(10);
        // Every synthetic frame is TCP; the source MAC's last byte is the
        // frame index, so this picks exactly one.
        let test = compile("eth.src[5] == 3").expect("compile");
        let v = View::filtered(store.snapshot(), &test);
        assert!(v.is_filtered());
        assert_eq!(v.len(), 1);
        assert_eq!(v.total(), 10);
        assert_eq!(v.get(0).map(|f| f.number), Some(4));
        assert_eq!(v.row_of(4), Some(0));
        assert_eq!(v.row_of(5), None, "a hidden frame has no displayed row");
        // The nearest displayed row at or after a hidden frame.
        assert_eq!(v.row_at_or_after(1), Some(0));
        assert_eq!(v.row_at_or_after(9), None);
    }

    #[test]
    fn a_filter_matching_nothing_gives_an_empty_view() {
        let store = store_with(5);
        let test = compile("arp").expect("compile");
        let v = View::filtered(store.snapshot(), &test);
        assert!(v.is_empty());
        assert_eq!(v.total(), 5);
        assert!(v.get(0).is_none());
    }

    #[test]
    fn filtering_does_not_redissect() {
        // Frames in the view are the very same `Arc`s the store holds.
        let store = store_with(4);
        let snap = store.snapshot();
        let test = compile("tcp").expect("compile");
        let v = View::filtered(snap.clone(), &test);
        assert_eq!(v.len(), 4);
        for row in 0..4 {
            let from_view = v.get(row).expect("row");
            let from_snapshot = snap.get(row).expect("row");
            assert!(Arc::ptr_eq(from_view, from_snapshot));
        }
    }
}
