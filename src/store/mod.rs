//! The capture store: an append-only, chunked ring of dissected frames.
//!
//! Frames live in fixed-size chunks (`CHUNK` frames). Sealed chunks are
//! immutable `Arc`s, so a `Snapshot` is a handful of `Arc` clones plus the
//! (small) open chunk, and indexing is O(1). Eviction removes whole chunks from
//! the front, so the configured limits are honoured to within one chunk.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::capture::Timestamp;
use crate::dissect::Frame;

/// Frames per sealed chunk. Also the eviction granularity.
pub const CHUNK: usize = 4096;

/// Ring-buffer limits; eviction happens when either is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: u64,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: 1_000_000,
            max_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreStats {
    /// Frames currently held.
    pub frames: u64,
    /// Approximate bytes currently held (payload + tree + bookkeeping).
    pub bytes: u64,
    pub evicted_frames: u64,
    pub evicted_bytes: u64,
    /// Number the next appended frame must carry.
    pub next_number: u32,
}

#[derive(Debug)]
struct Chunk {
    frames: Vec<Arc<Frame>>,
    bytes: u64,
}

#[derive(Debug, Default)]
struct Inner {
    sealed: Arc<Vec<Arc<Chunk>>>,
    open: Vec<Arc<Frame>>,
    open_bytes: u64,
    /// Number of the first frame currently held.
    first_number: u32,
    next_number: u32,
    /// Timestamp of the first frame ever appended; survives eviction.
    start_ts: Option<Timestamp>,
    bytes: u64,
    evicted_frames: u64,
    evicted_bytes: u64,
}

/// Shared between the dissection worker (writer) and the UI (reader).
#[derive(Debug)]
pub struct Store {
    inner: Mutex<Inner>,
    limits: Mutex<Limits>,
    /// Bumped on every mutation; readers compare it before re-snapshotting.
    version: AtomicU64,
}

/// An immutable view of the store at one instant. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Snapshot {
    sealed: Arc<Vec<Arc<Chunk>>>,
    open: Arc<Vec<Arc<Frame>>>,
    first_number: u32,
    start_ts: Option<Timestamp>,
    version: u64,
}

impl Store {
    pub fn new(limits: Limits) -> Arc<Store> {
        Arc::new(Store {
            inner: Mutex::new(Inner {
                first_number: 1,
                next_number: 1,
                ..Inner::default()
            }),
            limits: Mutex::new(limits),
            version: AtomicU64::new(0),
        })
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn limits(&self) -> Limits {
        self.limits.lock().map(|l| *l).unwrap_or_default()
    }

    pub fn set_limits(&self, limits: Limits) {
        if let Ok(mut l) = self.limits.lock() {
            *l = limits;
        }
        if let Ok(mut inner) = self.inner.lock() {
            self.evict(&mut inner, limits);
            self.version.fetch_add(1, Ordering::Release);
        }
    }

    /// Frame numbers are assigned by the single dequeuing worker so they
    /// follow arrival order even once dissection is parallel; the store
    /// checks continuity rather than numbering.
    pub fn next_number(&self) -> u32 {
        self.inner.lock().map(|i| i.next_number).unwrap_or(1)
    }

    /// Append a batch in numbering order. Frames whose number does not match
    /// `next_number` are renumbered so the store never holds a gap.
    pub fn append(&self, batch: Vec<Arc<Frame>>) {
        if batch.is_empty() {
            return;
        }
        let limits = self.limits();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        for mut frame in batch {
            if frame.number != inner.next_number {
                Arc::make_mut(&mut frame).number = inner.next_number;
            }
            inner.next_number = inner.next_number.wrapping_add(1);
            if inner.start_ts.is_none() {
                inner.start_ts = Some(frame.ts);
            }
            let size = frame.approx_size() as u64;
            inner.open_bytes += size;
            inner.bytes += size;
            inner.open.push(frame);
            if inner.open.len() >= CHUNK {
                Self::seal(&mut inner);
            }
        }
        self.evict(&mut inner, limits);
        self.version.fetch_add(1, Ordering::Release);
    }

    fn seal(inner: &mut Inner) {
        let frames = std::mem::take(&mut inner.open);
        let bytes = std::mem::take(&mut inner.open_bytes);
        Arc::make_mut(&mut inner.sealed).push(Arc::new(Chunk { frames, bytes }));
    }

    fn evict(&self, inner: &mut Inner, limits: Limits) {
        let over = |inner: &Inner| {
            let frames = inner.sealed.len() as u64 * CHUNK as u64 + inner.open.len() as u64;
            frames > limits.max_frames || inner.bytes > limits.max_bytes
        };
        while over(inner) && !inner.sealed.is_empty() {
            let chunk = Arc::make_mut(&mut inner.sealed).remove(0);
            inner.bytes -= chunk.bytes;
            inner.evicted_bytes += chunk.bytes;
            inner.evicted_frames += chunk.frames.len() as u64;
            inner.first_number = inner.first_number.wrapping_add(chunk.frames.len() as u32);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            *inner = Inner {
                first_number: 1,
                next_number: 1,
                ..Inner::default()
            };
            self.version.fetch_add(1, Ordering::Release);
        }
    }

    pub fn stats(&self) -> StoreStats {
        let Ok(inner) = self.inner.lock() else {
            return StoreStats::default();
        };
        StoreStats {
            frames: inner.sealed.len() as u64 * CHUNK as u64 + inner.open.len() as u64,
            bytes: inner.bytes,
            evicted_frames: inner.evicted_frames,
            evicted_bytes: inner.evicted_bytes,
            next_number: inner.next_number,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let Ok(inner) = self.inner.lock() else {
            return Snapshot::empty();
        };
        Snapshot {
            sealed: Arc::clone(&inner.sealed),
            open: Arc::new(inner.open.clone()),
            first_number: inner.first_number,
            start_ts: inner.start_ts,
            version: self.version.load(Ordering::Acquire),
        }
    }
}

impl Snapshot {
    pub fn empty() -> Snapshot {
        Snapshot {
            sealed: Arc::new(Vec::new()),
            open: Arc::new(Vec::new()),
            first_number: 1,
            start_ts: None,
            version: 0,
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn len(&self) -> usize {
        self.sealed.len() * CHUNK + self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Timestamp of the first frame of the capture (not the first held one).
    pub fn start_ts(&self) -> Option<Timestamp> {
        self.start_ts
    }

    /// The frame at row `row` (0-based position among held frames).
    pub fn get(&self, row: usize) -> Option<&Arc<Frame>> {
        let chunk = row / CHUNK;
        let idx = row % CHUNK;
        if chunk < self.sealed.len() {
            self.sealed[chunk].frames.get(idx)
        } else if chunk == self.sealed.len() {
            self.open.get(idx)
        } else {
            None
        }
    }

    /// Row of the frame with `number`, if it is still held.
    pub fn row_of(&self, number: u32) -> Option<usize> {
        let row = number.wrapping_sub(self.first_number) as usize;
        (number >= self.first_number && row < self.len()).then_some(row)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Frame>> {
        self.sealed
            .iter()
            .flat_map(|c| c.frames.iter())
            .chain(self.open.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::RawFrame;
    use crate::dissect::{dissect, Reassembly};
    use netscope_ffi::LinkType;

    fn frame(n: u32, len: usize) -> Arc<Frame> {
        let mut reassembly = Reassembly::new();
        Arc::new(dissect(
            LinkType::ETHERNET,
            n,
            RawFrame {
                ts: Timestamp {
                    secs: i64::from(n),
                    nanos: 0,
                },
                caplen: len as u32,
                orig_len: len as u32,
                bytes: Arc::from(vec![0u8; len]),
            },
            &mut reassembly,
        ))
    }

    fn fill(store: &Store, count: u32, len: usize) {
        let mut n = store.next_number();
        let batch: Vec<_> = (0..count)
            .map(|_| {
                let f = frame(n, len);
                n += 1;
                f
            })
            .collect();
        store.append(batch);
    }

    #[test]
    fn indexing_spans_sealed_and_open_chunks() {
        let store = Store::new(Limits::default());
        fill(&store, CHUNK as u32 + 10, 64);
        let s = store.snapshot();
        assert_eq!(s.len(), CHUNK + 10);
        assert_eq!(s.get(0).map(|f| f.number), Some(1));
        assert_eq!(s.get(CHUNK - 1).map(|f| f.number), Some(CHUNK as u32));
        assert_eq!(s.get(CHUNK).map(|f| f.number), Some(CHUNK as u32 + 1));
        assert_eq!(s.get(CHUNK + 9).map(|f| f.number), Some(CHUNK as u32 + 10));
        assert!(s.get(CHUNK + 10).is_none());
        assert_eq!(s.row_of(CHUNK as u32 + 3), Some(CHUNK + 2));
    }

    #[test]
    fn evicts_whole_chunks_by_frame_count() {
        let store = Store::new(Limits {
            max_frames: 2 * CHUNK as u64,
            max_bytes: u64::MAX,
        });
        fill(&store, 3 * CHUNK as u32 + 1, 64);
        let st = store.stats();
        // Three sealed chunks + 1 open = over by one chunk and a frame; the
        // oldest two chunks go so we are under the limit again.
        assert_eq!(st.evicted_frames, 2 * CHUNK as u64);
        assert_eq!(st.frames, CHUNK as u64 + 1);
        let s = store.snapshot();
        assert_eq!(s.get(0).map(|f| f.number), Some(2 * CHUNK as u32 + 1));
        assert_eq!(s.row_of(1), None);
        assert_eq!(s.row_of(2 * CHUNK as u32 + 1), Some(0));
        // Numbering continues across eviction.
        assert_eq!(st.next_number, 3 * CHUNK as u32 + 2);
    }

    #[test]
    fn evicts_by_bytes() {
        let store = Store::new(Limits {
            max_frames: u64::MAX,
            max_bytes: 1,
        });
        fill(&store, 2 * CHUNK as u32, 100);
        // Cannot evict the open chunk; both sealed chunks go.
        assert_eq!(store.stats().evicted_frames, 2 * CHUNK as u64);
        assert_eq!(store.stats().frames, 0);
        fill(&store, 5, 100);
        assert_eq!(store.stats().frames, 5);
    }

    #[test]
    fn snapshots_are_immutable_and_cheap() {
        let store = Store::new(Limits::default());
        fill(&store, 10, 8);
        let before = store.snapshot();
        fill(&store, 10, 8);
        assert_eq!(before.len(), 10);
        assert_eq!(store.snapshot().len(), 20);
        assert_ne!(before.version(), store.version());
        assert_eq!(before.start_ts(), Some(Timestamp { secs: 1, nanos: 0 }));
    }

    #[test]
    fn misnumbered_frames_are_renumbered_contiguously() {
        let store = Store::new(Limits::default());
        store.append(vec![frame(99, 8), frame(5, 8)]);
        let s = store.snapshot();
        assert_eq!(s.get(0).map(|f| f.number), Some(1));
        assert_eq!(s.get(1).map(|f| f.number), Some(2));
    }
}
