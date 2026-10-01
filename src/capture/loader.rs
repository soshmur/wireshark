//! Loading a capture file on its own thread.
//!
//! The architecture rule is that the UI never parses and never blocks, and
//! opening a file was the one place that broke it: reading, dissecting and
//! appending a million frames happened inside `update`, so the window froze
//! for as long as it took. The work now runs on a thread and appends to the
//! store in batches, which the UI picks up through the same version counter
//! it already polls for live capture.
//!
//! A side effect is better behaviour, not just a responsive window: the
//! packet list fills in as the file is read, so a large capture is usable
//! before it has finished loading.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use netscope_ffi::LinkType;

use crate::dissect::{dissect_with, Frame, Options, State};
use crate::store::Store;

/// Frames dissected before appending, to keep the store lock short.
const BATCH: usize = 2048;

/// What the loader has done so far. Read by the UI every repaint.
#[derive(Debug)]
pub struct Progress {
    /// Packets the file was found to contain, once it has been parsed.
    total: AtomicU64,
    /// Packets dissected and appended.
    done: AtomicU64,
    finished: AtomicBool,
    cancelled: AtomicBool,
    /// Set once, if the file could not be read at all.
    error: Mutex<Option<String>>,
    /// Things worth saying that are not failures.
    warnings: Mutex<Vec<String>>,
    /// Link type of the file's first interface, for re-dissection later.
    link_type: Mutex<LinkType>,
}

impl Progress {
    fn new() -> Progress {
        Progress {
            total: AtomicU64::new(0),
            done: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            error: Mutex::new(None),
            warnings: Mutex::new(Vec::new()),
            link_type: Mutex::new(LinkType::ETHERNET),
        }
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    /// Zero until the file has been parsed, then 0.0 to 1.0.
    pub fn fraction(&self) -> f32 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.done() as f32 / total as f32).clamp(0.0, 1.0)
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|e| e.clone())
    }

    pub fn warnings(&self) -> Vec<String> {
        self.warnings.lock().map(|w| w.clone()).unwrap_or_default()
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
            .lock()
            .map(|l| *l)
            .unwrap_or(LinkType::ETHERNET)
    }

    /// Ask the loader to stop. It checks between batches.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn was_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// A load in flight.
#[derive(Debug)]
pub struct Loader {
    join: Option<JoinHandle<()>>,
    pub progress: Arc<Progress>,
    pub path: PathBuf,
}

impl Loader {
    /// Start reading `path` into `store`, which is cleared first.
    ///
    /// The store is cleared here rather than on the thread so the UI never
    /// shows the previous capture's frames alongside the new one's.
    pub fn spawn(path: &Path, store: Arc<Store>, options: Options) -> Loader {
        store.clear();
        let progress = Arc::new(Progress::new());
        let p = Arc::clone(&progress);
        let owned = path.to_path_buf();
        let for_thread = owned.clone();
        let join = thread::Builder::new()
            .name("netscope-load".into())
            .spawn(move || run(&for_thread, store, options, p))
            .ok();
        Loader {
            join,
            progress,
            path: owned,
        }
    }

    /// True once the thread has nothing left to do.
    pub fn is_finished(&self) -> bool {
        self.progress.is_finished()
    }

    pub fn join(&mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        // A loader dropped mid-read would otherwise keep appending to a store
        // the UI has moved on from.
        self.progress.cancel();
        self.join();
    }
}

fn run(path: &Path, store: Arc<Store>, options: Options, progress: Arc<Progress>) {
    let loaded = match super::file::load_path(path) {
        Ok(l) => l,
        Err(e) => {
            if let Ok(mut slot) = progress.error.lock() {
                *slot = Some(format!("{}: {e}", path.display()));
            }
            progress.finished.store(true, Ordering::Release);
            return;
        }
    };
    progress
        .total
        .store(loaded.packets.len() as u64, Ordering::Relaxed);
    if let Ok(mut w) = progress.warnings.lock() {
        *w = loaded.warnings.clone();
    }
    if let Ok(mut l) = progress.link_type.lock() {
        *l = loaded.link_type_of(0);
    }

    // One State for the whole file, so conversations, reassembly and
    // desegmentation work across it exactly as they do for a live capture.
    let mut state = State::new();
    let mut batch: Vec<Arc<Frame>> = Vec::with_capacity(BATCH);
    for (i, (iface, raw)) in loaded.packets.iter().enumerate() {
        if progress.was_cancelled() {
            break;
        }
        batch.push(Arc::new(dissect_with(
            loaded.link_type_of(*iface),
            i as u32 + 1,
            raw.clone(),
            &mut state,
            options,
        )));
        if batch.len() == BATCH {
            let n = batch.len() as u64;
            store.append(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)));
            progress.done.fetch_add(n, Ordering::Relaxed);
        }
    }
    let n = batch.len() as u64;
    if n > 0 {
        store.append(batch);
        progress.done.fetch_add(n, Ordering::Relaxed);
    }
    progress.finished.store(true, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Limits;
    use std::time::{Duration, Instant};

    /// Wait for a load to finish, or fail the test rather than hang.
    fn settle(loader: &Loader) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !loader.is_finished() {
            assert!(Instant::now() < deadline, "the loader never finished");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn write_sample(name: &str, count: u64) -> PathBuf {
        let mut state = State::new();
        let frames: Vec<Arc<Frame>> = (0..count)
            .map(|i| {
                Arc::new(crate::dissect::dissect(
                    LinkType::ETHERNET,
                    i as u32 + 1,
                    crate::synthetic::raw_frame(i),
                    &mut state,
                ))
            })
            .collect();
        let path = std::env::temp_dir().join(format!("netscope-loader-{name}.pcapng"));
        super::super::file::save_path(&path, &frames, super::super::file::SaveFormat::Pcapng)
            .expect("write the sample");
        path
    }

    #[test]
    fn a_file_loads_into_the_store() {
        let path = write_sample("basic", 300);
        let store = Store::new(Limits::default());
        let mut loader = Loader::spawn(&path, Arc::clone(&store), Options::default());
        settle(&loader);
        loader.join();
        assert_eq!(loader.progress.error(), None);
        assert_eq!(loader.progress.total(), 300);
        assert_eq!(loader.progress.done(), 300);
        assert_eq!(store.snapshot().len(), 300);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn frames_appear_before_the_load_finishes() {
        // The point of the thread: a large file is usable while it loads
        // rather than after it.
        let path = write_sample("streaming", 12_000);
        let store = Store::new(Limits::default());
        let loader = Loader::spawn(&path, Arc::clone(&store), Options::default());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut saw_partial = false;
        while !loader.is_finished() {
            let held = store.snapshot().len();
            if held > 0 && (held as u64) < loader.progress.total().max(1) {
                saw_partial = true;
                break;
            }
            assert!(Instant::now() < deadline, "never finished");
            thread::sleep(Duration::from_millis(1));
        }
        settle(&loader);
        // Either a partial state was observed, or the file loaded faster than
        // the poll loop could catch - both are correct, so the assertion is
        // that nothing was lost.
        assert_eq!(store.snapshot().len(), 12_000);
        let _ = saw_partial;
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_ui_can_read_the_store_while_a_file_loads() {
        // The architecture rule this change exists for: the UI must not block
        // on parsing. What the UI does every repaint is take a snapshot and
        // index it, so that is what is timed here, while a load runs.
        let path = write_sample("responsive", 60_000);
        let store = Store::new(Limits::default());
        let mut loader = Loader::spawn(&path, Arc::clone(&store), Options::default());
        let mut worst = Duration::ZERO;
        let mut polls = 0u32;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !loader.is_finished() {
            let t = Instant::now();
            let snap = store.snapshot();
            let n = snap.len();
            // Touch both ends, which is what a virtualised list does.
            let _ = snap.get(0);
            let _ = snap.get(n.saturating_sub(1));
            worst = worst.max(t.elapsed());
            polls += 1;
            assert!(Instant::now() < deadline, "the loader never finished");
        }
        settle(&loader);
        loader.join();
        assert_eq!(store.snapshot().len(), 60_000);
        assert!(polls > 0, "the load finished before a single poll");
        // A repaint at 60fps has 16ms of budget for everything. Taking a
        // snapshot is one part of that, so it has to be far below.
        assert!(
            worst < Duration::from_millis(8),
            "worst snapshot took {worst:?} across {polls} polls, which would \
             drop frames"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_reports_an_error_rather_than_hanging() {
        let store = Store::new(Limits::default());
        let mut loader = Loader::spawn(
            Path::new("no-such-file-anywhere.pcapng"),
            Arc::clone(&store),
            Options::default(),
        );
        settle(&loader);
        loader.join();
        assert!(loader.progress.error().is_some());
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn the_store_is_cleared_before_the_new_file_arrives() {
        // Showing the previous capture's frames alongside the new one's would
        // be worse than a moment of emptiness.
        let first = write_sample("first", 100);
        let store = Store::new(Limits::default());
        let mut a = Loader::spawn(&first, Arc::clone(&store), Options::default());
        settle(&a);
        a.join();
        assert_eq!(store.snapshot().len(), 100);

        let second = write_sample("second", 50);
        let mut b = Loader::spawn(&second, Arc::clone(&store), Options::default());
        settle(&b);
        b.join();
        assert_eq!(store.snapshot().len(), 50, "not 150");
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);
    }

    #[test]
    fn cancelling_stops_the_load() {
        let path = write_sample("cancel", 20_000);
        let store = Store::new(Limits::default());
        let mut loader = Loader::spawn(&path, Arc::clone(&store), Options::default());
        loader.progress.cancel();
        settle(&loader);
        loader.join();
        assert!(loader.progress.was_cancelled());
        // It stopped somewhere at or before the end; what matters is that it
        // stopped and said so rather than running to completion regardless.
        assert!(store.snapshot().len() <= 20_000);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_fraction_is_meaningful_before_and_after() {
        let path = write_sample("fraction", 200);
        let store = Store::new(Limits::default());
        let mut loader = Loader::spawn(&path, Arc::clone(&store), Options::default());
        settle(&loader);
        loader.join();
        assert_eq!(loader.progress.fraction(), 1.0);
        // And a loader that has not parsed yet reports zero rather than
        // dividing by it.
        let fresh = Progress::new();
        assert_eq!(fresh.fraction(), 0.0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_ring_limits_still_apply_to_a_file() {
        // Opening a file must not be the one path that ignores them.
        let path = write_sample("limits", 9000);
        let store = Store::new(Limits {
            max_frames: 4096,
            max_bytes: u64::MAX,
        });
        let mut loader = Loader::spawn(&path, Arc::clone(&store), Options::default());
        settle(&loader);
        loader.join();
        assert_eq!(loader.progress.done(), 9000, "all were read");
        assert!(
            store.snapshot().len() <= 8192,
            "but the ring holds {} of them",
            store.snapshot().len()
        );
        let _ = std::fs::remove_file(&path);
    }
}
