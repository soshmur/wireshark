//! The dissection worker: drains the capture channel, numbers and dissects
//! frames, and appends them to the store in batches.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError};
use netscope_ffi::LinkType;

use crate::capture::RawFrame;
use crate::dissect::Options;
use crate::dissect::State;
use crate::store::Store;

/// Largest batch appended under one store lock.
const BATCH: usize = 1024;
const IDLE_POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub struct Worker {
    join: Option<JoinHandle<()>>,
    processed: Arc<AtomicU64>,
}

impl Worker {
    /// Start a worker consuming `rx` into `store`. It exits when the sender
    /// side (the capture thread) goes away and the channel is drained.
    pub fn spawn(
        rx: Receiver<RawFrame>,
        store: Arc<Store>,
        link_type: LinkType,
        options: Options,
    ) -> Worker {
        let processed = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&processed);
        let join = thread::Builder::new()
            .name("netscope-dissect".into())
            .spawn(move || run(rx, store, link_type, counter, options))
            .ok();
        Worker { join, processed }
    }

    pub fn processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    /// Wait for the channel to drain and the thread to exit. Only returns once
    /// the capture side has dropped its sender.
    pub fn join(&mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn run(
    rx: Receiver<RawFrame>,
    store: Arc<Store>,
    link_type: LinkType,
    processed: Arc<AtomicU64>,
    options: Options,
) {
    let mut next = store.next_number();
    let mut batch = Vec::with_capacity(BATCH);
    let mut state = State::new();
    loop {
        let first = match rx.recv_timeout(IDLE_POLL) {
            Ok(f) => f,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        batch.push(Arc::new(crate::dissect::dissect_with(
            link_type, next, first, &mut state, options,
        )));
        next = next.wrapping_add(1);
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(f) => {
                    batch.push(Arc::new(crate::dissect::dissect_with(
                        link_type, next, f, &mut state, options,
                    )));
                    next = next.wrapping_add(1);
                }
                Err(_) => break,
            }
        }
        processed.fetch_add(batch.len() as u64, Ordering::Relaxed);
        store.append(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)));
    }
}
