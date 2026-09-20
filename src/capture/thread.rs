//! Stage 1 of the pipeline: the capture thread.
//!
//! It runs the libpcap read loop and nothing else. Frames go into a bounded
//! channel with `try_send`; when the channel is full the frame is dropped and
//! counted. The thread never blocks on a consumer and never touches the UI.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use netscope_ffi::{LinkType, OpenOptions, Read};

use super::frame::{RawFrame, Timestamp};

/// Everything needed to open a device and start capturing.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub device: String,
    pub snaplen: i32,
    pub promiscuous: bool,
    /// libpcap BPF capture filter, applied in the kernel/driver. Distinct from
    /// the display filter, which is evaluated over already-stored frames.
    pub bpf: Option<String>,
    /// Bounded channel depth between capture and dissection.
    pub channel_capacity: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            device: String::new(),
            snaplen: 262_144,
            promiscuous: true,
            bpf: None,
            channel_capacity: 65_536,
        }
    }
}

/// Counters shared between the capture thread and readers. All relaxed: they are
/// monotonic gauges for display, not synchronisation.
#[derive(Debug, Default)]
pub struct CaptureStats {
    /// Frames handed to the channel.
    pub received: AtomicU64,
    /// Captured bytes handed to the channel.
    pub bytes: AtomicU64,
    /// Frames dropped because the channel was full.
    pub dropped_channel: AtomicU64,
    /// Frames the driver saw (pcap_stats ps_recv).
    pub kernel_received: AtomicU64,
    /// Frames the driver dropped for lack of buffer (ps_drop).
    pub kernel_dropped: AtomicU64,
    /// Frames the interface dropped (ps_ifdrop).
    pub kernel_if_dropped: AtomicU64,
}

/// A plain-value copy of the counters for the UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub received: u64,
    pub bytes: u64,
    pub dropped_channel: u64,
    pub kernel_received: u64,
    pub kernel_dropped: u64,
    pub kernel_if_dropped: u64,
}

impl CaptureStats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped_channel: self.dropped_channel.load(Ordering::Relaxed),
            kernel_received: self.kernel_received.load(Ordering::Relaxed),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            kernel_if_dropped: self.kernel_if_dropped.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default)]
struct Shared {
    stats: CaptureStats,
    stop: AtomicBool,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
}

/// A running (or finished) capture. Dropping it stops the thread.
#[derive(Debug)]
pub struct Capture {
    shared: Arc<Shared>,
    join: Option<JoinHandle<()>>,
    link_type: LinkType,
    device: String,
}

impl Capture {
    /// Open `cfg.device` on a new thread and start reading. Returns once the
    /// device is open (or has failed to open) so errors surface synchronously.
    pub fn start(cfg: CaptureConfig) -> Result<(Capture, Receiver<RawFrame>), String> {
        let shared = Arc::new(Shared::default());
        let (tx, rx) = bounded::<RawFrame>(cfg.channel_capacity.max(1));
        let (ready_tx, ready_rx) = bounded::<Result<LinkType, String>>(1);

        let thread_shared = Arc::clone(&shared);
        let device = cfg.device.clone();
        let join = thread::Builder::new()
            .name("netscope-capture".into())
            .spawn(move || run_loop(cfg, thread_shared, tx, ready_tx))
            .map_err(|e| format!("could not spawn capture thread: {e}"))?;

        match ready_rx.recv() {
            Ok(Ok(link_type)) => Ok((
                Capture {
                    shared,
                    join: Some(join),
                    link_type,
                    device,
                },
                rx,
            )),
            Ok(Err(msg)) => {
                let _ = join.join();
                Err(msg)
            }
            Err(_) => {
                let _ = join.join();
                Err("capture thread exited before opening the device".into())
            }
        }
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.shared.stats.snapshot()
    }

    /// `true` while the read loop is alive.
    pub fn is_running(&self) -> bool {
        !self.shared.finished.load(Ordering::Acquire)
    }

    /// The error that ended the loop, if it ended on one.
    pub fn error(&self) -> Option<String> {
        self.shared
            .error
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Ask the loop to stop and wait for it. Returns within one read timeout.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// How many frames between `pcap_stats` refreshes.
const STATS_EVERY: u64 = 1_000;

fn run_loop(
    cfg: CaptureConfig,
    shared: Arc<Shared>,
    tx: Sender<RawFrame>,
    ready: Sender<Result<LinkType, String>>,
) {
    let opts = OpenOptions {
        snaplen: cfg.snaplen,
        promiscuous: cfg.promiscuous,
        bpf: cfg.bpf.clone(),
        ..OpenOptions::default()
    };
    let mut handle = match netscope_ffi::open(&cfg.device, &opts) {
        Ok(h) => h,
        Err(e) => {
            let _ = ready.send(Err(e.0));
            shared.finished.store(true, Ordering::Release);
            return;
        }
    };
    let _ = ready.send(Ok(handle.link_type()));

    let stats = &shared.stats;
    let mut since_stats = 0u64;
    let refresh_kernel = |handle: &mut netscope_ffi::Handle| {
        if let Ok(k) = handle.stats() {
            stats
                .kernel_received
                .store(u64::from(k.received), Ordering::Relaxed);
            stats
                .kernel_dropped
                .store(u64::from(k.dropped), Ordering::Relaxed);
            stats
                .kernel_if_dropped
                .store(u64::from(k.if_dropped), Ordering::Relaxed);
        }
    };

    while !shared.stop.load(Ordering::Acquire) {
        match handle.read() {
            Ok(Read::Packet(p)) => {
                let frame = RawFrame {
                    ts: Timestamp {
                        secs: p.ts_secs,
                        nanos: p.ts_nanos,
                    },
                    caplen: p.data.len() as u32,
                    orig_len: p.orig_len,
                    bytes: Arc::from(p.data),
                };
                let len = frame.bytes.len() as u64;
                match tx.try_send(frame) {
                    Ok(()) => {
                        stats.received.fetch_add(1, Ordering::Relaxed);
                        stats.bytes.fetch_add(len, Ordering::Relaxed);
                    }
                    Err(TrySendError::Full(_)) => {
                        stats.dropped_channel.fetch_add(1, Ordering::Relaxed);
                    }
                    // Consumer went away; nothing left to do.
                    Err(TrySendError::Disconnected(_)) => break,
                }
                since_stats += 1;
                if since_stats >= STATS_EVERY {
                    since_stats = 0;
                    refresh_kernel(&mut handle);
                }
            }
            Ok(Read::Timeout) => refresh_kernel(&mut handle),
            Ok(Read::End) => break,
            Err(e) => {
                if let Ok(mut guard) = shared.error.lock() {
                    *guard = Some(e.0);
                }
                break;
            }
        }
    }
    refresh_kernel(&mut handle);
    shared.finished.store(true, Ordering::Release);
}
