//! The raw frame as it leaves the capture thread. No parsing has happened yet.

use std::sync::Arc;

/// A capture timestamp with nanosecond resolution, seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

/// One link-layer frame plus its capture metadata. Bytes are shared so later
/// stages can hold onto them without copying.
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "the Phase 0 consumer only counts frames; Phase 1 reads every field"
)]
pub struct RawFrame {
    pub ts: Timestamp,
    /// Bytes actually captured (`bytes.len()`), kept explicit to mirror the pcap header.
    pub caplen: u32,
    /// Length on the wire before snaplen truncation.
    pub orig_len: u32,
    pub bytes: Arc<[u8]>,
}
