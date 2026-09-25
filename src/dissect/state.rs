//! Per-worker dissection state: everything a dissector may carry from one
//! frame to the next.
//!
//! One `State` belongs to one dissection worker and is never shared, which is
//! what lets the tables inside be plain `HashMap`s with no locking. A frame
//! dissected with a fresh `State` sees no history, so tests and fuzz targets
//! get deterministic results by construction.

use super::reassembly::Reassembly;
use super::stream::StreamTable;

#[derive(Debug, Default)]
pub struct State {
    /// IPv4 fragments awaiting the rest of their datagram.
    pub reassembly: Reassembly,
    /// Conversation ids, and the per-conversation analysis state.
    pub streams: StreamTable,
}

impl State {
    pub fn new() -> State {
        State {
            reassembly: Reassembly::new(),
            streams: StreamTable::new(),
        }
    }
}
