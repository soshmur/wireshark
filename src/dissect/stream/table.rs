//! The stream id table: 5-tuple to stable id, plus the per-conversation TCP
//! sequence state.
//!
//! One map, not two. Splitting the ids from the analysis state was tempting
//! because the ids must survive for the whole capture while the analysis only
//! matters while a conversation is live - but two tables means two caps and
//! two eviction policies that can disagree about whether a stream exists. At
//! ~150 bytes an entry, one table capped at 200k conversations costs about
//! 30 MB worst case, against a frame ring measured in gigabytes.

use std::collections::HashMap;

use crate::capture::Timestamp;

use super::tcp::{Analysis, Findings, Segment};
use super::Endpoint;

/// A conversation, keyed so both directions land on the same entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    lo: Endpoint,
    hi: Endpoint,
    proto: u8,
}

/// Which way round a frame runs relative to the stream's first frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Source is the endpoint that sent the stream's first frame.
    Forward,
    Reverse,
}

impl StreamKey {
    /// Canonical key: endpoints sorted, so A->B and B->A agree.
    pub fn new(a: Endpoint, b: Endpoint, proto: u8) -> StreamKey {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        StreamKey { lo, hi, proto }
    }

    pub fn proto(&self) -> u8 {
        self.proto
    }

    pub fn endpoints(&self) -> (Endpoint, Endpoint) {
        (self.lo, self.hi)
    }
}

/// What a lookup tells the dissector. Carries the key so a follow-up call
/// can reach the same entry without rebuilding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lookup {
    pub id: u32,
    pub direction: Direction,
    /// True when this frame created the stream.
    pub first: bool,
    pub key: StreamKey,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    id: u32,
    /// The source endpoint of the frame that created the stream; a frame
    /// whose source matches runs in the forward direction.
    origin: Endpoint,
    last_seen: Timestamp,
    /// TCP sequence state. Unused for UDP, and cheap enough at ~150 bytes
    /// that giving every entry one is better than a second table with its
    /// own cap and its own eviction policy to reason about.
    analysis: Analysis,
}

/// Ids and liveness for every conversation seen.
#[derive(Debug)]
pub struct StreamTable {
    ids: HashMap<StreamKey, Entry>,
    next_id: u32,
    /// Beyond this many conversations, the least recently seen are dropped.
    /// A dropped conversation that reappears is given a new id, which is
    /// wrong but bounded; the alternative is unbounded memory on a capture
    /// that sees millions of short flows.
    pub max_streams: usize,
    /// Conversations idle for longer than this are dropped first.
    pub idle_timeout_secs: i64,
}

impl Default for StreamTable {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamTable {
    pub fn new() -> StreamTable {
        StreamTable {
            ids: HashMap::new(),
            next_id: 0,
            max_streams: 200_000,
            idle_timeout_secs: 300,
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Ids handed out so far, which is also the id the next new stream gets.
    pub fn next_id(&self) -> u32 {
        self.next_id
    }

    /// The stream this frame belongs to, creating it if it is new.
    ///
    /// `fresh` says the frame starts a connection (a TCP SYN without ACK).
    /// Such a frame always begins a new stream even if the 5-tuple was seen
    /// before, because ports are reused and two connections between the same
    /// ports are two conversations, not one.
    pub fn lookup(
        &mut self,
        src: Endpoint,
        dst: Endpoint,
        proto: u8,
        now: Timestamp,
        fresh: bool,
    ) -> Lookup {
        let key = StreamKey::new(src, dst, proto);
        if fresh {
            if let Some(e) = self.ids.get_mut(&key) {
                // Port reuse: a new connection on an old 5-tuple.
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                *e = Entry {
                    id,
                    origin: src,
                    last_seen: now,
                    analysis: Analysis::default(),
                };
                return Lookup {
                    id,
                    direction: Direction::Forward,
                    first: true,
                    key,
                };
            }
        }
        if let Some(e) = self.ids.get_mut(&key) {
            e.last_seen = now;
            let direction = if e.origin == src {
                Direction::Forward
            } else {
                Direction::Reverse
            };
            return Lookup {
                id: e.id,
                direction,
                first: false,
                key,
            };
        }
        self.evict_if_full(now);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.ids.insert(
            key,
            Entry {
                id,
                origin: src,
                last_seen: now,
                analysis: Analysis::default(),
            },
        );
        Lookup {
            id,
            direction: Direction::Forward,
            first: true,
            key,
        }
    }

    /// Fold a segment into the conversation's TCP state and report what the
    /// analyser made of it. A stream evicted between the lookup and this call
    /// cannot happen (eviction only runs when a new stream is created), but
    /// if it ever did the segment is simply not analysed.
    pub fn analyse(&mut self, look: &Lookup, seg: &Segment) -> Findings {
        match self.ids.get_mut(&look.key) {
            Some(e) => e.analysis.observe(look.direction, seg),
            None => Findings::default(),
        }
    }

    /// Read-only access to a conversation's TCP state.
    pub fn analysis(&self, key: &StreamKey) -> Option<&Analysis> {
        self.ids.get(key).map(|e| &e.analysis)
    }

    /// Drop idle conversations, then the oldest, until there is room.
    fn evict_if_full(&mut self, now: Timestamp) {
        if self.ids.len() < self.max_streams {
            return;
        }
        let cutoff = now.secs.saturating_sub(self.idle_timeout_secs);
        self.ids.retain(|_, e| e.last_seen.secs >= cutoff);
        if self.ids.len() < self.max_streams {
            return;
        }
        // Still full: drop the oldest tenth in one pass rather than one entry
        // per frame, which would rescan the map on every packet.
        let mut times: Vec<i64> = self.ids.values().map(|e| e.last_seen.secs).collect();
        let nth = times.len() / 10;
        times.sort_unstable();
        let Some(&threshold) = times.get(nth) else {
            return;
        };
        self.ids.retain(|_, e| e.last_seen.secs > threshold);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> Timestamp {
        Timestamp { secs, nanos: 0 }
    }

    fn a(port: u16) -> Endpoint {
        Endpoint::v4([10, 0, 0, 1], port)
    }

    fn b(port: u16) -> Endpoint {
        Endpoint::v4([10, 0, 0, 2], port)
    }

    #[test]
    fn both_directions_are_one_stream() {
        let mut t = StreamTable::new();
        let out = t.lookup(a(1000), b(80), 6, ts(0), false);
        let back = t.lookup(b(80), a(1000), 6, ts(1), false);
        assert_eq!(out.id, back.id);
        assert!(out.first, "the first frame creates the stream");
        assert!(!back.first);
        assert_eq!(out.direction, Direction::Forward);
        assert_eq!(back.direction, Direction::Reverse);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn different_tuples_are_different_streams() {
        let mut t = StreamTable::new();
        assert_eq!(t.lookup(a(1000), b(80), 6, ts(0), false).id, 0);
        assert_eq!(t.lookup(a(1001), b(80), 6, ts(0), false).id, 1);
        assert_eq!(t.lookup(a(1000), b(443), 6, ts(0), false).id, 2);
        // Same endpoints, different protocol.
        assert_eq!(t.lookup(a(1000), b(80), 17, ts(0), false).id, 3);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn a_syn_on_a_reused_tuple_starts_a_new_stream() {
        // Ports are reused. Two connections between the same pair are two
        // conversations, and Follow Stream must not splice them together.
        let mut t = StreamTable::new();
        let first = t.lookup(a(1000), b(80), 6, ts(0), true);
        let same = t.lookup(a(1000), b(80), 6, ts(1), false);
        assert_eq!(first.id, same.id);
        let second = t.lookup(a(1000), b(80), 6, ts(60), true);
        assert_ne!(second.id, first.id, "a new SYN is a new connection");
        assert!(second.first);
        // And traffic after it belongs to the new one.
        assert_eq!(t.lookup(b(80), a(1000), 6, ts(61), false).id, second.id);
    }

    #[test]
    fn direction_follows_whoever_spoke_first() {
        let mut t = StreamTable::new();
        // Server speaks first (a capture joined mid-stream).
        let s = t.lookup(b(80), a(1000), 6, ts(0), false);
        assert_eq!(s.direction, Direction::Forward);
        let c = t.lookup(a(1000), b(80), 6, ts(1), false);
        assert_eq!(c.direction, Direction::Reverse);
    }

    #[test]
    fn ipv4_and_ipv6_endpoints_do_not_collide() {
        let mut t = StreamTable::new();
        let v4 = Endpoint::v4([0, 0, 0, 1], 1);
        let mut sixteen = [0u8; 16];
        sixteen[3] = 1;
        let v6 = Endpoint::v6(sixteen, 1);
        assert_ne!(v4, v6, "the family must be part of the identity");
        let x = t.lookup(v4, b(80), 6, ts(0), false);
        let y = t.lookup(v6, b(80), 6, ts(0), false);
        assert_ne!(x.id, y.id);
    }

    #[test]
    fn the_table_is_bounded() {
        let mut t = StreamTable::new();
        t.max_streams = 64;
        t.idle_timeout_secs = 10;
        for i in 0..1000u16 {
            t.lookup(a(i), b(80), 6, ts(i64::from(i)), false);
        }
        assert!(
            t.len() <= t.max_streams,
            "held {} with a cap of {}",
            t.len(),
            t.max_streams
        );
        // Ids keep climbing even as entries are dropped, so an id is never
        // silently reused for a different conversation.
        assert_eq!(t.next_id(), 1000);
    }
}
