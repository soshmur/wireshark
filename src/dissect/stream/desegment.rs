//! Holding bytes of an incomplete PDU until the rest of it arrives.
//!
//! A TCP stream is bytes, not messages. An HTTP response or a TLS record can
//! start in one segment and finish three segments later, and a dissector
//! handed one segment at a time can only report what happens to be in it.
//! Desegmentation gives the sub-dissector the whole message.
//!
//! # How it fits the flat driver
//!
//! Dissection is a flat loop: a layer runs, records a handoff, and returns;
//! the driver then runs the next layer. TCP therefore cannot see what its
//! sub-dissector concluded — by the time HTTP says "I need more", TCP has
//! already returned.
//!
//! So the two halves are split by who knows what and when:
//!
//! - **Before the handoff**, TCP asks whether this stream and direction have
//!   bytes pending. That it can know. If so it prepends them to the payload,
//!   publishes the result as a new data source, and hands off into that.
//! - **After parsing**, the sub-dissector says how much it consumed. What is
//!   left becomes the new pending buffer.
//!
//! Neither half needs to know what the other concluded, and the loop stays
//! flat.
//!
//! # What it deliberately does not do
//!
//! Out-of-order segments are not held and replayed. A stream that arrives out
//! of order stops being desegmented until it lines up again, and the frames
//! in between are dissected individually. Holding them would mean a second
//! reassembly buffer with its own ordering, cap and timeout, and the analyser
//! already reports the reordering that caused it.

use std::collections::HashMap;

use crate::capture::Timestamp;
use crate::dissect::ctx::Proto;

use super::Direction;

/// Bytes held per direction of one conversation. Beyond this the pending
/// buffer is dropped and the stream falls back to per-segment dissection: a
/// sub-dissector that keeps asking for more, because a length field said so,
/// must not be able to make netscope hold a gigabyte.
pub const MAX_PENDING_PER_DIRECTION: usize = 1 << 20;

/// Directions holding bytes, across all conversations.
pub const MAX_PENDING_DIRECTIONS: usize = 4096;

/// Pending bytes are abandoned if nothing continues the stream for this long.
pub const IDLE_TIMEOUT_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    stream: u32,
    reverse: bool,
}

#[derive(Debug)]
struct Pending {
    bytes: Vec<u8>,
    origin: Origin,
    last_seen: Timestamp,
}

/// Where a held message came from, carried forward each time it grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {
    /// The dissector that asked for more. The same one gets the combined
    /// buffer, rather than re-running the port heuristics on a fragment.
    pub proto: Proto,
    /// Frame the message started in.
    pub first_frame: u32,
    /// Frames that have contributed to it, including the current one.
    pub frames: u32,
}

/// What TCP should do with a segment's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefix {
    /// Nothing pending: dissect the payload where it lies.
    None,
    /// Pending bytes exist; dissect this buffer instead.
    Combined { bytes: Vec<u8>, origin: Origin },
}

#[derive(Debug, Default)]
pub struct Desegment {
    pending: HashMap<Key, Pending>,
}

impl Desegment {
    pub fn new() -> Desegment {
        Desegment::default()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn key(stream: u32, dir: Direction) -> Key {
        Key {
            stream,
            reverse: dir == Direction::Reverse,
        }
    }

    /// Take whatever is pending for this direction and combine it with
    /// `payload`. Called by TCP before handing off.
    pub fn take(&mut self, stream: u32, dir: Direction, payload: &[u8], now: Timestamp) -> Prefix {
        let key = Self::key(stream, dir);
        let Some(p) = self.pending.remove(&key) else {
            return Prefix::None;
        };
        // Abandon a buffer nothing has continued for a minute: the connection
        // is gone, or the length that asked for more was nonsense.
        if now.secs.saturating_sub(p.last_seen.secs) > IDLE_TIMEOUT_SECS {
            return Prefix::None;
        }
        let mut bytes = p.bytes;
        bytes.extend_from_slice(payload);
        Prefix::Combined {
            bytes,
            origin: Origin {
                frames: p.origin.frames + 1,
                ..p.origin
            },
        }
    }

    /// Keep `bytes` until more of the stream arrives. Returns false when the
    /// request was refused, in which case the caller must dissect what it has
    /// rather than waiting for bytes that will never be held.
    pub fn keep(
        &mut self,
        stream: u32,
        dir: Direction,
        bytes: &[u8],
        origin: Origin,
        now: Timestamp,
    ) -> bool {
        if bytes.is_empty() || bytes.len() > MAX_PENDING_PER_DIRECTION {
            return false;
        }
        let key = Self::key(stream, dir);
        if !self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING_DIRECTIONS {
            self.expire(now);
            if self.pending.len() >= MAX_PENDING_DIRECTIONS {
                return false;
            }
        }
        self.pending.insert(
            key,
            Pending {
                bytes: bytes.to_vec(),
                origin: Origin {
                    frames: origin.frames.max(1),
                    ..origin
                },
                last_seen: now,
            },
        );
        true
    }

    /// Forget this direction's pending bytes: the stream reset, closed, or
    /// went out of order.
    pub fn forget(&mut self, stream: u32, dir: Direction) {
        self.pending.remove(&Self::key(stream, dir));
    }

    /// Drop buffers nothing has continued within the timeout.
    pub fn expire(&mut self, now: Timestamp) {
        let cutoff = now.secs.saturating_sub(IDLE_TIMEOUT_SECS);
        self.pending.retain(|_, p| p.last_seen.secs >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> Timestamp {
        Timestamp { secs, nanos: 0 }
    }

    /// A message starting in `frame`, nothing held yet.
    fn start(proto: Proto, frame: u32) -> Origin {
        Origin {
            proto,
            first_frame: frame,
            frames: 1,
        }
    }

    const FWD: Direction = Direction::Forward;
    const REV: Direction = Direction::Reverse;

    #[test]
    fn nothing_pending_means_dissect_in_place() {
        let mut d = Desegment::new();
        assert_eq!(d.take(0, FWD, b"abc", ts(0)), Prefix::None);
    }

    #[test]
    fn held_bytes_come_back_in_front_of_the_next_payload() {
        let mut d = Desegment::new();
        assert!(d.keep(0, FWD, b"GET /", start(Proto::Http, 1), ts(0)));
        match d.take(0, FWD, b" HTTP/1.1", ts(1)) {
            Prefix::Combined { bytes, origin } => {
                assert_eq!(bytes, b"GET / HTTP/1.1");
                assert_eq!(origin.proto, Proto::Http);
                assert_eq!(origin.first_frame, 1);
                assert_eq!(origin.frames, 2, "the frame being dissected counts too");
            }
            other => panic!("{other:?}"),
        }
        // Taking consumes: a second call finds nothing.
        assert_eq!(d.take(0, FWD, b"x", ts(2)), Prefix::None);
    }

    #[test]
    fn the_two_directions_are_independent() {
        let mut d = Desegment::new();
        d.keep(0, FWD, b"out", start(Proto::Http, 1), ts(0));
        d.keep(0, REV, b"back", start(Proto::Http, 2), ts(0));
        let Prefix::Combined { bytes, .. } = d.take(0, REV, b"!", ts(1)) else {
            panic!("reverse should have bytes");
        };
        assert_eq!(bytes, b"back!");
        let Prefix::Combined { bytes, .. } = d.take(0, FWD, b"!", ts(1)) else {
            panic!("forward should have bytes");
        };
        assert_eq!(bytes, b"out!");
    }

    #[test]
    fn streams_do_not_share_a_buffer() {
        let mut d = Desegment::new();
        d.keep(0, FWD, b"zero", start(Proto::Http, 1), ts(0));
        d.keep(1, FWD, b"one", start(Proto::Tls, 2), ts(0));
        let Prefix::Combined { bytes, origin } = d.take(1, FWD, b"!", ts(1)) else {
            panic!("stream 1 should have bytes");
        };
        assert_eq!(bytes, b"one!");
        assert_eq!(origin.proto, Proto::Tls);
        let Prefix::Combined { bytes, origin } = d.take(0, FWD, b"!", ts(1)) else {
            panic!("stream 0 should have bytes");
        };
        assert_eq!(bytes, b"zero!");
        assert_eq!(origin.proto, Proto::Http);
    }

    #[test]
    fn an_oversized_buffer_is_refused_rather_than_held() {
        // A length field saying "I need 4 GB more" must not be able to make
        // netscope hold it.
        let mut d = Desegment::new();
        let huge = vec![0u8; MAX_PENDING_PER_DIRECTION + 1];
        assert!(!d.keep(0, FWD, &huge, start(Proto::Tls, 1), ts(0)));
        assert!(d.is_empty());
        // And the caller is told, so it can dissect what it has.
        assert_eq!(d.take(0, FWD, b"x", ts(1)), Prefix::None);
    }

    #[test]
    fn empty_bytes_are_not_held() {
        let mut d = Desegment::new();
        assert!(!d.keep(0, FWD, b"", start(Proto::Http, 1), ts(0)));
        assert!(d.is_empty());
    }

    #[test]
    fn a_stale_buffer_is_abandoned() {
        let mut d = Desegment::new();
        d.keep(0, FWD, b"half a message", start(Proto::Http, 1), ts(0));
        // Two minutes later the rest arrives. Splicing it on would produce a
        // message that never existed.
        assert_eq!(d.take(0, FWD, b"rest", ts(120)), Prefix::None);
    }

    #[test]
    fn the_number_of_held_directions_is_bounded() {
        let mut d = Desegment::new();
        for i in 0..(MAX_PENDING_DIRECTIONS as u32 * 2) {
            d.keep(i, FWD, b"x", start(Proto::Http, 1), ts(i64::from(i)));
        }
        assert!(
            d.len() <= MAX_PENDING_DIRECTIONS,
            "held {} with a cap of {MAX_PENDING_DIRECTIONS}",
            d.len()
        );
    }

    #[test]
    fn forgetting_drops_the_buffer() {
        let mut d = Desegment::new();
        d.keep(0, FWD, b"half", start(Proto::Http, 1), ts(0));
        d.forget(0, FWD);
        assert_eq!(d.take(0, FWD, b"rest", ts(1)), Prefix::None);
    }

    #[test]
    fn continuing_a_buffer_keeps_the_first_frame() {
        let mut d = Desegment::new();
        d.keep(0, FWD, b"a", start(Proto::Http, 10), ts(0));
        let Prefix::Combined { origin, .. } = d.take(0, FWD, b"b", ts(1)) else {
            panic!("expected pending bytes");
        };
        assert_eq!((origin.first_frame, origin.frames), (10, 2));
        // Still incomplete: hold again, carrying the origin forward.
        d.keep(0, FWD, b"ab", origin, ts(1));
        let Prefix::Combined { origin, .. } = d.take(0, FWD, b"c", ts(2)) else {
            panic!("expected pending bytes");
        };
        assert_eq!(
            (origin.first_frame, origin.frames),
            (10, 3),
            "the message still starts in frame 10"
        );
    }
}
