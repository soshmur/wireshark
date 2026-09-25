//! TCP sequence analysis.
//!
//! One `Analysis` per conversation, holding a little state for each
//! direction, classifies every segment as it arrives: retransmission,
//! out-of-order, a gap where a segment was never captured, a duplicate ACK,
//! a zero window, and so on.
//!
//! Everything here is a *heuristic over what was captured*, not a claim about
//! what the endpoints did. A capture taken in the middle of a connection, or
//! one that missed packets, will produce findings that say so rather than
//! being silently wrong — `LostSegment` means "the capture has a hole here",
//! which is usually a capture problem and not a network one.
//!
//! Sequence numbers are 32-bit and wrap. Every comparison in this file goes
//! through `seq_lt`/`seq_gt`, which compare the signed difference, so a
//! connection that wraps past 2^32 is analysed correctly rather than
//! reporting every segment after the wrap as a gap.

use crate::capture::Timestamp;
use crate::dissect::expert::Severity;

use super::Direction;

/// Reordering that arrives within this window is treated as the network
/// delivering out of order rather than as a retransmission. Wireshark uses
/// 3 ms; the exact value matters less than having one, since without it every
/// reordered segment is reported as a retransmission.
const OUT_OF_ORDER_NANOS: i128 = 3_000_000;

/// A retransmission this soon after the third duplicate ACK is the sender
/// reacting to those ACKs rather than to a timeout.
const FAST_RETRANSMIT_NANOS: i128 = 20_000_000;

/// What the analyser concluded about one segment. At most one *sequence*
/// finding applies, because they are alternative explanations of the same
/// observation; the window and ACK findings are independent and are reported
/// alongside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Findings {
    pub sequence: Option<SeqFinding>,
    /// This ACK repeats the previous one and acknowledges nothing new.
    pub duplicate_ack: Option<DupAck>,
    /// The sender advertised a window of zero: it cannot accept data.
    pub zero_window: bool,
    /// This segment fills the peer's advertised window exactly; the sender
    /// cannot send more until the peer acknowledges.
    pub window_full: bool,
    /// A probe to keep the connection alive, not real data.
    pub keep_alive: bool,
    /// An ACK for data this capture never saw.
    pub ack_lost_segment: bool,
    /// Bytes sent but not yet acknowledged, after this segment.
    pub bytes_in_flight: u32,
}

impl Findings {
    /// True when nothing worth reporting was found. `bytes_in_flight` is a
    /// measurement rather than a finding and does not count: an ordinary
    /// segment in a healthy transfer has bytes in flight and nothing wrong
    /// with it.
    pub fn is_empty(&self) -> bool {
        Findings {
            bytes_in_flight: 0,
            ..*self
        } == Findings::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqFinding {
    /// Bytes already seen, sent again after a timeout.
    Retransmission,
    /// Sent again in response to duplicate ACKs rather than a timeout.
    FastRetransmission,
    /// Sent again although the peer had already acknowledged it.
    SpuriousRetransmission,
    /// Arrived after a later segment, within the reordering window.
    OutOfOrder,
    /// Partly old bytes and partly new.
    Overlap,
    /// The sequence jumped forward: something between was never captured.
    LostSegment,
}

impl SeqFinding {
    pub fn abbrev(self) -> &'static str {
        match self {
            SeqFinding::Retransmission => "tcp.analysis.retransmission",
            SeqFinding::FastRetransmission => "tcp.analysis.fast_retransmission",
            SeqFinding::SpuriousRetransmission => "tcp.analysis.spurious_retransmission",
            SeqFinding::OutOfOrder => "tcp.analysis.out_of_order",
            SeqFinding::Overlap => "tcp.analysis.overlap",
            SeqFinding::LostSegment => "tcp.analysis.lost_segment",
        }
    }

    /// How much attention this deserves. A resend is normal on any real
    /// network; a gap or an overlap means the capture or the sender is doing
    /// something that will mislead anyone reading the stream.
    pub fn severity(self) -> Severity {
        match self {
            SeqFinding::Retransmission
            | SeqFinding::FastRetransmission
            | SeqFinding::SpuriousRetransmission
            | SeqFinding::OutOfOrder => Severity::Note,
            SeqFinding::Overlap | SeqFinding::LostSegment => Severity::Warn,
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            SeqFinding::Retransmission => "This frame is a (suspected) retransmission",
            SeqFinding::FastRetransmission => "This frame is a (suspected) fast retransmission",
            SeqFinding::SpuriousRetransmission => {
                "This frame is a (suspected) spurious retransmission"
            }
            SeqFinding::OutOfOrder => "This frame is a (suspected) out-of-order segment",
            SeqFinding::Overlap => "This frame overlaps bytes already seen",
            SeqFinding::LostSegment => "Previous segment(s) not captured (common at capture start)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DupAck {
    /// 1 for the first repeat, 2 for the second, and so on.
    pub number: u32,
    /// The frame carrying the ACK this one repeats.
    pub frame: u32,
}

/// One segment as the dissector read it, before analysis.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    pub frame: u32,
    pub ts: Timestamp,
    pub seq: u32,
    pub ack: u32,
    pub payload_len: u32,
    pub window: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub ack_flag: bool,
    /// Window scale from this direction's SYN, if it carried one.
    pub window_scale: Option<u8>,
}

impl Segment {
    /// Bytes this segment consumes of the sequence space. SYN and FIN each
    /// take one, which is why a bare SYN advances the sequence number.
    fn seq_len(&self) -> u32 {
        self.payload_len + u32::from(self.syn) + u32::from(self.fin)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DirState {
    seen: bool,
    /// The sequence number expected next: the highest `seq + seq_len` seen.
    next_seq: u32,
    /// Initial sequence number, for relative numbering.
    isn: u32,
    /// Highest ACK this direction has sent.
    last_ack: u32,
    /// Whether `last_ack` has been set.
    acked: bool,
    /// Window this direction last advertised, already scaled.
    last_window: u32,
    /// Scale factor from this direction's SYN; `None` until seen.
    window_scale: Option<u8>,
    /// Consecutive repeats of `last_ack`.
    dup_ack_count: u32,
    /// Frame of the ACK the repeats are repeating.
    dup_ack_frame: u32,
    /// When `next_seq` was last advanced, for the reordering window.
    last_advance: Option<Timestamp>,
    /// When this direction last sent its third duplicate ACK.
    third_dup_ack: Option<Timestamp>,
    pub frames: u64,
    pub bytes: u64,
}

/// Per-conversation TCP state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Analysis {
    dirs: [DirState; 2],
    /// True once a SYN has been seen, meaning sequence numbers are anchored
    /// to a real connection start rather than to wherever the capture began.
    pub saw_syn: bool,
}

fn idx(d: Direction) -> usize {
    match d {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    }
}

/// `a < b` in sequence space, comparing the signed difference so the
/// comparison stays correct across the 2^32 wrap.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn seq_le(a: u32, b: u32) -> bool {
    !seq_gt(a, b)
}

fn nanos_between(a: Timestamp, b: Timestamp) -> i128 {
    let secs = i128::from(b.secs - a.secs);
    secs * 1_000_000_000 + i128::from(b.nanos) - i128::from(a.nanos)
}

impl Analysis {
    /// Relative sequence number: how far into the stream this is, counting
    /// from the first sequence number seen in that direction.
    pub fn relative(&self, dir: Direction, seq: u32) -> u32 {
        let d = &self.dirs[idx(dir)];
        if d.seen {
            seq.wrapping_sub(d.isn)
        } else {
            0
        }
    }

    pub fn frames(&self, dir: Direction) -> u64 {
        self.dirs[idx(dir)].frames
    }

    pub fn bytes(&self, dir: Direction) -> u64 {
        self.dirs[idx(dir)].bytes
    }

    /// Classify `seg`, then fold it into the state.
    pub fn observe(&mut self, dir: Direction, seg: &Segment) -> Findings {
        let me = idx(dir);
        let peer = 1 - me;
        let mut out = Findings::default();
        if seg.syn {
            self.saw_syn = true;
        }

        // Window scale is announced on the SYN and applies to every later
        // segment in that direction, so it is recorded before anything uses
        // the window.
        if let Some(s) = seg.window_scale {
            self.dirs[me].window_scale = Some(s);
        }
        // The scale does not apply to the SYN's own window.
        let scaled = if seg.syn {
            seg.window
        } else {
            match self.dirs[me].window_scale {
                Some(s) => seg.window << s.min(14),
                None => seg.window,
            }
        };

        let seq_len = seg.seq_len();
        let first = !self.dirs[me].seen;
        // What this direction expected *before* this segment. The keep-alive
        // test needs it: comparing against the updated value makes every
        // legitimate one-byte segment look like a probe, because after the
        // update its own sequence number is exactly `next_seq - 1`.
        let expected_before = self.dirs[me].next_seq;
        if first {
            self.dirs[me].seen = true;
            self.dirs[me].isn = seg.seq;
            self.dirs[me].next_seq = seg.seq.wrapping_add(seq_len);
            self.dirs[me].last_advance = Some(seg.ts);
        } else {
            out.sequence = self.classify_sequence(me, peer, seg, seq_len);
            let end = seg.seq.wrapping_add(seq_len);
            if seq_gt(end, self.dirs[me].next_seq) {
                self.dirs[me].next_seq = end;
                self.dirs[me].last_advance = Some(seg.ts);
            }
        }

        // A keep-alive sits one byte before what the peer expects, carrying
        // nothing or one garbage byte. It is not a retransmission even though
        // it looks like one, so it overrides the sequence finding.
        if !seg.syn
            && !seg.fin
            && !seg.rst
            && seg.payload_len <= 1
            && !first
            && seg.seq == expected_before.wrapping_sub(1)
        {
            out.keep_alive = true;
            out.sequence = None;
        }

        out.zero_window = scaled == 0 && !seg.rst && !seg.fin && !seg.syn;

        if seg.ack_flag {
            out.duplicate_ack = self.classify_ack(me, peer, seg, scaled, seq_len);
            // An ACK for data we never saw: the capture started mid-stream or
            // dropped the segment being acknowledged.
            if self.dirs[peer].seen && seq_gt(seg.ack, self.dirs[peer].next_seq) {
                out.ack_lost_segment = true;
            }
            self.dirs[me].last_ack = seg.ack;
            self.dirs[me].acked = true;
        }
        self.dirs[me].last_window = scaled;

        // In flight: sent but not yet acknowledged by the peer. Only
        // meaningful when the peer's ACK falls inside the range this
        // direction has actually sent. On a capture joined mid-stream the two
        // sides' sequence numbers bear no relation to anything we saw, and
        // subtracting them yields a number that looks like gigabytes.
        let peer_ack = self.dirs[peer].last_ack;
        let in_range = self.dirs[peer].acked
            && self.dirs[me].seen
            && !seq_lt(peer_ack, self.dirs[me].isn)
            && seq_le(peer_ack, self.dirs[me].next_seq);
        out.bytes_in_flight = if in_range {
            self.dirs[me].next_seq.wrapping_sub(peer_ack)
        } else {
            0
        };

        // The sender has filled the window the peer advertised.
        if seg.payload_len > 0 && self.dirs[peer].last_window > 0 {
            out.window_full = out.bytes_in_flight >= self.dirs[peer].last_window;
        }

        self.dirs[me].frames += 1;
        self.dirs[me].bytes += u64::from(seg.payload_len);
        out
    }

    fn classify_sequence(
        &mut self,
        me: usize,
        peer: usize,
        seg: &Segment,
        seq_len: u32,
    ) -> Option<SeqFinding> {
        let next = self.dirs[me].next_seq;
        let end = seg.seq.wrapping_add(seq_len);

        if seq_gt(seg.seq, next) {
            // A jump forward: whatever sits in the gap was never captured.
            return Some(SeqFinding::LostSegment);
        }
        if seq_len == 0 {
            // A pure ACK repeats no data, so none of the retransmission
            // findings apply to it.
            return None;
        }
        if seq_gt(end, next) {
            // Starts inside what we have but runs past it.
            return if seq_lt(seg.seq, next) {
                Some(SeqFinding::Overlap)
            } else {
                None // seg.seq == next: the ordinary case.
            };
        }

        // Every byte has been seen before. Which explanation fits?
        if self.dirs[peer].acked && seq_le(end, self.dirs[peer].last_ack) {
            return Some(SeqFinding::SpuriousRetransmission);
        }
        if let Some(third) = self.dirs[peer].third_dup_ack {
            if nanos_between(third, seg.ts) <= FAST_RETRANSMIT_NANOS {
                return Some(SeqFinding::FastRetransmission);
            }
        }
        if let Some(last) = self.dirs[me].last_advance {
            if nanos_between(last, seg.ts) <= OUT_OF_ORDER_NANOS {
                return Some(SeqFinding::OutOfOrder);
            }
        }
        Some(SeqFinding::Retransmission)
    }

    fn classify_ack(
        &mut self,
        me: usize,
        peer: usize,
        seg: &Segment,
        scaled: u32,
        seq_len: u32,
    ) -> Option<DupAck> {
        // A duplicate ACK carries no data, changes nothing, and repeats the
        // previous acknowledgement while the peer still has data outstanding.
        let repeats = self.dirs[me].acked
            && seg.ack == self.dirs[me].last_ack
            && seq_len == 0
            && !seg.syn
            && !seg.fin
            && !seg.rst
            && scaled == self.dirs[me].last_window
            && self.dirs[peer].seen
            && seq_lt(seg.ack, self.dirs[peer].next_seq);
        if !repeats {
            self.dirs[me].dup_ack_count = 0;
            self.dirs[me].dup_ack_frame = seg.frame;
            self.dirs[me].third_dup_ack = None;
            return None;
        }
        self.dirs[me].dup_ack_count += 1;
        let number = self.dirs[me].dup_ack_count;
        if number == 3 {
            self.dirs[me].third_dup_ack = Some(seg.ts);
        }
        Some(DupAck {
            number,
            frame: self.dirs[me].dup_ack_frame,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(ms: i64) -> Timestamp {
        Timestamp {
            secs: ms / 1000,
            nanos: ((ms % 1000) * 1_000_000) as u32,
        }
    }

    /// A data segment with sensible defaults.
    fn seg(frame: u32, ms: i64, seq: u32, len: u32) -> Segment {
        Segment {
            frame,
            ts: ts(ms),
            seq,
            ack: 1,
            payload_len: len,
            window: 65535,
            syn: false,
            fin: false,
            rst: false,
            ack_flag: true,
            window_scale: None,
        }
    }

    fn ack(frame: u32, ms: i64, ack: u32) -> Segment {
        Segment {
            ack,
            payload_len: 0,
            ..seg(frame, ms, 1, 0)
        }
    }

    const FWD: Direction = Direction::Forward;
    const REV: Direction = Direction::Reverse;

    #[test]
    fn ordinary_traffic_produces_no_findings() {
        let mut a = Analysis::default();
        assert!(a.observe(FWD, &seg(1, 0, 1000, 100)).is_empty());
        assert!(a.observe(FWD, &seg(2, 10, 1100, 100)).is_empty());
        assert!(a.observe(FWD, &seg(3, 20, 1200, 100)).is_empty());
    }

    #[test]
    fn a_repeat_after_a_pause_is_a_retransmission() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        a.observe(FWD, &seg(2, 10, 1100, 100));
        // Same bytes again, long after: a timeout retransmission.
        let f = a.observe(FWD, &seg(3, 500, 1100, 100));
        assert_eq!(f.sequence, Some(SeqFinding::Retransmission));
    }

    #[test]
    fn a_repeat_within_the_reordering_window_is_out_of_order() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        // 1200 arrives before 1100.
        a.observe(FWD, &seg(2, 10, 1200, 100));
        let f = a.observe(FWD, &seg(3, 10, 1100, 100));
        assert_eq!(
            f.sequence,
            Some(SeqFinding::OutOfOrder),
            "same millisecond means the network reordered, not the sender resent"
        );
    }

    #[test]
    fn a_gap_is_reported_as_a_lost_segment() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        // 1100..1200 never captured.
        let f = a.observe(FWD, &seg(2, 10, 1200, 100));
        assert_eq!(f.sequence, Some(SeqFinding::LostSegment));
        // And the state moves on, so the next segment is ordinary.
        assert!(a.observe(FWD, &seg(3, 20, 1300, 100)).is_empty());
    }

    #[test]
    fn a_segment_that_is_partly_new_is_an_overlap() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        // Starts 50 bytes back but runs 50 past what we have.
        let f = a.observe(FWD, &seg(2, 500, 1050, 100));
        assert_eq!(f.sequence, Some(SeqFinding::Overlap));
    }

    #[test]
    fn resending_data_the_peer_already_acknowledged_is_spurious() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        a.observe(REV, &ack(2, 5, 1100));
        let f = a.observe(FWD, &seg(3, 500, 1000, 100));
        assert_eq!(f.sequence, Some(SeqFinding::SpuriousRetransmission));
    }

    #[test]
    fn duplicate_acks_are_counted_and_point_at_the_original() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        a.observe(FWD, &seg(2, 1, 1200, 100)); // gap: 1100..1200 lost
        let first = a.observe(REV, &ack(3, 2, 1100));
        assert_eq!(first.duplicate_ack, None, "the first ACK is not a repeat");
        let d1 = a.observe(REV, &ack(4, 3, 1100)).duplicate_ack;
        let d2 = a.observe(REV, &ack(5, 4, 1100)).duplicate_ack;
        let d3 = a.observe(REV, &ack(6, 5, 1100)).duplicate_ack;
        assert_eq!(d1.map(|d| d.number), Some(1));
        assert_eq!(d2.map(|d| d.number), Some(2));
        assert_eq!(d3.map(|d| d.number), Some(3));
        assert_eq!(d3.map(|d| d.frame), Some(3), "points at the ACK repeated");
    }

    #[test]
    fn a_resend_just_after_three_duplicate_acks_is_a_fast_retransmission() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        a.observe(FWD, &seg(2, 1, 1200, 100));
        a.observe(REV, &ack(3, 2, 1100));
        a.observe(REV, &ack(4, 3, 1100));
        a.observe(REV, &ack(5, 4, 1100));
        a.observe(REV, &ack(6, 5, 1100));
        // The sender reacts immediately, not after a timeout.
        let f = a.observe(FWD, &seg(7, 6, 1100, 100));
        assert_eq!(f.sequence, Some(SeqFinding::FastRetransmission));
    }

    #[test]
    fn an_ack_that_moves_forward_ends_the_duplicate_run() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 200));
        a.observe(REV, &ack(2, 1, 1100));
        assert!(a.observe(REV, &ack(3, 2, 1100)).duplicate_ack.is_some());
        assert_eq!(a.observe(REV, &ack(4, 3, 1200)).duplicate_ack, None);
        // And the count restarts rather than continuing from 2.
        a.observe(FWD, &seg(5, 4, 1200, 100));
        assert_eq!(
            a.observe(REV, &ack(6, 5, 1200))
                .duplicate_ack
                .map(|d| d.number),
            Some(1)
        );
    }

    #[test]
    fn a_zero_window_is_reported() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        let stall = Segment {
            window: 0,
            ..ack(2, 1, 1100)
        };
        assert!(a.observe(REV, &stall).zero_window);
        // But a RST with a zero window is just a reset.
        let reset = Segment {
            window: 0,
            rst: true,
            ..ack(3, 2, 1100)
        };
        assert!(!a.observe(REV, &reset).zero_window);
    }

    #[test]
    fn the_window_scale_from_the_syn_applies_to_later_segments() {
        // Without the scale the peer looks like it advertised 1,000 bytes and
        // a 1,500-byte segment would read as having filled the window. With
        // it the real window is 128,000 and nothing is full.
        let mut a = Analysis::default();
        a.observe(
            FWD,
            &Segment {
                syn: true,
                ack_flag: false,
                window: 1000,
                window_scale: Some(7),
                ..seg(1, 0, 1000, 0)
            },
        );
        a.observe(
            REV,
            &Segment {
                syn: true,
                ack: 1001,
                window: 1000,
                window_scale: Some(7),
                ..seg(2, 1, 5000, 0)
            },
        );
        a.observe(FWD, &ack(3, 2, 5001));
        // The peer's first segment after the handshake: 1000 << 7 = 128,000.
        a.observe(
            REV,
            &Segment {
                window: 1000,
                ..ack(4, 3, 1001)
            },
        );
        let f = a.observe(
            FWD,
            &Segment {
                ack: 5001,
                ..seg(5, 4, 1001, 1500)
            },
        );
        assert_eq!(f.bytes_in_flight, 1500);
        assert!(!f.window_full, "1,500 of a 128,000-byte window is not full");
    }

    #[test]
    fn filling_the_peers_window_is_reported() {
        let mut a = Analysis::default();
        // The peer advertises a small window and acknowledges nothing.
        a.observe(FWD, &seg(1, 0, 1000, 0));
        let small = Segment {
            window: 100,
            ..ack(2, 1, 1000)
        };
        a.observe(REV, &small);
        let f = a.observe(FWD, &seg(3, 2, 1000, 100));
        assert!(f.window_full, "100 bytes exactly fills a 100-byte window");
        assert_eq!(f.bytes_in_flight, 100);
    }

    #[test]
    fn a_keep_alive_is_not_a_retransmission() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        // One byte at next_seq - 1, long after: a keep-alive probe.
        let f = a.observe(FWD, &seg(2, 5000, 1099, 1));
        assert!(f.keep_alive);
        assert_eq!(f.sequence, None, "a keep-alive must not read as a resend");
    }

    #[test]
    fn a_one_byte_segment_that_advances_the_stream_is_not_a_keep_alive() {
        // A probe re-sends the last byte already sent. A one-byte segment at
        // the expected sequence number is ordinary data, and calling it a
        // keep-alive was a false positive on every small write.
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 0));
        let f = a.observe(FWD, &seg(2, 10, 1000, 1));
        assert!(!f.keep_alive);
        assert_eq!(f.sequence, None);
        // And the genuine probe still is one.
        let f = a.observe(FWD, &seg(3, 5000, 1000, 1));
        assert!(f.keep_alive);
    }

    #[test]
    fn an_ack_for_data_never_captured_is_reported() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        // Acknowledges far beyond anything this capture saw sent.
        let f = a.observe(REV, &ack(2, 1, 9000));
        assert!(f.ack_lost_segment);
    }

    #[test]
    fn sequence_numbers_that_wrap_are_handled() {
        // The failure this guards against: after the wrap, every segment
        // looks like an enormous backward jump and is reported as a
        // retransmission, or an enormous forward one and reported as a gap.
        let mut a = Analysis::default();
        let base = u32::MAX - 150;
        a.observe(FWD, &seg(1, 0, base, 100));
        let after_wrap = base.wrapping_add(100);
        assert!(
            a.observe(FWD, &seg(2, 10, after_wrap, 100)).is_empty(),
            "the segment straddling the wrap is ordinary"
        );
        let next = after_wrap.wrapping_add(100);
        assert!(a.observe(FWD, &seg(3, 20, next, 100)).is_empty());
        // And a genuine resend after the wrap is still caught.
        let f = a.observe(FWD, &seg(4, 500, after_wrap, 100));
        assert_eq!(f.sequence, Some(SeqFinding::Retransmission));
    }

    #[test]
    fn relative_numbering_counts_from_the_first_segment_seen() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1_000_000, 100));
        assert_eq!(a.relative(FWD, 1_000_000), 0);
        assert_eq!(a.relative(FWD, 1_000_100), 100);
        // Each direction has its own initial sequence number.
        a.observe(REV, &seg(2, 1, 7_000_000, 0));
        assert_eq!(a.relative(REV, 7_000_050), 50);
    }

    #[test]
    fn the_first_segment_in_a_direction_is_never_a_finding() {
        // A capture joined mid-stream must not report its very first segment
        // as a gap just because the sequence number is not zero.
        let mut a = Analysis::default();
        assert!(a.observe(FWD, &seg(1, 0, 123_456, 100)).is_empty());
        assert!(a.observe(REV, &seg(2, 1, 987_654, 100)).is_empty());
    }

    #[test]
    fn per_direction_counters_add_up() {
        let mut a = Analysis::default();
        a.observe(FWD, &seg(1, 0, 1000, 100));
        a.observe(FWD, &seg(2, 1, 1100, 50));
        a.observe(REV, &seg(3, 2, 5000, 10));
        assert_eq!(a.frames(FWD), 2);
        assert_eq!(a.bytes(FWD), 150);
        assert_eq!(a.frames(REV), 1);
        assert_eq!(a.bytes(REV), 10);
    }
}
