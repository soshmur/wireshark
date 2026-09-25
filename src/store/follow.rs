//! Follow Stream: the bytes of one conversation, in order, rebuilt from the
//! frames the store already holds.
//!
//! Nothing is kept per stream while capturing. Following walks the snapshot
//! once, gathers the frames carrying the stream id, orders each direction by
//! sequence number and joins them. Memory therefore does not grow with
//! traffic, which matters for a ring measured in gigabytes; the cost is one
//! pass over the store each time, which is milliseconds for the stream
//! lengths anyone actually reads.
//!
//! What it reconstructs is *what was captured*, which is not always what was
//! sent. Retransmissions are dropped, overlaps keep the bytes seen first, and
//! a range nothing covered is reported as a gap rather than silently closed
//! up — a stream with a hole in it must not look like a stream without one.

use crate::dissect::stream::Direction;
use crate::dissect::Frame;

use super::Snapshot;

/// One run of bytes from one end of the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub direction: Direction,
    /// Frame the run started in.
    pub frame: u32,
    pub bytes: Vec<u8>,
    /// Bytes missing immediately before this run, from segments the capture
    /// never saw.
    pub gap_before: u64,
}

/// Everything gathered for one stream.
#[derive(Debug, Clone, Default)]
pub struct Stream {
    pub id: u32,
    pub chunks: Vec<Chunk>,
    /// Frames that carried payload, per direction.
    pub frames: [u32; 2],
    pub bytes: [u64; 2],
    /// Total bytes the capture is missing.
    pub missing: u64,
    /// Frame numbers involved, in capture order.
    pub frame_numbers: Vec<u32>,
}

impl Stream {
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// The conversation as one run of bytes per direction.
    pub fn joined(&self, direction: Direction) -> Vec<u8> {
        let mut out = Vec::new();
        for c in self.chunks.iter().filter(|c| c.direction == direction) {
            out.extend_from_slice(&c.bytes);
        }
        out
    }
}

/// One segment's contribution, before ordering.
#[derive(Debug)]
struct Piece {
    direction: Direction,
    frame: u32,
    seq: u32,
    bytes: Vec<u8>,
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    }
}

/// `a` comes before `b` in sequence space, comparing the signed difference so
/// a stream that wraps past 2^32 still orders correctly.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// The payload a frame contributed to its stream, if any.
///
/// Read from the dissection tree rather than re-parsed: `tcp.stream` says
/// which conversation, `tcp.seq` where in it, and the transport layer's own
/// node bounds the payload.
fn piece_of(frame: &Frame, id: u32) -> Option<Piece> {
    let stream = frame
        .tree
        .find("tcp.stream")
        .chain(frame.tree.find("udp.stream"))
        .find_map(|n| n.unsigned())?;
    if stream != u64::from(id) {
        return None;
    }
    // Which way round: the frame's own direction bit is not stored, so it is
    // recovered by comparing against the first frame seen for the stream.
    // The caller supplies that via `origin`; here we only need the payload.
    let (seq, payload) = payload_of(frame)?;
    if payload.is_empty() {
        return None;
    }
    Some(Piece {
        direction: Direction::Forward,
        frame: frame.number,
        seq,
        bytes: payload,
    })
}

/// A frame's transport payload and its sequence number.
fn payload_of(frame: &Frame) -> Option<(u32, Vec<u8>)> {
    let tcp = frame.tree.find("tcp").next();
    if let Some(tcp) = tcp {
        let seq = frame
            .tree
            .find("tcp.seq")
            .next()
            .and_then(|n| n.unsigned())
            .unwrap_or(0) as u32;
        // The payload runs from the end of the TCP header to the end of the
        // layer's data source.
        let source = frame.source(tcp.source())?;
        let start = tcp.range().end;
        let bytes = source.get(start..)?.to_vec();
        return Some((seq, bytes));
    }
    let udp = frame.tree.find("udp").next()?;
    let source = frame.source(udp.source())?;
    let start = udp.range().end;
    // UDP has no sequence space; capture order is the only order.
    Some((frame.number, source.get(start..)?.to_vec()))
}

/// Gather stream `id` from `snapshot`.
pub fn follow(snapshot: &Snapshot, id: u32) -> Stream {
    let mut out = Stream {
        id,
        ..Stream::default()
    };
    // The direction bit is not on the frame, so it is recovered here: the
    // first frame of the stream defines "forward", and every later frame is
    // compared against its addresses.
    let mut origin: Option<(crate::dissect::Addr, crate::dissect::Addr)> = None;
    let mut pieces: Vec<Piece> = Vec::new();
    let mut is_udp = false;

    for frame in snapshot.iter() {
        let Some(mut piece) = piece_of(frame, id) else {
            continue;
        };
        let key = (frame.summary.source, frame.summary.destination);
        match &origin {
            None => origin = Some(key),
            Some((s, _)) => {
                if key.0 != *s {
                    piece.direction = Direction::Reverse;
                }
            }
        }
        is_udp |= frame.tree.find("udp.stream").next().is_some();
        out.frame_numbers.push(frame.number);
        let i = dir_index(piece.direction);
        out.frames[i] += 1;
        out.bytes[i] += piece.bytes.len() as u64;
        pieces.push(piece);
    }
    if pieces.is_empty() {
        return out;
    }
    out.chunks = if is_udp {
        // Datagrams have no sequence space: capture order is the order.
        pieces
            .into_iter()
            .map(|p| Chunk {
                direction: p.direction,
                frame: p.frame,
                bytes: p.bytes,
                gap_before: 0,
            })
            .collect()
    } else {
        assemble(pieces, &mut out.missing)
    };
    out
}

/// Order each direction by sequence number, drop what was already seen, and
/// record gaps. Directions are then interleaved by the frame each run began
/// in, so the result reads as a conversation.
fn assemble(pieces: Vec<Piece>, missing: &mut u64) -> Vec<Chunk> {
    let mut out: Vec<Chunk> = Vec::new();
    for dir in [Direction::Forward, Direction::Reverse] {
        let mut side: Vec<Piece> = pieces
            .iter()
            .filter(|p| p.direction == dir)
            .map(|p| Piece {
                direction: p.direction,
                frame: p.frame,
                seq: p.seq,
                bytes: p.bytes.clone(),
            })
            .collect();
        if side.is_empty() {
            continue;
        }
        // Sort by sequence, and by frame within equal sequences so a
        // retransmission follows the segment it repeats.
        side.sort_by(|a, b| {
            if a.seq == b.seq {
                a.frame.cmp(&b.frame)
            } else if seq_lt(a.seq, b.seq) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        let mut next = side[0].seq;
        for p in side {
            let end = p.seq.wrapping_add(p.bytes.len() as u32);
            if !seq_lt(next, end) {
                // Every byte already taken: a retransmission.
                continue;
            }
            let mut gap = 0u64;
            let bytes = if seq_lt(next, p.seq) {
                // A hole: nothing covered `next..p.seq`.
                gap = u64::from(p.seq.wrapping_sub(next));
                *missing += gap;
                p.bytes
            } else {
                // Overlap: keep the bytes already taken, add only what is new.
                let skip = next.wrapping_sub(p.seq) as usize;
                p.bytes.get(skip..).unwrap_or(&[]).to_vec()
            };
            if bytes.is_empty() {
                continue;
            }
            next = end;
            out.push(Chunk {
                direction: dir,
                frame: p.frame,
                bytes,
                gap_before: gap,
            });
        }
    }
    // Interleave the two directions by the frame each run came from, so the
    // transcript reads in the order the conversation happened.
    out.sort_by_key(|c| c.frame);
    out
}

/// How a chunk's bytes are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// Printable ASCII as itself, everything else as a dot.
    #[default]
    Ascii,
    /// Offset, hex, ASCII.
    Hex,
    /// UTF-8, with invalid sequences replaced.
    Utf8,
}

/// Render `bytes` for display.
pub fn render(bytes: &[u8], view: View) -> String {
    match view {
        View::Ascii => bytes
            .iter()
            .map(|b| match b {
                0x20..=0x7e => *b as char,
                b'\n' => '\n',
                b'\t' => '\t',
                b'\r' => '\r',
                _ => '.',
            })
            .collect(),
        View::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        View::Hex => {
            let mut out = String::with_capacity(bytes.len() * 4);
            for (i, row) in bytes.chunks(16).enumerate() {
                out.push_str(&format!("{:08x}  ", i * 16));
                for (j, b) in row.iter().enumerate() {
                    out.push_str(&format!("{b:02x} "));
                    if j == 7 {
                        out.push(' ');
                    }
                }
                for j in row.len()..16 {
                    out.push_str("   ");
                    if j == 7 {
                        out.push(' ');
                    }
                }
                out.push(' ');
                for b in row {
                    out.push(match b {
                        0x20..=0x7e => *b as char,
                        _ => '.',
                    });
                }
                out.push('\n');
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(frame: u32, seq: u32, bytes: &[u8]) -> Piece {
        Piece {
            direction: Direction::Forward,
            frame,
            seq,
            bytes: bytes.to_vec(),
        }
    }

    fn assembled(pieces: Vec<Piece>) -> (Vec<u8>, u64) {
        let mut missing = 0;
        let chunks = assemble(pieces, &mut missing);
        let mut bytes = Vec::new();
        for c in &chunks {
            bytes.extend_from_slice(&c.bytes);
        }
        (bytes, missing)
    }

    #[test]
    fn segments_in_order_join_end_to_end() {
        let (bytes, missing) = assembled(vec![piece(1, 100, b"hello "), piece(2, 106, b"world")]);
        assert_eq!(bytes, b"hello world");
        assert_eq!(missing, 0);
    }

    #[test]
    fn segments_out_of_order_are_put_back_in_order() {
        let (bytes, missing) = assembled(vec![piece(2, 106, b"world"), piece(1, 100, b"hello ")]);
        assert_eq!(bytes, b"hello world");
        assert_eq!(missing, 0);
    }

    #[test]
    fn a_retransmission_contributes_nothing() {
        // The application received these bytes once. A transcript showing
        // them twice would be a lie about the conversation.
        let (bytes, missing) = assembled(vec![
            piece(1, 100, b"hello "),
            piece(2, 100, b"hello "),
            piece(3, 106, b"world"),
        ]);
        assert_eq!(bytes, b"hello world");
        assert_eq!(missing, 0);
    }

    #[test]
    fn an_overlap_keeps_the_bytes_seen_first() {
        // The second segment repeats three bytes and adds two. Only the new
        // ones are taken, and taking the whole thing would duplicate "llo".
        let (bytes, missing) = assembled(vec![piece(1, 100, b"hello"), piece(2, 102, b"llo!!")]);
        assert_eq!(bytes, b"hello!!");
        assert_eq!(missing, 0);
    }

    #[test]
    fn a_hole_nothing_fills_is_reported() {
        // Bytes 106..112 were never captured. Joining "hello " to "world"
        // would produce a stream the sender never sent.
        let mut missing = 0;
        let chunks = assemble(
            vec![piece(1, 100, b"hello "), piece(2, 112, b"world")],
            &mut missing,
        );
        assert_eq!(missing, 6);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].gap_before, 0);
        assert_eq!(
            chunks[1].gap_before, 6,
            "the gap is attributed to the run after it"
        );
    }

    #[test]
    fn a_stream_that_wraps_past_the_sequence_limit_still_orders() {
        let base = u32::MAX - 3;
        let (bytes, missing) = assembled(vec![
            piece(2, base.wrapping_add(4), b"after"),
            piece(1, base, b"befo"),
        ]);
        assert_eq!(bytes, b"befoafter");
        assert_eq!(missing, 0);
    }

    #[test]
    fn the_two_directions_are_assembled_independently() {
        // Overlapping sequence numbers in opposite directions are unrelated;
        // treating them as one stream would drop half the conversation.
        let mut missing = 0;
        let chunks = assemble(
            vec![
                piece(1, 100, b"request"),
                Piece {
                    direction: Direction::Reverse,
                    frame: 2,
                    seq: 100,
                    bytes: b"response".to_vec(),
                },
            ],
            &mut missing,
        );
        assert_eq!(missing, 0);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].bytes, b"request");
        assert_eq!(chunks[1].bytes, b"response");
    }

    #[test]
    fn ascii_keeps_text_and_dots_the_rest() {
        assert_eq!(render(b"GET /\r\n\x00\xff", View::Ascii), "GET /\r\n..");
    }

    #[test]
    fn utf8_replaces_invalid_sequences_rather_than_failing() {
        assert_eq!(render(&[0xe2, 0x9c, 0x93], View::Utf8), "\u{2713}");
        assert!(!render(&[0xff, 0xfe], View::Utf8).is_empty());
    }

    #[test]
    fn hex_lines_up_in_sixteens() {
        let out = render(b"abc", View::Hex);
        assert!(out.starts_with("00000000  61 62 63 "), "{out:?}");
        assert!(out.trim_end().ends_with("abc"), "{out:?}");
        // Two rows for seventeen bytes.
        let long = render(&[0x41; 17], View::Hex);
        assert_eq!(long.lines().count(), 2);
        assert!(long
            .lines()
            .nth(1)
            .is_some_and(|l| l.starts_with("00000010")));
    }
}
