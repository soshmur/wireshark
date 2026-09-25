//! Classic pcap reader. Every length is bounds-checked and every field is
//! treated as adversarial: a savefile is untrusted input like any other.

use std::fmt;
use std::sync::Arc;

use super::{Format, Header, Precision, MAGIC_MICROS, MAGIC_NANOS};
use crate::capture::{RawFrame, Timestamp};

/// A record header is four 32-bit fields.
const RECORD_HEADER: usize = 16;
const FILE_HEADER: usize = 24;

/// Refuse a record claiming more bytes than this. libpcap's own limit is
/// 262,144; files in the wild occasionally carry more, so the cap is
/// generous, but a record claiming four gigabytes is a corrupt length field
/// and allocating for it would be the bug the field was aiming for.
pub const MAX_RECORD: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    NotPcap,
    /// The Kuznetsov variant, which shares pcap's shape but not its record
    /// layout. Named rather than misread.
    Modified,
    Truncated {
        at: usize,
    },
    BadRecord {
        at: usize,
        what: &'static str,
    },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotPcap => write!(f, "not a pcap file"),
            ReadError::Modified => write!(
                f,
                "this is a modified-format pcap (magic a1b2cd34), which netscope cannot read; \
                 convert it with `editcap` or `tcpdump -r`"
            ),
            ReadError::Truncated { at } => write!(f, "file truncated at byte {at}"),
            ReadError::BadRecord { at, what } => write!(f, "bad record at byte {at}: {what}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// A parsed file: one link type for every packet, which is what makes this
/// format simpler than pcapng and less able to describe a real capture.
#[derive(Debug, Clone)]
pub struct File {
    pub header: Header,
    pub frames: Vec<RawFrame>,
    /// Records that could not be read, with the reason. A file truncated
    /// mid-capture is ordinary — the writer was killed — so the packets
    /// before the damage are returned rather than the whole read failing.
    pub truncated_at: Option<usize>,
}

struct Endian(bool);

impl Endian {
    fn u32(&self, b: &[u8], at: usize) -> Option<u32> {
        let s = b.get(at..at + 4)?;
        let a = [s[0], s[1], s[2], s[3]];
        Some(if self.0 {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn u16(&self, b: &[u8], at: usize) -> Option<u16> {
        let s = b.get(at..at + 2)?;
        Some(if self.0 {
            u16::from_le_bytes([s[0], s[1]])
        } else {
            u16::from_be_bytes([s[0], s[1]])
        })
    }
}

/// Parse a pcap file.
pub fn read(data: &[u8]) -> Result<File, ReadError> {
    match super::sniff(data) {
        Format::Pcap => {}
        Format::PcapModified => return Err(ReadError::Modified),
        _ => return Err(ReadError::NotPcap),
    }
    let first = data.get(..4).ok_or(ReadError::NotPcap)?;
    let be = u32::from_be_bytes([first[0], first[1], first[2], first[3]]);
    // If the magic reads correctly big-endian, the file is big-endian.
    let (little, precision) = match be {
        MAGIC_MICROS => (false, Precision::Micro),
        MAGIC_NANOS => (false, Precision::Nano),
        _ => {
            let le = u32::from_le_bytes([first[0], first[1], first[2], first[3]]);
            match le {
                MAGIC_MICROS => (true, Precision::Micro),
                MAGIC_NANOS => (true, Precision::Nano),
                _ => return Err(ReadError::NotPcap),
            }
        }
    };
    let e = Endian(little);
    if data.len() < FILE_HEADER {
        return Err(ReadError::Truncated { at: data.len() });
    }
    let header = Header {
        little_endian: little,
        version_major: e.u16(data, 4).ok_or(ReadError::NotPcap)?,
        version_minor: e.u16(data, 6).ok_or(ReadError::NotPcap)?,
        thiszone: e.u32(data, 8).ok_or(ReadError::NotPcap)? as i32,
        sigfigs: e.u32(data, 12).ok_or(ReadError::NotPcap)?,
        snaplen: e.u32(data, 16).ok_or(ReadError::NotPcap)?,
        link_type: e.u32(data, 20).ok_or(ReadError::NotPcap)?,
        ts_per_sec: precision.per_sec(),
    };

    let mut frames = Vec::new();
    let mut truncated_at = None;
    let mut at = FILE_HEADER;
    while at < data.len() {
        // A partial record header is a file cut short, not a corrupt one.
        if at + RECORD_HEADER > data.len() {
            truncated_at = Some(at);
            break;
        }
        let secs = e.u32(data, at).ok_or(ReadError::Truncated { at })?;
        let frac = e.u32(data, at + 4).ok_or(ReadError::Truncated { at })?;
        let caplen = e.u32(data, at + 8).ok_or(ReadError::Truncated { at })?;
        let orig_len = e.u32(data, at + 12).ok_or(ReadError::Truncated { at })?;
        if caplen > MAX_RECORD {
            return Err(ReadError::BadRecord {
                at,
                what: "captured length is implausibly large",
            });
        }
        // A capture cannot hold more bytes than the wire carried. Trusting
        // caplen > orig_len would mean reading bytes the file says are not
        // part of the packet.
        if caplen > orig_len && orig_len != 0 {
            return Err(ReadError::BadRecord {
                at,
                what: "captured length exceeds original length",
            });
        }
        let body = at + RECORD_HEADER;
        let end = match body.checked_add(caplen as usize) {
            Some(end) => end,
            None => {
                return Err(ReadError::BadRecord {
                    at,
                    what: "record length overflows",
                })
            }
        };
        let Some(bytes) = data.get(body..end) else {
            truncated_at = Some(at);
            break;
        };
        // The fractional field counts whatever unit the magic declared.
        let nanos = match precision {
            Precision::Micro => frac.saturating_mul(1000),
            Precision::Nano => frac,
        };
        frames.push(RawFrame {
            ts: Timestamp {
                secs: i64::from(secs) + i64::from(header.thiszone),
                // A file may claim more than a second's worth of fraction;
                // clamping keeps `Timestamp` well formed rather than letting
                // the value wrap somewhere later.
                nanos: nanos.min(999_999_999),
            },
            caplen,
            orig_len,
            bytes: Arc::from(bytes),
        });
        at = end;
    }
    Ok(File {
        header,
        frames,
        truncated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::writer::Writer;

    /// A minimal file with `n` one-byte packets.
    fn sample(precision: Precision, n: u32) -> Vec<u8> {
        let mut w = Writer::new(Vec::new(), 1, 65535, precision).expect("header");
        for i in 0..n {
            w.packet(
                Timestamp {
                    secs: 1_700_000_000 + i64::from(i),
                    nanos: 123_456_789,
                },
                1,
                &[0xab],
            )
            .expect("packet");
        }
        w.finish().expect("finish")
    }

    #[test]
    fn a_written_file_reads_back() {
        let bytes = sample(Precision::Micro, 3);
        let f = read(&bytes).expect("read");
        assert_eq!(f.frames.len(), 3);
        assert_eq!(f.header.link_type, 1);
        assert_eq!(f.header.snaplen, 65535);
        assert_eq!(&*f.frames[0].bytes, &[0xab]);
        assert_eq!(f.truncated_at, None);
    }

    #[test]
    fn microsecond_files_lose_the_last_three_digits() {
        // 123_456_789 ns is 123_456 us. The rounding is the format's, and
        // reading it back must not invent precision that is not there.
        let bytes = sample(Precision::Micro, 1);
        let f = read(&bytes).expect("read");
        assert_eq!(f.frames[0].ts.nanos, 123_456_000);
        assert_eq!(f.header.ts_per_sec, 1_000_000);
    }

    #[test]
    fn nanosecond_files_keep_every_digit() {
        let bytes = sample(Precision::Nano, 1);
        let f = read(&bytes).expect("read");
        assert_eq!(f.frames[0].ts.nanos, 123_456_789);
        assert_eq!(f.header.ts_per_sec, 1_000_000_000);
    }

    #[test]
    fn both_byte_orders_read() {
        // Byte-swap the magic and every subsequent field of a small file.
        let le = sample(Precision::Micro, 2);
        let mut be = Vec::with_capacity(le.len());
        let swap32 = |v: &[u8]| [v[3], v[2], v[1], v[0]];
        be.extend_from_slice(&swap32(&le[0..4]));
        be.extend_from_slice(&[le[5], le[4], le[7], le[6]]); // two u16 versions
        for off in (8..24).step_by(4) {
            be.extend_from_slice(&swap32(&le[off..off + 4]));
        }
        let mut at = 24;
        while at + 16 <= le.len() {
            for off in (at..at + 16).step_by(4) {
                be.extend_from_slice(&swap32(&le[off..off + 4]));
            }
            let caplen =
                u32::from_le_bytes([le[at + 8], le[at + 9], le[at + 10], le[at + 11]]) as usize;
            be.extend_from_slice(&le[at + 16..at + 16 + caplen]);
            at += 16 + caplen;
        }
        let f = read(&be).expect("big-endian read");
        assert!(!f.header.little_endian);
        assert_eq!(f.frames.len(), 2);
        assert_eq!(&*f.frames[0].bytes, &[0xab]);
    }

    #[test]
    fn a_file_cut_mid_capture_yields_what_it_has() {
        // A writer killed part-way through is ordinary. Losing the packets
        // before the damage because of it would not be.
        let bytes = sample(Precision::Micro, 4);
        for cut in [30usize, 40, bytes.len() - 1] {
            let f = read(&bytes[..cut]).expect("partial read");
            assert!(f.truncated_at.is_some(), "cut at {cut} should be reported");
            assert!(f.frames.len() < 4);
        }
    }

    #[test]
    fn an_absurd_capture_length_is_refused_not_allocated() {
        let mut bytes = sample(Precision::Micro, 1);
        // Overwrite the first record's caplen with 4 GB.
        bytes[24 + 8..24 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        match read(&bytes) {
            Err(ReadError::BadRecord { what, .. }) => {
                assert!(what.contains("implausibly large"), "{what}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_capture_longer_than_the_wire_length_is_refused() {
        // caplen > orig_len means the file is describing bytes it says are
        // not part of the packet.
        let mut bytes = sample(Precision::Micro, 1);
        bytes[24 + 8..24 + 12].copy_from_slice(&100u32.to_le_bytes());
        bytes[24 + 12..24 + 16].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(read(&bytes), Err(ReadError::BadRecord { .. })));
    }

    #[test]
    fn the_modified_format_is_refused_by_name() {
        let mut bytes = sample(Precision::Micro, 1);
        bytes[0..4].copy_from_slice(&super::super::MAGIC_MODIFIED.to_le_bytes());
        let e = read(&bytes).expect_err("should be refused");
        assert_eq!(e, ReadError::Modified);
        assert!(e.to_string().contains("editcap"), "and say what to do");
    }

    #[test]
    fn a_pcapng_file_is_not_read_as_pcap() {
        let shb = crate::pcapng::BLOCK_SHB.to_be_bytes();
        let mut bytes = shb.to_vec();
        bytes.extend_from_slice(&[0; 40]);
        assert_eq!(read(&bytes).unwrap_err(), ReadError::NotPcap);
    }

    #[test]
    fn an_empty_or_tiny_file_does_not_panic() {
        assert!(read(b"").is_err());
        assert!(read(b"\xd4\xc3\xb2\xa1").is_err());
        let mut short = MAGIC_MICROS.to_le_bytes().to_vec();
        short.extend_from_slice(&[0; 10]);
        assert!(matches!(read(&short), Err(ReadError::Truncated { .. })));
    }

    #[test]
    fn a_fractional_field_beyond_one_second_is_clamped() {
        let mut bytes = sample(Precision::Micro, 1);
        bytes[24 + 4..24 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let f = read(&bytes).expect("read");
        assert!(f.frames[0].ts.nanos <= 999_999_999);
    }
}
