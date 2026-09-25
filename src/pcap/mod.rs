//! Classic pcap (the libpcap savefile format) reading and writing, hand
//! written against the layout.
//!
//! The format is a 24-byte header and then, for each packet, a 16-byte
//! record header and its bytes. What makes it fiddly is that four things
//! vary and only the magic number says which: byte order, timestamp
//! precision, and — in two variants that are not this format but share its
//! shape — the meaning of the record header's fields.
//!
//! | magic (as written) | meaning |
//! |---|---|
//! | `a1b2c3d4` | big-endian, microsecond timestamps |
//! | `d4c3b2a1` | little-endian, microsecond timestamps |
//! | `a1b23c4d` | big-endian, nanosecond timestamps |
//! | `4d3cb2a1` | little-endian, nanosecond timestamps |
//! | `a1b2cd34` | Alexey Kuznetsov's modified format — refused |
//! | `34cdb2a1` | the same, byte-swapped — refused |
//!
//! The modified format inserts four extra fields into every record header.
//! Reading it as ordinary pcap does not fail; it silently yields packets
//! whose lengths and timestamps are nonsense. Refusing it by name is the
//! only honest option, so `ReadError::Modified` says what the file is.

pub mod reader;
pub mod writer;

pub use reader::{read, File, ReadError};
pub use writer::Writer;

/// Written first in the file, in the writer's byte order.
pub const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
/// Same, but record timestamps count nanoseconds (libpcap 1.5 and later).
pub const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
/// Kuznetsov's modified format, which this does not read.
pub const MAGIC_MODIFIED: u32 = 0xa1b2_cd34;

/// The fixed part of the file, before any packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// True when the file was written little-endian.
    pub little_endian: bool,
    pub version_major: u16,
    pub version_minor: u16,
    /// Seconds the capturing host's clock was offset from UTC. Universally
    /// zero in practice, and kept only so a round trip preserves it.
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub link_type: u32,
    /// Timestamp units per second: 1e6 or 1e9.
    pub ts_per_sec: u64,
}

/// How precise the timestamps in a file are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Precision {
    #[default]
    Micro,
    Nano,
}

impl Precision {
    pub fn per_sec(self) -> u64 {
        match self {
            Precision::Micro => 1_000_000,
            Precision::Nano => 1_000_000_000,
        }
    }

    pub fn magic(self) -> u32 {
        match self {
            Precision::Micro => MAGIC_MICROS,
            Precision::Nano => MAGIC_NANOS,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Precision::Micro => "microsecond",
            Precision::Nano => "nanosecond",
        }
    }
}

/// Which format a file is, judged by its first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    Pcapng,
    /// Looks like pcap but is a variant this does not read.
    PcapModified,
    Unknown,
}

/// Identify a file from its first bytes.
///
/// By content, never by file name. A `.pcap` that is really pcapng is
/// common — tcpdump has written pcapng by default for years on some
/// systems — and choosing a parser from the extension turns that into a
/// parse error, or worse, a misparse.
pub fn sniff(data: &[u8]) -> Format {
    let Some(first) = data.get(..4) else {
        return Format::Unknown;
    };
    let be = u32::from_be_bytes([first[0], first[1], first[2], first[3]]);
    let le = u32::from_le_bytes([first[0], first[1], first[2], first[3]]);
    if be == crate::pcapng::BLOCK_SHB {
        return Format::Pcapng;
    }
    match (be, le) {
        (MAGIC_MICROS, _) | (_, MAGIC_MICROS) | (MAGIC_NANOS, _) | (_, MAGIC_NANOS) => Format::Pcap,
        (MAGIC_MODIFIED, _) | (_, MAGIC_MODIFIED) => Format::PcapModified,
        _ => Format::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_magic(m: [u8; 4]) -> Vec<u8> {
        let mut v = m.to_vec();
        v.extend_from_slice(&[0; 20]);
        v
    }

    #[test]
    fn every_pcap_magic_is_recognised_either_way_round() {
        for magic in [MAGIC_MICROS, MAGIC_NANOS] {
            assert_eq!(sniff(&with_magic(magic.to_be_bytes())), Format::Pcap);
            assert_eq!(sniff(&with_magic(magic.to_le_bytes())), Format::Pcap);
        }
    }

    #[test]
    fn pcapng_is_told_apart_from_pcap() {
        let shb = crate::pcapng::BLOCK_SHB.to_be_bytes();
        assert_eq!(sniff(&with_magic(shb)), Format::Pcapng);
    }

    #[test]
    fn the_modified_format_is_named_rather_than_misread() {
        // Reading it as ordinary pcap does not fail, it yields nonsense.
        assert_eq!(
            sniff(&with_magic(MAGIC_MODIFIED.to_be_bytes())),
            Format::PcapModified
        );
        assert_eq!(
            sniff(&with_magic(MAGIC_MODIFIED.to_le_bytes())),
            Format::PcapModified
        );
    }

    #[test]
    fn anything_else_is_unknown_rather_than_guessed() {
        assert_eq!(sniff(b""), Format::Unknown);
        assert_eq!(sniff(b"\x00\x01"), Format::Unknown);
        assert_eq!(sniff(&with_magic(*b"RIFF")), Format::Unknown);
        assert_eq!(sniff(&with_magic([0; 4])), Format::Unknown);
    }

    #[test]
    fn precision_and_magic_agree() {
        assert_eq!(Precision::Micro.magic(), MAGIC_MICROS);
        assert_eq!(Precision::Nano.magic(), MAGIC_NANOS);
        assert_eq!(Precision::Micro.per_sec(), 1_000_000);
        assert_eq!(Precision::Nano.per_sec(), 1_000_000_000);
    }
}
