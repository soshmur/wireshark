//! pcapng (IETF draft-ietf-opsawg-pcapng) reading and writing, hand-written
//! against the block layout. Phase 2 needs enough to round-trip fixtures:
//! Section Header, Interface Description (with `if_tsresol`) and Enhanced
//! Packet blocks. Unknown blocks are skipped on read. Phase 5 completes it.

pub mod reader;
pub mod writer;

pub const BLOCK_SHB: u32 = 0x0A0D_0D0A;
pub const BLOCK_IDB: u32 = 0x0000_0001;
pub const BLOCK_EPB: u32 = 0x0000_0006;
pub const BLOCK_SPB: u32 = 0x0000_0003;
pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

pub const OPT_ENDOFOPT: u16 = 0;
pub const OPT_COMMENT: u16 = 1;
pub const OPT_IF_NAME: u16 = 2;
pub const OPT_IF_TSRESOL: u16 = 9;
pub const OPT_SHB_USERAPPL: u16 = 4;

/// An interface as described by an IDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub link_type: u16,
    pub snaplen: u32,
    pub name: Option<String>,
    /// Timestamp units per second (10^6 for the default 6, 10^9 for 9).
    pub ts_per_sec: u64,
}

impl Interface {
    /// Decode `if_tsresol`: high bit set means base 2, else base 10.
    pub fn ts_per_sec_from_tsresol(tsresol: u8) -> u64 {
        if tsresol & 0x80 != 0 {
            1u64 << (tsresol & 0x7f).min(63)
        } else {
            10u64.pow(u32::from(tsresol.min(19)))
        }
    }
}

/// Pad `len` up to a multiple of four.
pub fn pad4(len: usize) -> usize {
    (len + 3) & !3
}

pub use reader::{read, ReadError, Section};
pub use writer::Writer;
