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
pub const BLOCK_ISB: u32 = 0x0000_0005;
pub const BLOCK_NRB: u32 = 0x0000_0004;
pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

pub const OPT_ENDOFOPT: u16 = 0;
pub const OPT_COMMENT: u16 = 1;
pub const OPT_IF_NAME: u16 = 2;
pub const OPT_IF_TSRESOL: u16 = 9;
pub const OPT_IF_TSOFFSET: u16 = 14;
pub const OPT_IF_DESCRIPTION: u16 = 3;
pub const OPT_SHB_USERAPPL: u16 = 4;

// Interface Statistics options. These are the capture's own account of what
// it missed, which is not something to discard quietly: a file reporting a
// million dropped packets describes a very different capture from one
// reporting none.
pub const OPT_ISB_IFRECV: u16 = 4;
pub const OPT_ISB_IFDROP: u16 = 5;
pub const OPT_ISB_FILTERACCEPT: u16 = 6;
pub const OPT_ISB_OSDROP: u16 = 7;

/// What an Interface Statistics Block says the capture saw and missed.
///
/// All counts are what the *file* claims, not anything netscope measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets the interface received.
    pub received: Option<u64>,
    /// Packets the capture driver dropped.
    pub dropped: Option<u64>,
    /// Packets that passed the capture filter.
    pub filter_accepted: Option<u64>,
    /// Packets the operating system dropped.
    pub os_dropped: Option<u64>,
}

impl Stats {
    pub fn is_empty(&self) -> bool {
        *self == Stats::default()
    }

    /// Everything the file says went missing, however it was lost.
    pub fn total_lost(&self) -> u64 {
        self.dropped.unwrap_or(0) + self.os_dropped.unwrap_or(0)
    }
}

/// An interface as described by an IDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub link_type: u16,
    pub snaplen: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    /// Timestamp units per second (10^6 for the default 6, 10^9 for 9).
    pub ts_per_sec: u64,
    /// Counts from the interface's last ISB, if the file carried one.
    pub stats: Stats,
    /// Seconds added to every timestamp on this interface (`if_tsoffset`).
    ///
    /// Writers use it to store small timestamps against a base, and a reader
    /// that ignores it reports times decades adrift without any sign that
    /// something was missed.
    pub ts_offset: i64,
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
