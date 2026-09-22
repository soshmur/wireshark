//! Minimal pcapng reader: SHB (either endianness), IDB with `if_tsresol`,
//! EPB and SPB. Other blocks are skipped. Every length is bounds-checked.

use std::fmt;
use std::sync::Arc;

use super::*;
use crate::capture::{RawFrame, Timestamp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    NotPcapng,
    Truncated { at: usize },
    BadBlock { at: usize, what: &'static str },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotPcapng => write!(f, "not a pcapng file"),
            ReadError::Truncated { at } => write!(f, "file truncated at byte {at}"),
            ReadError::BadBlock { at, what } => write!(f, "bad block at byte {at}: {what}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// One packet with the interface it was captured on.
#[derive(Debug, Clone)]
pub struct Packet {
    pub interface: u32,
    pub frame: RawFrame,
}

/// A parsed section (files with multiple sections are concatenated).
#[derive(Debug, Clone, Default)]
pub struct Section {
    pub interfaces: Vec<Interface>,
    pub packets: Vec<Packet>,
    pub user_appl: Option<String>,
}

struct Endian(bool); // true = little

impl Endian {
    fn u16(&self, b: &[u8], at: usize) -> Option<u16> {
        let s = b.get(at..at + 2)?;
        Some(if self.0 {
            u16::from_le_bytes([s[0], s[1]])
        } else {
            u16::from_be_bytes([s[0], s[1]])
        })
    }

    fn u32(&self, b: &[u8], at: usize) -> Option<u32> {
        let s = b.get(at..at + 4)?;
        let a = [s[0], s[1], s[2], s[3]];
        Some(if self.0 {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
}

/// Walk options; calls `f(code, value)` for each until `opt_endofopt`.
fn options(e: &Endian, body: &[u8], mut at: usize, mut f: impl FnMut(u16, &[u8])) {
    while let (Some(code), Some(len)) = (e.u16(body, at), e.u16(body, at + 2)) {
        if code == OPT_ENDOFOPT {
            break;
        }
        let Some(value) = body.get(at + 4..at + 4 + usize::from(len)) else {
            break;
        };
        f(code, value);
        at += 4 + pad4(usize::from(len));
    }
}

/// Parse a whole file held in memory.
pub fn read(data: &[u8]) -> Result<Section, ReadError> {
    let mut section = Section::default();
    let mut endian = Endian(true);
    let mut at = 0usize;
    let mut seen_shb = false;
    while at + 12 <= data.len() {
        // Block type is endian-dependent except for the SHB, whose magic
        // tells us the byte order.
        let raw_type = data.get(at..at + 4).ok_or(ReadError::Truncated { at })?;
        let is_shb = raw_type == BLOCK_SHB.to_le_bytes() || raw_type == BLOCK_SHB.to_be_bytes();
        if is_shb {
            let magic = data
                .get(at + 8..at + 12)
                .ok_or(ReadError::Truncated { at })?;
            endian = if magic == BYTE_ORDER_MAGIC.to_le_bytes() {
                Endian(true)
            } else if magic == BYTE_ORDER_MAGIC.to_be_bytes() {
                Endian(false)
            } else {
                return Err(ReadError::NotPcapng);
            };
            seen_shb = true;
        } else if !seen_shb {
            return Err(ReadError::NotPcapng);
        }
        let block_type = endian.u32(data, at).ok_or(ReadError::Truncated { at })?;
        let total = endian
            .u32(data, at + 4)
            .ok_or(ReadError::Truncated { at })? as usize;
        if total < 12 || !total.is_multiple_of(4) {
            return Err(ReadError::BadBlock {
                at,
                what: "block length",
            });
        }
        let body = data
            .get(at + 8..at + total - 4)
            .ok_or(ReadError::Truncated { at })?;
        let trailer = endian
            .u32(data, at + total - 4)
            .ok_or(ReadError::Truncated { at })? as usize;
        if trailer != total {
            return Err(ReadError::BadBlock {
                at,
                what: "trailing block length mismatch",
            });
        }
        match block_type {
            BLOCK_SHB => {
                // New section: interfaces restart.
                section.interfaces.clear();
                options(&endian, body, 16, |code, v| {
                    if code == OPT_SHB_USERAPPL {
                        section.user_appl = Some(String::from_utf8_lossy(v).into_owned());
                    }
                });
            }
            BLOCK_IDB => {
                let link_type = endian.u16(body, 0).ok_or(ReadError::BadBlock {
                    at,
                    what: "IDB too short",
                })?;
                let snaplen = endian.u32(body, 4).unwrap_or(0);
                let mut iface = Interface {
                    link_type,
                    snaplen,
                    name: None,
                    ts_per_sec: 1_000_000,
                };
                options(&endian, body, 8, |code, v| match code {
                    OPT_IF_NAME => iface.name = Some(String::from_utf8_lossy(v).into_owned()),
                    OPT_IF_TSRESOL => {
                        if let Some(&r) = v.first() {
                            iface.ts_per_sec = Interface::ts_per_sec_from_tsresol(r);
                        }
                    }
                    _ => {}
                });
                section.interfaces.push(iface);
            }
            BLOCK_EPB => {
                let interface = endian.u32(body, 0).ok_or(ReadError::BadBlock {
                    at,
                    what: "EPB too short",
                })?;
                let ts_hi = endian.u32(body, 4).unwrap_or(0);
                let ts_lo = endian.u32(body, 8).unwrap_or(0);
                let caplen = endian.u32(body, 12).unwrap_or(0) as usize;
                let orig_len = endian.u32(body, 16).unwrap_or(0);
                let bytes = body.get(20..20 + caplen).ok_or(ReadError::BadBlock {
                    at,
                    what: "EPB captured length exceeds block",
                })?;
                let per_sec = section
                    .interfaces
                    .get(interface as usize)
                    .map_or(1_000_000, |i| i.ts_per_sec);
                let ts_units = (u64::from(ts_hi) << 32) | u64::from(ts_lo);
                let ts = Timestamp {
                    secs: (ts_units / per_sec) as i64,
                    nanos: ((ts_units % per_sec) * (1_000_000_000 / per_sec.max(1))) as u32,
                };
                section.packets.push(Packet {
                    interface,
                    frame: RawFrame {
                        ts,
                        caplen: caplen as u32,
                        orig_len,
                        bytes: Arc::from(bytes),
                    },
                });
            }
            BLOCK_SPB => {
                let orig_len = endian.u32(body, 0).unwrap_or(0);
                let snaplen = section.interfaces.first().map_or(0, |i| i.snaplen) as usize;
                let caplen = if snaplen > 0 {
                    (orig_len as usize).min(snaplen)
                } else {
                    orig_len as usize
                };
                let bytes = body.get(4..4 + caplen).ok_or(ReadError::BadBlock {
                    at,
                    what: "SPB length exceeds block",
                })?;
                section.packets.push(Packet {
                    interface: 0,
                    frame: RawFrame {
                        ts: Timestamp::default(),
                        caplen: caplen as u32,
                        orig_len,
                        bytes: Arc::from(bytes),
                    },
                });
            }
            _ => {}
        }
        at += total;
    }
    if !seen_shb {
        return Err(ReadError::NotPcapng);
    }
    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapng::Writer;

    #[test]
    fn round_trips_nanosecond_timestamps() {
        let mut w = Writer::new(Vec::new(), "test").unwrap();
        let id = w.interface(1, 65535, "eth0").unwrap();
        let ts = Timestamp {
            secs: 1_700_000_000,
            nanos: 123_456_789,
        };
        w.packet(id, ts, 100, &[1, 2, 3, 4, 5]).unwrap();
        let bytes = w.finish().unwrap();
        let s = read(&bytes).unwrap();
        assert_eq!(s.interfaces.len(), 1);
        assert_eq!(s.interfaces[0].link_type, 1);
        assert_eq!(s.interfaces[0].name.as_deref(), Some("eth0"));
        assert_eq!(s.interfaces[0].ts_per_sec, 1_000_000_000);
        assert_eq!(s.packets.len(), 1);
        assert_eq!(s.packets[0].frame.ts, ts);
        assert_eq!(s.packets[0].frame.orig_len, 100);
        assert_eq!(&*s.packets[0].frame.bytes, &[1, 2, 3, 4, 5]);
        assert_eq!(s.user_appl.as_deref(), Some("test"));
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        assert!(matches!(read(b"hello world!"), Err(ReadError::NotPcapng)));
        let mut w = Writer::new(Vec::new(), "t").unwrap();
        w.interface(1, 0, "").unwrap();
        w.packet(0, Timestamp::default(), 4, &[0; 4]).unwrap();
        let bytes = w.finish().unwrap();
        for cut in 1..bytes.len() {
            // Must never panic; may succeed with fewer packets or error.
            let _ = read(&bytes[..cut]);
        }
    }

    #[test]
    fn tsresol_decoding() {
        assert_eq!(Interface::ts_per_sec_from_tsresol(6), 1_000_000);
        assert_eq!(Interface::ts_per_sec_from_tsresol(9), 1_000_000_000);
        assert_eq!(Interface::ts_per_sec_from_tsresol(0x80 | 10), 1024);
    }
}
