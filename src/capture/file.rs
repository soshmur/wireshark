//! Reading a capture from a file, and writing one back out.
//!
//! The format is decided by the first bytes, never the name. Both formats
//! land on the same shape — a table of interfaces and a list of packets that
//! each name one — so everything downstream works the same way whether the
//! frames came from a file or a network card.

use std::fmt;
use std::io;
use std::path::Path;
use std::sync::Arc;

use netscope_ffi::LinkType;

use crate::capture::{RawFrame, Timestamp};
use crate::dissect::{dissect_with, Frame, Options, State};
use crate::pcap::{self, Format, Precision};
use crate::pcapng;

/// An interface a file describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub link_type: LinkType,
    pub snaplen: u32,
    pub name: Option<String>,
    /// Timestamp units per second, as the file declared them.
    pub ts_per_sec: u64,
}

/// A capture read from a file.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub interfaces: Vec<Iface>,
    /// Each packet with the index of the interface it arrived on.
    pub packets: Vec<(usize, RawFrame)>,
    pub format: Format,
    /// Things the reader wants to say that are not failures: a truncated
    /// tail, a packet naming an interface the file never described.
    pub warnings: Vec<String>,
}

impl Loaded {
    pub fn link_type_of(&self, interface: usize) -> LinkType {
        self.interfaces
            .get(interface)
            .map_or(LinkType::ETHERNET, |i| i.link_type)
    }

    /// Dissect everything, exactly as the live worker would.
    ///
    /// The same `dissect_with` the capture pipeline calls, so a file and a
    /// live capture of the same bytes produce identical trees. One `State`
    /// for the whole file, so conversations and reassembly work across it.
    pub fn dissect_all(&self, options: Options) -> Vec<Arc<Frame>> {
        let mut state = State::new();
        self.packets
            .iter()
            .enumerate()
            .map(|(i, (iface, raw))| {
                Arc::new(dissect_with(
                    self.link_type_of(*iface),
                    i as u32 + 1,
                    raw.clone(),
                    &mut state,
                    options,
                ))
            })
            .collect()
    }
}

#[derive(Debug)]
pub enum LoadError {
    Io(io::Error),
    /// The file is not a capture this can read. The message names what it
    /// looks like instead of saying "invalid file".
    Format(String),
    Empty,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "{e}"),
            LoadError::Format(m) => write!(f, "{m}"),
            LoadError::Empty => write!(f, "the file is empty"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<io::Error> for LoadError {
    fn from(e: io::Error) -> LoadError {
        LoadError::Io(e)
    }
}

pub fn load_path(path: &Path) -> Result<Loaded, LoadError> {
    let data = std::fs::read(path)?;
    load(&data)
}

/// Read a capture from bytes, choosing the parser by content.
pub fn load(data: &[u8]) -> Result<Loaded, LoadError> {
    if data.is_empty() {
        return Err(LoadError::Empty);
    }
    match pcap::sniff(data) {
        Format::Pcap => load_pcap(data),
        Format::Pcapng => load_pcapng(data),
        Format::PcapModified => Err(LoadError::Format(pcap::ReadError::Modified.to_string())),
        Format::Unknown => Err(LoadError::Format(
            "not a pcap or pcapng file (the first four bytes match neither format)".into(),
        )),
    }
}

fn load_pcap(data: &[u8]) -> Result<Loaded, LoadError> {
    let file = pcap::read(data).map_err(|e| LoadError::Format(e.to_string()))?;
    let mut warnings = Vec::new();
    if let Some(at) = file.truncated_at {
        warnings.push(format!(
            "the file is truncated at byte {at}; {} packets were read before it",
            file.frames.len()
        ));
    }
    let iface = Iface {
        link_type: LinkType(file.header.link_type as i32),
        snaplen: file.header.snaplen,
        name: None,
        ts_per_sec: file.header.ts_per_sec,
    };
    Ok(Loaded {
        interfaces: vec![iface],
        packets: file.frames.into_iter().map(|f| (0, f)).collect(),
        format: Format::Pcap,
        warnings,
    })
}

fn load_pcapng(data: &[u8]) -> Result<Loaded, LoadError> {
    let section = pcapng::read(data).map_err(|e| LoadError::Format(e.to_string()))?;
    let mut warnings = Vec::new();
    let interfaces: Vec<Iface> = section
        .interfaces
        .iter()
        .map(|i| Iface {
            link_type: LinkType(i32::from(i.link_type)),
            snaplen: i.snaplen,
            name: i.name.clone(),
            ts_per_sec: i.ts_per_sec,
        })
        .collect();
    let mut unknown_iface = 0usize;
    let packets: Vec<(usize, RawFrame)> = section
        .packets
        .into_iter()
        .map(|p| {
            let idx = p.interface as usize;
            // A packet naming an interface the file never described is
            // malformed, but the packet's bytes are still there. Attributing
            // it to interface 0 shows it rather than dropping it, and the
            // warning says how often that happened.
            if idx >= interfaces.len() {
                unknown_iface += 1;
                (0, p.frame)
            } else {
                (idx, p.frame)
            }
        })
        .collect();
    if unknown_iface > 0 {
        warnings.push(format!(
            "{unknown_iface} packets name an interface the file does not describe; \
             they are shown as interface 0"
        ));
    }
    if interfaces.is_empty() {
        warnings.push("the file describes no interfaces; assuming Ethernet".into());
    }
    let mut kinds: Vec<LinkType> = interfaces.iter().map(|i| i.link_type).collect();
    kinds.sort_by_key(|k| k.0);
    kinds.dedup();
    if kinds.len() > 1 {
        warnings.push(format!(
            "the file mixes {} link types; each packet is dissected as its own",
            kinds.len()
        ));
    }
    Ok(Loaded {
        interfaces,
        packets,
        format: Format::Pcapng,
        warnings,
    })
}

/// Which file format to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SaveFormat {
    /// Keeps per-interface metadata and nanosecond timestamps.
    #[default]
    Pcapng,
    /// One link type for the whole file; precision chosen from the data.
    Pcap,
}

impl SaveFormat {
    pub fn extension(self) -> &'static str {
        match self {
            SaveFormat::Pcapng => "pcapng",
            SaveFormat::Pcap => "pcap",
        }
    }
}

/// What a save did, for the message afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub frames: usize,
    pub bytes: usize,
    pub format: SaveFormat,
    /// Set for pcap, which stores one precision for the whole file.
    pub precision: Option<Precision>,
    /// Anything the user should know: a lossy conversion, a dropped link
    /// type.
    pub notes: Vec<String>,
}

/// Write `frames` to a file.
pub fn save_path(path: &Path, frames: &[Arc<Frame>], format: SaveFormat) -> io::Result<Saved> {
    let (bytes, saved) = encode(frames, format)?;
    std::fs::write(path, &bytes)?;
    Ok(saved)
}

/// Encode `frames`, returning the file bytes and what was done.
pub fn encode(frames: &[Arc<Frame>], format: SaveFormat) -> io::Result<(Vec<u8>, Saved)> {
    let mut notes = Vec::new();
    let bytes = match format {
        SaveFormat::Pcapng => {
            let mut w = pcapng::Writer::new(Vec::new(), "netscope")?;
            // One IDB per distinct link type, in first-seen order, so a
            // mixed capture survives the round trip.
            let mut kinds: Vec<LinkType> = Vec::new();
            for f in frames {
                if !kinds.contains(&f.link_type) {
                    kinds.push(f.link_type);
                }
            }
            if kinds.is_empty() {
                kinds.push(LinkType::ETHERNET);
            }
            for k in &kinds {
                w.interface(k.0 as u16, 262_144, &k.name())?;
            }
            for f in frames {
                let id = kinds.iter().position(|k| *k == f.link_type).unwrap_or(0);
                w.packet(id as u32, f.ts, f.orig_len, &f.bytes)?;
            }
            w.finish()?
        }
        SaveFormat::Pcap => {
            // One link type for the whole file. If the frames disagree, the
            // majority wins and the rest are dropped rather than written
            // under a header that would make them dissect as nonsense.
            let link = frames.first().map_or(LinkType::ETHERNET, |f| f.link_type);
            let odd = frames.iter().filter(|f| f.link_type != link).count();
            if odd > 0 {
                notes.push(format!(
                    "{odd} frames use a different link type and were not written; \
                     save as pcapng to keep them"
                ));
            }
            let precision = crate::pcap::writer::precision_for(frames.iter().map(|f| &f.ts));
            if precision == Precision::Nano {
                notes.push(
                    "written with nanosecond timestamps; tools older than libpcap 1.5 \
                     cannot read this file"
                        .into(),
                );
            }
            let mut w = pcap::Writer::new(Vec::new(), link.0 as u32, 262_144, precision)?;
            for f in frames.iter().filter(|f| f.link_type == link) {
                w.packet(f.ts, f.orig_len, &f.bytes)?;
            }
            w.finish()?
        }
    };
    let precision = (format == SaveFormat::Pcap)
        .then(|| crate::pcap::writer::precision_for(frames.iter().map(|f| &f.ts)));
    let written = match format {
        SaveFormat::Pcapng => frames.len(),
        SaveFormat::Pcap => {
            let link = frames.first().map_or(LinkType::ETHERNET, |f| f.link_type);
            frames.iter().filter(|f| f.link_type == link).count()
        }
    };
    Ok((
        bytes.clone(),
        Saved {
            frames: written,
            bytes: bytes.len(),
            format,
            precision,
            notes,
        },
    ))
}

/// A frame as it would be written, for tests and round-trip checks.
pub fn raw_of(frame: &Frame) -> RawFrame {
    RawFrame {
        ts: frame.ts,
        caplen: frame.bytes.len() as u32,
        orig_len: frame.orig_len,
        bytes: Arc::clone(&frame.bytes),
    }
}

/// A timestamp rounded to a file format's precision, for comparisons.
pub fn at_precision(ts: Timestamp, per_sec: u64) -> Timestamp {
    let div = (1_000_000_000u64 / per_sec.max(1)).max(1) as u32;
    Timestamp {
        secs: ts.secs,
        nanos: ts.nanos / div * div,
    }
}
