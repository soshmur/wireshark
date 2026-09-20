//! The one and only unsafe boundary of netscope.
//!
//! This crate wraps the `pcap` crate (libpcap / Npcap) and a handful of OS
//! privilege probes behind a small, `pcap`-free API. Nothing outside this crate
//! imports `pcap` or `windows-sys`, and the application crate is compiled with
//! `#![forbid(unsafe_code)]`.
//!
//! Scope is deliberately tiny: enumerate devices, open one, pull raw frames with
//! timestamps, read kernel drop counters. No parsing happens here.

#![deny(unsafe_code)]
#![warn(clippy::all)]

use std::fmt;

#[cfg(windows)]
#[allow(unsafe_code)]
mod win;

/// Any failure from the capture library, flattened to a message. Callers never
/// see `pcap` types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<pcap::Error> for Error {
    fn from(e: pcap::Error) -> Self {
        Error(e.to_string())
    }
}

/// One capture-capable interface as reported by the OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The name libpcap wants back in `open` (e.g. `\Device\NPF_{GUID}` or `eth0`).
    pub name: String,
    /// Human-readable description when the OS has one.
    pub description: Option<String>,
    /// IPv4/IPv6 addresses assigned to the interface, as text.
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_running: bool,
    pub is_loopback: bool,
    pub is_wireless: bool,
    /// `Some(true)` = connected, `Some(false)` = disconnected, `None` = unknown/N.A.
    pub connected: Option<bool>,
}

/// A libpcap DLT_* value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkType(pub i32);

impl LinkType {
    pub const NULL: LinkType = LinkType(0);
    pub const ETHERNET: LinkType = LinkType(1);
    pub const RAW: LinkType = LinkType(12);
    pub const IEEE802_11: LinkType = LinkType(105);
    pub const LINUX_SLL: LinkType = LinkType(113);
    pub const IEEE802_11_RADIOTAP: LinkType = LinkType(127);
    pub const LINUX_SLL2: LinkType = LinkType(276);

    /// libpcap's short name for the link type (e.g. `EN10MB`).
    pub fn name(self) -> String {
        pcap::Linktype(self.0)
            .get_name()
            .unwrap_or_else(|_| format!("DLT_{}", self.0))
    }

    /// libpcap's longer description (e.g. `Ethernet`).
    pub fn description(self) -> String {
        pcap::Linktype(self.0)
            .get_description()
            .unwrap_or_else(|_| format!("Unknown link type {}", self.0))
    }
}

/// Kernel/driver-side counters for an open handle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelStats {
    pub received: u32,
    pub dropped: u32,
    pub if_dropped: u32,
}

/// A frame borrowed from the capture buffer. Copy it out before the next read.
#[derive(Debug)]
pub struct Packet<'a> {
    pub ts_secs: i64,
    pub ts_nanos: u32,
    /// Original length on the wire; may exceed `data.len()` when snaplen truncates.
    pub orig_len: u32,
    pub data: &'a [u8],
}

/// The result of one blocking read with a timeout.
#[derive(Debug)]
pub enum Read<'a> {
    Packet(Packet<'a>),
    /// The read timeout elapsed with no frame; loop again and check for stop.
    Timeout,
    /// The source is exhausted (only for offline sources; live devices never end).
    End,
}

/// Options for `open`.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    pub snaplen: i32,
    pub promiscuous: bool,
    /// Read timeout in milliseconds; bounds how long `next` blocks.
    pub timeout_ms: i32,
    /// Kernel buffer size in bytes.
    pub buffer_size: i32,
    /// A BPF *capture* filter compiled by libpcap. Not the display filter.
    pub bpf: Option<String>,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            snaplen: 262_144,
            promiscuous: true,
            timeout_ms: 100,
            buffer_size: 16 * 1024 * 1024,
            bpf: None,
        }
    }
}

/// An open live capture. Not `Sync`; use it from one thread.
pub struct Handle {
    cap: pcap::Capture<pcap::Active>,
    link_type: LinkType,
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("link_type", &self.link_type)
            .finish()
    }
}

impl Handle {
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Block for at most the configured timeout and return the next frame.
    pub fn read(&mut self) -> Result<Read<'_>, Error> {
        match self.cap.next_packet() {
            Ok(p) => {
                // Live handles report microseconds. Nanosecond precision only
                // matters for files, which netscope parses itself.
                let usec = i64::from(p.header.ts.tv_usec);
                let nanos = (usec.clamp(0, 999_999) * 1_000) as u32;
                Ok(Read::Packet(Packet {
                    ts_secs: i64::from(p.header.ts.tv_sec),
                    ts_nanos: nanos,
                    orig_len: p.header.len,
                    data: p.data,
                }))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(Read::Timeout),
            Err(pcap::Error::NoMorePackets) => Ok(Read::End),
            Err(e) => Err(e.into()),
        }
    }

    /// Driver-side counters since the handle was opened.
    pub fn stats(&mut self) -> Result<KernelStats, Error> {
        let s = self.cap.stats()?;
        Ok(KernelStats {
            received: s.received,
            dropped: s.dropped,
            if_dropped: s.if_dropped,
        })
    }
}

/// Enumerate capture-capable interfaces.
pub fn list_devices() -> Result<Vec<DeviceInfo>, Error> {
    let devs = pcap::Device::list()?;
    Ok(devs
        .into_iter()
        .map(|d| {
            let flags = d.flags;
            DeviceInfo {
                name: d.name,
                description: d.desc,
                addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
                is_up: flags.is_up(),
                is_running: flags.is_running(),
                is_loopback: flags.is_loopback(),
                is_wireless: flags.is_wireless(),
                connected: match flags.connection_status {
                    pcap::ConnectionStatus::Connected => Some(true),
                    pcap::ConnectionStatus::Disconnected => Some(false),
                    pcap::ConnectionStatus::Unknown | pcap::ConnectionStatus::NotApplicable => None,
                },
            }
        })
        .collect())
}

/// Open a live capture on `device` and apply the BPF filter, if any.
pub fn open(device: &str, opts: &OpenOptions) -> Result<Handle, Error> {
    let inactive = pcap::Capture::from_device(device)?
        .snaplen(opts.snaplen)
        .promisc(opts.promiscuous)
        .timeout(opts.timeout_ms)
        .buffer_size(opts.buffer_size);
    let mut cap = inactive.open()?;
    if let Some(bpf) = opts.bpf.as_deref() {
        if !bpf.trim().is_empty() {
            cap.filter(bpf, true)?;
        }
    }
    let link_type = LinkType(cap.get_datalink().0);
    Ok(Handle { cap, link_type })
}

/// Windows: make `wpcap.dll` resolvable and check that it loads. Must be called
/// before any other function in this crate; on other platforms it is a no-op.
///
/// Returns a human-readable reason when the DLL is not available.
pub fn wpcap_available() -> Result<(), String> {
    #[cfg(windows)]
    {
        win::prepare_dll_search_path();
        win::load_wpcap()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Whether the current process runs with an elevated (Administrator) token.
/// `None` on platforms where the notion does not apply.
pub fn is_elevated() -> Option<bool> {
    #[cfg(windows)]
    {
        win::is_elevated()
    }
    #[cfg(not(windows))]
    {
        None
    }
}
