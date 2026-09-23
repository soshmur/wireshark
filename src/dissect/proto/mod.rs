//! One hand-written dissector per protocol. Each has the shape
//! `fn(&[u8], &mut Ctx) -> Result<Node, DissectError>`, is pure, bounds-checks
//! every read through `Cursor`, and hands its payload on via `Ctx::call_next`.

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod eth;
pub mod http;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod llc;
pub mod null;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod vlan;

use super::ctx::{Ctx, NetAddrs, Proto};
use super::cursor::Result;
use super::node::Value;

/// The `data` pseudo-protocol: whatever no dissector claimed.
pub fn data(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let range = ctx.base..ctx.base + data.len();
    ctx.push_protocol("data");
    let node = ctx.begin("data", range.clone());
    ctx.leaf("data.data", range.clone(), Value::Bytes);
    ctx.leaf("data.len", range, Value::Unsigned(data.len() as u64));
    ctx.end();
    let _ = node;
    Ok(())
}

/// Dispatch on an EtherType, shared by Ethernet, 802.1Q and SNAP.
pub fn ethertype_next(ethertype: u16) -> Proto {
    match ethertype {
        0x0800 => Proto::Ipv4,
        0x0806 => Proto::Arp,
        0x8100 | 0x88A8 => Proto::Vlan,
        0x86DD => Proto::Ipv6,
        _ => Proto::Data,
    }
}

/// Dispatch on an IP protocol number, shared by IPv4 and IPv6.
pub fn ipproto_next(proto: u8) -> Proto {
    match proto {
        1 => Proto::Icmp,
        6 => Proto::Tcp,
        17 => Proto::Udp,
        58 => Proto::Icmpv6,
        _ => Proto::Data,
    }
}

/// Checksum verification result; the numeric value stored in a
/// `*.checksum.status` field (see `registry::CHECKSUM_STATUS`).
pub const CK_BAD: u64 = 0;
pub const CK_GOOD: u64 = 1;
pub const CK_UNVERIFIED: u64 = 2;
pub const CK_NOT_PRESENT: u64 = 3;

/// Internet checksum (RFC 1071) over `parts`, in order.
pub fn inet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;
    for part in parts {
        let mut bytes = part.iter();
        if let Some(hi) = carry_byte.take() {
            let lo = bytes.next().copied().unwrap_or(0);
            sum += u32::from(u16::from_be_bytes([hi, lo]));
        }
        let (pairs, rest) = bytes.as_slice().as_chunks::<2>();
        for c in pairs {
            sum += u32::from(u16::from_be_bytes(*c));
        }
        if let [odd] = rest {
            carry_byte = Some(*odd);
        }
    }
    if let Some(hi) = carry_byte {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Pseudo-header checksum for TCP/UDP over the addresses in `ctx`.
pub fn transport_checksum(ctx: &Ctx, proto: u8, segment: &[u8]) -> Option<u16> {
    let len = (segment.len() as u32).to_be_bytes();
    match ctx.net_addrs? {
        NetAddrs::V4(src, dst) => {
            let pseudo = [0u8, proto, len[2], len[3]];
            Some(inet_checksum(&[&src, &dst, &pseudo, segment]))
        }
        NetAddrs::V6(src, dst) => {
            let pseudo = [len[0], len[1], len[2], len[3], 0, 0, 0, proto];
            Some(inet_checksum(&[&src, &dst, &pseudo, segment]))
        }
    }
}

pub use super::node::{fmt_ipv4 as ipv4_str, fmt_ipv6 as ipv6_str, fmt_mac as mac_str};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_valid_header_is_zero() {
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(inet_checksum(&[&hdr]), 0);
        let mut zeroed = hdr;
        zeroed[10] = 0;
        zeroed[11] = 0;
        assert_eq!(inet_checksum(&[&zeroed]), 0xb861);
        // Splitting across parts at an odd boundary gives the same result.
        assert_eq!(inet_checksum(&[&zeroed[..3], &zeroed[3..]]), 0xb861);
    }
}

/// Joins short names ("SYN, ACK") into a fixed stack buffer. Flag summaries
/// are built once per frame, so avoiding a `Vec` and a `join` here is worth
/// the small ceiling; anything longer is truncated rather than allocating.
pub struct NameList {
    buf: [u8; 96],
    len: usize,
}

impl Default for NameList {
    fn default() -> Self {
        NameList::new()
    }
}

impl NameList {
    pub fn new() -> NameList {
        NameList {
            buf: [0; 96],
            len: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, name: &str) {
        if !self.is_empty() {
            self.extend(b", ");
        }
        self.extend(name.as_bytes());
    }

    fn extend(&mut self, bytes: &[u8]) {
        let room = self.buf.len() - self.len;
        let n = bytes.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII names are ever pushed, so this cannot fail; the fallback
        // keeps the function total rather than panicking on a future misuse.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

#[cfg(test)]
mod name_list_tests {
    use super::NameList;

    #[test]
    fn joins_and_truncates() {
        let mut n = NameList::new();
        assert!(n.is_empty());
        n.push("SYN");
        n.push("ACK");
        assert_eq!(n.as_str(), "SYN, ACK");
        let mut n = NameList::new();
        for _ in 0..40 {
            n.push("LONGNAME");
        }
        assert_eq!(n.as_str().len(), 96);
    }
}
