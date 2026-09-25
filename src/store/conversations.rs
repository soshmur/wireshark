//! The conversations table: one row per 5-tuple, totalled from a snapshot.
//!
//! Built on demand from the frames already held, for the same reason Follow
//! Stream is: totals kept incrementally would have to be maintained by the
//! dissection worker, and would then disagree with the store as soon as the
//! ring evicted anything. Counting what is held means the table always
//! describes exactly the frames the packet list is showing.

use std::collections::HashMap;

use crate::capture::Timestamp;
use crate::dissect::{Addr, Frame, Value};

use super::Snapshot;

/// Which layer a row is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Link layer: MAC to MAC.
    Ethernet,
    /// Network layer: address to address, ports ignored.
    Ip,
    Tcp,
    Udp,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Ethernet => "Ethernet",
            Kind::Ip => "IPv4 · IPv6",
            Kind::Tcp => "TCP",
            Kind::Udp => "UDP",
        }
    }

    pub const ALL: [Kind; 4] = [Kind::Ethernet, Kind::Ip, Kind::Tcp, Kind::Udp];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    a: Addr,
    b: Addr,
    port_a: u16,
    port_b: u16,
    /// Part of the identity at the transport layers. Ports are reused, and
    /// two connections between the same pair are two conversations - the
    /// same reason the stream table starts a new id on a SYN. Without this
    /// they would share a row and their totals would be added together.
    stream: Option<u32>,
}

/// One conversation's totals.
#[derive(Debug, Clone)]
pub struct Row {
    pub a: Addr,
    pub b: Addr,
    /// Zero for the layers that have no ports.
    pub port_a: u16,
    pub port_b: u16,
    /// Packets and bytes A to B, then B to A.
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub first: Timestamp,
    pub last: Timestamp,
    /// Stream id, for the layers that have one.
    pub stream: Option<u32>,
}

impl Row {
    pub fn total_packets(&self) -> u64 {
        self.packets[0] + self.packets[1]
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes[0] + self.bytes[1]
    }

    /// Seconds between the first and last frame.
    pub fn duration(&self) -> f64 {
        let secs = (self.last.secs - self.first.secs) as f64;
        let nanos = f64::from(self.last.nanos) - f64::from(self.first.nanos);
        (secs + nanos / 1e9).max(0.0)
    }

    /// Bits per second over the conversation's lifetime, or `None` when it
    /// is too short to divide by.
    pub fn bits_per_second(&self) -> Option<f64> {
        let d = self.duration();
        (d > 0.000_001).then(|| self.total_bytes() as f64 * 8.0 / d)
    }
}

fn ordered(a: Addr, pa: u16, b: Addr, pb: u16, stream: Option<u32>) -> (Key, bool) {
    // Sorting the endpoints makes both directions land on one row; the flag
    // says whether this frame ran in the stored order or the other way.
    let forward = (addr_key(a), pa) <= (addr_key(b), pb);
    if forward {
        (
            Key {
                a,
                b,
                port_a: pa,
                port_b: pb,
                stream,
            },
            true,
        )
    } else {
        (
            Key {
                a: b,
                b: a,
                port_a: pb,
                port_b: pa,
                stream,
            },
            false,
        )
    }
}

/// A sortable form of an address, so endpoint ordering is deterministic.
fn addr_key(a: Addr) -> (u8, [u8; 16]) {
    let mut bytes = [0u8; 16];
    match a {
        Addr::None => (0, bytes),
        Addr::Mac(m) => {
            bytes[..6].copy_from_slice(&m);
            (1, bytes)
        }
        Addr::Ipv4(v) => {
            bytes[..4].copy_from_slice(&v);
            (2, bytes)
        }
        Addr::Ipv6(v) => {
            bytes.copy_from_slice(&v);
            (3, bytes)
        }
    }
}

/// A frame's endpoints at one layer, if it has them.
fn endpoints_at(frame: &Frame, kind: Kind) -> Option<(Addr, u16, Addr, u16, Option<u32>)> {
    let field = |name: &str| frame.tree.find(name).next().and_then(|n| n.unsigned());
    match kind {
        Kind::Ethernet => {
            let src = mac_of(frame, "eth.src")?;
            let dst = mac_of(frame, "eth.dst")?;
            Some((src, 0, dst, 0, None))
        }
        Kind::Ip => {
            let (s, d) = net_addrs(frame)?;
            Some((s, 0, d, 0, None))
        }
        Kind::Tcp => {
            let (s, d) = net_addrs(frame)?;
            let sp = field("tcp.srcport")? as u16;
            let dp = field("tcp.dstport")? as u16;
            Some((s, sp, d, dp, field("tcp.stream").map(|v| v as u32)))
        }
        Kind::Udp => {
            let (s, d) = net_addrs(frame)?;
            let sp = field("udp.srcport")? as u16;
            let dp = field("udp.dstport")? as u16;
            Some((s, sp, d, dp, field("udp.stream").map(|v| v as u32)))
        }
    }
}

/// The address a node holds, whatever family it is.
fn addr_of(frame: &Frame, field: &str) -> Option<Addr> {
    match frame.tree.find(field).next()?.value() {
        Value::Mac(m) => Some(Addr::Mac(m)),
        Value::Ipv4(v) => Some(Addr::Ipv4(v)),
        Value::Ipv6(v) => Some(Addr::Ipv6(v)),
        _ => None,
    }
}

fn mac_of(frame: &Frame, field: &str) -> Option<Addr> {
    match addr_of(frame, field)? {
        a @ Addr::Mac(_) => Some(a),
        _ => None,
    }
}

fn net_addrs(frame: &Frame) -> Option<(Addr, Addr)> {
    if let (Some(s), Some(d)) = (addr_of(frame, "ip.src"), addr_of(frame, "ip.dst")) {
        return Some((s, d));
    }
    Some((addr_of(frame, "ipv6.src")?, addr_of(frame, "ipv6.dst")?))
}

/// Total every conversation at `kind` across the snapshot.
pub fn conversations(snapshot: &Snapshot, kind: Kind) -> Vec<Row> {
    let mut rows: HashMap<Key, Row> = HashMap::new();
    for frame in snapshot.iter() {
        let Some((s, sp, d, dp, stream)) = endpoints_at(frame, kind) else {
            continue;
        };
        let (key, forward) = ordered(s, sp, d, dp, stream);
        let i = usize::from(!forward);
        let bytes = u64::from(frame.orig_len);
        rows.entry(key)
            .and_modify(|r| {
                r.packets[i] += 1;
                r.bytes[i] += bytes;
                r.last = frame.ts;
                if r.stream.is_none() {
                    r.stream = stream;
                }
            })
            .or_insert_with(|| {
                let mut r = Row {
                    a: key.a,
                    b: key.b,
                    port_a: key.port_a,
                    port_b: key.port_b,
                    packets: [0, 0],
                    bytes: [0, 0],
                    first: frame.ts,
                    last: frame.ts,
                    stream,
                };
                r.packets[i] = 1;
                r.bytes[i] = bytes;
                r
            });
    }
    let mut out: Vec<Row> = rows.into_values().collect();
    // Busiest first: the reason to open this table is to find what is using
    // the link.
    out.sort_by_key(|r| std::cmp::Reverse(r.total_bytes()));
    out
}

/// A display filter selecting this conversation, for the "apply as filter"
/// action.
pub fn filter_for(row: &Row, kind: Kind) -> String {
    let a = row.a.to_string();
    let b = row.b.to_string();
    match kind {
        Kind::Ethernet => format!("eth.addr == {a} && eth.addr == {b}"),
        Kind::Ip => {
            let field = if matches!(row.a, Addr::Ipv6(_)) {
                "ipv6.addr"
            } else {
                "ip.addr"
            };
            format!("{field} == {a} && {field} == {b}")
        }
        Kind::Tcp | Kind::Udp => match row.stream {
            Some(id) if kind == Kind::Tcp => format!("tcp.stream == {id}"),
            Some(id) => format!("udp.stream == {id}"),
            None => {
                let proto = if kind == Kind::Tcp { "tcp" } else { "udp" };
                let field = if matches!(row.a, Addr::Ipv6(_)) {
                    "ipv6.addr"
                } else {
                    "ip.addr"
                };
                format!(
                    "{field} == {a} && {field} == {b} && {proto}.port == {} && {proto}.port == {}",
                    row.port_a, row.port_b
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_ordering_is_symmetric() {
        // Both directions must produce the same key, or a conversation shows
        // up as two rows that each know half the traffic.
        let a = Addr::Ipv4([10, 0, 0, 1]);
        let b = Addr::Ipv4([10, 0, 0, 2]);
        let (k1, f1) = ordered(a, 1000, b, 80, Some(0));
        let (k2, f2) = ordered(b, 80, a, 1000, Some(0));
        assert_eq!(k1, k2);
        assert_ne!(f1, f2, "and they must be recorded in opposite columns");
    }

    #[test]
    fn the_same_addresses_on_different_ports_are_different_conversations() {
        let a = Addr::Ipv4([10, 0, 0, 1]);
        let b = Addr::Ipv4([10, 0, 0, 2]);
        assert_ne!(
            ordered(a, 1000, b, 80, Some(0)).0,
            ordered(a, 1001, b, 80, Some(1)).0
        );
    }

    #[test]
    fn the_same_five_tuple_used_twice_gives_two_rows() {
        // Ports are reused. Adding a later connection's totals to an earlier
        // one's would describe traffic that never shared a conversation.
        let a = Addr::Ipv4([10, 0, 0, 1]);
        let b = Addr::Ipv4([10, 0, 0, 2]);
        assert_ne!(
            ordered(a, 1000, b, 80, Some(0)).0,
            ordered(a, 1000, b, 80, Some(2)).0
        );
    }

    #[test]
    fn address_families_do_not_collide() {
        let v4 = Addr::Ipv4([0, 0, 0, 1]);
        let mac = Addr::Mac([0, 0, 0, 0, 0, 1]);
        assert_ne!(addr_key(v4), addr_key(mac));
    }

    #[test]
    fn duration_and_rate_survive_a_single_frame() {
        // One frame means zero duration, and dividing by it would give an
        // infinite bit rate.
        let ts = Timestamp {
            secs: 100,
            nanos: 0,
        };
        let row = Row {
            a: Addr::None,
            b: Addr::None,
            port_a: 0,
            port_b: 0,
            packets: [1, 0],
            bytes: [100, 0],
            first: ts,
            last: ts,
            stream: None,
        };
        assert_eq!(row.duration(), 0.0);
        assert_eq!(row.bits_per_second(), None);
    }

    #[test]
    fn a_rate_is_bits_not_bytes() {
        let row = Row {
            a: Addr::None,
            b: Addr::None,
            port_a: 0,
            port_b: 0,
            packets: [1, 1],
            bytes: [500, 500],
            first: Timestamp { secs: 0, nanos: 0 },
            last: Timestamp { secs: 1, nanos: 0 },
            stream: None,
        };
        assert_eq!(row.duration(), 1.0);
        assert_eq!(row.bits_per_second(), Some(8000.0));
    }
}
