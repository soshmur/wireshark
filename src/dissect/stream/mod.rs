//! Conversation tracking by 5-tuple.
//!
//! A *stream* is one bidirectional conversation: the same TCP connection or
//! the same UDP flow seen in both directions. Frames carry a stream id so the
//! filter language can select a conversation (`tcp.stream == 3`) and so
//! Follow Stream knows what to gather.
//!
//! Ids are assigned in the order conversations are first seen and never
//! reused within a capture, which is what makes them usable in a filter that
//! the user types after the fact.

pub mod table;

pub use table::{Direction, Lookup, StreamKey, StreamTable};

use crate::dissect::ctx::NetAddrs;

/// One end of a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// IPv4 addresses are held in the low four bytes with the rest zero, so
    /// one representation orders and hashes both families.
    pub addr: [u8; 16],
    pub v6: bool,
    pub port: u16,
}

impl Endpoint {
    pub fn v4(addr: [u8; 4], port: u16) -> Endpoint {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr);
        Endpoint {
            addr: a,
            v6: false,
            port,
        }
    }

    pub fn v6(addr: [u8; 16], port: u16) -> Endpoint {
        Endpoint {
            addr,
            v6: true,
            port,
        }
    }

    /// The address as it should be rendered.
    pub fn text(&self) -> String {
        if self.v6 {
            crate::dissect::node::fmt_ipv6(self.addr)
        } else {
            let mut v4 = [0u8; 4];
            v4.copy_from_slice(&self.addr[..4]);
            crate::dissect::node::fmt_ipv4(v4)
        }
    }
}

/// The two endpoints of a frame's transport layer, in wire order.
pub fn endpoints(addrs: NetAddrs, sport: u16, dport: u16) -> (Endpoint, Endpoint) {
    match addrs {
        NetAddrs::V4(s, d) => (Endpoint::v4(s, sport), Endpoint::v4(d, dport)),
        NetAddrs::V6(s, d) => (Endpoint::v6(s, sport), Endpoint::v6(d, dport)),
    }
}
