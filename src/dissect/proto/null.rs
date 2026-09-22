//! DLT_NULL / DLT_LOOP (BSD and Npcap loopback): a 4-byte address family.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::{Node, Value};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();
    let (raw, r) = c.take(4)?;
    // Written in the capturing host's byte order; accept either.
    let le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let family = if le <= 0xff { le } else { be };
    ctx.set_protocol("null");
    let mut node = Node::new("null", start..c.abs(), Value::None)
        .with_source(s)
        .with_text("Null/Loopback");
    node.push(Node::new("null.family", r, Value::Unsigned(u64::from(family))).with_source(s));
    let next = match family {
        2 => Proto::Ipv4,
        24 | 28 | 30 => Proto::Ipv6,
        _ => Proto::Data,
    };
    ctx.call_next(next, c.pos());
    Ok(node)
}
