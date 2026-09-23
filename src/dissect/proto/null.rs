//! DLT_NULL / DLT_LOOP (BSD and Npcap loopback): a 4-byte address family.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (raw, r) = c.take(4)?;
    // Written in the capturing host's byte order; accept either.
    let le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let family = if le <= 0xff { le } else { be };

    ctx.set_protocol("null");
    let node = ctx.begin("null", start..c.abs());
    ctx.leaf("null.family", r, Value::Unsigned(u64::from(family)));
    ctx.end_at(node, c.abs());

    let next = match family {
        2 => Proto::Ipv4,
        24 | 28 | 30 => Proto::Ipv6,
        _ => Proto::Data,
    };
    ctx.call_next(next, c.pos());
    Ok(())
}
