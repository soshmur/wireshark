//! Ethernet II and IEEE 802.3 framing.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::{Node, Value};
use crate::dissect::registry::{enum_name, ETHERTYPES};

use super::{ethertype_next, mac_str};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();
    let (dst, dst_r) = c.mac()?;
    let (src, src_r) = c.mac()?;
    let (tl, tl_r) = c.u16()?;

    ctx.set_protocol("eth");
    ctx.summary.source = mac_str(src);
    ctx.summary.destination = mac_str(dst);

    let mut node = Node::new("eth", start..c.abs(), Value::None)
        .with_source(s)
        .reserve(4);
    node.push(Node::new("eth.dst", dst_r, Value::Mac(dst)).with_source(s));
    node.push(Node::new("eth.src", src_r, Value::Mac(src)).with_source(s));

    if tl <= 1500 {
        // IEEE 802.3 length field: the payload is LLC.
        node.push(Node::new("eth.len", tl_r, Value::Unsigned(u64::from(tl))).with_source(s));
        ctx.call_next(Proto::Llc, c.pos());
        return Ok(node);
    }

    node.push(Node::new("eth.type", tl_r, Value::Unsigned(u64::from(tl))).with_source(s));
    if enum_name(ETHERTYPES, u64::from(tl)).is_none() {
        ctx.set_info(format!("Ethertype 0x{tl:04x}"));
    }
    ctx.call_next(ethertype_next(tl), c.pos());
    Ok(node)
}
