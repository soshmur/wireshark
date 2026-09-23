//! Ethernet II and IEEE 802.3 framing.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{enum_name, ETHERTYPES};

use super::ethertype_next;
use crate::dissect::Addr;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (dst, dst_r) = c.mac()?;
    let (src, src_r) = c.mac()?;
    let (tl, tl_r) = c.u16()?;

    ctx.set_protocol("eth");
    ctx.summary.source = Addr::Mac(src);
    ctx.summary.destination = Addr::Mac(dst);

    let eth = ctx.begin("eth", start..c.abs());
    ctx.leaf("eth.dst", dst_r, Value::Mac(dst));
    ctx.leaf("eth.src", src_r, Value::Mac(src));

    if tl <= 1500 {
        // IEEE 802.3 length field: the payload is LLC, bounded by that length
        // so any trailer after it is left for the driver to account for.
        ctx.leaf("eth.len", tl_r, Value::Unsigned(u64::from(tl)));
        ctx.end_at(eth, c.abs());
        ctx.call_next_bounded(Proto::Llc, c.pos(), usize::from(tl));
        return Ok(());
    }

    ctx.leaf("eth.type", tl_r, Value::Unsigned(u64::from(tl)));
    ctx.end_at(eth, c.abs());
    if enum_name(ETHERTYPES, u64::from(tl)).is_none() {
        ctx.set_info(format!("Ethertype 0x{tl:04x}"));
    }
    ctx.call_next(ethertype_next(tl), c.pos());
    Ok(())
}
