//! IEEE 802.1Q tag.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;

use super::ethertype_next;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (tci, tci_r) = c.u16()?;
    let (etype, etype_r) = c.u16()?;
    let pcp = tci >> 13;
    let dei = (tci >> 12) & 1 == 1;
    let id = tci & 0x0fff;

    ctx.set_protocol("vlan");
    let text = format!(
        "802.1Q Virtual LAN, PRI: {pcp}, DEI: {}, ID: {id}",
        u8::from(dei)
    );
    let node = ctx.begin_text("vlan", start..c.abs(), &text);
    ctx.leaf(
        "vlan.priority",
        tci_r.clone(),
        Value::Unsigned(u64::from(pcp)),
    );
    ctx.leaf("vlan.dei", tci_r.clone(), Value::Bool(dei));
    ctx.leaf("vlan.id", tci_r, Value::Unsigned(u64::from(id)));
    ctx.leaf("vlan.etype", etype_r, Value::Unsigned(u64::from(etype)));
    ctx.end_at(node, c.abs());

    ctx.call_next(ethertype_next(etype), c.pos());
    Ok(())
}
