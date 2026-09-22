//! IEEE 802.1Q tag.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::{Node, Value};

use super::ethertype_next;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();
    let (tci, tci_r) = c.u16()?;
    let (etype, etype_r) = c.u16()?;
    let pcp = tci >> 13;
    let dei = (tci >> 12) & 1 == 1;
    let id = tci & 0x0fff;

    ctx.set_protocol("vlan");
    let mut node = Node::new("vlan", start..c.abs(), Value::None)
        .with_source(s)
        .with_text(format!(
            "802.1Q Virtual LAN, PRI: {pcp}, DEI: {}, ID: {id}",
            u8::from(dei)
        ));
    node.push(
        Node::new(
            "vlan.priority",
            tci_r.clone(),
            Value::Unsigned(u64::from(pcp)),
        )
        .with_source(s),
    );
    node.push(Node::new("vlan.dei", tci_r.clone(), Value::Bool(dei)).with_source(s));
    node.push(Node::new("vlan.id", tci_r, Value::Unsigned(u64::from(id))).with_source(s));
    node.push(Node::new("vlan.etype", etype_r, Value::Unsigned(u64::from(etype))).with_source(s));
    ctx.call_next(ethertype_next(etype), c.pos());
    Ok(node)
}
