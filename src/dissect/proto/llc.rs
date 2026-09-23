//! IEEE 802.2 LLC with the SNAP extension.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;

use super::ethertype_next;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (dsap, dsap_r) = c.u8()?;
    let (ssap, ssap_r) = c.u8()?;
    let (ctrl, ctrl_r) = c.u8()?;
    // I and S frames (low two control bits != 11) carry a 16-bit control field.
    let ctrl_r = if ctrl & 0x03 != 0x03 {
        let (_, r2) = c.u8()?;
        ctrl_r.start..r2.end
    } else {
        ctrl_r
    };

    ctx.set_protocol("llc");
    let node = ctx.begin("llc", start..start);
    ctx.leaf("llc.dsap", dsap_r, Value::Unsigned(u64::from(dsap)));
    ctx.leaf("llc.ssap", ssap_r, Value::Unsigned(u64::from(ssap)));
    ctx.leaf("llc.control", ctrl_r, Value::Unsigned(u64::from(ctrl)));

    if dsap == 0xaa && ssap == 0xaa && ctrl == 0x03 {
        // SNAP: 3-byte OUI + 2-byte protocol id.
        let (oui, oui_r) = c.u24()?;
        let (pid, pid_r) = c.u16()?;
        ctx.leaf("llc.oui", oui_r, Value::Unsigned(u64::from(oui)));
        if oui == 0 {
            ctx.leaf("llc.type", pid_r, Value::Unsigned(u64::from(pid)));
            ctx.call_next(ethertype_next(pid), c.pos());
        } else {
            ctx.leaf("llc.pid", pid_r, Value::Unsigned(u64::from(pid)));
            ctx.set_info(format!("SNAP OUI 0x{oui:06x} PID 0x{pid:04x}"));
            ctx.call_next(Proto::Data, c.pos());
        }
        let text = format!("Logical-Link Control (SNAP), OUI 0x{oui:06x}, PID 0x{pid:04x}");
        ctx.set_text(node, &text);
    } else {
        let text = format!("Logical-Link Control, DSAP 0x{dsap:02x}, SSAP 0x{ssap:02x}");
        ctx.set_text(node, &text);
        ctx.set_info(format!("LLC DSAP 0x{dsap:02x} SSAP 0x{ssap:02x}"));
        ctx.call_next(Proto::Data, c.pos());
    }
    ctx.end_at(node, c.abs());
    Ok(())
}
