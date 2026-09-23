//! Address Resolution Protocol (RFC 826).

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;

use super::{ipv4_str, mac_str};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (hw_type, hw_type_r) = c.u16()?;
    let (proto_type, proto_type_r) = c.u16()?;
    let (hw_size, hw_size_r) = c.u8()?;
    let (proto_size, proto_size_r) = c.u8()?;
    let (opcode, opcode_r) = c.u16()?;

    ctx.set_protocol("arp");
    let node = ctx.begin("arp", start..start);
    ctx.leaf(
        "arp.hw.type",
        hw_type_r,
        Value::Unsigned(u64::from(hw_type)),
    );
    ctx.leaf(
        "arp.proto.type",
        proto_type_r,
        Value::Unsigned(u64::from(proto_type)),
    );
    ctx.leaf(
        "arp.hw.size",
        hw_size_r,
        Value::Unsigned(u64::from(hw_size)),
    );
    ctx.leaf(
        "arp.proto.size",
        proto_size_r,
        Value::Unsigned(u64::from(proto_size)),
    );
    ctx.leaf("arp.opcode", opcode_r, Value::Unsigned(u64::from(opcode)));

    let eth_ipv4 = hw_type == 1 && proto_type == 0x0800 && hw_size == 6 && proto_size == 4;
    if eth_ipv4 {
        let (sha, sha_r) = c.mac()?;
        let (spa, spa_r) = c.ipv4()?;
        let (tha, tha_r) = c.mac()?;
        let (tpa, tpa_r) = c.ipv4()?;
        ctx.leaf("arp.src.hw_mac", sha_r, Value::Mac(sha));
        ctx.leaf("arp.src.proto_ipv4", spa_r, Value::Ipv4(spa));
        ctx.leaf("arp.dst.hw_mac", tha_r, Value::Mac(tha));
        ctx.leaf("arp.dst.proto_ipv4", tpa_r, Value::Ipv4(tpa));
        let info = match opcode {
            1 if spa == tpa => format!("ARP Announcement for {}", ipv4_str(spa)),
            1 if spa == [0; 4] => format!("Who has {}? (ARP Probe)", ipv4_str(tpa)),
            1 => format!("Who has {}? Tell {}", ipv4_str(tpa), ipv4_str(spa)),
            2 => format!("{} is at {}", ipv4_str(spa), mac_str(sha)),
            _ => format!("ARP opcode {opcode}"),
        };
        ctx.set_info(info);
    } else {
        let (_, sha_r) = c.take(usize::from(hw_size))?;
        let (_, spa_r) = c.take(usize::from(proto_size))?;
        let (_, tha_r) = c.take(usize::from(hw_size))?;
        let (_, tpa_r) = c.take(usize::from(proto_size))?;
        ctx.leaf("arp.src.hw", sha_r, Value::Bytes);
        ctx.leaf("arp.src.proto", spa_r, Value::Bytes);
        ctx.leaf("arp.dst.hw", tha_r, Value::Bytes);
        ctx.leaf("arp.dst.proto", tpa_r, Value::Bytes);
        ctx.set_info(format!(
            "ARP hw type {hw_type}, proto 0x{proto_type:04x}, opcode {opcode}"
        ));
    }
    // Trailing bytes (Ethernet pads short frames to 60) belong to no layer;
    // the driver accounts for them once it can see the whole frame.
    ctx.end_at(node, c.abs());
    Ok(())
}
