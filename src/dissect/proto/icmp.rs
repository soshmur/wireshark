//! ICMPv4 (RFC 792). Error messages carry the offending IP header, which is
//! dissected as a nested layer.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{enum_name, ICMP_TYPES};

use super::{inet_checksum, CK_BAD, CK_GOOD, CK_UNVERIFIED};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let (code, code_r) = c.u8()?;
    let (checksum, checksum_r) = c.u16()?;

    ctx.set_protocol("icmp");
    let type_name = enum_name(ICMP_TYPES, u64::from(ty)).unwrap_or("Unknown");
    let icmp = ctx.begin("icmp", start..start + data.len());
    ctx.leaf("icmp.type", ty_r, Value::Unsigned(u64::from(ty)));
    ctx.leaf("icmp.code", code_r, Value::Unsigned(u64::from(code)));
    ctx.leaf(
        "icmp.checksum",
        checksum_r.clone(),
        Value::Unsigned(u64::from(checksum)),
    );
    let status = if !ctx.options().validate_ip_checksums {
        CK_UNVERIFIED
    } else if inet_checksum(&[data]) == 0 {
        CK_GOOD
    } else {
        CK_BAD
    };
    ctx.leaf("icmp.checksum.status", checksum_r, Value::Unsigned(status));

    match ty {
        0 | 8 | 13 | 14 => {
            let (ident, ident_r) = c.u16()?;
            let (seq, seq_r) = c.u16()?;
            ctx.leaf("icmp.ident", ident_r, Value::Unsigned(u64::from(ident)));
            ctx.leaf("icmp.seq", seq_r, Value::Unsigned(u64::from(seq)));
            ctx.set_info(format!("{type_name} id=0x{ident:04x}, seq={seq}"));
            if !c.is_empty() {
                ctx.leaf("icmp.data", c.rest_range(), Value::Bytes);
            }
        }
        3 | 4 | 5 | 11 | 12 => {
            match ty {
                3 if code == 4 => {
                    let (_, unused_r) = c.u16()?;
                    let (mtu, mtu_r) = c.u16()?;
                    ctx.leaf("icmp.unused", unused_r, Value::Unsigned(0));
                    ctx.leaf("icmp.mtu", mtu_r, Value::Unsigned(u64::from(mtu)));
                }
                5 => {
                    let (gw, gw_r) = c.ipv4()?;
                    ctx.leaf("icmp.gateway", gw_r, Value::Ipv4(gw));
                }
                12 => {
                    let (ptr, ptr_r) = c.u8()?;
                    let (_, unused_r) = c.take(3)?;
                    ctx.leaf("icmp.pointer", ptr_r, Value::Unsigned(u64::from(ptr)));
                    ctx.leaf("icmp.unused", unused_r, Value::Unsigned(0));
                }
                _ => {
                    let (unused, unused_r) = c.u32()?;
                    ctx.leaf("icmp.unused", unused_r, Value::Unsigned(u64::from(unused)));
                }
            }
            let detail = match (ty, code) {
                (3, 0) => "Destination network unreachable",
                (3, 1) => "Destination host unreachable",
                (3, 2) => "Destination protocol unreachable",
                (3, 3) => "Destination port unreachable",
                (3, 4) => "Fragmentation needed",
                (3, 13) => "Communication administratively filtered",
                (11, 0) => "Time to live exceeded in transit",
                (11, 1) => "Fragment reassembly time exceeded",
                _ => type_name,
            };
            ctx.set_info(detail);
            // The original datagram's header + 8 bytes follows; dissect it
            // nested so its addresses do not overwrite the summary columns.
            if !c.is_empty() {
                let saved = (ctx.summary.clone(), ctx.net_addrs, ctx.protocol_count());
                nested_ipv4(c.rest(), c.abs(), ctx);
                ctx.summary = saved.0;
                ctx.net_addrs = saved.1;
                ctx.truncate_protocols(saved.2);
            }
        }
        _ => {
            ctx.set_info(format!("{type_name} (type {ty}, code {code})"));
            if !c.is_empty() {
                ctx.leaf("icmp.data", c.rest_range(), Value::Bytes);
            }
        }
    }
    ctx.end();
    let _ = icmp;
    Ok(())
}

/// Dissect an embedded IPv4 datagram (and its transport header) as child
/// nodes. Errors become `[Malformed]` children rather than failing ICMP.
pub fn nested_ipv4(data: &[u8], base: usize, ctx: &mut Ctx) {
    if ctx.nesting >= 2 {
        return;
    }
    ctx.nesting += 1;
    let saved_base = ctx.base;
    let mut proto = Proto::Ipv4;
    let mut offset = base;
    let mut len: Option<usize> = None;
    let end = base + data.len();
    for _ in 0..4 {
        ctx.base = offset;
        let rel = offset - base;
        let slice_end = len.map_or(end, |l| (offset + l).min(end));
        let slice = data.get(rel..slice_end - base).unwrap_or(&[]);
        let result = match proto {
            Proto::Ipv4 => super::ipv4::dissect(slice, ctx),
            Proto::Tcp => super::tcp::dissect(slice, ctx),
            Proto::Udp => super::udp::dissect(slice, ctx),
            Proto::Icmp => dissect(slice, ctx),
            _ => super::data(slice, ctx),
        };
        if let Err(e) = result {
            let text = format!("[Malformed Packet: {}] {e}", proto.name());
            ctx.leaf_text("_ws.malformed", offset..end, Value::None, &text);
            ctx.take_next();
            break;
        }
        match ctx.take_next() {
            Some(h) if h.source == ctx.source && h.offset < end => {
                proto = h.proto;
                offset = h.offset;
                len = h.len;
            }
            _ => break,
        }
    }
    ctx.base = saved_base;
    ctx.nesting -= 1;
}
