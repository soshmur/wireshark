//! ICMPv6 (RFC 4443) including Neighbor Discovery messages (RFC 4861).

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{enum_name, ICMPV6_TYPES};

use super::{ipv6_str, transport_checksum, CK_BAD, CK_GOOD, CK_UNVERIFIED};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let (code, code_r) = c.u8()?;
    let (checksum, checksum_r) = c.u16()?;

    ctx.set_protocol("icmpv6");
    let type_name = enum_name(ICMPV6_TYPES, u64::from(ty)).unwrap_or("Unknown");
    let node = ctx.begin("icmpv6", start..start + data.len());
    ctx.leaf("icmpv6.type", ty_r, Value::Unsigned(u64::from(ty)));
    ctx.leaf("icmpv6.code", code_r, Value::Unsigned(u64::from(code)));
    ctx.leaf(
        "icmpv6.checksum",
        checksum_r.clone(),
        Value::Unsigned(u64::from(checksum)),
    );
    let status = if !ctx.options().validate_transport_checksums {
        CK_UNVERIFIED
    } else {
        match transport_checksum(ctx, 58, data) {
            Some(0) => CK_GOOD,
            Some(_) => CK_BAD,
            None => CK_UNVERIFIED,
        }
    };
    ctx.leaf(
        "icmpv6.checksum.status",
        checksum_r,
        Value::Unsigned(status),
    );

    match ty {
        128 | 129 => {
            let (ident, ident_r) = c.u16()?;
            let (seq, seq_r) = c.u16()?;
            ctx.leaf(
                "icmpv6.echo.identifier",
                ident_r,
                Value::Unsigned(u64::from(ident)),
            );
            ctx.leaf(
                "icmpv6.echo.sequence_number",
                seq_r,
                Value::Unsigned(u64::from(seq)),
            );
            ctx.set_info(format!("{type_name} id=0x{ident:04x}, seq={seq}"));
            if !c.is_empty() {
                ctx.leaf("icmpv6.data", c.rest_range(), Value::Bytes);
            }
        }
        133 => {
            let (res, res_r) = c.u32()?;
            ctx.leaf("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res)));
            ctx.set_info("Router Solicitation");
            options(&mut c, ctx);
        }
        134 => {
            let (hlim, hlim_r) = c.u8()?;
            let (flags, flags_r) = c.u8()?;
            let (lifetime, lifetime_r) = c.u16()?;
            let (reach, reach_r) = c.u32()?;
            let (retrans, retrans_r) = c.u32()?;
            ctx.leaf(
                "icmpv6.nd.ra.cur_hop_limit",
                hlim_r,
                Value::Unsigned(u64::from(hlim)),
            );
            ctx.begin_value(
                "icmpv6.nd.ra.flag",
                flags_r.clone(),
                Value::Unsigned(u64::from(flags)),
            );
            ctx.leaf(
                "icmpv6.nd.ra.flag.m",
                flags_r.clone(),
                Value::Bool(flags & 0x80 != 0),
            );
            ctx.leaf(
                "icmpv6.nd.ra.flag.o",
                flags_r,
                Value::Bool(flags & 0x40 != 0),
            );
            ctx.end();
            ctx.leaf(
                "icmpv6.nd.ra.router_lifetime",
                lifetime_r,
                Value::Unsigned(u64::from(lifetime)),
            );
            ctx.leaf(
                "icmpv6.nd.ra.reachable_time",
                reach_r,
                Value::Unsigned(u64::from(reach)),
            );
            ctx.leaf(
                "icmpv6.nd.ra.retrans_timer",
                retrans_r,
                Value::Unsigned(u64::from(retrans)),
            );
            ctx.set_info("Router Advertisement");
            options(&mut c, ctx);
        }
        135 => {
            let (res, res_r) = c.u32()?;
            let (target, target_r) = c.ipv6()?;
            ctx.leaf("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res)));
            ctx.leaf("icmpv6.nd.ns.target_address", target_r, Value::Ipv6(target));
            ctx.set_info(format!("Neighbor Solicitation for {}", ipv6_str(target)));
            options(&mut c, ctx);
        }
        136 => {
            let (flags, flags_r) = c.u32()?;
            let (target, target_r) = c.ipv6()?;
            ctx.begin_value(
                "icmpv6.nd.na.flag",
                flags_r.clone(),
                Value::Unsigned(u64::from(flags >> 29)),
            );
            ctx.leaf(
                "icmpv6.nd.na.flag.r",
                flags_r.clone(),
                Value::Bool(flags & 0x8000_0000 != 0),
            );
            ctx.leaf(
                "icmpv6.nd.na.flag.s",
                flags_r.clone(),
                Value::Bool(flags & 0x4000_0000 != 0),
            );
            ctx.leaf(
                "icmpv6.nd.na.flag.o",
                flags_r,
                Value::Bool(flags & 0x2000_0000 != 0),
            );
            ctx.end();
            ctx.leaf("icmpv6.nd.na.target_address", target_r, Value::Ipv6(target));
            let mut tags = Vec::new();
            if flags & 0x8000_0000 != 0 {
                tags.push("rtr");
            }
            if flags & 0x4000_0000 != 0 {
                tags.push("sol");
            }
            if flags & 0x2000_0000 != 0 {
                tags.push("ovr");
            }
            ctx.set_info(format!(
                "Neighbor Advertisement {} is at ({})",
                ipv6_str(target),
                tags.join(", ")
            ));
            options(&mut c, ctx);
        }
        137 => {
            let (res, res_r) = c.u32()?;
            let (target, target_r) = c.ipv6()?;
            let (dest, dest_r) = c.ipv6()?;
            ctx.leaf("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res)));
            ctx.leaf("icmpv6.nd.rd.target_address", target_r, Value::Ipv6(target));
            ctx.leaf(
                "icmpv6.nd.rd.destination_address",
                dest_r,
                Value::Ipv6(dest),
            );
            ctx.set_info(format!(
                "Redirect {} to {}",
                ipv6_str(dest),
                ipv6_str(target)
            ));
            options(&mut c, ctx);
        }
        1..=4 => {
            match ty {
                2 => {
                    let (mtu, mtu_r) = c.u32()?;
                    ctx.leaf("icmpv6.mtu", mtu_r, Value::Unsigned(u64::from(mtu)));
                    ctx.set_info(format!("Packet Too Big (MTU {mtu})"));
                }
                4 => {
                    let (ptr, ptr_r) = c.u32()?;
                    ctx.leaf("icmpv6.pointer", ptr_r, Value::Unsigned(u64::from(ptr)));
                    ctx.set_info(format!("Parameter Problem (pointer {ptr})"));
                }
                _ => {
                    let (res, res_r) = c.u32()?;
                    ctx.leaf("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res)));
                    let detail = match (ty, code) {
                        (1, 0) => "No route to destination",
                        (1, 1) => "Communication administratively prohibited",
                        (1, 3) => "Address unreachable",
                        (1, 4) => "Port unreachable",
                        (3, 0) => "Hop limit exceeded in transit",
                        (3, 1) => "Fragment reassembly time exceeded",
                        _ => type_name,
                    };
                    ctx.set_info(detail);
                }
            }
            // Invoking packet: shown as data (IPv6 nesting is not dissected).
            if !c.is_empty() {
                ctx.leaf("icmpv6.data", c.rest_range(), Value::Bytes);
            }
        }
        _ => {
            ctx.set_info(format!("{type_name} (type {ty}, code {code})"));
            if !c.is_empty() {
                ctx.leaf("icmpv6.data", c.rest_range(), Value::Bytes);
            }
        }
    }
    ctx.end();
    let _ = node;
    Ok(())
}

/// Neighbor Discovery TLV options; a bad option becomes a malformed child.
fn options(c: &mut Cursor, ctx: &mut Ctx) {
    while !c.is_empty() {
        let start = c.abs();
        if let Err(e) = option(c, ctx) {
            let text = format!("[Malformed option: {e}]");
            ctx.leaf_text(
                "_ws.malformed",
                start..c.abs() + c.remaining(),
                Value::None,
                &text,
            );
            break;
        }
    }
}

fn option(c: &mut Cursor, ctx: &mut Ctx) -> Result<()> {
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let opt = ctx.begin("icmpv6.opt", start..start);
    ctx.leaf("icmpv6.opt.type", ty_r, Value::Unsigned(u64::from(ty)));
    let (len, len_r) = match c.u8() {
        Ok(v) => v,
        Err(e) => {
            ctx.end_at(opt, c.abs());
            return Err(e);
        }
    };
    ctx.leaf(
        "icmpv6.opt.length",
        len_r.clone(),
        Value::Unsigned(u64::from(len)),
    );
    if len == 0 {
        ctx.end_at(opt, c.abs());
        return Err(DissectError::Invalid {
            at: len_r.start,
            what: "ICMPv6 option length 0",
        });
    }
    let mut body = match c.sub(usize::from(len) * 8 - 2) {
        Ok(v) => v,
        Err(e) => {
            ctx.end_at(opt, c.abs());
            return Err(e);
        }
    };
    let text = match ty {
        1 | 2 if body.remaining() >= 6 => {
            let (mac, mac_r) = body.mac()?;
            ctx.leaf("icmpv6.opt.linkaddr", mac_r, Value::Mac(mac));
            format!(
                "ICMPv6 Option ({} link-layer address: {})",
                if ty == 1 { "Source" } else { "Target" },
                super::mac_str(mac)
            )
        }
        3 if body.remaining() >= 30 => {
            let (plen, plen_r) = body.u8()?;
            body.u8()?;
            let (valid, valid_r) = body.u32()?;
            let (pref, pref_r) = body.u32()?;
            body.u32()?;
            let (prefix, prefix_r) = body.ipv6()?;
            ctx.leaf(
                "icmpv6.opt.prefix.length",
                plen_r,
                Value::Unsigned(u64::from(plen)),
            );
            ctx.leaf(
                "icmpv6.opt.prefix.valid_lifetime",
                valid_r,
                Value::Unsigned(u64::from(valid)),
            );
            ctx.leaf(
                "icmpv6.opt.prefix.preferred_lifetime",
                pref_r,
                Value::Unsigned(u64::from(pref)),
            );
            ctx.leaf("icmpv6.opt.prefix", prefix_r, Value::Ipv6(prefix));
            format!(
                "ICMPv6 Option (Prefix information: {}/{plen})",
                ipv6_str(prefix)
            )
        }
        5 if body.remaining() >= 6 => {
            body.u16()?;
            let (mtu, mtu_r) = body.u32()?;
            ctx.leaf("icmpv6.opt.mtu", mtu_r, Value::Unsigned(u64::from(mtu)));
            format!("ICMPv6 Option (MTU: {mtu})")
        }
        _ => {
            ctx.leaf("icmpv6.opt.data", body.rest_range(), Value::Bytes);
            format!("ICMPv6 Option (type {ty}, {} bytes)", usize::from(len) * 8)
        }
    };
    ctx.set_text(opt, &text);
    ctx.end_at(opt, c.abs());
    Ok(())
}
