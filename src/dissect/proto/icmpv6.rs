//! ICMPv6 (RFC 4443) including Neighbor Discovery messages (RFC 4861).

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::{Node, Value};
use crate::dissect::registry::{enum_name, ICMPV6_TYPES};

use super::{ipv6_str, transport_checksum, CK_BAD, CK_GOOD, CK_UNVERIFIED};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let (code, code_r) = c.u8()?;
    let (checksum, checksum_r) = c.u16()?;

    ctx.set_protocol("icmpv6");
    let type_name = enum_name(ICMPV6_TYPES, u64::from(ty)).unwrap_or("Unknown");
    let mut node = Node::new("icmpv6", start..start + data.len(), Value::None)
        .with_source(s)
        .reserve(8);
    node.push(Node::new("icmpv6.type", ty_r, Value::Unsigned(u64::from(ty))).with_source(s));
    node.push(Node::new("icmpv6.code", code_r, Value::Unsigned(u64::from(code))).with_source(s));
    node.push(
        Node::new(
            "icmpv6.checksum",
            checksum_r.clone(),
            Value::Unsigned(u64::from(checksum)),
        )
        .with_source(s),
    );
    let status = match transport_checksum(ctx, 58, data) {
        Some(0) => CK_GOOD,
        Some(_) => CK_BAD,
        None => CK_UNVERIFIED,
    };
    node.push(
        Node::new(
            "icmpv6.checksum.status",
            checksum_r,
            Value::Unsigned(status),
        )
        .with_source(s),
    );

    match ty {
        128 | 129 => {
            let (ident, ident_r) = c.u16()?;
            let (seq, seq_r) = c.u16()?;
            node.push(
                Node::new(
                    "icmpv6.echo.identifier",
                    ident_r,
                    Value::Unsigned(u64::from(ident)),
                )
                .with_source(s),
            );
            node.push(
                Node::new(
                    "icmpv6.echo.sequence_number",
                    seq_r,
                    Value::Unsigned(u64::from(seq)),
                )
                .with_source(s),
            );
            ctx.set_info(format!("{type_name} id=0x{ident:04x}, seq={seq}"));
            if !c.is_empty() {
                node.push(Node::new("icmpv6.data", c.rest_range(), Value::Bytes).with_source(s));
            }
        }
        133 => {
            let (res, res_r) = c.u32()?;
            node.push(
                Node::new("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res))).with_source(s),
            );
            ctx.set_info("Router Solicitation");
            options(&mut c, &mut node);
        }
        134 => {
            let (hlim, hlim_r) = c.u8()?;
            let (flags, flags_r) = c.u8()?;
            let (lifetime, lifetime_r) = c.u16()?;
            let (reach, reach_r) = c.u32()?;
            let (retrans, retrans_r) = c.u32()?;
            node.push(
                Node::new(
                    "icmpv6.nd.ra.cur_hop_limit",
                    hlim_r,
                    Value::Unsigned(u64::from(hlim)),
                )
                .with_source(s),
            );
            let mut fl = Node::new(
                "icmpv6.nd.ra.flag",
                flags_r.clone(),
                Value::Unsigned(u64::from(flags)),
            )
            .with_source(s);
            fl.push(
                Node::new(
                    "icmpv6.nd.ra.flag.m",
                    flags_r.clone(),
                    Value::Bool(flags & 0x80 != 0),
                )
                .with_source(s),
            );
            fl.push(
                Node::new(
                    "icmpv6.nd.ra.flag.o",
                    flags_r,
                    Value::Bool(flags & 0x40 != 0),
                )
                .with_source(s),
            );
            node.push(fl);
            node.push(
                Node::new(
                    "icmpv6.nd.ra.router_lifetime",
                    lifetime_r,
                    Value::Unsigned(u64::from(lifetime)),
                )
                .with_source(s),
            );
            node.push(
                Node::new(
                    "icmpv6.nd.ra.reachable_time",
                    reach_r,
                    Value::Unsigned(u64::from(reach)),
                )
                .with_source(s),
            );
            node.push(
                Node::new(
                    "icmpv6.nd.ra.retrans_timer",
                    retrans_r,
                    Value::Unsigned(u64::from(retrans)),
                )
                .with_source(s),
            );
            ctx.set_info("Router Advertisement");
            options(&mut c, &mut node);
        }
        135 => {
            let (res, res_r) = c.u32()?;
            let (target, target_r) = c.ipv6()?;
            node.push(
                Node::new("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res))).with_source(s),
            );
            node.push(
                Node::new("icmpv6.nd.ns.target_address", target_r, Value::Ipv6(target))
                    .with_source(s),
            );
            ctx.set_info(format!("Neighbor Solicitation for {}", ipv6_str(target)));
            options(&mut c, &mut node);
        }
        136 => {
            let (flags, flags_r) = c.u32()?;
            let (target, target_r) = c.ipv6()?;
            let mut fl = Node::new(
                "icmpv6.nd.na.flag",
                flags_r.clone(),
                Value::Unsigned(u64::from(flags >> 29)),
            )
            .with_source(s);
            fl.push(
                Node::new(
                    "icmpv6.nd.na.flag.r",
                    flags_r.clone(),
                    Value::Bool(flags & 0x8000_0000 != 0),
                )
                .with_source(s),
            );
            fl.push(
                Node::new(
                    "icmpv6.nd.na.flag.s",
                    flags_r.clone(),
                    Value::Bool(flags & 0x4000_0000 != 0),
                )
                .with_source(s),
            );
            fl.push(
                Node::new(
                    "icmpv6.nd.na.flag.o",
                    flags_r,
                    Value::Bool(flags & 0x2000_0000 != 0),
                )
                .with_source(s),
            );
            node.push(fl);
            node.push(
                Node::new("icmpv6.nd.na.target_address", target_r, Value::Ipv6(target))
                    .with_source(s),
            );
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
            options(&mut c, &mut node);
        }
        137 => {
            let (res, res_r) = c.u32()?;
            let (target, target_r) = c.ipv6()?;
            let (dest, dest_r) = c.ipv6()?;
            node.push(
                Node::new("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res))).with_source(s),
            );
            node.push(
                Node::new("icmpv6.nd.rd.target_address", target_r, Value::Ipv6(target))
                    .with_source(s),
            );
            node.push(
                Node::new(
                    "icmpv6.nd.rd.destination_address",
                    dest_r,
                    Value::Ipv6(dest),
                )
                .with_source(s),
            );
            ctx.set_info(format!(
                "Redirect {} to {}",
                ipv6_str(dest),
                ipv6_str(target)
            ));
            options(&mut c, &mut node);
        }
        1..=4 => {
            match ty {
                2 => {
                    let (mtu, mtu_r) = c.u32()?;
                    node.push(
                        Node::new("icmpv6.mtu", mtu_r, Value::Unsigned(u64::from(mtu)))
                            .with_source(s),
                    );
                    ctx.set_info(format!("Packet Too Big (MTU {mtu})"));
                }
                4 => {
                    let (ptr, ptr_r) = c.u32()?;
                    node.push(
                        Node::new("icmpv6.pointer", ptr_r, Value::Unsigned(u64::from(ptr)))
                            .with_source(s),
                    );
                    ctx.set_info(format!("Parameter Problem (pointer {ptr})"));
                }
                _ => {
                    let (res, res_r) = c.u32()?;
                    node.push(
                        Node::new("icmpv6.reserved", res_r, Value::Unsigned(u64::from(res)))
                            .with_source(s),
                    );
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
                node.push(Node::new("icmpv6.data", c.rest_range(), Value::Bytes).with_source(s));
            }
        }
        _ => {
            ctx.set_info(format!("{type_name} (type {ty}, code {code})"));
            if !c.is_empty() {
                node.push(Node::new("icmpv6.data", c.rest_range(), Value::Bytes).with_source(s));
            }
        }
    }
    Ok(node)
}

/// Neighbor Discovery TLV options; a bad option becomes a malformed child.
fn options(c: &mut Cursor, node: &mut Node) {
    let s = c.source();
    while !c.is_empty() {
        let start = c.abs();
        let r = (|| -> Result<Node> {
            let (ty, ty_r) = c.u8()?;
            let (len, len_r) = c.u8()?;
            let mut opt = Node::new("icmpv6.opt", start..start, Value::None).with_source(s);
            opt.push(
                Node::new("icmpv6.opt.type", ty_r, Value::Unsigned(u64::from(ty))).with_source(s),
            );
            opt.push(
                Node::new(
                    "icmpv6.opt.length",
                    len_r.clone(),
                    Value::Unsigned(u64::from(len)),
                )
                .with_source(s),
            );
            if len == 0 {
                return Err(crate::dissect::cursor::DissectError::Invalid {
                    at: len_r.start,
                    what: "ICMPv6 option length 0",
                });
            }
            let mut body = c.sub(usize::from(len) * 8 - 2)?;
            match ty {
                1 | 2 if body.remaining() >= 6 => {
                    let (mac, mac_r) = body.mac()?;
                    opt.push(
                        Node::new("icmpv6.opt.linkaddr", mac_r, Value::Mac(mac)).with_source(s),
                    );
                    opt.text = Some(
                        format!(
                            "ICMPv6 Option ({} link-layer address: {})",
                            if ty == 1 { "Source" } else { "Target" },
                            super::mac_str(mac)
                        )
                        .into(),
                    );
                }
                3 if body.remaining() >= 30 => {
                    let (plen, plen_r) = body.u8()?;
                    let (_, _flags_r) = body.u8()?;
                    let (valid, valid_r) = body.u32()?;
                    let (pref, pref_r) = body.u32()?;
                    let (_, _res_r) = body.u32()?;
                    let (prefix, prefix_r) = body.ipv6()?;
                    opt.push(
                        Node::new(
                            "icmpv6.opt.prefix.length",
                            plen_r,
                            Value::Unsigned(u64::from(plen)),
                        )
                        .with_source(s),
                    );
                    opt.push(
                        Node::new(
                            "icmpv6.opt.prefix.valid_lifetime",
                            valid_r,
                            Value::Unsigned(u64::from(valid)),
                        )
                        .with_source(s),
                    );
                    opt.push(
                        Node::new(
                            "icmpv6.opt.prefix.preferred_lifetime",
                            pref_r,
                            Value::Unsigned(u64::from(pref)),
                        )
                        .with_source(s),
                    );
                    opt.push(
                        Node::new("icmpv6.opt.prefix", prefix_r, Value::Ipv6(prefix))
                            .with_source(s),
                    );
                    opt.text = Some(
                        format!(
                            "ICMPv6 Option (Prefix information: {}/{plen})",
                            ipv6_str(prefix)
                        )
                        .into(),
                    );
                }
                5 if body.remaining() >= 6 => {
                    body.u16()?;
                    let (mtu, mtu_r) = body.u32()?;
                    opt.push(
                        Node::new("icmpv6.opt.mtu", mtu_r, Value::Unsigned(u64::from(mtu)))
                            .with_source(s),
                    );
                    opt.text = Some(format!("ICMPv6 Option (MTU: {mtu})").into());
                }
                _ => {
                    opt.push(
                        Node::new("icmpv6.opt.data", body.rest_range(), Value::Bytes)
                            .with_source(s),
                    );
                    opt.text = Some(
                        format!("ICMPv6 Option (type {ty}, {} bytes)", usize::from(len) * 8).into(),
                    );
                }
            }
            opt.range = start..c.abs();
            Ok(opt)
        })();
        match r {
            Ok(opt) => node.push(opt),
            Err(e) => {
                node.push(
                    Node::new("_ws.malformed", start..c.abs() + c.remaining(), Value::None)
                        .with_source(s)
                        .with_text(format!("[Malformed option: {e}]")),
                );
                break;
            }
        }
    }
}
