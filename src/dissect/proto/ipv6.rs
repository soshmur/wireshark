//! Internet Protocol version 6 (RFC 8200) with hop-by-hop, destination,
//! routing and fragment extension headers.

use crate::dissect::ctx::{Ctx, NetAddrs, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{enum_name, IPPROTOS};
use crate::dissect::Addr;

use super::ipproto_next;

/// Upper bound on chained extension headers; beyond this the packet is
/// treated as malformed rather than looping.
const MAX_EXT_HEADERS: usize = 16;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();

    let (vtf, vtf_r) = c.u32()?;
    let version = (vtf >> 28) as u8;
    if version != 6 {
        return Err(DissectError::Invalid {
            at: vtf_r.start,
            what: "IP version (expected 6)",
        });
    }
    let tclass = (vtf >> 20) & 0xff;
    let flow = vtf & 0x000f_ffff;
    let (plen, plen_r) = c.u16()?;
    let (nxt, nxt_r) = c.u8()?;
    let (hlim, hlim_r) = c.u8()?;
    let (src, src_r) = c.ipv6()?;
    let (dst, dst_r) = c.ipv6()?;

    ctx.set_protocol("ipv6");
    ctx.summary.source = Addr::Ipv6(src);
    ctx.summary.destination = Addr::Ipv6(dst);
    ctx.net_addrs = Some(NetAddrs::V6(src, dst));

    let ip = ctx.begin("ipv6", start..start);
    ctx.leaf(
        "ipv6.version",
        vtf_r.clone(),
        Value::Unsigned(u64::from(version)),
    );
    ctx.leaf(
        "ipv6.tclass",
        vtf_r.clone(),
        Value::Unsigned(u64::from(tclass)),
    );
    ctx.leaf("ipv6.flow", vtf_r, Value::Unsigned(u64::from(flow)));
    ctx.leaf("ipv6.plen", plen_r, Value::Unsigned(u64::from(plen)));
    ctx.leaf("ipv6.nxt", nxt_r, Value::Unsigned(u64::from(nxt)));
    ctx.leaf("ipv6.hlim", hlim_r, Value::Unsigned(u64::from(hlim)));
    ctx.leaf("ipv6.src", src_r, Value::Ipv6(src));
    ctx.leaf("ipv6.dst", dst_r, Value::Ipv6(dst));

    // Payload is bounded by the payload length field (jumbograms aside).
    let payload_len = usize::from(plen).min(c.remaining());
    let mut pc = c.sub(payload_len)?;

    // Walk extension headers.
    let mut next = nxt;
    let mut is_fragment = false;
    for _ in 0..MAX_EXT_HEADERS {
        match next {
            0 | 60 => next = options_header(&mut pc, ctx, next)?,
            43 => next = routing_header(&mut pc, ctx)?,
            44 => {
                let (n, frag) = fragment_header(&mut pc, ctx)?;
                next = n;
                is_fragment = frag;
            }
            _ => break,
        }
    }
    ctx.end_at(ip, c.abs());

    let name = enum_name(IPPROTOS, u64::from(next)).unwrap_or("Unknown");
    let payload_off = pc.abs() - ctx.base;
    if is_fragment {
        // IPv6 fragment state is not implemented; show the fragment
        // payload as data.
        ctx.set_info(format!("Fragmented IPv6 (proto={name} {next})"));
        ctx.call_next_bounded(Proto::Data, payload_off, pc.remaining());
        return Ok(());
    }
    if next == 59 {
        ctx.set_info("No next header");
        return Ok(());
    }
    ctx.call_next_bounded(ipproto_next(next), payload_off, pc.remaining());
    Ok(())
}

/// Hop-by-Hop (0) or Destination (60) options header; returns the next header.
fn options_header(c: &mut Cursor, ctx: &mut Ctx, kind: u8) -> Result<u8> {
    let start = c.abs();
    let (nxt, nxt_r) = c.u8()?;
    let (hlen, hlen_r) = c.u8()?;
    let total = (usize::from(hlen) + 1) * 8;
    let (abbrev, nxt_abbrev, len_abbrev, name) = if kind == 0 {
        (
            "ipv6.hopopts",
            "ipv6.hopopts.nxt",
            "ipv6.hopopts.len",
            "Hop-by-Hop Options",
        )
    } else {
        (
            "ipv6.dstopts",
            "ipv6.dstopts.nxt",
            "ipv6.dstopts.len",
            "Destination Options",
        )
    };
    let text = format!("{name} ({total} bytes)");
    let node = ctx.begin_text(abbrev, start..start, &text);
    ctx.leaf(nxt_abbrev, nxt_r, Value::Unsigned(u64::from(nxt)));
    ctx.leaf(len_abbrev, hlen_r, Value::Unsigned(u64::from(hlen)));
    let mut oc = match c.sub(total - 2) {
        Ok(v) => v,
        Err(e) => {
            ctx.end_at(node, c.abs());
            return Err(e);
        }
    };
    while !oc.is_empty() {
        if let Err(e) = option(&mut oc, ctx) {
            let text = format!("[Malformed option: {e}]");
            ctx.leaf_text("_ws.malformed", oc.rest_range(), Value::None, &text);
            break;
        }
    }
    ctx.end_at(node, c.abs());
    Ok(nxt)
}

fn option(c: &mut Cursor, ctx: &mut Ctx) -> Result<()> {
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let opt = ctx.begin("ipv6.opt", start..start);
    ctx.leaf("ipv6.opt.type", ty_r, Value::Unsigned(u64::from(ty)));
    if ty == 0 {
        ctx.set_text(opt, "Pad1");
        ctx.end_at(opt, c.abs());
        return Ok(());
    }
    let (len, len_r) = match c.u8() {
        Ok(v) => v,
        Err(e) => {
            ctx.end_at(opt, c.abs());
            return Err(e);
        }
    };
    ctx.leaf("ipv6.opt.length", len_r, Value::Unsigned(u64::from(len)));
    let (body, body_r) = match c.take(usize::from(len)) {
        Ok(v) => v,
        Err(e) => {
            ctx.end_at(opt, c.abs());
            return Err(e);
        }
    };
    let text = match ty {
        1 => format!("PadN ({} bytes)", usize::from(len) + 2),
        5 if body.len() == 2 => {
            let v = u16::from_be_bytes([body[0], body[1]]);
            ctx.leaf(
                "ipv6.opt.router_alert",
                body_r,
                Value::Unsigned(u64::from(v)),
            );
            format!("Router Alert: {v}")
        }
        _ => {
            ctx.leaf("ipv6.opt.data", body_r, Value::Bytes);
            format!("Option {ty} ({} bytes)", usize::from(len) + 2)
        }
    };
    ctx.set_text(opt, &text);
    ctx.end_at(opt, c.abs());
    Ok(())
}

fn routing_header(c: &mut Cursor, ctx: &mut Ctx) -> Result<u8> {
    let start = c.abs();
    let (nxt, nxt_r) = c.u8()?;
    let (hlen, hlen_r) = c.u8()?;
    let (ty, ty_r) = c.u8()?;
    let (segleft, segleft_r) = c.u8()?;
    let total = (usize::from(hlen) + 1) * 8;
    let text = format!("Routing Header, Type {ty}, Segments Left {segleft}");
    let node = ctx.begin_text("ipv6.routing", start..start, &text);
    ctx.leaf("ipv6.routing.nxt", nxt_r, Value::Unsigned(u64::from(nxt)));
    ctx.leaf("ipv6.routing.len", hlen_r, Value::Unsigned(u64::from(hlen)));
    ctx.leaf("ipv6.routing.type", ty_r, Value::Unsigned(u64::from(ty)));
    ctx.leaf(
        "ipv6.routing.segleft",
        segleft_r,
        Value::Unsigned(u64::from(segleft)),
    );
    let mut rc = match c.sub(total - 4) {
        Ok(v) => v,
        Err(e) => {
            ctx.end_at(node, c.abs());
            return Err(e);
        }
    };
    match ty {
        0 | 2 | 4 => {
            // 4 reserved bytes, then a list of addresses.
            if let Ok((_, res_r)) = rc.take(4) {
                ctx.leaf("ipv6.routing.data", res_r, Value::Bytes);
            }
            while rc.remaining() >= 16 {
                let (a, r) = rc.ipv6()?;
                ctx.leaf("ipv6.routing.addr", r, Value::Ipv6(a));
            }
            if !rc.is_empty() {
                ctx.leaf("ipv6.routing.data", rc.rest_range(), Value::Bytes);
            }
        }
        _ => {
            ctx.leaf("ipv6.routing.data", rc.rest_range(), Value::Bytes);
        }
    }
    ctx.end_at(node, c.abs());
    Ok(nxt)
}

/// Returns (next header, is_fragment).
fn fragment_header(c: &mut Cursor, ctx: &mut Ctx) -> Result<(u8, bool)> {
    let start = c.abs();
    let (nxt, nxt_r) = c.u8()?;
    let (res, res_r) = c.u8()?;
    let (off_m, off_r) = c.u16()?;
    let (ident, ident_r) = c.u32()?;
    let offset = usize::from(off_m >> 3) * 8;
    let more = off_m & 1 == 1;
    let text = format!(
        "Fragment Header, offset {offset}, more {}, ID 0x{ident:08x}",
        if more { "yes" } else { "no" }
    );
    let node = ctx.begin_text("ipv6.fraghdr", start..c.abs(), &text);
    ctx.leaf("ipv6.fraghdr.nxt", nxt_r, Value::Unsigned(u64::from(nxt)));
    ctx.leaf(
        "ipv6.fraghdr.reserved_octet",
        res_r,
        Value::Unsigned(u64::from(res)),
    );
    ctx.leaf(
        "ipv6.fraghdr.offset",
        off_r.clone(),
        Value::Unsigned(offset as u64),
    );
    ctx.leaf(
        "ipv6.fraghdr.reserved_bits",
        off_r.clone(),
        Value::Unsigned(u64::from((off_m >> 1) & 3)),
    );
    ctx.leaf("ipv6.fraghdr.more", off_r, Value::Bool(more));
    ctx.leaf(
        "ipv6.fraghdr.ident",
        ident_r,
        Value::Unsigned(u64::from(ident)),
    );
    ctx.end_at(node, c.abs());
    // An atomic fragment (offset 0, more 0) is a whole datagram.
    Ok((nxt, offset > 0 || more))
}
