//! Internet Protocol version 6 (RFC 8200) with hop-by-hop, destination,
//! routing and fragment extension headers.

use crate::dissect::ctx::{Ctx, NetAddrs, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::{Node, Value};
use crate::dissect::registry::{enum_name, IPPROTOS};

use super::{ipproto_next, ipv6_str};

/// Upper bound on chained extension headers; beyond this the packet is
/// treated as malformed rather than looping.
const MAX_EXT_HEADERS: usize = 16;

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
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
    ctx.summary.source = ipv6_str(src);
    ctx.summary.destination = ipv6_str(dst);
    ctx.net_addrs = Some(NetAddrs::V6(src, dst));

    let mut node = Node::new("ipv6", start..start, Value::None)
        .with_source(s)
        .reserve(10);
    node.push(
        Node::new(
            "ipv6.version",
            vtf_r.clone(),
            Value::Unsigned(u64::from(version)),
        )
        .with_source(s),
    );
    node.push(
        Node::new(
            "ipv6.tclass",
            vtf_r.clone(),
            Value::Unsigned(u64::from(tclass)),
        )
        .with_source(s),
    );
    node.push(Node::new("ipv6.flow", vtf_r, Value::Unsigned(u64::from(flow))).with_source(s));
    node.push(Node::new("ipv6.plen", plen_r, Value::Unsigned(u64::from(plen))).with_source(s));
    node.push(Node::new("ipv6.nxt", nxt_r, Value::Unsigned(u64::from(nxt))).with_source(s));
    node.push(Node::new("ipv6.hlim", hlim_r, Value::Unsigned(u64::from(hlim))).with_source(s));
    node.push(Node::new("ipv6.src", src_r, Value::Ipv6(src)).with_source(s));
    node.push(Node::new("ipv6.dst", dst_r, Value::Ipv6(dst)).with_source(s));

    // Payload is bounded by the payload length field (jumbograms aside).
    let payload_len = usize::from(plen).min(c.remaining());
    let mut pc = c.sub(payload_len)?;

    // Walk extension headers.
    let mut next = nxt;
    let mut is_fragment = false;
    for _ in 0..MAX_EXT_HEADERS {
        match next {
            0 | 60 => {
                let (n, ext) = options_header(&mut pc, next)?;
                node.push(ext);
                next = n;
            }
            43 => {
                let (n, ext) = routing_header(&mut pc)?;
                node.push(ext);
                next = n;
            }
            44 => {
                let (n, ext, frag) = fragment_header(&mut pc)?;
                node.push(ext);
                next = n;
                is_fragment = frag;
            }
            _ => break,
        }
    }
    node.range = start..c.abs();

    let name = enum_name(IPPROTOS, u64::from(next)).unwrap_or("Unknown");
    if is_fragment {
        // IPv6 fragment reassembly is not implemented; show the fragment payload.
        ctx.set_info(format!("Fragmented IPv6 (proto={name} {next})"));
        let payload_off = pc.abs() - ctx.base;
        ctx.call_next_bounded(Proto::Data, payload_off, pc.remaining());
        return Ok(node);
    }
    if next == 59 {
        ctx.set_info("No next header");
        return Ok(node);
    }
    let payload_off = pc.abs() - ctx.base;
    ctx.call_next_bounded(ipproto_next(next), payload_off, pc.remaining());
    Ok(node)
}

/// Hop-by-Hop (0) or Destination (60) options header.
fn options_header(c: &mut Cursor, kind: u8) -> Result<(u8, Node)> {
    let s = c.source();
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
    let mut node = Node::new(abbrev, start..start, Value::None)
        .with_source(s)
        .with_text(format!("{name} ({total} bytes)"));
    node.push(Node::new(nxt_abbrev, nxt_r, Value::Unsigned(u64::from(nxt))).with_source(s));
    node.push(Node::new(len_abbrev, hlen_r, Value::Unsigned(u64::from(hlen))).with_source(s));
    let mut oc = c.sub(total - 2)?;
    while !oc.is_empty() {
        match option(&mut oc) {
            Ok(opt) => node.push(opt),
            Err(e) => {
                node.push(
                    Node::new("_ws.malformed", oc.rest_range(), Value::None)
                        .with_source(s)
                        .with_text(format!("[Malformed option: {e}]")),
                );
                break;
            }
        }
    }
    node.range = start..c.abs();
    Ok((nxt, node))
}

fn option(c: &mut Cursor) -> Result<Node> {
    let s = c.source();
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let mut opt = Node::new("ipv6.opt", start..start, Value::None).with_source(s);
    opt.push(Node::new("ipv6.opt.type", ty_r, Value::Unsigned(u64::from(ty))).with_source(s));
    if ty == 0 {
        opt.range = start..c.abs();
        opt.text = Some("Pad1".into());
        return Ok(opt);
    }
    let (len, len_r) = c.u8()?;
    opt.push(Node::new("ipv6.opt.length", len_r, Value::Unsigned(u64::from(len))).with_source(s));
    let (body, body_r) = c.take(usize::from(len))?;
    match ty {
        1 => opt.text = Some(format!("PadN ({} bytes)", usize::from(len) + 2).into()),
        5 if body.len() == 2 => {
            let v = u16::from_be_bytes([body[0], body[1]]);
            opt.push(
                Node::new(
                    "ipv6.opt.router_alert",
                    body_r,
                    Value::Unsigned(u64::from(v)),
                )
                .with_source(s),
            );
            opt.text = Some(format!("Router Alert: {v}").into());
        }
        _ => {
            opt.push(Node::new("ipv6.opt.data", body_r, Value::Bytes).with_source(s));
            opt.text = Some(format!("Option {ty} ({} bytes)", usize::from(len) + 2).into());
        }
    }
    opt.range = start..c.abs();
    Ok(opt)
}

fn routing_header(c: &mut Cursor) -> Result<(u8, Node)> {
    let s = c.source();
    let start = c.abs();
    let (nxt, nxt_r) = c.u8()?;
    let (hlen, hlen_r) = c.u8()?;
    let (ty, ty_r) = c.u8()?;
    let (segleft, segleft_r) = c.u8()?;
    let total = (usize::from(hlen) + 1) * 8;
    let mut node = Node::new("ipv6.routing", start..start, Value::None)
        .with_source(s)
        .with_text(format!(
            "Routing Header, Type {ty}, Segments Left {segleft}"
        ));
    node.push(Node::new("ipv6.routing.nxt", nxt_r, Value::Unsigned(u64::from(nxt))).with_source(s));
    node.push(
        Node::new("ipv6.routing.len", hlen_r, Value::Unsigned(u64::from(hlen))).with_source(s),
    );
    node.push(Node::new("ipv6.routing.type", ty_r, Value::Unsigned(u64::from(ty))).with_source(s));
    node.push(
        Node::new(
            "ipv6.routing.segleft",
            segleft_r,
            Value::Unsigned(u64::from(segleft)),
        )
        .with_source(s),
    );
    let mut rc = c.sub(total - 4)?;
    match ty {
        0 | 2 | 4 => {
            // 4 reserved bytes, then a list of addresses.
            let (_, res_r) = rc.take(4)?;
            node.push(Node::new("ipv6.routing.data", res_r, Value::Bytes).with_source(s));
            while rc.remaining() >= 16 {
                let (a, r) = rc.ipv6()?;
                node.push(Node::new("ipv6.routing.addr", r, Value::Ipv6(a)).with_source(s));
            }
            if !rc.is_empty() {
                node.push(
                    Node::new("ipv6.routing.data", rc.rest_range(), Value::Bytes).with_source(s),
                );
            }
        }
        _ => {
            node.push(Node::new("ipv6.routing.data", rc.rest_range(), Value::Bytes).with_source(s));
        }
    }
    node.range = start..c.abs();
    Ok((nxt, node))
}

/// Returns (next header, node, is_fragment).
fn fragment_header(c: &mut Cursor) -> Result<(u8, Node, bool)> {
    let s = c.source();
    let start = c.abs();
    let (nxt, nxt_r) = c.u8()?;
    let (res, res_r) = c.u8()?;
    let (off_m, off_r) = c.u16()?;
    let (ident, ident_r) = c.u32()?;
    let offset = usize::from(off_m >> 3) * 8;
    let more = off_m & 1 == 1;
    let mut node = Node::new("ipv6.fraghdr", start..c.abs(), Value::None)
        .with_source(s)
        .with_text(format!(
            "Fragment Header, offset {offset}, more {}, ID 0x{ident:08x}",
            if more { "yes" } else { "no" }
        ));
    node.push(Node::new("ipv6.fraghdr.nxt", nxt_r, Value::Unsigned(u64::from(nxt))).with_source(s));
    node.push(
        Node::new(
            "ipv6.fraghdr.reserved_octet",
            res_r,
            Value::Unsigned(u64::from(res)),
        )
        .with_source(s),
    );
    node.push(
        Node::new(
            "ipv6.fraghdr.offset",
            off_r.clone(),
            Value::Unsigned(offset as u64),
        )
        .with_source(s),
    );
    node.push(
        Node::new(
            "ipv6.fraghdr.reserved_bits",
            off_r.clone(),
            Value::Unsigned(u64::from((off_m >> 1) & 3)),
        )
        .with_source(s),
    );
    node.push(Node::new("ipv6.fraghdr.more", off_r, Value::Bool(more)).with_source(s));
    node.push(
        Node::new(
            "ipv6.fraghdr.ident",
            ident_r,
            Value::Unsigned(u64::from(ident)),
        )
        .with_source(s),
    );
    // An atomic fragment (offset 0, more 0) is a whole datagram.
    Ok((nxt, node, offset > 0 || more))
}
