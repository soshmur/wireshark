//! Internet Protocol version 4 (RFC 791) with options and fragment
//! reassembly.

use std::sync::Arc;

use crate::dissect::ctx::{Ctx, NetAddrs, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::{Node, Value};
use crate::dissect::reassembly::{FragKey, FragResult};
use crate::dissect::registry::{enum_name, IPPROTOS};

use super::{inet_checksum, ipproto_next, ipv4_str, CK_BAD, CK_GOOD, CK_UNVERIFIED};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();

    let (vihl, vihl_r) = c.u8()?;
    let version = vihl >> 4;
    let ihl = usize::from(vihl & 0x0f) * 4;
    if version != 4 {
        return Err(DissectError::Invalid {
            at: vihl_r.start,
            what: "IP version (expected 4)",
        });
    }
    if ihl < 20 {
        return Err(DissectError::Invalid {
            at: vihl_r.start,
            what: "IPv4 header length (IHL < 5)",
        });
    }
    let (dsfield, dsfield_r) = c.u8()?;
    let (total_len, total_len_r) = c.u16()?;
    let (id, id_r) = c.u16()?;
    let (flags_off, flags_r) = c.u16()?;
    let (ttl, ttl_r) = c.u8()?;
    let (proto, proto_r) = c.u8()?;
    let (checksum, checksum_r) = c.u16()?;
    let (src, src_r) = c.ipv4()?;
    let (dst, dst_r) = c.ipv4()?;

    let rb = flags_off & 0x8000 != 0;
    let df = flags_off & 0x4000 != 0;
    let mf = flags_off & 0x2000 != 0;
    let frag_off = usize::from(flags_off & 0x1fff) * 8;

    ctx.set_protocol("ip");
    ctx.summary.source = ipv4_str(src);
    ctx.summary.destination = ipv4_str(dst);
    ctx.net_addrs = Some(NetAddrs::V4(src, dst));

    let mut node = Node::new("ip", start..start, Value::None)
        .with_source(s)
        .reserve(16);
    node.push(
        Node::new(
            "ip.version",
            vihl_r.clone(),
            Value::Unsigned(u64::from(version)),
        )
        .with_source(s),
    );
    node.push(Node::new("ip.hdr_len", vihl_r, Value::Unsigned(ihl as u64)).with_source(s));
    let mut ds = Node::new(
        "ip.dsfield",
        dsfield_r.clone(),
        Value::Unsigned(u64::from(dsfield)),
    )
    .with_source(s);
    ds.push(
        Node::new(
            "ip.dsfield.dscp",
            dsfield_r.clone(),
            Value::Unsigned(u64::from(dsfield >> 2)),
        )
        .with_source(s),
    );
    ds.push(
        Node::new(
            "ip.dsfield.ecn",
            dsfield_r,
            Value::Unsigned(u64::from(dsfield & 3)),
        )
        .with_source(s),
    );
    node.push(ds);
    node.push(
        Node::new("ip.len", total_len_r, Value::Unsigned(u64::from(total_len))).with_source(s),
    );
    node.push(Node::new("ip.id", id_r, Value::Unsigned(u64::from(id))).with_source(s));

    let mut flag_names = Vec::new();
    if rb {
        flag_names.push("Reserved");
    }
    if df {
        flag_names.push("Don't fragment");
    }
    if mf {
        flag_names.push("More fragments");
    }
    let mut flags = Node::new(
        "ip.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags_off >> 13)),
    )
    .with_source(s)
    .with_text(format!(
        "Flags: 0x{:x}{}",
        flags_off >> 13,
        if flag_names.is_empty() {
            String::new()
        } else {
            format!(" ({})", flag_names.join(", "))
        }
    ));
    flags.push(Node::new("ip.flags.rb", flags_r.clone(), Value::Bool(rb)).with_source(s));
    flags.push(Node::new("ip.flags.df", flags_r.clone(), Value::Bool(df)).with_source(s));
    flags.push(Node::new("ip.flags.mf", flags_r.clone(), Value::Bool(mf)).with_source(s));
    node.push(flags);
    node.push(
        Node::new("ip.frag_offset", flags_r, Value::Unsigned(frag_off as u64)).with_source(s),
    );
    node.push(Node::new("ip.ttl", ttl_r, Value::Unsigned(u64::from(ttl))).with_source(s));
    node.push(Node::new("ip.proto", proto_r, Value::Unsigned(u64::from(proto))).with_source(s));

    // Header checksum over the whole header including options.
    let header_bytes = data.get(..ihl);
    let computed = header_bytes.map(|h| inet_checksum(&[h]));
    node.push(
        Node::new(
            "ip.checksum",
            checksum_r.clone(),
            Value::Unsigned(u64::from(checksum)),
        )
        .with_source(s),
    );
    let status = match computed {
        Some(0) => CK_GOOD,
        Some(_) => CK_BAD,
        None => CK_UNVERIFIED,
    };
    node.push(Node::new("ip.checksum.status", checksum_r, Value::Unsigned(status)).with_source(s));
    node.push(Node::new("ip.src", src_r, Value::Ipv4(src)).with_source(s));
    node.push(Node::new("ip.dst", dst_r, Value::Ipv4(dst)).with_source(s));

    // Options occupy the rest of the header.
    let opts_len = ihl - 20;
    if opts_len > 0 {
        let opts_start = c.abs();
        let mut oc = c.sub(opts_len)?;
        let mut options = Node::new(
            "ip.options",
            opts_start..oc.abs() + oc.remaining(),
            Value::None,
        )
        .with_source(s)
        .with_text(format!("Options: ({opts_len} bytes)"));
        while !oc.is_empty() {
            match option(&mut oc) {
                Ok((opt, eol)) => {
                    options.push(opt);
                    if eol {
                        // Everything after EOL is padding to the 32-bit boundary.
                        if !oc.is_empty() {
                            options.push(
                                Node::new("ip.opt.padding", oc.rest_range(), Value::Bytes)
                                    .with_source(s),
                            );
                        }
                        break;
                    }
                }
                Err(e) => {
                    options.push(
                        Node::new("_ws.malformed", oc.rest_range(), Value::None)
                            .with_source(s)
                            .with_text(format!("[Malformed option: {e}]")),
                    );
                    break;
                }
            }
        }
        node.push(options);
    }
    node.range = start..c.abs();

    // The payload is bounded by total length (and by what was captured).
    let payload_len = usize::from(total_len)
        .saturating_sub(ihl)
        .min(c.remaining());
    let payload_off = c.pos();
    let payload_end = payload_off + payload_len;
    let next = ipproto_next(proto);
    let proto_name = enum_name(IPPROTOS, u64::from(proto)).unwrap_or("Unknown");
    if next == Proto::Data {
        ctx.set_info(format!("{proto_name} ({proto})"));
    }

    if mf || frag_off > 0 {
        // A fragment. Try to reassemble; the payload of this frame is shown
        // as data either way.
        let payload = data.get(payload_off..payload_end).unwrap_or(&[]);
        ctx.set_info(format!(
            "Fragmented IP protocol (proto={proto_name} {proto}, off={frag_off}, ID={id:04x})"
        ));
        let key = FragKey {
            src,
            dst,
            id,
            proto,
        };
        let result = if ctx.nesting == 0 {
            ctx.reassembly
                .add(key, frag_off, mf, payload, ctx.frame_number, ctx.ts)
        } else {
            FragResult::Rejected("nested fragment")
        };
        match result {
            FragResult::Complete { data: whole, frags } => {
                let total = whole.len();
                let src_id = ctx.add_source(Arc::from(whole));
                let mut fr = Node::new("ip.fragments", 0..total, Value::None)
                    .with_source(src_id)
                    .with_text(format!("[{} IPv4 Fragments ({total} bytes)]", frags.len()));
                for f in &frags {
                    fr.push(
                        Node::new("ip.fragment", f.offset..f.offset + f.len, Value::None)
                            .with_source(src_id)
                            .with_text(format!(
                                "[Frame: {}, payload: {}-{} ({} bytes)]",
                                f.frame,
                                f.offset,
                                f.offset + f.len,
                                f.len
                            )),
                    );
                }
                fr.push(
                    Node::new(
                        "ip.fragment.count",
                        0..0,
                        Value::Unsigned(frags.len() as u64),
                    )
                    .with_source(src_id),
                );
                fr.push(
                    Node::new("ip.reassembled.length", 0..0, Value::Unsigned(total as u64))
                        .with_source(src_id),
                );
                fr.push(
                    Node::new("ip.reassembled.data", 0..total, Value::Bytes).with_source(src_id),
                );
                node.push(fr);
                ctx.call_next_in_source(next, src_id);
            }
            FragResult::Pending { .. } | FragResult::Rejected(_) => {
                // A generated note: the payload bytes are shown by the `data`
                // layer that follows, so this note carries no byte range.
                let mut frag = Node::new("ip.fragment", c.abs()..c.abs(), Value::None)
                    .with_source(s)
                    .with_text(format!(
                        "[Fragment of IPv4 datagram ID 0x{id:04x}, offset {frag_off}]"
                    ));
                if let FragResult::Rejected(why) = result {
                    frag.push(
                        Node::new("_ws.malformed", 0..0, Value::None)
                            .with_source(s)
                            .with_text(format!("[Reassembly rejected: {why}]")),
                    );
                }
                node.push(frag);
                ctx.call_next_bounded(Proto::Data, payload_off, payload_len);
            }
        }
        return Ok(node);
    }

    // Not a fragment: hand the payload on, clipped to the IP total length.
    ctx.call_next_bounded(next, payload_off, payload_len);
    Ok(node)
}

/// One IPv4 option; the flag is `true` for End-of-Options.
fn option(c: &mut Cursor) -> Result<(Node, bool)> {
    let s = c.source();
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let mut opt = Node::new("ip.opt", start..start, Value::None).with_source(s);
    opt.push(Node::new("ip.opt.type", ty_r, Value::Unsigned(u64::from(ty))).with_source(s));
    match ty {
        0 => {
            opt.range = start..c.abs();
            opt.text = Some("End of Options List (EOL)".into());
            return Ok((opt, true));
        }
        1 => {
            opt.range = start..c.abs();
            opt.text = Some("No-Operation (NOP)".into());
            return Ok((opt, false));
        }
        _ => {}
    }
    let (len, len_r) = c.u8()?;
    if len < 2 {
        return Err(DissectError::Invalid {
            at: len_r.start,
            what: "IPv4 option length (< 2)",
        });
    }
    opt.push(Node::new("ip.opt.len", len_r, Value::Unsigned(u64::from(len))).with_source(s));
    let (body, body_r) = c.take(usize::from(len) - 2)?;
    match ty {
        148 if body.len() == 2 => {
            let v = u16::from_be_bytes([body[0], body[1]]);
            opt.push(Node::new("ip.opt.ra", body_r, Value::Unsigned(u64::from(v))).with_source(s));
            opt.text = Some(format!("Router Alert ({len} bytes): {v}").into());
        }
        7 | 131 | 137 if !body.is_empty() => {
            let ptr = body[0];
            opt.push(
                Node::new(
                    "ip.opt.ptr",
                    body_r.start..body_r.start + 1,
                    Value::Unsigned(u64::from(ptr)),
                )
                .with_source(s),
            );
            let mut off = 1;
            while off + 4 <= body.len() {
                let a = [body[off], body[off + 1], body[off + 2], body[off + 3]];
                opt.push(
                    Node::new(
                        "ip.opt.route",
                        body_r.start + off..body_r.start + off + 4,
                        Value::Ipv4(a),
                    )
                    .with_source(s),
                );
                off += 4;
            }
            let name = match ty {
                7 => "Record Route",
                131 => "Loose Source Route",
                _ => "Strict Source Route",
            };
            opt.text = Some(format!("{name} ({len} bytes)").into());
        }
        _ => {
            opt.push(Node::new("ip.opt.data", body_r, Value::Bytes).with_source(s));
            opt.text = Some(format!("Option {ty} ({len} bytes)").into());
        }
    }
    opt.range = start..c.abs();
    Ok((opt, false))
}
