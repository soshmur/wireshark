//! Internet Protocol version 4 (RFC 791) with options and fragment
//! reassembly.

use std::sync::Arc;

use crate::dissect::ctx::{Ctx, NetAddrs, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;
use crate::dissect::reassembly::{FragKey, FragResult};
use crate::dissect::registry::{enum_name, IPPROTOS};
use crate::dissect::Addr;

use super::{inet_checksum, ipproto_next, CK_BAD, CK_GOOD, CK_UNVERIFIED};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
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
    ctx.summary.source = Addr::Ipv4(src);
    ctx.summary.destination = Addr::Ipv4(dst);
    ctx.net_addrs = Some(NetAddrs::V4(src, dst));

    let ip = ctx.begin("ip", start..start);
    ctx.leaf(
        "ip.version",
        vihl_r.clone(),
        Value::Unsigned(u64::from(version)),
    );
    ctx.leaf("ip.hdr_len", vihl_r, Value::Unsigned(ihl as u64));
    let ds = ctx.begin_value(
        "ip.dsfield",
        dsfield_r.clone(),
        Value::Unsigned(u64::from(dsfield)),
    );
    ctx.leaf(
        "ip.dsfield.dscp",
        dsfield_r.clone(),
        Value::Unsigned(u64::from(dsfield >> 2)),
    );
    ctx.leaf(
        "ip.dsfield.ecn",
        dsfield_r.clone(),
        Value::Unsigned(u64::from(dsfield & 3)),
    );
    ctx.end();
    let _ = ds;
    ctx.leaf("ip.len", total_len_r, Value::Unsigned(u64::from(total_len)));
    ctx.leaf("ip.id", id_r, Value::Unsigned(u64::from(id)));

    let mut names = super::NameList::new();
    if rb {
        names.push("Reserved");
    }
    if df {
        names.push("Don't fragment");
    }
    if mf {
        names.push("More fragments");
    }
    let fl = ctx.begin_value(
        "ip.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags_off >> 13)),
    );
    let bits = flags_off >> 13;
    if names.is_empty() {
        ctx.set_textf(fl, format_args!("Flags: 0x{bits:x}"));
    } else {
        ctx.set_textf(fl, format_args!("Flags: 0x{bits:x} ({})", names.as_str()));
    }
    ctx.leaf("ip.flags.rb", flags_r.clone(), Value::Bool(rb));
    ctx.leaf("ip.flags.df", flags_r.clone(), Value::Bool(df));
    ctx.leaf("ip.flags.mf", flags_r.clone(), Value::Bool(mf));
    ctx.end();
    let _ = fl;
    ctx.leaf("ip.frag_offset", flags_r, Value::Unsigned(frag_off as u64));
    ctx.leaf("ip.ttl", ttl_r, Value::Unsigned(u64::from(ttl)));
    ctx.leaf("ip.proto", proto_r, Value::Unsigned(u64::from(proto)));

    // Header checksum over the whole header including options.
    let status = match data.get(..ihl).map(|h| inet_checksum(&[h])) {
        Some(0) => CK_GOOD,
        Some(_) => CK_BAD,
        None => CK_UNVERIFIED,
    };
    ctx.leaf(
        "ip.checksum",
        checksum_r.clone(),
        Value::Unsigned(u64::from(checksum)),
    );
    ctx.leaf("ip.checksum.status", checksum_r, Value::Unsigned(status));
    ctx.leaf("ip.src", src_r, Value::Ipv4(src));
    ctx.leaf("ip.dst", dst_r, Value::Ipv4(dst));

    // Options occupy the rest of the header.
    let opts_len = ihl - 20;
    if opts_len > 0 {
        let opts_start = c.abs();
        let mut oc = c.sub(opts_len)?;
        let text = format!("Options: ({opts_len} bytes)");
        let opts = ctx.begin_text("ip.options", opts_start..opts_start + opts_len, &text);
        while !oc.is_empty() {
            let depth = ctx.depth();
            match option(&mut oc, ctx) {
                Ok(false) => {}
                Ok(true) => {
                    // Everything after EOL is padding to the 32-bit boundary.
                    if !oc.is_empty() {
                        ctx.leaf("ip.opt.padding", oc.rest_range(), Value::Bytes);
                    }
                    break;
                }
                Err(e) => {
                    ctx.restore_depth(depth);
                    ctx.leaf_textf(
                        "_ws.malformed",
                        oc.rest_range(),
                        Value::None,
                        format_args!("[Malformed option: {e}]"),
                    );
                    break;
                }
            }
        }
        ctx.end();
        let _ = opts;
    }
    // The IP layer node covers its header; the fragment notes below are its
    // children, so the container is closed only at the end.
    let header_end = c.abs();

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
        // A fragment. Try to reassemble; this frame's payload is shown as
        // data either way.
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
                ctx.in_source(src_id, |ctx| {
                    let text = format!("[{} IPv4 Fragments ({total} bytes)]", frags.len());
                    let fr = ctx.begin_text("ip.fragments", 0..total, &text);
                    for f in &frags {
                        let text = format!(
                            "[Frame: {}, payload: {}-{} ({} bytes)]",
                            f.frame,
                            f.offset,
                            f.offset + f.len,
                            f.len
                        );
                        ctx.leaf_text(
                            "ip.fragment",
                            f.offset..f.offset + f.len,
                            Value::None,
                            &text,
                        );
                    }
                    ctx.leaf(
                        "ip.fragment.count",
                        0..0,
                        Value::Unsigned(frags.len() as u64),
                    );
                    ctx.leaf("ip.reassembled.length", 0..0, Value::Unsigned(total as u64));
                    ctx.leaf("ip.reassembled.data", 0..total, Value::Bytes);
                    ctx.end();
                    let _ = fr;
                });
                ctx.call_next_in_source(next, src_id);
            }
            FragResult::Pending { .. } | FragResult::Rejected(_) => {
                // A generated note: the payload bytes are shown by the `data`
                // layer that follows, so this note carries no byte range.
                let text = format!("[Fragment of IPv4 datagram ID 0x{id:04x}, offset {frag_off}]");
                let frag = ctx.begin_text("ip.fragment", c.abs()..c.abs(), &text);
                if let FragResult::Rejected(why) = result {
                    let text = format!("[Reassembly rejected: {why}]");
                    ctx.leaf_text("_ws.malformed", 0..0, Value::None, &text);
                }
                ctx.end();
                let _ = frag;
                ctx.call_next_bounded(Proto::Data, payload_off, payload_len);
            }
        }
        ctx.end_at(ip, header_end);
        return Ok(());
    }

    ctx.end_at(ip, header_end);
    ctx.call_next_bounded(next, payload_off, payload_len);
    Ok(())
}

/// One IPv4 option; the flag is `true` for End-of-Options.
fn option(c: &mut Cursor, ctx: &mut Ctx) -> Result<bool> {
    let start = c.abs();
    let (ty, ty_r) = c.u8()?;
    let opt = ctx.begin("ip.opt", start..start);
    ctx.leaf("ip.opt.type", ty_r, Value::Unsigned(u64::from(ty)));
    match ty {
        0 => {
            ctx.set_text(opt, "End of Options List (EOL)");
            ctx.end_at(opt, c.abs());
            return Ok(true);
        }
        1 => {
            ctx.set_text(opt, "No-Operation (NOP)");
            ctx.end_at(opt, c.abs());
            return Ok(false);
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
    ctx.leaf("ip.opt.len", len_r, Value::Unsigned(u64::from(len)));
    let (body, body_r) = c.take(usize::from(len) - 2)?;
    let text = match ty {
        148 if body.len() == 2 => {
            let v = u16::from_be_bytes([body[0], body[1]]);
            ctx.leaf("ip.opt.ra", body_r, Value::Unsigned(u64::from(v)));
            format!("Router Alert ({len} bytes): {v}")
        }
        7 | 131 | 137 if !body.is_empty() => {
            let ptr = body[0];
            ctx.leaf(
                "ip.opt.ptr",
                body_r.start..body_r.start + 1,
                Value::Unsigned(u64::from(ptr)),
            );
            let mut off = 1;
            while off + 4 <= body.len() {
                let a = [body[off], body[off + 1], body[off + 2], body[off + 3]];
                ctx.leaf(
                    "ip.opt.route",
                    body_r.start + off..body_r.start + off + 4,
                    Value::Ipv4(a),
                );
                off += 4;
            }
            let name = match ty {
                7 => "Record Route",
                131 => "Loose Source Route",
                _ => "Strict Source Route",
            };
            format!("{name} ({len} bytes)")
        }
        _ => {
            ctx.leaf("ip.opt.data", body_r, Value::Bytes);
            format!("Option {ty} ({len} bytes)")
        }
    };
    ctx.set_text(opt, &text);
    ctx.end_at(opt, c.abs());
    Ok(false)
}
