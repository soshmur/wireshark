//! Domain Name System (RFC 1035) including compression pointers with a hard
//! hop limit, and the common record types.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{enum_name, DNS_RCODES, DNS_TYPES};

use super::{ipv4_str, ipv6_str};

/// Maximum compression pointers followed while reading one name. Real names
/// need a handful; a loop needs infinity.
const MAX_POINTER_HOPS: usize = 32;
/// Maximum labels in one name (RFC 1035 limits names to 255 octets).
const MAX_LABELS: usize = 128;
/// Maximum resource records parsed per section, so a claimed count of 65535
/// on a 40-byte packet fails fast instead of looping.
const MAX_RECORDS: u16 = 4096;

/// Read a possibly-compressed name starting at `pos` in `msg`.
/// Returns the name and the offset just past its in-line part.
pub fn read_name(msg: &[u8], pos: usize) -> std::result::Result<(String, usize), &'static str> {
    let mut name = String::new();
    let mut labels = 0usize;
    let mut hops = 0usize;
    let mut p = pos;
    let mut end: Option<usize> = None;
    loop {
        let &len = msg.get(p).ok_or("name runs past end of message")?;
        match len & 0xc0 {
            0xc0 => {
                let &lo = msg.get(p + 1).ok_or("truncated compression pointer")?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(lo);
                if end.is_none() {
                    end = Some(p + 2);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err("compression pointer loop");
                }
                // Pointers must go strictly backwards (RFC 1035 §4.1.4: "a prior
                // occurrence"); that alone makes loops impossible, and the hop
                // limit is the belt to that brace.
                if target >= p {
                    return Err("forward compression pointer");
                }
                p = target;
            }
            0x00 => {
                if len == 0 {
                    let end = end.unwrap_or(p + 1);
                    if name.is_empty() {
                        name.push_str("<Root>");
                    }
                    return Ok((name, end));
                }
                labels += 1;
                if labels > MAX_LABELS {
                    return Err("too many labels");
                }
                let label = msg
                    .get(p + 1..p + 1 + usize::from(len))
                    .ok_or("label runs past end of message")?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    if (0x21..0x7f).contains(&b) && b != b'.' {
                        name.push(b as char);
                    } else {
                        name.push_str(&format!("\\{b:03}"));
                    }
                }
                p += 1 + usize::from(len);
            }
            _ => return Err("unsupported label type"),
        }
    }
}

struct Msg<'a> {
    bytes: &'a [u8],
    base: usize,
}

impl Msg<'_> {
    fn name_at(&self, pos: usize) -> Result<(String, usize)> {
        read_name(self.bytes, pos).map_err(|what| DissectError::Invalid {
            at: self.base + pos,
            what,
        })
    }
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let msg = Msg {
        bytes: data,
        base: ctx.base,
    };
    let (id, id_r) = c.u16()?;
    let (flags, flags_r) = c.u16()?;
    let (qd, qd_r) = c.u16()?;
    let (an, an_r) = c.u16()?;
    let (ns, ns_r) = c.u16()?;
    let (ar, ar_r) = c.u16()?;

    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xf;
    let rcode = flags & 0xf;

    ctx.set_protocol("dns");
    let text = format!(
        "Domain Name System ({})",
        if response { "response" } else { "query" }
    );
    let dns = ctx.begin_text("dns", start..start + data.len(), &text);
    ctx.leaf("dns.id", id_r, Value::Unsigned(u64::from(id)));

    let flags_text = format!(
        "Flags: 0x{flags:04x} {}",
        if response {
            "Standard query response"
        } else {
            "Standard query"
        }
    );
    ctx.begin_value_text(
        "dns.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags)),
        &flags_text,
    );
    let bit = |mask: u16| flags & mask != 0;
    ctx.leaf("dns.flags.response", flags_r.clone(), Value::Bool(response));
    ctx.leaf(
        "dns.flags.opcode",
        flags_r.clone(),
        Value::Unsigned(u64::from(opcode)),
    );
    if response {
        ctx.leaf(
            "dns.flags.authoritative",
            flags_r.clone(),
            Value::Bool(bit(0x0400)),
        );
    }
    ctx.leaf(
        "dns.flags.truncated",
        flags_r.clone(),
        Value::Bool(bit(0x0200)),
    );
    ctx.leaf(
        "dns.flags.recdesired",
        flags_r.clone(),
        Value::Bool(bit(0x0100)),
    );
    if response {
        ctx.leaf(
            "dns.flags.recavail",
            flags_r.clone(),
            Value::Bool(bit(0x0080)),
        );
    }
    ctx.leaf("dns.flags.z", flags_r.clone(), Value::Bool(bit(0x0040)));
    if response {
        ctx.leaf(
            "dns.flags.authenticated",
            flags_r.clone(),
            Value::Bool(bit(0x0020)),
        );
    }
    ctx.leaf(
        "dns.flags.checkdisable",
        flags_r.clone(),
        Value::Bool(bit(0x0010)),
    );
    if response {
        ctx.leaf(
            "dns.flags.rcode",
            flags_r,
            Value::Unsigned(u64::from(rcode)),
        );
    }
    ctx.end();
    ctx.leaf("dns.count.queries", qd_r, Value::Unsigned(u64::from(qd)));
    ctx.leaf("dns.count.answers", an_r, Value::Unsigned(u64::from(an)));
    ctx.leaf("dns.count.auth_rr", ns_r, Value::Unsigned(u64::from(ns)));
    ctx.leaf("dns.count.add_rr", ar_r, Value::Unsigned(u64::from(ar)));

    let mut info = if response {
        format!("Standard query response 0x{id:04x}")
    } else {
        format!("Standard query 0x{id:04x}")
    };
    if response && rcode != 0 {
        info.push(' ');
        info.push_str(enum_name(DNS_RCODES, u64::from(rcode)).unwrap_or("Error"));
    }

    // Questions, then answer, authority and additional sections.
    let mut pos = c.pos();
    let mut ok = true;
    if qd > 0 {
        let sec_start = ctx.base + pos;
        let sec = ctx.begin("dns.queries", sec_start..sec_start);
        for _ in 0..qd.min(MAX_RECORDS) {
            match question(&msg, pos, ctx) {
                Ok((next, text)) => {
                    info.push(' ');
                    info.push_str(&text);
                    pos = next;
                }
                Err(e) => {
                    malformed(&msg, pos, ctx, &e);
                    ok = false;
                    break;
                }
            }
        }
        ctx.end_at(sec, section_end(&msg, pos, ok));
    }
    for (count, abbrev) in [
        (an, "dns.answers"),
        (ns, "dns.authority"),
        (ar, "dns.additional"),
    ] {
        if !ok || count == 0 {
            continue;
        }
        let sec_start = ctx.base + pos;
        let sec = ctx.begin(abbrev, sec_start..sec_start);
        for _ in 0..count.min(MAX_RECORDS) {
            match record(&msg, pos, ctx) {
                Ok((next, text)) => {
                    if abbrev == "dns.answers" {
                        info.push(' ');
                        info.push_str(&text);
                    }
                    pos = next;
                }
                Err(e) => {
                    malformed(&msg, pos, ctx, &e);
                    ok = false;
                    break;
                }
            }
        }
        ctx.end_at(sec, section_end(&msg, pos, ok));
    }
    if !ok {
        info.push_str(" [Malformed]");
    }
    ctx.set_info(info);
    ctx.end();
    let _ = dns;
    Ok(())
}

/// A section spans its records; a trailing malformed node reaches to the end
/// of the message, so extend the section over it.
fn section_end(msg: &Msg, pos: usize, ok: bool) -> usize {
    if ok {
        msg.base + pos
    } else {
        msg.base + msg.bytes.len()
    }
}

fn malformed(msg: &Msg, pos: usize, ctx: &mut Ctx, e: &DissectError) {
    let text = format!("[Malformed Packet: dns] {e}");
    ctx.leaf_text(
        "_ws.malformed",
        msg.base + pos..msg.base + msg.bytes.len(),
        Value::None,
        &text,
    );
}

fn question(msg: &Msg, pos: usize, ctx: &mut Ctx) -> Result<(usize, String)> {
    let (name, after) = msg.name_at(pos)?;
    let mut c = Cursor::new(msg.bytes, msg.base, ctx.source);
    c.skip(after)?;
    let (ty, ty_r) = c.u16()?;
    let (class, class_r) = c.u16()?;
    let type_name = enum_name(DNS_TYPES, u64::from(ty)).unwrap_or("Unknown");
    let text = format!("{name}: type {type_name}, class {}", class_name(class));
    let q = ctx.begin_text("dns.qry", msg.base + pos..c.abs(), &text);
    ctx.leaf(
        "dns.qry.name",
        msg.base + pos..msg.base + after,
        Value::Str(name.clone()),
    );
    ctx.leaf("dns.qry.type", ty_r, Value::Unsigned(u64::from(ty)));
    ctx.leaf("dns.qry.class", class_r, Value::Unsigned(u64::from(class)));
    ctx.end();
    let _ = q;
    Ok((c.pos(), format!("{type_name} {name}")))
}

fn class_name(class: u16) -> String {
    match class & 0x7fff {
        1 => "IN".into(),
        3 => "CH".into(),
        4 => "HS".into(),
        255 => "ANY".into(),
        other => format!("0x{other:04x}"),
    }
}

fn record(msg: &Msg, pos: usize, ctx: &mut Ctx) -> Result<(usize, String)> {
    let (name, after) = msg.name_at(pos)?;
    let mut c = Cursor::new(msg.bytes, msg.base, ctx.source);
    c.skip(after)?;
    let (ty, ty_r) = c.u16()?;
    let (class, class_r) = c.u16()?;
    let (ttl, ttl_r) = c.u32()?;
    let (rdlen, rdlen_r) = c.u16()?;
    let rd_pos = c.pos();
    let (rdata, rd_r) = c.take(usize::from(rdlen))?;
    let type_name = enum_name(DNS_TYPES, u64::from(ty)).unwrap_or("Unknown");

    let r = ctx.begin("dns.resp", msg.base + pos..c.abs());
    ctx.leaf(
        "dns.resp.name",
        msg.base + pos..msg.base + after,
        Value::Str(name.clone()),
    );
    ctx.leaf("dns.resp.type", ty_r, Value::Unsigned(u64::from(ty)));
    ctx.leaf("dns.resp.class", class_r, Value::Unsigned(u64::from(class)));
    ctx.leaf("dns.resp.ttl", ttl_r, Value::Unsigned(u64::from(ttl)));
    ctx.leaf("dns.resp.len", rdlen_r, Value::Unsigned(u64::from(rdlen)));

    let mut rc = Cursor::new(rdata, rd_r.start, ctx.source);
    let value: String = match ty {
        1 if rdata.len() == 4 => {
            let (a, ar) = rc.ipv4()?;
            ctx.leaf("dns.a", ar, Value::Ipv4(a));
            ipv4_str(a)
        }
        28 if rdata.len() == 16 => {
            let (a, ar) = rc.ipv6()?;
            ctx.leaf("dns.aaaa", ar, Value::Ipv6(a));
            ipv6_str(a)
        }
        2 | 5 | 12 => {
            let (target, _) = msg.name_at(rd_pos)?;
            let abbrev = match ty {
                2 => "dns.ns",
                5 => "dns.cname",
                _ => "dns.ptr.domain_name",
            };
            ctx.leaf(abbrev, rd_r.clone(), Value::Str(target.clone()));
            target
        }
        15 => {
            let (pref, pref_r) = rc.u16()?;
            let (mx, _) = msg.name_at(rd_pos + 2)?;
            ctx.leaf(
                "dns.mx.preference",
                pref_r,
                Value::Unsigned(u64::from(pref)),
            );
            ctx.leaf(
                "dns.mx.mail_exchange",
                rd_r.start + 2..rd_r.end,
                Value::Str(mx.clone()),
            );
            format!("{pref} {mx}")
        }
        16 => {
            let mut texts = Vec::new();
            while !rc.is_empty() {
                let (len, _) = rc.u8()?;
                let (txt, txt_r) = rc.take(usize::from(len))?;
                let t = String::from_utf8_lossy(txt).into_owned();
                ctx.leaf("dns.txt", txt_r, Value::Str(t.clone()));
                texts.push(t);
            }
            texts.join(" ")
        }
        6 => {
            let (mname, p1) = msg.name_at(rd_pos)?;
            let (rname, p2) = msg.name_at(p1)?;
            let mut c3 = Cursor::new(msg.bytes, msg.base, ctx.source);
            c3.skip(p2)?;
            let (serial, serial_r) = c3.u32()?;
            let (refresh, refresh_r) = c3.u32()?;
            let (retry, retry_r) = c3.u32()?;
            let (expire, expire_r) = c3.u32()?;
            let (min, min_r) = c3.u32()?;
            ctx.leaf(
                "dns.soa.mname",
                msg.base + rd_pos..msg.base + p1,
                Value::Str(mname.clone()),
            );
            ctx.leaf(
                "dns.soa.rname",
                msg.base + p1..msg.base + p2,
                Value::Str(rname.clone()),
            );
            ctx.leaf(
                "dns.soa.serial_number",
                serial_r,
                Value::Unsigned(u64::from(serial)),
            );
            ctx.leaf(
                "dns.soa.refresh_interval",
                refresh_r,
                Value::Unsigned(u64::from(refresh)),
            );
            ctx.leaf(
                "dns.soa.retry_interval",
                retry_r,
                Value::Unsigned(u64::from(retry)),
            );
            ctx.leaf(
                "dns.soa.expire_limit",
                expire_r,
                Value::Unsigned(u64::from(expire)),
            );
            ctx.leaf(
                "dns.soa.minimum_ttl",
                min_r,
                Value::Unsigned(u64::from(min)),
            );
            format!("{mname} {rname} {serial}")
        }
        33 => {
            let (prio, prio_r) = rc.u16()?;
            let (weight, weight_r) = rc.u16()?;
            let (port, port_r) = rc.u16()?;
            let (target, _) = msg.name_at(rd_pos + 6)?;
            ctx.leaf("dns.srv.priority", prio_r, Value::Unsigned(u64::from(prio)));
            ctx.leaf(
                "dns.srv.weight",
                weight_r,
                Value::Unsigned(u64::from(weight)),
            );
            ctx.leaf("dns.srv.port", port_r, Value::Unsigned(u64::from(port)));
            ctx.leaf(
                "dns.srv.target",
                rd_r.start + 6..rd_r.end,
                Value::Str(target.clone()),
            );
            format!("{prio} {weight} {port} {target}")
        }
        _ => {
            ctx.leaf("dns.resp.data", rd_r, Value::Bytes);
            format!("{rdlen} bytes")
        }
    };
    let text = format!(
        "{name}: type {type_name}, class {}, {value}",
        class_name(class)
    );
    ctx.set_text(r, &text);
    ctx.end();
    Ok((c.pos(), format!("{type_name} {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_and_compressed_names() {
        let mut m = vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        let base_len = m.len();
        m.extend_from_slice(&[4, b'm', b'a', b'i', b'l', 0xc0, 4]);
        assert_eq!(read_name(&m, 0), Ok(("www.example.com".into(), base_len)));
        assert_eq!(
            read_name(&m, base_len),
            Ok(("mail.example.com".into(), base_len + 7))
        );
    }

    #[test]
    fn pointer_loops_are_rejected() {
        let m = [0xc0, 0x02, 0xc0, 0x00];
        assert!(read_name(&m, 0).is_err());
        // A backward pointer to a label that points back again.
        let m2 = [1, b'a', 0xc0, 0x00];
        assert!(read_name(&m2, 2).is_err());
        let self_ref = [0xc0, 0x00];
        assert!(read_name(&self_ref, 0).is_err());
        let fwd = [0xc0, 0x02, 0x00];
        assert!(read_name(&fwd, 0).is_err());
    }

    #[test]
    fn truncated_names_are_errors() {
        assert!(read_name(&[5, b'a'], 0).is_err());
        assert!(read_name(&[], 0).is_err());
        assert!(read_name(&[0xc0], 0).is_err());
        assert_eq!(read_name(&[0], 0), Ok(("<Root>".into(), 1)));
    }
}
