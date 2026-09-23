//! DHCP over BOOTP (RFC 2131 / RFC 2132).

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{enum_name, DHCP_MSG_TYPES, DHCP_OPTIONS};

use super::{ipv4_str, mac_str};

const MAGIC: u32 = 0x6382_5363;

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (op, op_r) = c.u8()?;
    let (htype, htype_r) = c.u8()?;
    let (hlen, hlen_r) = c.u8()?;
    let (hops, hops_r) = c.u8()?;
    let (xid, xid_r) = c.u32()?;
    let (secs, secs_r) = c.u16()?;
    let (flags, flags_r) = c.u16()?;
    let (ciaddr, ciaddr_r) = c.ipv4()?;
    let (yiaddr, yiaddr_r) = c.ipv4()?;
    let (siaddr, siaddr_r) = c.ipv4()?;
    let (giaddr, giaddr_r) = c.ipv4()?;
    let (chaddr, chaddr_r) = c.take(16)?;
    let (sname, sname_r) = c.take(64)?;
    let (file, file_r) = c.take(128)?;

    ctx.set_protocol("dhcp");
    let node = ctx.begin("dhcp", start..start + data.len());
    ctx.leaf("dhcp.type", op_r, Value::Unsigned(u64::from(op)));
    ctx.leaf("dhcp.hw.type", htype_r, Value::Unsigned(u64::from(htype)));
    ctx.leaf("dhcp.hw.len", hlen_r, Value::Unsigned(u64::from(hlen)));
    ctx.leaf("dhcp.hops", hops_r, Value::Unsigned(u64::from(hops)));
    ctx.leaf("dhcp.id", xid_r, Value::Unsigned(u64::from(xid)));
    ctx.leaf("dhcp.secs", secs_r, Value::Unsigned(u64::from(secs)));
    ctx.begin_value(
        "dhcp.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags)),
    );
    ctx.leaf("dhcp.flags.bc", flags_r, Value::Bool(flags & 0x8000 != 0));
    ctx.end();
    ctx.leaf("dhcp.ip.client", ciaddr_r, Value::Ipv4(ciaddr));
    ctx.leaf("dhcp.ip.your", yiaddr_r, Value::Ipv4(yiaddr));
    ctx.leaf("dhcp.ip.server", siaddr_r, Value::Ipv4(siaddr));
    ctx.leaf("dhcp.ip.relay", giaddr_r, Value::Ipv4(giaddr));
    let mut mac_text = String::new();
    if htype == 1 && hlen == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&chaddr[..6]);
        ctx.leaf(
            "dhcp.hw.mac_addr",
            chaddr_r.start..chaddr_r.start + 6,
            Value::Mac(mac),
        );
        ctx.leaf(
            "dhcp.hw.addr_padding",
            chaddr_r.start + 6..chaddr_r.end,
            Value::Bytes,
        );
        mac_text = mac_str(mac);
    } else {
        ctx.leaf("dhcp.hw.addr_padding", chaddr_r, Value::Bytes);
    }
    ctx.leaf("dhcp.server", sname_r, Value::Str(cstr(sname)));
    ctx.leaf("dhcp.file", file_r, Value::Str(cstr(file)));

    let mut msg_type: Option<u8> = None;
    if c.remaining() >= 4 {
        let (cookie, cookie_r) = c.u32()?;
        ctx.leaf("dhcp.cookie", cookie_r, Value::Unsigned(u64::from(cookie)));
        if cookie == MAGIC {
            while !c.is_empty() {
                let depth = ctx.depth();
                match option(&mut c, ctx) {
                    Ok((mt, end)) => {
                        if mt.is_some() {
                            msg_type = mt;
                        }
                        if end {
                            if !c.is_empty() {
                                ctx.leaf("dhcp.option.padding", c.rest_range(), Value::Bytes);
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        ctx.restore_depth(depth);
                        let text = format!("[Malformed option: {e}]");
                        ctx.leaf_text("_ws.malformed", c.rest_range(), Value::None, &text);
                        break;
                    }
                }
            }
        }
    }
    let kind = msg_type
        .and_then(|t| enum_name(DHCP_MSG_TYPES, u64::from(t)))
        .unwrap_or(if op == 1 {
            "Boot Request"
        } else {
            "Boot Reply"
        });
    let text = format!("Dynamic Host Configuration Protocol ({kind})");
    ctx.set_text(node, &text);
    let mut info = format!("DHCP {kind:<8} - Transaction ID 0x{xid:x}");
    if !mac_text.is_empty() && op == 1 {
        info.push_str(&format!(" from {mac_text}"));
    }
    if yiaddr != [0; 4] {
        info.push_str(&format!(" ({})", ipv4_str(yiaddr)));
    }
    ctx.set_info(info);
    ctx.end();
    Ok(())
}

/// Returns (message type if option 53, is_end).
fn option(c: &mut Cursor, ctx: &mut Ctx) -> Result<(Option<u8>, bool)> {
    let start = c.abs();
    let (code, code_r) = c.u8()?;
    let opt = ctx.begin("dhcp.option", start..start);
    ctx.leaf("dhcp.option.type", code_r, Value::Unsigned(u64::from(code)));
    match code {
        0 => {
            ctx.set_text(opt, "Option: (0) Pad");
            ctx.end_at(opt, c.abs());
            return Ok((None, false));
        }
        255 => {
            ctx.set_text(opt, "Option: (255) End");
            ctx.leaf("dhcp.option.end", start..c.abs(), Value::None);
            ctx.end_at(opt, c.abs());
            return Ok((None, true));
        }
        _ => {}
    }
    let (len, len_r) = c.u8()?;
    ctx.leaf("dhcp.option.length", len_r, Value::Unsigned(u64::from(len)));
    let (body, body_r) = c.take(usize::from(len))?;
    let name = enum_name(DHCP_OPTIONS, u64::from(code)).unwrap_or("Unknown");
    let mut msg_type = None;
    let mut detail = String::new();
    let mut bc = Cursor::new(body, body_r.start, ctx.source);
    match code {
        53 if len == 1 => {
            let (t, r) = bc.u8()?;
            msg_type = Some(t);
            ctx.leaf("dhcp.option.dhcp", r, Value::Unsigned(u64::from(t)));
            detail = enum_name(DHCP_MSG_TYPES, u64::from(t))
                .unwrap_or("Unknown")
                .to_string();
        }
        1 | 3 | 6 | 28 | 42 | 50 | 54 if len % 4 == 0 && len > 0 => {
            let abbrev = match code {
                1 => "dhcp.option.subnet_mask",
                3 => "dhcp.option.router",
                6 => "dhcp.option.domain_name_server",
                28 => "dhcp.option.broadcast_address",
                42 => "dhcp.option.ntp_server",
                50 => "dhcp.option.requested_ip_address",
                _ => "dhcp.option.dhcp_server_id",
            };
            let mut addrs = Vec::new();
            while bc.remaining() >= 4 {
                let (a, r) = bc.ipv4()?;
                ctx.leaf(abbrev, r, Value::Ipv4(a));
                addrs.push(ipv4_str(a));
            }
            detail = addrs.join(", ");
        }
        51 | 58 | 59 if len == 4 => {
            let abbrev = match code {
                51 => "dhcp.option.ip_address_lease_time",
                58 => "dhcp.option.renewal_time_value",
                _ => "dhcp.option.rebinding_time_value",
            };
            let (v, r) = bc.u32()?;
            ctx.leaf(abbrev, r, Value::Unsigned(u64::from(v)));
            detail = format!("{v}s");
        }
        57 if len == 2 => {
            let (v, r) = bc.u16()?;
            ctx.leaf(
                "dhcp.option.dhcp_max_message_size",
                r,
                Value::Unsigned(u64::from(v)),
            );
            detail = v.to_string();
        }
        12 | 15 | 60 => {
            let abbrev = match code {
                12 => "dhcp.option.hostname",
                15 => "dhcp.option.domain_name",
                _ => "dhcp.option.vendor_class_id",
            };
            let text = String::from_utf8_lossy(body).into_owned();
            ctx.leaf(abbrev, body_r.clone(), Value::Str(text.clone()));
            detail = text;
        }
        61 => {
            ctx.leaf("dhcp.option.client_id", body_r.clone(), Value::Bytes);
        }
        55 => {
            let mut items = Vec::new();
            for (i, &b) in body.iter().enumerate() {
                let r = body_r.start + i..body_r.start + i + 1;
                ctx.leaf(
                    "dhcp.option.request_list_item",
                    r,
                    Value::Unsigned(u64::from(b)),
                );
                items.push(b.to_string());
            }
            detail = items.join(",");
        }
        _ => {
            ctx.leaf("dhcp.option.value", body_r.clone(), Value::Bytes);
        }
    }
    let text = if detail.is_empty() {
        format!("Option: ({code}) {name}")
    } else {
        format!("Option: ({code}) {name} = {detail}")
    };
    ctx.set_text(opt, &text);
    ctx.end_at(opt, c.abs());
    Ok((msg_type, false))
}
