//! DHCP over BOOTP (RFC 2131 / RFC 2132).

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::{Node, Value};
use crate::dissect::registry::{enum_name, DHCP_MSG_TYPES, DHCP_OPTIONS};

use super::{ipv4_str, mac_str};

const MAGIC: u32 = 0x6382_5363;

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
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
    let mut node = Node::new("dhcp", start..start + data.len(), Value::None).with_source(s);
    node.push(Node::new("dhcp.type", op_r, Value::Unsigned(u64::from(op))).with_source(s));
    node.push(Node::new("dhcp.hw.type", htype_r, Value::Unsigned(u64::from(htype))).with_source(s));
    node.push(Node::new("dhcp.hw.len", hlen_r, Value::Unsigned(u64::from(hlen))).with_source(s));
    node.push(Node::new("dhcp.hops", hops_r, Value::Unsigned(u64::from(hops))).with_source(s));
    node.push(Node::new("dhcp.id", xid_r, Value::Unsigned(u64::from(xid))).with_source(s));
    node.push(Node::new("dhcp.secs", secs_r, Value::Unsigned(u64::from(secs))).with_source(s));
    let mut fl = Node::new(
        "dhcp.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags)),
    )
    .with_source(s);
    fl.push(Node::new("dhcp.flags.bc", flags_r, Value::Bool(flags & 0x8000 != 0)).with_source(s));
    node.push(fl);
    node.push(Node::new("dhcp.ip.client", ciaddr_r, Value::Ipv4(ciaddr)).with_source(s));
    node.push(Node::new("dhcp.ip.your", yiaddr_r, Value::Ipv4(yiaddr)).with_source(s));
    node.push(Node::new("dhcp.ip.server", siaddr_r, Value::Ipv4(siaddr)).with_source(s));
    node.push(Node::new("dhcp.ip.relay", giaddr_r, Value::Ipv4(giaddr)).with_source(s));
    let mut mac_text = String::new();
    if htype == 1 && hlen == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&chaddr[..6]);
        node.push(
            Node::new(
                "dhcp.hw.mac_addr",
                chaddr_r.start..chaddr_r.start + 6,
                Value::Mac(mac),
            )
            .with_source(s),
        );
        node.push(
            Node::new(
                "dhcp.hw.addr_padding",
                chaddr_r.start + 6..chaddr_r.end,
                Value::Bytes,
            )
            .with_source(s),
        );
        mac_text = mac_str(mac);
    } else {
        node.push(Node::new("dhcp.hw.addr_padding", chaddr_r, Value::Bytes).with_source(s));
    }
    node.push(Node::new("dhcp.server", sname_r, Value::Str(cstr(sname))).with_source(s));
    node.push(Node::new("dhcp.file", file_r, Value::Str(cstr(file))).with_source(s));

    let mut msg_type: Option<u8> = None;
    if c.remaining() >= 4 {
        let (cookie, cookie_r) = c.u32()?;
        node.push(
            Node::new("dhcp.cookie", cookie_r, Value::Unsigned(u64::from(cookie))).with_source(s),
        );
        if cookie == MAGIC {
            while !c.is_empty() {
                match option(&mut c) {
                    Ok((opt, mt, end)) => {
                        if mt.is_some() {
                            msg_type = mt;
                        }
                        node.push(opt);
                        if end {
                            if !c.is_empty() {
                                node.push(
                                    Node::new("dhcp.option.padding", c.rest_range(), Value::Bytes)
                                        .with_source(s),
                                );
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        node.push(
                            Node::new("_ws.malformed", c.rest_range(), Value::None)
                                .with_source(s)
                                .with_text(format!("[Malformed option: {e}]")),
                        );
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
    node.text = Some(format!("Dynamic Host Configuration Protocol ({kind})").into());
    let mut info = format!("DHCP {kind:<8} - Transaction ID 0x{xid:x}");
    if !mac_text.is_empty() && op == 1 {
        info.push_str(&format!(" from {mac_text}"));
    }
    if yiaddr != [0; 4] {
        info.push_str(&format!(" ({})", ipv4_str(yiaddr)));
    }
    ctx.set_info(info);
    Ok(node)
}

/// Returns (node, message type if option 53, is_end).
fn option(c: &mut Cursor) -> Result<(Node, Option<u8>, bool)> {
    let s = c.source();
    let start = c.abs();
    let (code, code_r) = c.u8()?;
    let mut opt = Node::new("dhcp.option", start..start, Value::None).with_source(s);
    opt.push(
        Node::new("dhcp.option.type", code_r, Value::Unsigned(u64::from(code))).with_source(s),
    );
    match code {
        0 => {
            opt.range = start..c.abs();
            opt.text = Some("Option: (0) Pad".into());
            return Ok((opt, None, false));
        }
        255 => {
            opt.range = start..c.abs();
            opt.text = Some("Option: (255) End".into());
            opt.push(Node::new("dhcp.option.end", start..c.abs(), Value::None).with_source(s));
            return Ok((opt, None, true));
        }
        _ => {}
    }
    let (len, len_r) = c.u8()?;
    opt.push(
        Node::new("dhcp.option.length", len_r, Value::Unsigned(u64::from(len))).with_source(s),
    );
    let (body, body_r) = c.take(usize::from(len))?;
    let name = enum_name(DHCP_OPTIONS, u64::from(code)).unwrap_or("Unknown");
    let mut msg_type = None;
    let mut detail = String::new();
    let mut bc = Cursor::new(body, body_r.start, s);
    match code {
        53 if len == 1 => {
            let (t, r) = bc.u8()?;
            msg_type = Some(t);
            opt.push(
                Node::new("dhcp.option.dhcp", r, Value::Unsigned(u64::from(t))).with_source(s),
            );
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
                opt.push(Node::new(abbrev, r, Value::Ipv4(a)).with_source(s));
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
            opt.push(Node::new(abbrev, r, Value::Unsigned(u64::from(v))).with_source(s));
            detail = format!("{v}s");
        }
        57 if len == 2 => {
            let (v, r) = bc.u16()?;
            opt.push(
                Node::new(
                    "dhcp.option.dhcp_max_message_size",
                    r,
                    Value::Unsigned(u64::from(v)),
                )
                .with_source(s),
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
            opt.push(Node::new(abbrev, body_r.clone(), Value::Str(text.clone())).with_source(s));
            detail = text;
        }
        61 => {
            opt.push(
                Node::new("dhcp.option.client_id", body_r.clone(), Value::Bytes).with_source(s),
            );
        }
        55 => {
            let mut items = Vec::new();
            for (i, &b) in body.iter().enumerate() {
                let r = body_r.start + i..body_r.start + i + 1;
                opt.push(
                    Node::new(
                        "dhcp.option.request_list_item",
                        r,
                        Value::Unsigned(u64::from(b)),
                    )
                    .with_source(s),
                );
                items.push(b.to_string());
            }
            detail = items.join(",");
        }
        _ => {
            opt.push(Node::new("dhcp.option.value", body_r.clone(), Value::Bytes).with_source(s));
        }
    }
    opt.range = start..c.abs();
    opt.text = Some(
        if detail.is_empty() {
            format!("Option: ({code}) {name}")
        } else {
            format!("Option: ({code}) {name} = {detail}")
        }
        .into(),
    );
    Ok((opt, msg_type, false))
}
