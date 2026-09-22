//! Transmission Control Protocol (RFC 9293) with all flags and the common
//! options: MSS, window scale, SACK-permitted, SACK blocks, timestamps.

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::{Node, Value};

use super::{transport_checksum, CK_BAD, CK_GOOD, CK_UNVERIFIED};

const FLAG_NAMES: [(u16, &str, &str); 10] = [
    (0x800, "tcp.flags.res", "RES"),
    (0x100, "tcp.flags.ae", "AE"),
    (0x080, "tcp.flags.cwr", "CWR"),
    (0x040, "tcp.flags.ece", "ECE"),
    (0x020, "tcp.flags.urg", "URG"),
    (0x010, "tcp.flags.ack", "ACK"),
    (0x008, "tcp.flags.push", "PSH"),
    (0x004, "tcp.flags.reset", "RST"),
    (0x002, "tcp.flags.syn", "SYN"),
    (0x001, "tcp.flags.fin", "FIN"),
];

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();
    let (sport, sport_r) = c.u16()?;
    let (dport, dport_r) = c.u16()?;
    let (seq, seq_r) = c.u32()?;
    let (ack, ack_r) = c.u32()?;
    let (off_flags, off_flags_r) = c.u16()?;
    let (window, window_r) = c.u16()?;
    let (checksum, checksum_r) = c.u16()?;
    let (urg, urg_r) = c.u16()?;
    let hdr_len = usize::from(off_flags >> 12) * 4;
    let flags = off_flags & 0x0fff;
    if hdr_len < 20 {
        return Err(DissectError::Invalid {
            at: off_flags_r.start,
            what: "TCP header length (data offset < 5)",
        });
    }
    let hdr_r = off_flags_r.start..off_flags_r.start + 1;
    let flags_r = off_flags_r.start..off_flags_r.end;

    // Wireshark lists set flags lowest bit first: [SYN, ACK], [FIN, ACK].
    let mut set = String::with_capacity(32);
    for (bit, _, name) in FLAG_NAMES.iter().rev() {
        if flags & bit != 0 {
            if !set.is_empty() {
                set.push_str(", ");
            }
            set.push_str(name);
        }
    }
    let payload_len = data.len().saturating_sub(hdr_len);

    ctx.set_protocol("tcp");
    ctx.set_info(format!(
        "{sport} → {dport} [{set}] Seq={seq} Ack={ack} Win={window} Len={payload_len}"
    ));
    let mut node = Node::new("tcp", start..start, Value::None)
        .with_source(s)
        .reserve(14);
    node.push(Node::new("tcp.srcport", sport_r, Value::Unsigned(u64::from(sport))).with_source(s));
    node.push(Node::new("tcp.dstport", dport_r, Value::Unsigned(u64::from(dport))).with_source(s));
    node.push(Node::new("tcp.len", 0..0, Value::Unsigned(payload_len as u64)).with_source(s));
    node.push(Node::new("tcp.seq", seq_r, Value::Unsigned(u64::from(seq))).with_source(s));
    node.push(Node::new("tcp.ack", ack_r, Value::Unsigned(u64::from(ack))).with_source(s));
    node.push(Node::new("tcp.hdr_len", hdr_r, Value::Unsigned(hdr_len as u64)).with_source(s));

    let mut fl = Node::new(
        "tcp.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags)),
    )
    .with_source(s)
    .with_text(format!("Flags: 0x{flags:03x} ({set})"));
    for (bit, abbrev, _) in FLAG_NAMES {
        fl.push(Node::new(abbrev, flags_r.clone(), Value::Bool(flags & bit != 0)).with_source(s));
    }
    node.push(fl);
    node.push(
        Node::new(
            "tcp.window_size_value",
            window_r,
            Value::Unsigned(u64::from(window)),
        )
        .with_source(s),
    );
    node.push(
        Node::new(
            "tcp.checksum",
            checksum_r.clone(),
            Value::Unsigned(u64::from(checksum)),
        )
        .with_source(s),
    );
    let status = match transport_checksum(ctx, 6, data) {
        Some(0) => CK_GOOD,
        Some(_) => CK_BAD,
        None => CK_UNVERIFIED,
    };
    node.push(Node::new("tcp.checksum.status", checksum_r, Value::Unsigned(status)).with_source(s));
    node.push(
        Node::new("tcp.urgent_pointer", urg_r, Value::Unsigned(u64::from(urg))).with_source(s),
    );

    let opts_len = hdr_len - 20;
    if opts_len > 0 {
        let opts_start = c.abs();
        let mut oc = c.sub(opts_len)?;
        let mut options = Node::new(
            "tcp.options",
            opts_start..opts_start + opts_len,
            Value::None,
        )
        .with_source(s)
        .with_text(format!("Options: ({opts_len} bytes)"));
        while !oc.is_empty() {
            match option(&mut oc) {
                Ok((opt, eol)) => {
                    options.push(opt);
                    if eol {
                        // EOL: the rest of the header is padding.
                        if !oc.is_empty() {
                            options.push(
                                Node::new("tcp.options.data", oc.rest_range(), Value::Bytes)
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

    if payload_len > 0 {
        // The payload is the next layer, not a child of the TCP header.
        let payload = c.rest();
        let next = if super::tls::looks_like_tls(payload) {
            Proto::Tls
        } else if super::http::looks_like_http(payload) {
            Proto::Http
        } else {
            match (sport, dport) {
                (443, _) | (_, 443) | (8443, _) | (_, 8443) => Proto::Tls,
                (80, _) | (_, 80) | (8080, _) | (_, 8080) => Proto::Http,
                _ => Proto::Data,
            }
        };
        ctx.call_next(next, c.pos());
    }
    Ok(node)
}

/// One TCP option; the flag is `true` for End-of-Options.
fn option(c: &mut Cursor) -> Result<(Node, bool)> {
    let s = c.source();
    let start = c.abs();
    let (kind, kind_r) = c.u8()?;
    let kind_node =
        |r| Node::new("tcp.option_kind", r, Value::Unsigned(u64::from(kind))).with_source(s);
    match kind {
        0 => {
            let mut n = Node::new("tcp.options.eol", start..c.abs(), Value::None).with_source(s);
            n.push(kind_node(kind_r));
            return Ok((n, true));
        }
        1 => {
            let mut n = Node::new("tcp.options.nop", start..c.abs(), Value::None).with_source(s);
            n.push(kind_node(kind_r));
            return Ok((n, false));
        }
        _ => {}
    }
    let (len, len_r) = c.u8()?;
    if len < 2 {
        return Err(DissectError::Invalid {
            at: len_r.start,
            what: "TCP option length (< 2)",
        });
    }
    let body_len = usize::from(len) - 2;
    let len_node = || {
        Node::new(
            "tcp.option_len",
            len_r.clone(),
            Value::Unsigned(u64::from(len)),
        )
        .with_source(s)
    };
    let (abbrev, body_nodes, text): (&'static str, Vec<Node>, String) = match kind {
        2 if body_len == 2 => {
            let (mss, r) = c.u16()?;
            (
                "tcp.options.mss",
                vec![
                    Node::new("tcp.options.mss_val", r, Value::Unsigned(u64::from(mss)))
                        .with_source(s),
                ],
                format!("Maximum segment size: {mss} bytes"),
            )
        }
        3 if body_len == 1 => {
            let (shift, r) = c.u8()?;
            let mult = 1u64 << shift.min(14);
            (
                "tcp.options.wscale",
                vec![
                    Node::new(
                        "tcp.options.wscale.shift",
                        r.clone(),
                        Value::Unsigned(u64::from(shift)),
                    )
                    .with_source(s),
                    Node::new("tcp.options.wscale.multiplier", r, Value::Unsigned(mult))
                        .with_source(s),
                ],
                format!("Window scale: {shift} (multiply by {mult})"),
            )
        }
        4 if body_len == 0 => ("tcp.options.sack_perm", vec![], "SACK permitted".into()),
        5 if body_len % 8 == 0 => {
            let mut blocks = Vec::new();
            let mut texts = Vec::new();
            for _ in 0..body_len / 8 {
                let (le, le_r) = c.u32()?;
                let (re, re_r) = c.u32()?;
                blocks.push(
                    Node::new("tcp.options.sack_le", le_r, Value::Unsigned(u64::from(le)))
                        .with_source(s),
                );
                blocks.push(
                    Node::new("tcp.options.sack_re", re_r, Value::Unsigned(u64::from(re)))
                        .with_source(s),
                );
                texts.push(format!("{le}-{re}"));
            }
            (
                "tcp.options.sack",
                blocks,
                format!("SACK: {}", texts.join(" ")),
            )
        }
        8 if body_len == 8 => {
            let (tsval, v_r) = c.u32()?;
            let (tsecr, e_r) = c.u32()?;
            (
                "tcp.options.timestamp",
                vec![
                    Node::new(
                        "tcp.options.timestamp.tsval",
                        v_r,
                        Value::Unsigned(u64::from(tsval)),
                    )
                    .with_source(s),
                    Node::new(
                        "tcp.options.timestamp.tsecr",
                        e_r,
                        Value::Unsigned(u64::from(tsecr)),
                    )
                    .with_source(s),
                ],
                format!("Timestamps: TSval {tsval}, TSecr {tsecr}"),
            )
        }
        _ => {
            let (_, r) = c.take(body_len)?;
            (
                "tcp.options.unknown",
                vec![Node::new("tcp.options.data", r, Value::Bytes).with_source(s)],
                format!("Option kind {kind} ({len} bytes)"),
            )
        }
    };
    let mut n = Node::new(abbrev, start..c.abs(), Value::None)
        .with_source(s)
        .with_text(text);
    n.push(kind_node(kind_r));
    n.push(len_node());
    for b in body_nodes {
        n.push(b);
    }
    Ok((n, false))
}
