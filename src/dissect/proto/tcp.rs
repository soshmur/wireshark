//! Transmission Control Protocol (RFC 9293) with all flags and the common
//! options: MSS, window scale, SACK-permitted, SACK blocks, timestamps.

use std::fmt::Write as _;

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;

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

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
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
    let flags_r = off_flags_r.clone();

    // Wireshark lists set flags lowest bit first: [SYN, ACK], [FIN, ACK].
    let mut names = super::NameList::new();
    for (bit, _, name) in FLAG_NAMES.iter().rev() {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    let set = names.as_str();
    let payload_len = data.len().saturating_sub(hdr_len);

    ctx.set_protocol("tcp");
    ctx.set_info(format!(
        "{sport} → {dport} [{set}] Seq={seq} Ack={ack} Win={window} Len={payload_len}"
    ));
    let tcp = ctx.begin("tcp", start..start);
    ctx.leaf("tcp.srcport", sport_r, Value::Unsigned(u64::from(sport)));
    ctx.leaf("tcp.dstport", dport_r, Value::Unsigned(u64::from(dport)));
    ctx.leaf("tcp.len", 0..0, Value::Unsigned(payload_len as u64));
    ctx.leaf("tcp.seq", seq_r, Value::Unsigned(u64::from(seq)));
    ctx.leaf("tcp.ack", ack_r, Value::Unsigned(u64::from(ack)));
    ctx.leaf("tcp.hdr_len", hdr_r, Value::Unsigned(hdr_len as u64));

    let flags_text = format!("Flags: 0x{flags:03x} ({set})");
    ctx.begin_value_text(
        "tcp.flags",
        flags_r.clone(),
        Value::Unsigned(u64::from(flags)),
        &flags_text,
    );
    for (bit, abbrev, _) in FLAG_NAMES {
        ctx.leaf(abbrev, flags_r.clone(), Value::Bool(flags & bit != 0));
    }
    ctx.end();
    ctx.leaf(
        "tcp.window_size_value",
        window_r,
        Value::Unsigned(u64::from(window)),
    );
    ctx.leaf(
        "tcp.checksum",
        checksum_r.clone(),
        Value::Unsigned(u64::from(checksum)),
    );
    let status = match transport_checksum(ctx, 6, data) {
        Some(0) => CK_GOOD,
        Some(_) => CK_BAD,
        None => CK_UNVERIFIED,
    };
    ctx.leaf("tcp.checksum.status", checksum_r, Value::Unsigned(status));
    ctx.leaf("tcp.urgent_pointer", urg_r, Value::Unsigned(u64::from(urg)));

    let opts_len = hdr_len - 20;
    if opts_len > 0 {
        let opts_start = c.abs();
        let mut oc = c.sub(opts_len)?;
        ctx.begin_textf(
            "tcp.options",
            opts_start..opts_start + opts_len,
            format_args!("Options: ({opts_len} bytes)"),
        );
        while !oc.is_empty() {
            let depth = ctx.depth();
            match option(&mut oc, ctx) {
                Ok(false) => {}
                Ok(true) => {
                    // EOL: the rest of the header is padding.
                    if !oc.is_empty() {
                        ctx.leaf("tcp.options.data", oc.rest_range(), Value::Bytes);
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
    }
    ctx.end_at(tcp, c.abs());

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
    Ok(())
}

/// One TCP option; the flag is `true` for End-of-Options.
fn option(c: &mut Cursor, ctx: &mut Ctx) -> Result<bool> {
    let start = c.abs();
    let (kind, kind_r) = c.u8()?;
    match kind {
        0 => {
            let n = ctx.begin("tcp.options.eol", start..c.abs());
            ctx.leaf("tcp.option_kind", kind_r, Value::Unsigned(u64::from(kind)));
            ctx.end_at(n, c.abs());
            return Ok(true);
        }
        1 => {
            let n = ctx.begin("tcp.options.nop", start..c.abs());
            ctx.leaf("tcp.option_kind", kind_r, Value::Unsigned(u64::from(kind)));
            ctx.end_at(n, c.abs());
            return Ok(false);
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
    // The option kind and length determine the node name; a truncated body
    // returns early and the caller restores the builder depth.
    let abbrev = match (kind, body_len) {
        (2, 2) => "tcp.options.mss",
        (3, 1) => "tcp.options.wscale",
        (4, 0) => "tcp.options.sack_perm",
        (5, n) if n % 8 == 0 => "tcp.options.sack",
        (8, 8) => "tcp.options.timestamp",
        _ => "tcp.options.unknown",
    };
    let node = ctx.begin(abbrev, start..start);
    ctx.leaf("tcp.option_kind", kind_r, Value::Unsigned(u64::from(kind)));
    ctx.leaf("tcp.option_len", len_r, Value::Unsigned(u64::from(len)));
    match abbrev {
        "tcp.options.mss" => {
            let (mss, r) = c.u16()?;
            ctx.leaf("tcp.options.mss_val", r, Value::Unsigned(u64::from(mss)));
            ctx.set_textf(node, format_args!("Maximum segment size: {mss} bytes"));
        }
        "tcp.options.wscale" => {
            let (shift, r) = c.u8()?;
            let mult = 1u64 << shift.min(14);
            ctx.leaf(
                "tcp.options.wscale.shift",
                r.clone(),
                Value::Unsigned(u64::from(shift)),
            );
            ctx.leaf("tcp.options.wscale.multiplier", r, Value::Unsigned(mult));
            ctx.set_textf(
                node,
                format_args!("Window scale: {shift} (multiply by {mult})"),
            );
        }
        "tcp.options.sack_perm" => ctx.set_text(node, "SACK permitted"),
        "tcp.options.sack" => {
            let mut blocks = Vec::with_capacity(body_len / 8);
            for _ in 0..body_len / 8 {
                let (le, le_r) = c.u32()?;
                let (re, re_r) = c.u32()?;
                ctx.leaf("tcp.options.sack_le", le_r, Value::Unsigned(u64::from(le)));
                ctx.leaf("tcp.options.sack_re", re_r, Value::Unsigned(u64::from(re)));
                blocks.push((le, re));
            }
            let mut text = String::from("SACK:");
            for (le, re) in blocks {
                let _ = write!(text, " {le}-{re}");
            }
            ctx.set_text(node, &text);
        }
        "tcp.options.timestamp" => {
            let (tsval, v_r) = c.u32()?;
            let (tsecr, e_r) = c.u32()?;
            ctx.leaf(
                "tcp.options.timestamp.tsval",
                v_r,
                Value::Unsigned(u64::from(tsval)),
            );
            ctx.leaf(
                "tcp.options.timestamp.tsecr",
                e_r,
                Value::Unsigned(u64::from(tsecr)),
            );
            ctx.set_textf(
                node,
                format_args!("Timestamps: TSval {tsval}, TSecr {tsecr}"),
            );
        }
        _ => {
            let (_, r) = c.take(body_len)?;
            ctx.leaf("tcp.options.data", r, Value::Bytes);
            ctx.set_textf(node, format_args!("Option kind {kind} ({len} bytes)"));
        }
    }
    ctx.end_at(node, c.abs());
    Ok(false)
}
