//! TLS record layer (RFC 8446 §5) with ClientHello / ServerHello parsing:
//! version, random, session id, cipher suites, and the SNI, ALPN and
//! supported_versions extensions. No decryption.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;
use crate::dissect::registry::{
    enum_name, TLS_ALERT_DESCS, TLS_CONTENT_TYPES, TLS_EXTENSIONS, TLS_HANDSHAKE_TYPES,
    TLS_VERSIONS,
};

/// Cheap heuristic used by TCP for dispatch: a plausible record header.
pub fn looks_like_tls(payload: &[u8]) -> bool {
    matches!(payload, [ct, 3, minor, ..] if (20..=24).contains(ct) && *minor <= 4)
}

fn version_name(v: u16) -> String {
    enum_name(TLS_VERSIONS, u64::from(v))
        .map(str::to_string)
        .unwrap_or_else(|| format!("0x{v:04x}"))
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    ctx.set_protocol("tls");
    let tls = ctx.begin_text("tls", start..start + data.len(), "Transport Layer Security");
    let mut infos: Vec<String> = Vec::new();
    let mut records = 0;
    // Bytes that do not start with a plausible record header are the tail of
    // a record begun in an earlier segment (or not TLS at all).
    while c.remaining() >= 5 && looks_like_tls(c.rest()) {
        let rec_start = c.abs();
        let (ct, ct_r) = c.u8()?;
        let (ver, ver_r) = c.u16()?;
        let (len, len_r) = c.u16()?;
        let ct_name = enum_name(TLS_CONTENT_TYPES, u64::from(ct)).unwrap_or("Unknown");
        let rec = ctx.begin("tls.record", rec_start..rec_start);
        ctx.leaf(
            "tls.record.content_type",
            ct_r,
            Value::Unsigned(u64::from(ct)),
        );
        ctx.leaf("tls.record.version", ver_r, Value::Unsigned(u64::from(ver)));
        ctx.leaf("tls.record.length", len_r, Value::Unsigned(u64::from(len)));
        let avail = c.remaining();
        let body_len = usize::from(len);
        if body_len > avail {
            // Record continues in the next segment (desegmentation is Phase 4).
            ctx.leaf("tls.continuation_data", c.rest_range(), Value::Bytes);
            let text = format!(
                "{}: {ct_name} Protocol (fragment, {avail} of {body_len} bytes)",
                version_name(ver)
            );
            ctx.set_text(rec, &text);
            c.skip(avail)?;
            ctx.end_at(rec, c.abs());
            infos.push(format!("{ct_name} [fragment]"));
            records += 1;
            break;
        }
        let mut body = c.sub(body_len)?;
        let depth = ctx.depth();
        let summary = match ct {
            20 => {
                ctx.leaf("tls.change_cipher_spec", body.rest_range(), Value::None);
                "Change Cipher Spec".to_string()
            }
            21 => match alert(&mut body, ctx) {
                Ok(text) => text,
                Err(_) => {
                    ctx.restore_depth(depth);
                    ctx.leaf("tls.app_data", body.rest_range(), Value::Bytes);
                    "Encrypted Alert".into()
                }
            },
            22 => match handshake(&mut body, ctx) {
                Ok(text) => text,
                Err(_) => {
                    ctx.restore_depth(depth);
                    ctx.leaf("tls.handshake.encrypted", body.rest_range(), Value::Bytes);
                    "Encrypted Handshake Message".into()
                }
            },
            23 => {
                ctx.leaf("tls.app_data", body.rest_range(), Value::Bytes);
                "Application Data".into()
            }
            _ => {
                ctx.leaf("tls.app_data", body.rest_range(), Value::Bytes);
                format!("Unknown content type {ct}")
            }
        };
        let text = format!(
            "{} Record Layer: {ct_name} Protocol: {summary}",
            version_name(ver)
        );
        ctx.set_text(rec, &text);
        ctx.end_at(rec, c.abs());
        infos.push(summary);
        records += 1;
        if records >= 64 {
            break;
        }
    }
    if !c.is_empty() {
        ctx.leaf("tls.continuation_data", c.rest_range(), Value::Bytes);
        if records == 0 {
            infos.push("Continuation Data".into());
        }
    }
    ctx.set_info(infos.join(", "));
    ctx.end();
    let _ = tls;
    Ok(())
}

fn alert(c: &mut Cursor, ctx: &mut Ctx) -> Result<String> {
    let start = c.abs();
    let (level, level_r) = c.u8()?;
    let (desc, desc_r) = c.u8()?;
    let text = format!(
        "Alert ({})",
        enum_name(TLS_ALERT_DESCS, u64::from(desc)).unwrap_or("Unknown")
    );
    let n = ctx.begin_text("tls.alert_message", start..c.abs(), &text);
    ctx.leaf(
        "tls.alert_message.level",
        level_r,
        Value::Unsigned(u64::from(level)),
    );
    ctx.leaf(
        "tls.alert_message.desc",
        desc_r,
        Value::Unsigned(u64::from(desc)),
    );
    ctx.end();
    let _ = n;
    Ok(text)
}

/// One or more handshake messages within a record.
fn handshake(c: &mut Cursor, ctx: &mut Ctx) -> Result<String> {
    let mut texts: Vec<String> = Vec::new();
    while c.remaining() >= 4 {
        let start = c.abs();
        let (ty, ty_r) = c.u8()?;
        let (len, len_r) = c.u24()?;
        // An unknown type after a ChangeCipherSpec is ciphertext, not a
        // message; without session state, that is the best available signal.
        let Some(name) = enum_name(TLS_HANDSHAKE_TYPES, u64::from(ty)) else {
            if texts.is_empty() {
                return Err(DissectError::Invalid {
                    at: start,
                    what: "handshake type (encrypted?)",
                });
            }
            break;
        };
        let text = format!("Handshake Protocol: {name}");
        let hs = ctx.begin_text("tls.handshake", start..start, &text);
        ctx.leaf("tls.handshake.type", ty_r, Value::Unsigned(u64::from(ty)));
        ctx.leaf(
            "tls.handshake.length",
            len_r,
            Value::Unsigned(u64::from(len)),
        );
        let body_len = (len as usize).min(c.remaining());
        let mut body = c.sub(body_len)?;
        let depth = ctx.depth();
        let result = match ty {
            1 => client_hello(&mut body, ctx),
            2 => server_hello(&mut body, ctx),
            11 => certificate(&mut body, ctx),
            _ => {
                if !body.is_empty() {
                    ctx.leaf("tls.handshake.encrypted", body.rest_range(), Value::Bytes);
                }
                Ok(())
            }
        };
        if let Err(e) = result {
            ctx.restore_depth(depth);
            let text = format!("[Malformed Packet: tls] {e}");
            ctx.leaf_text("_ws.malformed", body.rest_range(), Value::None, &text);
        }
        ctx.end_at(hs, c.abs());
        texts.push(name.to_string());
        if (len as usize) > body_len {
            break;
        }
    }
    if texts.is_empty() {
        return Err(DissectError::Truncated {
            at: c.abs(),
            need: 4,
            have: c.remaining(),
        });
    }
    Ok(texts.join(", "))
}

fn client_hello(c: &mut Cursor, ctx: &mut Ctx) -> Result<()> {
    let (ver, ver_r) = c.u16()?;
    let (_, rnd_r) = c.take(32)?;
    let (sid_len, sid_len_r) = c.u8()?;
    let (_, sid_r) = c.take(usize::from(sid_len))?;
    ctx.leaf(
        "tls.handshake.version",
        ver_r,
        Value::Unsigned(u64::from(ver)),
    );
    ctx.leaf("tls.handshake.random", rnd_r, Value::Bytes);
    ctx.leaf(
        "tls.handshake.session_id_length",
        sid_len_r,
        Value::Unsigned(u64::from(sid_len)),
    );
    if sid_len > 0 {
        ctx.leaf("tls.handshake.session_id", sid_r, Value::Bytes);
    }
    let (cs_len, cs_len_r) = c.u16()?;
    ctx.leaf(
        "tls.handshake.cipher_suites_length",
        cs_len_r,
        Value::Unsigned(u64::from(cs_len)),
    );
    let mut cs = c.sub(usize::from(cs_len))?;
    let text = format!("Cipher Suites ({} suites)", cs_len / 2);
    ctx.begin_text("tls.handshake.ciphersuites", cs.rest_range(), &text);
    while cs.remaining() >= 2 {
        let (suite, r) = cs.u16()?;
        ctx.leaf(
            "tls.handshake.ciphersuite",
            r,
            Value::Unsigned(u64::from(suite)),
        );
    }
    ctx.end();
    let (cm_len, cm_len_r) = c.u8()?;
    ctx.leaf(
        "tls.handshake.comp_methods_length",
        cm_len_r,
        Value::Unsigned(u64::from(cm_len)),
    );
    let mut cm = c.sub(usize::from(cm_len))?;
    ctx.begin("tls.handshake.comp_methods", cm.rest_range());
    while !cm.is_empty() {
        let (m, r) = cm.u8()?;
        ctx.leaf(
            "tls.handshake.comp_method",
            r,
            Value::Unsigned(u64::from(m)),
        );
    }
    ctx.end();
    if c.remaining() >= 2 {
        extensions(c, ctx)?;
    }
    Ok(())
}

fn server_hello(c: &mut Cursor, ctx: &mut Ctx) -> Result<()> {
    let (ver, ver_r) = c.u16()?;
    let (_, rnd_r) = c.take(32)?;
    let (sid_len, sid_len_r) = c.u8()?;
    let (_, sid_r) = c.take(usize::from(sid_len))?;
    let (suite, suite_r) = c.u16()?;
    let (cm, cm_r) = c.u8()?;
    ctx.leaf(
        "tls.handshake.version",
        ver_r,
        Value::Unsigned(u64::from(ver)),
    );
    ctx.leaf("tls.handshake.random", rnd_r, Value::Bytes);
    ctx.leaf(
        "tls.handshake.session_id_length",
        sid_len_r,
        Value::Unsigned(u64::from(sid_len)),
    );
    if sid_len > 0 {
        ctx.leaf("tls.handshake.session_id", sid_r, Value::Bytes);
    }
    ctx.leaf(
        "tls.handshake.ciphersuite",
        suite_r,
        Value::Unsigned(u64::from(suite)),
    );
    ctx.leaf(
        "tls.handshake.comp_method",
        cm_r,
        Value::Unsigned(u64::from(cm)),
    );
    if c.remaining() >= 2 {
        extensions(c, ctx)?;
    }
    Ok(())
}

fn certificate(c: &mut Cursor, ctx: &mut Ctx) -> Result<()> {
    let (total, total_r) = c.u24()?;
    ctx.leaf(
        "tls.handshake.certificates_length",
        total_r,
        Value::Unsigned(u64::from(total)),
    );
    let mut list = c.sub((total as usize).min(c.remaining()))?;
    while list.remaining() >= 3 {
        let (len, len_r) = list.u24()?;
        let (_, cert_r) = list.take((len as usize).min(list.remaining()))?;
        ctx.leaf(
            "tls.handshake.certificate_length",
            len_r,
            Value::Unsigned(u64::from(len)),
        );
        ctx.leaf("tls.handshake.certificate", cert_r, Value::Bytes);
    }
    Ok(())
}

fn extensions(c: &mut Cursor, ctx: &mut Ctx) -> Result<()> {
    let (ext_len, ext_len_r) = c.u16()?;
    ctx.leaf(
        "tls.handshake.extensions_length",
        ext_len_r,
        Value::Unsigned(u64::from(ext_len)),
    );
    let mut ec = c.sub(usize::from(ext_len).min(c.remaining()))?;
    while ec.remaining() >= 4 {
        let start = ec.abs();
        let (ty, ty_r) = ec.u16()?;
        let (len, len_r) = ec.u16()?;
        let name = enum_name(TLS_EXTENSIONS, u64::from(ty)).unwrap_or("unknown");
        let ext = ctx.begin("tls.handshake.extension", start..start);
        ctx.leaf(
            "tls.handshake.extension.type",
            ty_r,
            Value::Unsigned(u64::from(ty)),
        );
        ctx.leaf(
            "tls.handshake.extension.len",
            len_r,
            Value::Unsigned(u64::from(len)),
        );
        let mut body = match ec.sub(usize::from(len)) {
            Ok(b) => b,
            Err(e) => {
                let text = format!("[Malformed extension: {e}]");
                ctx.leaf_text("_ws.malformed", ec.rest_range(), Value::None, &text);
                let text = format!("Extension: {name} (len={len})");
                ctx.set_text(ext, &text);
                ctx.end_at(ext, ec.abs() + ec.remaining());
                break;
            }
        };
        let mut detail = String::new();
        let depth = ctx.depth();
        let parsed: Result<()> = match ty {
            0 => server_name(&mut body, ctx, &mut detail),
            16 => alpn(&mut body, ctx, &mut detail),
            43 => supported_versions(&mut body, ctx, &mut detail),
            _ => {
                if !body.is_empty() {
                    ctx.leaf(
                        "tls.handshake.extension.data",
                        body.rest_range(),
                        Value::Bytes,
                    );
                }
                Ok(())
            }
        };
        if let Err(e) = parsed {
            ctx.restore_depth(depth);
            let text = format!("[Malformed extension: {e}]");
            ctx.leaf_text("_ws.malformed", body.rest_range(), Value::None, &text);
        }
        let text = if detail.is_empty() {
            format!("Extension: {name} (len={len})")
        } else {
            format!("Extension: {name} (len={len}) {detail}")
        };
        ctx.set_text(ext, &text);
        ctx.end_at(ext, ec.abs());
    }
    Ok(())
}

fn server_name(c: &mut Cursor, ctx: &mut Ctx, detail: &mut String) -> Result<()> {
    if c.is_empty() {
        // ServerHello echoes an empty SNI extension.
        return Ok(());
    }
    let (list_len, list_len_r) = c.u16()?;
    ctx.leaf(
        "tls.handshake.extensions_server_name_list_len",
        list_len_r,
        Value::Unsigned(u64::from(list_len)),
    );
    let mut list = c.sub(usize::from(list_len).min(c.remaining()))?;
    while list.remaining() >= 3 {
        let (ty, ty_r) = list.u8()?;
        let (len, len_r) = list.u16()?;
        let (name, name_r) = list.take(usize::from(len))?;
        ctx.leaf(
            "tls.handshake.extensions_server_name_type",
            ty_r,
            Value::Unsigned(u64::from(ty)),
        );
        ctx.leaf(
            "tls.handshake.extensions_server_name_len",
            len_r,
            Value::Unsigned(u64::from(len)),
        );
        let text = String::from_utf8_lossy(name).into_owned();
        ctx.leaf(
            "tls.handshake.extensions_server_name",
            name_r,
            Value::Str(text.clone()),
        );
        if ty == 0 {
            *detail = format!("name={text}");
        }
    }
    Ok(())
}

fn alpn(c: &mut Cursor, ctx: &mut Ctx, detail: &mut String) -> Result<()> {
    let (len, len_r) = c.u16()?;
    ctx.leaf(
        "tls.handshake.extensions_alpn_len",
        len_r,
        Value::Unsigned(u64::from(len)),
    );
    let mut list = c.sub(usize::from(len).min(c.remaining()))?;
    let mut names = Vec::new();
    while !list.is_empty() {
        let (n, n_r) = list.u8()?;
        let (proto, proto_r) = list.take(usize::from(n))?;
        ctx.leaf(
            "tls.handshake.extensions_alpn_str_len",
            n_r,
            Value::Unsigned(u64::from(n)),
        );
        let text = String::from_utf8_lossy(proto).into_owned();
        ctx.leaf(
            "tls.handshake.extensions_alpn_str",
            proto_r,
            Value::Str(text.clone()),
        );
        names.push(text);
    }
    *detail = names.join(",");
    Ok(())
}

fn supported_versions(c: &mut Cursor, ctx: &mut Ctx, detail: &mut String) -> Result<()> {
    let mut names = Vec::new();
    if c.remaining() == 2 {
        // ServerHello form: a single selected version.
        let (v, r) = c.u16()?;
        ctx.leaf(
            "tls.handshake.extensions.supported_version",
            r,
            Value::Unsigned(u64::from(v)),
        );
        names.push(version_name(v));
    } else {
        let (len, len_r) = c.u8()?;
        ctx.leaf(
            "tls.handshake.extensions.supported_versions_len",
            len_r,
            Value::Unsigned(u64::from(len)),
        );
        let mut list = c.sub(usize::from(len).min(c.remaining()))?;
        while list.remaining() >= 2 {
            let (v, r) = list.u16()?;
            ctx.leaf(
                "tls.handshake.extensions.supported_version",
                r,
                Value::Unsigned(u64::from(v)),
            );
            names.push(version_name(v));
        }
    }
    *detail = names.join(",");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_accepts_record_headers_only() {
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00, 0x10]));
        assert!(looks_like_tls(&[0x17, 0x03, 0x03, 0x00, 0x10]));
        assert!(!looks_like_tls(&[0x16, 0x02, 0x01]));
        assert!(!looks_like_tls(b"GET / HTTP/1.1"));
        assert!(!looks_like_tls(&[]));
    }
}
