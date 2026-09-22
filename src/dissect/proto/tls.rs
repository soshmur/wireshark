//! TLS record layer (RFC 8446 §5) with ClientHello / ServerHello parsing:
//! version, random, session id, cipher suites, and the SNI, ALPN and
//! supported_versions extensions. No decryption.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::{Cursor, Result};
use crate::dissect::node::{Node, Value};
use crate::dissect::registry::{enum_name, TLS_CONTENT_TYPES, TLS_HANDSHAKE_TYPES, TLS_VERSIONS};

/// Cheap heuristic used by TCP for dispatch: a plausible record header.
pub fn looks_like_tls(payload: &[u8]) -> bool {
    matches!(payload, [ct, 3, minor, ..] if (20..=24).contains(ct) && *minor <= 4)
}

fn version_name(v: u16) -> String {
    enum_name(TLS_VERSIONS, u64::from(v))
        .map(str::to_string)
        .unwrap_or_else(|| format!("0x{v:04x}"))
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let s = c.source();
    let start = c.abs();
    ctx.set_protocol("tls");
    let mut node = Node::new("tls", start..start + data.len(), Value::None)
        .with_source(s)
        .with_text("Transport Layer Security");
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
        let mut rec = Node::new("tls.record", rec_start..rec_start, Value::None).with_source(s);
        rec.push(
            Node::new(
                "tls.record.content_type",
                ct_r,
                Value::Unsigned(u64::from(ct)),
            )
            .with_source(s),
        );
        rec.push(
            Node::new("tls.record.version", ver_r, Value::Unsigned(u64::from(ver))).with_source(s),
        );
        rec.push(
            Node::new("tls.record.length", len_r, Value::Unsigned(u64::from(len))).with_source(s),
        );
        let avail = c.remaining();
        let body_len = usize::from(len);
        if body_len > avail {
            // Record continues in the next segment (reassembly is Phase 4).
            rec.push(
                Node::new("tls.continuation_data", c.rest_range(), Value::Bytes).with_source(s),
            );
            rec.text = Some(
                format!(
                    "{}: {ct_name} Protocol (fragment, {avail} of {body_len} bytes)",
                    version_name(ver)
                )
                .into(),
            );
            rec.range = rec_start..c.abs() + avail;
            c.skip(avail)?;
            node.push(rec);
            infos.push(format!("{ct_name} [fragment]"));
            records += 1;
            break;
        }
        let mut body = c.sub(body_len)?;
        let summary = match ct {
            20 => {
                rec.push(
                    Node::new("tls.change_cipher_spec", body.rest_range(), Value::None)
                        .with_source(s),
                );
                "Change Cipher Spec".to_string()
            }
            21 => match alert(&mut body) {
                Ok((n, text)) => {
                    rec.push(n);
                    text
                }
                Err(_) => {
                    rec.push(
                        Node::new("tls.app_data", body.rest_range(), Value::Bytes).with_source(s),
                    );
                    "Encrypted Alert".into()
                }
            },
            22 => match handshake(&mut body) {
                Ok((nodes, text)) => {
                    for n in nodes {
                        rec.push(n);
                    }
                    text
                }
                Err(_) => {
                    rec.push(
                        Node::new("tls.handshake.encrypted", body.rest_range(), Value::Bytes)
                            .with_source(s),
                    );
                    "Encrypted Handshake Message".into()
                }
            },
            23 => {
                rec.push(Node::new("tls.app_data", body.rest_range(), Value::Bytes).with_source(s));
                "Application Data".into()
            }
            _ => {
                rec.push(Node::new("tls.app_data", body.rest_range(), Value::Bytes).with_source(s));
                format!("Unknown content type {ct}")
            }
        };
        rec.text = Some(
            format!(
                "{} Record Layer: {ct_name} Protocol: {summary}",
                version_name(ver)
            )
            .into(),
        );
        rec.range = rec_start..c.abs();
        node.push(rec);
        infos.push(summary);
        records += 1;
        if records >= 64 {
            break;
        }
    }
    if !c.is_empty() {
        node.push(Node::new("tls.continuation_data", c.rest_range(), Value::Bytes).with_source(s));
        if records == 0 {
            infos.push("Continuation Data".into());
        }
    }
    ctx.set_info(infos.join(", "));
    Ok(node)
}

fn alert(c: &mut Cursor) -> Result<(Node, String)> {
    let s = c.source();
    let start = c.abs();
    let (level, level_r) = c.u8()?;
    let (desc, desc_r) = c.u8()?;
    let mut n = Node::new("tls.alert_message", start..c.abs(), Value::None).with_source(s);
    n.push(
        Node::new(
            "tls.alert_message.level",
            level_r,
            Value::Unsigned(u64::from(level)),
        )
        .with_source(s),
    );
    n.push(
        Node::new(
            "tls.alert_message.desc",
            desc_r,
            Value::Unsigned(u64::from(desc)),
        )
        .with_source(s),
    );
    let text = format!(
        "Alert ({})",
        enum_name(crate::dissect::registry::TLS_ALERT_DESCS, u64::from(desc)).unwrap_or("Unknown")
    );
    n.text = Some(text.clone().into());
    Ok((n, text))
}

/// One or more handshake messages within a record.
fn handshake(c: &mut Cursor) -> Result<(Vec<Node>, String)> {
    let s = c.source();
    let mut out = Vec::new();
    let mut texts = Vec::new();
    while c.remaining() >= 4 {
        let start = c.abs();
        let (ty, ty_r) = c.u8()?;
        let (len, len_r) = c.u24()?;
        // An unknown type after a ChangeCipherSpec is ciphertext, not a message;
        // without session state, an unknown type is the best available signal.
        let Some(name) = enum_name(TLS_HANDSHAKE_TYPES, u64::from(ty)) else {
            if out.is_empty() {
                return Err(crate::dissect::cursor::DissectError::Invalid {
                    at: start,
                    what: "handshake type (encrypted?)",
                });
            }
            break;
        };
        let mut hs = Node::new("tls.handshake", start..start, Value::None).with_source(s);
        hs.push(
            Node::new("tls.handshake.type", ty_r, Value::Unsigned(u64::from(ty))).with_source(s),
        );
        hs.push(
            Node::new(
                "tls.handshake.length",
                len_r,
                Value::Unsigned(u64::from(len)),
            )
            .with_source(s),
        );
        let body_len = (len as usize).min(c.remaining());
        let mut body = c.sub(body_len)?;
        let result = match ty {
            1 => client_hello(&mut body, &mut hs),
            2 => server_hello(&mut body, &mut hs),
            11 => certificate(&mut body, &mut hs),
            _ => {
                if !body.is_empty() {
                    hs.push(
                        Node::new("tls.handshake.encrypted", body.rest_range(), Value::Bytes)
                            .with_source(s),
                    );
                }
                Ok(())
            }
        };
        if let Err(e) = result {
            hs.push(
                Node::new("_ws.malformed", body.rest_range(), Value::None)
                    .with_source(s)
                    .with_text(format!("[Malformed Packet: tls] {e}")),
            );
        }
        hs.range = start..c.abs();
        hs.text = Some(format!("Handshake Protocol: {name}").into());
        out.push(hs);
        texts.push(name.to_string());
        if (len as usize) > body_len {
            break;
        }
    }
    if out.is_empty() {
        return Err(crate::dissect::cursor::DissectError::Truncated {
            at: c.abs(),
            need: 4,
            have: c.remaining(),
        });
    }
    Ok((out, texts.join(", ")))
}

fn client_hello(c: &mut Cursor, hs: &mut Node) -> Result<()> {
    let s = c.source();
    let (ver, ver_r) = c.u16()?;
    let (_, rnd_r) = c.take(32)?;
    let (sid_len, sid_len_r) = c.u8()?;
    let (_, sid_r) = c.take(usize::from(sid_len))?;
    hs.push(
        Node::new(
            "tls.handshake.version",
            ver_r,
            Value::Unsigned(u64::from(ver)),
        )
        .with_source(s),
    );
    hs.push(Node::new("tls.handshake.random", rnd_r, Value::Bytes).with_source(s));
    hs.push(
        Node::new(
            "tls.handshake.session_id_length",
            sid_len_r,
            Value::Unsigned(u64::from(sid_len)),
        )
        .with_source(s),
    );
    if sid_len > 0 {
        hs.push(Node::new("tls.handshake.session_id", sid_r, Value::Bytes).with_source(s));
    }
    let (cs_len, cs_len_r) = c.u16()?;
    hs.push(
        Node::new(
            "tls.handshake.cipher_suites_length",
            cs_len_r,
            Value::Unsigned(u64::from(cs_len)),
        )
        .with_source(s),
    );
    let mut cs = c.sub(usize::from(cs_len))?;
    let mut suites = Node::new("tls.handshake.ciphersuites", cs.rest_range(), Value::None)
        .with_source(s)
        .with_text(format!("Cipher Suites ({} suites)", cs_len / 2));
    while cs.remaining() >= 2 {
        let (suite, r) = cs.u16()?;
        suites.push(
            Node::new(
                "tls.handshake.ciphersuite",
                r,
                Value::Unsigned(u64::from(suite)),
            )
            .with_source(s),
        );
    }
    hs.push(suites);
    let (cm_len, cm_len_r) = c.u8()?;
    hs.push(
        Node::new(
            "tls.handshake.comp_methods_length",
            cm_len_r,
            Value::Unsigned(u64::from(cm_len)),
        )
        .with_source(s),
    );
    let mut cm = c.sub(usize::from(cm_len))?;
    let mut methods =
        Node::new("tls.handshake.comp_methods", cm.rest_range(), Value::None).with_source(s);
    while !cm.is_empty() {
        let (m, r) = cm.u8()?;
        methods.push(
            Node::new(
                "tls.handshake.comp_method",
                r,
                Value::Unsigned(u64::from(m)),
            )
            .with_source(s),
        );
    }
    hs.push(methods);
    if c.remaining() >= 2 {
        extensions(c, hs)?;
    }
    Ok(())
}

fn server_hello(c: &mut Cursor, hs: &mut Node) -> Result<()> {
    let s = c.source();
    let (ver, ver_r) = c.u16()?;
    let (_, rnd_r) = c.take(32)?;
    let (sid_len, sid_len_r) = c.u8()?;
    let (_, sid_r) = c.take(usize::from(sid_len))?;
    let (suite, suite_r) = c.u16()?;
    let (cm, cm_r) = c.u8()?;
    hs.push(
        Node::new(
            "tls.handshake.version",
            ver_r,
            Value::Unsigned(u64::from(ver)),
        )
        .with_source(s),
    );
    hs.push(Node::new("tls.handshake.random", rnd_r, Value::Bytes).with_source(s));
    hs.push(
        Node::new(
            "tls.handshake.session_id_length",
            sid_len_r,
            Value::Unsigned(u64::from(sid_len)),
        )
        .with_source(s),
    );
    if sid_len > 0 {
        hs.push(Node::new("tls.handshake.session_id", sid_r, Value::Bytes).with_source(s));
    }
    hs.push(
        Node::new(
            "tls.handshake.ciphersuite",
            suite_r,
            Value::Unsigned(u64::from(suite)),
        )
        .with_source(s),
    );
    hs.push(
        Node::new(
            "tls.handshake.comp_method",
            cm_r,
            Value::Unsigned(u64::from(cm)),
        )
        .with_source(s),
    );
    if c.remaining() >= 2 {
        extensions(c, hs)?;
    }
    Ok(())
}

fn certificate(c: &mut Cursor, hs: &mut Node) -> Result<()> {
    let s = c.source();
    let (total, total_r) = c.u24()?;
    hs.push(
        Node::new(
            "tls.handshake.certificates_length",
            total_r,
            Value::Unsigned(u64::from(total)),
        )
        .with_source(s),
    );
    let mut list = c.sub((total as usize).min(c.remaining()))?;
    while list.remaining() >= 3 {
        let (len, len_r) = list.u24()?;
        let (_, cert_r) = list.take((len as usize).min(list.remaining()))?;
        hs.push(
            Node::new(
                "tls.handshake.certificate_length",
                len_r,
                Value::Unsigned(u64::from(len)),
            )
            .with_source(s),
        );
        hs.push(Node::new("tls.handshake.certificate", cert_r, Value::Bytes).with_source(s));
    }
    Ok(())
}

fn extensions(c: &mut Cursor, hs: &mut Node) -> Result<()> {
    let s = c.source();
    let (ext_len, ext_len_r) = c.u16()?;
    hs.push(
        Node::new(
            "tls.handshake.extensions_length",
            ext_len_r,
            Value::Unsigned(u64::from(ext_len)),
        )
        .with_source(s),
    );
    let mut ec = c.sub(usize::from(ext_len).min(c.remaining()))?;
    while ec.remaining() >= 4 {
        let start = ec.abs();
        let (ty, ty_r) = ec.u16()?;
        let (len, len_r) = ec.u16()?;
        let name =
            enum_name(crate::dissect::registry::TLS_EXTENSIONS, u64::from(ty)).unwrap_or("unknown");
        let mut ext =
            Node::new("tls.handshake.extension", start..start, Value::None).with_source(s);
        ext.push(
            Node::new(
                "tls.handshake.extension.type",
                ty_r,
                Value::Unsigned(u64::from(ty)),
            )
            .with_source(s),
        );
        ext.push(
            Node::new(
                "tls.handshake.extension.len",
                len_r,
                Value::Unsigned(u64::from(len)),
            )
            .with_source(s),
        );
        let mut body = match ec.sub(usize::from(len)) {
            Ok(b) => b,
            Err(e) => {
                ext.push(
                    Node::new("_ws.malformed", ec.rest_range(), Value::None)
                        .with_source(s)
                        .with_text(format!("[Malformed extension: {e}]")),
                );
                ext.range = start..ec.abs() + ec.remaining();
                ext.text = Some(format!("Extension: {name} (len={len})").into());
                hs.push(ext);
                break;
            }
        };
        let mut detail = String::new();
        let parsed: Result<()> = match ty {
            0 => server_name(&mut body, &mut ext, &mut detail),
            16 => alpn(&mut body, &mut ext, &mut detail),
            43 => supported_versions(&mut body, &mut ext, &mut detail),
            _ => {
                if !body.is_empty() {
                    ext.push(
                        Node::new(
                            "tls.handshake.extension.data",
                            body.rest_range(),
                            Value::Bytes,
                        )
                        .with_source(s),
                    );
                }
                Ok(())
            }
        };
        if let Err(e) = parsed {
            ext.push(
                Node::new("_ws.malformed", body.rest_range(), Value::None)
                    .with_source(s)
                    .with_text(format!("[Malformed extension: {e}]")),
            );
        }
        ext.range = start..ec.abs();
        ext.text = Some(
            if detail.is_empty() {
                format!("Extension: {name} (len={len})")
            } else {
                format!("Extension: {name} (len={len}) {detail}")
            }
            .into(),
        );
        hs.push(ext);
    }
    Ok(())
}

fn server_name(c: &mut Cursor, ext: &mut Node, detail: &mut String) -> Result<()> {
    let s = c.source();
    if c.is_empty() {
        // ServerHello echoes an empty SNI extension.
        return Ok(());
    }
    let (list_len, list_len_r) = c.u16()?;
    ext.push(
        Node::new(
            "tls.handshake.extensions_server_name_list_len",
            list_len_r,
            Value::Unsigned(u64::from(list_len)),
        )
        .with_source(s),
    );
    let mut list = c.sub(usize::from(list_len).min(c.remaining()))?;
    while list.remaining() >= 3 {
        let (ty, ty_r) = list.u8()?;
        let (len, len_r) = list.u16()?;
        let (name, name_r) = list.take(usize::from(len))?;
        ext.push(
            Node::new(
                "tls.handshake.extensions_server_name_type",
                ty_r,
                Value::Unsigned(u64::from(ty)),
            )
            .with_source(s),
        );
        ext.push(
            Node::new(
                "tls.handshake.extensions_server_name_len",
                len_r,
                Value::Unsigned(u64::from(len)),
            )
            .with_source(s),
        );
        let text = String::from_utf8_lossy(name).into_owned();
        ext.push(
            Node::new(
                "tls.handshake.extensions_server_name",
                name_r,
                Value::Str(text.clone()),
            )
            .with_source(s),
        );
        if ty == 0 {
            *detail = format!("name={text}");
        }
    }
    Ok(())
}

fn alpn(c: &mut Cursor, ext: &mut Node, detail: &mut String) -> Result<()> {
    let s = c.source();
    let (len, len_r) = c.u16()?;
    ext.push(
        Node::new(
            "tls.handshake.extensions_alpn_len",
            len_r,
            Value::Unsigned(u64::from(len)),
        )
        .with_source(s),
    );
    let mut list = c.sub(usize::from(len).min(c.remaining()))?;
    let mut names = Vec::new();
    while !list.is_empty() {
        let (n, n_r) = list.u8()?;
        let (proto, proto_r) = list.take(usize::from(n))?;
        ext.push(
            Node::new(
                "tls.handshake.extensions_alpn_str_len",
                n_r,
                Value::Unsigned(u64::from(n)),
            )
            .with_source(s),
        );
        let text = String::from_utf8_lossy(proto).into_owned();
        ext.push(
            Node::new(
                "tls.handshake.extensions_alpn_str",
                proto_r,
                Value::Str(text.clone()),
            )
            .with_source(s),
        );
        names.push(text);
    }
    *detail = names.join(",");
    Ok(())
}

fn supported_versions(c: &mut Cursor, ext: &mut Node, detail: &mut String) -> Result<()> {
    let s = c.source();
    let mut names = Vec::new();
    if c.remaining() == 2 {
        // ServerHello form: a single selected version.
        let (v, r) = c.u16()?;
        ext.push(
            Node::new(
                "tls.handshake.extensions.supported_version",
                r,
                Value::Unsigned(u64::from(v)),
            )
            .with_source(s),
        );
        names.push(version_name(v));
    } else {
        let (len, len_r) = c.u8()?;
        ext.push(
            Node::new(
                "tls.handshake.extensions.supported_versions_len",
                len_r,
                Value::Unsigned(u64::from(len)),
            )
            .with_source(s),
        );
        let mut list = c.sub(usize::from(len).min(c.remaining()))?;
        while list.remaining() >= 2 {
            let (v, r) = list.u16()?;
            ext.push(
                Node::new(
                    "tls.handshake.extensions.supported_version",
                    r,
                    Value::Unsigned(u64::from(v)),
                )
                .with_source(s),
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
