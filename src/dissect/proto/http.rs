//! HTTP/1.x request and response headers (RFC 9112). Bodies are shown as
//! file data; multi-segment messages are handled once TCP reassembly exists.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::Result;
use crate::dissect::node::{Node, Value};

const METHODS: [&str; 9] = [
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

/// Cheap heuristic used by TCP for dispatch.
pub fn looks_like_http(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/1.") || METHODS.iter().any(|m| payload.starts_with(m.as_bytes()))
}

fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| from + p)
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<Node> {
    let s = ctx.source;
    let base = ctx.base;
    ctx.set_protocol("http");
    let mut node = Node::new("http", base..base + data.len(), Value::None).with_source(s);

    let Some(first_end) = find_crlf(data, 0) else {
        // No complete line: treat as continuation of a message we do not have.
        node.text = Some("Hypertext Transfer Protocol (continuation)".into());
        node.push(
            Node::new("http.file_data", base..base + data.len(), Value::Bytes).with_source(s),
        );
        ctx.set_info("Continuation");
        return Ok(node);
    };
    let first = String::from_utf8_lossy(&data[..first_end]).into_owned();
    let first_r = base..base + first_end;
    let is_response = first.starts_with("HTTP/");
    let mut parts = first.splitn(3, ' ');
    let (a, b, c) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    if is_response {
        let mut resp = Node::new("http.response", first_r.clone(), Value::None)
            .with_source(s)
            .with_text(first.clone());
        resp.push(
            Node::new(
                "http.response.version",
                first_r.clone(),
                Value::Str(a.into()),
            )
            .with_source(s),
        );
        let code = b.parse::<u64>().unwrap_or(0);
        resp.push(
            Node::new("http.response.code", first_r.clone(), Value::Unsigned(code)).with_source(s),
        );
        resp.push(
            Node::new(
                "http.response.phrase",
                first_r.clone(),
                Value::Str(c.into()),
            )
            .with_source(s),
        );
        node.push(resp);
        ctx.set_info(format!("{a} {b} {c}"));
    } else {
        let mut req = Node::new("http.request", first_r.clone(), Value::None)
            .with_source(s)
            .with_text(first.clone());
        req.push(
            Node::new("http.request.method", first_r.clone(), Value::Str(a.into())).with_source(s),
        );
        req.push(
            Node::new("http.request.uri", first_r.clone(), Value::Str(b.into())).with_source(s),
        );
        req.push(
            Node::new(
                "http.request.version",
                first_r.clone(),
                Value::Str(c.into()),
            )
            .with_source(s),
        );
        node.push(req);
        ctx.set_info(format!("{a} {b} {c}"));
    }
    node.text = Some(
        format!(
            "Hypertext Transfer Protocol ({})",
            if is_response { "response" } else { "request" }
        )
        .into(),
    );

    // Header lines until the empty line.
    let line_abbrev = if is_response {
        "http.response.line"
    } else {
        "http.request.line"
    };
    let mut pos = first_end + 2;
    let mut body_start = None;
    while let Some(end) = find_crlf(data, pos) {
        if end == pos {
            body_start = Some(pos + 2);
            break;
        }
        let line = String::from_utf8_lossy(&data[pos..end]).into_owned();
        let r = base + pos..base + end;
        node.push(Node::new(line_abbrev, r.clone(), Value::Str(line.clone())).with_source(s));
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            // Headers worth their own field; the rest are covered by the
            // line node already pushed above.
            let named = [
                ("host", "http.host"),
                ("user-agent", "http.user_agent"),
                ("content-type", "http.content_type"),
                ("server", "http.server"),
                ("connection", "http.connection"),
            ]
            .into_iter()
            .find(|(header, _)| name.eq_ignore_ascii_case(header))
            .map(|(_, abbrev)| abbrev);
            if let Some(abbrev) = named {
                node.push(Node::new(abbrev, r.clone(), Value::Str(value.into())).with_source(s));
            } else if name.eq_ignore_ascii_case("content-length") {
                if let Ok(len) = value.parse::<u64>() {
                    node.push(
                        Node::new("http.content_length", r, Value::Unsigned(len)).with_source(s),
                    );
                }
            }
        }
        pos = end + 2;
    }
    if let Some(b) = body_start {
        if b < data.len() {
            node.push(
                Node::new("http.file_data", base + b..base + data.len(), Value::Bytes)
                    .with_source(s),
            );
        }
    }
    Ok(node)
}
