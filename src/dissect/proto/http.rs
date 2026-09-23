//! HTTP/1.x request and response headers (RFC 9112). Bodies are shown as
//! file data; multi-segment messages are handled once TCP reassembly exists.

use crate::dissect::ctx::Ctx;
use crate::dissect::cursor::Result;
use crate::dissect::node::Value;

const METHODS: [&str; 9] = [
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

/// Headers that get a field of their own; the rest are covered by the line.
const NAMED: [(&str, &str); 5] = [
    ("host", "http.host"),
    ("user-agent", "http.user_agent"),
    ("content-type", "http.content_type"),
    ("server", "http.server"),
    ("connection", "http.connection"),
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

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let base = ctx.base;
    ctx.set_protocol("http");
    let http = ctx.begin("http", base..base + data.len());

    let Some(first_end) = find_crlf(data, 0) else {
        // No complete line: a continuation of a message we do not have.
        ctx.set_text(http, "Hypertext Transfer Protocol (continuation)");
        ctx.leaf("http.file_data", base..base + data.len(), Value::Bytes);
        ctx.set_info("Continuation");
        ctx.end();
        return Ok(());
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
        ctx.begin_text("http.response", first_r.clone(), &first);
        ctx.leaf(
            "http.response.version",
            first_r.clone(),
            Value::Str(a.into()),
        );
        ctx.leaf(
            "http.response.code",
            first_r.clone(),
            Value::Unsigned(b.parse::<u64>().unwrap_or(0)),
        );
        ctx.leaf(
            "http.response.phrase",
            first_r.clone(),
            Value::Str(c.into()),
        );
        ctx.end();
    } else {
        ctx.begin_text("http.request", first_r.clone(), &first);
        ctx.leaf("http.request.method", first_r.clone(), Value::Str(a.into()));
        ctx.leaf("http.request.uri", first_r.clone(), Value::Str(b.into()));
        ctx.leaf("http.request.version", first_r, Value::Str(c.into()));
        ctx.end();
    }
    ctx.set_info(format!("{a} {b} {c}"));
    let text = format!(
        "Hypertext Transfer Protocol ({})",
        if is_response { "response" } else { "request" }
    );
    ctx.set_text(http, &text);

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
        ctx.leaf(line_abbrev, r.clone(), Value::Str(line.clone()));
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            let named = NAMED
                .iter()
                .find(|(header, _)| name.eq_ignore_ascii_case(header))
                .map(|(_, abbrev)| *abbrev);
            if let Some(abbrev) = named {
                ctx.leaf(abbrev, r, Value::Str(value.into()));
            } else if name.eq_ignore_ascii_case("content-length") {
                if let Ok(len) = value.parse::<u64>() {
                    ctx.leaf("http.content_length", r, Value::Unsigned(len));
                }
            }
        }
        pos = end + 2;
    }
    if let Some(b) = body_start {
        if b < data.len() {
            ctx.leaf("http.file_data", base + b..base + data.len(), Value::Bytes);
        }
    }
    ctx.end();
    Ok(())
}
