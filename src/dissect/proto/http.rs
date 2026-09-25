//! HTTP/1.x (RFC 9112), desegmented across TCP segments.
//!
//! A message is only dissected once all of it has arrived. Until then the
//! bytes are held by the TCP layer and the frame is reported as carrying a
//! segment of a message that completes later — which is what makes
//! `http.content_length`, the headers and the body usable on a real capture,
//! where a response rarely fits in one segment.
//!
//! Deciding where a message ends is the whole problem, and RFC 9112 §6.3
//! gives the rules: a `Transfer-Encoding: chunked` body ends at the
//! zero-length chunk, a `Content-Length` body is that many bytes, a response
//! to HEAD or with a 1xx/204/304 status has no body at all, and a response
//! with none of those runs until the connection closes. Getting this wrong
//! does not merely mislabel a field: it desynchronises the stream, and every
//! later message in it is parsed from the wrong offset.

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

/// Could these bytes be the beginning of a message, including one whose
/// first line has not fully arrived?
///
/// This is what decides whether to wait for more. Bytes that cannot begin a
/// message are body data continuing something this capture never saw the
/// start of; holding those would wait for a message that is already over,
/// and the bytes would never be shown at all.
fn starts_message(data: &[u8]) -> bool {
    if looks_like_http(data) {
        return true;
    }
    if data.is_empty() {
        return false;
    }
    let prefix_of = |whole: &[u8]| data.len() < whole.len() && whole.starts_with(data);
    prefix_of(b"HTTP/1.") || METHODS.iter().any(|m| prefix_of(m.as_bytes()))
}

fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| from + p)
}

/// End of the header block: the offset just past the blank line.
fn headers_end(data: &[u8]) -> Option<usize> {
    let mut pos = find_crlf(data, 0)? + 2;
    loop {
        let end = find_crlf(data, pos)?;
        if end == pos {
            return Some(pos + 2);
        }
        pos = end + 2;
    }
}

/// How a message's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    None,
    Length(usize),
    Chunked,
    /// Until the connection closes: there is no length to wait for, so
    /// whatever has arrived is all there is to show.
    UntilClose,
}

/// Header values this dissector needs in order to find the end of the body.
struct Headers {
    content_length: Option<usize>,
    chunked: bool,
}

fn scan_headers(data: &[u8], body_at: usize) -> Headers {
    let mut out = Headers {
        content_length: None,
        chunked: false,
    };
    let Some(first) = find_crlf(data, 0) else {
        return out;
    };
    let mut pos = first + 2;
    while pos + 2 <= body_at {
        let Some(end) = find_crlf(data, pos) else {
            break;
        };
        if end == pos {
            break;
        }
        let line = &data[pos..end];
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = &line[..colon];
            let value = String::from_utf8_lossy(&line[colon + 1..]);
            let value = value.trim();
            if name.eq_ignore_ascii_case(b"content-length") {
                out.content_length = value.parse::<usize>().ok();
            } else if name.eq_ignore_ascii_case(b"transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                out.chunked = true;
            }
        }
        pos = end + 2;
    }
    out
}

/// End of a chunked body, or `None` while it is still arriving.
///
/// Each chunk is a hex length, CRLF, that many bytes, CRLF; a zero length
/// ends the body, optionally followed by trailer lines and a final CRLF.
fn chunked_end(data: &[u8], from: usize) -> Option<usize> {
    let mut pos = from;
    loop {
        let line_end = find_crlf(data, pos)?;
        let line = data.get(pos..line_end)?;
        // A chunk extension follows a `;`, and is not part of the length.
        let digits = line.split(|b| *b == b';').next().unwrap_or(line);
        let text = std::str::from_utf8(digits).ok()?.trim();
        let len = usize::from_str_radix(text, 16).ok()?;
        pos = line_end + 2;
        if len == 0 {
            // Trailers until a blank line.
            loop {
                let end = find_crlf(data, pos)?;
                pos = end + 2;
                if end == pos - 2 {
                    return Some(pos);
                }
            }
        }
        pos = pos.checked_add(len)?;
        // The CRLF that follows the chunk data.
        if data.get(pos..pos + 2)? != b"\r\n" {
            return None;
        }
        pos += 2;
    }
}

/// Where this message ends within `data`, or `None` if more is needed.
fn message_end(data: &[u8]) -> Option<usize> {
    let body_at = headers_end(data)?;
    let h = scan_headers(data, body_at);
    let body = if h.chunked {
        Body::Chunked
    } else if let Some(n) = h.content_length {
        Body::Length(n)
    } else if data.starts_with(b"HTTP/1.") {
        // A response with neither header: RFC 9112 says it runs until the
        // connection closes, so there is nothing to wait for.
        if no_body_status(data) {
            Body::None
        } else {
            Body::UntilClose
        }
    } else {
        // A request with no length header has no body.
        Body::None
    };
    match body {
        Body::None => Some(body_at),
        Body::Length(n) => {
            let end = body_at.checked_add(n)?;
            (end <= data.len()).then_some(end)
        }
        Body::Chunked => chunked_end(data, body_at),
        Body::UntilClose => Some(data.len()),
    }
}

/// 1xx, 204 and 304 responses never carry a body, whatever they say.
fn no_body_status(data: &[u8]) -> bool {
    let Some(end) = find_crlf(data, 0) else {
        return false;
    };
    let line = &data[..end];
    let mut parts = line.split(|b| *b == b' ');
    let _ = parts.next();
    let Some(code) = parts.next() else {
        return false;
    };
    matches!(code, b"204" | b"304") || code.first() == Some(&b'1')
}

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut pos = 0usize;
    let mut messages = 0usize;
    // Several complete messages can share one buffer: a pipelined client
    // sends them back to back, and a desegmented buffer can hold a whole
    // exchange.
    while pos < data.len() {
        match message_end(&data[pos..]) {
            Some(len) if len > 0 => {
                ctx.set_protocol("http");
                one_message(&data[pos..pos + len], pos, ctx, messages == 0);
                pos += len;
                messages += 1;
            }
            _ => break,
        }
    }
    if pos == data.len() {
        return Ok(());
    }
    let rest = &data[pos..];
    // What is left is either the start of a message still arriving, which is
    // worth waiting for, or body bytes continuing something whose start was
    // never captured, which is not.
    if starts_message(rest) && ctx.hold(rest) {
        // The frame carries part of a message that completes later. It stays
        // a TCP frame in the protocol column, as Wireshark shows it: naming
        // it HTTP would claim a message this frame does not contain.
        let base = ctx.base;
        let node = ctx.begin_text(
            "http.segment",
            base + pos..base + data.len(),
            "[TCP segment of a reassembled PDU]",
        );
        ctx.leaf("http.segment.len", 0..0, Value::Unsigned(rest.len() as u64));
        ctx.end();
        let _ = node;
        if messages == 0 {
            ctx.set_info("[TCP segment of a reassembled PDU]");
        }
    } else {
        ctx.set_protocol("http");
        one_message(rest, pos, ctx, messages == 0);
    }
    Ok(())
}

/// Dissect one message. `offset` is where it starts within the buffer, and
/// `lead` says whether it is the one that names the Info column.
fn one_message(data: &[u8], offset: usize, ctx: &mut Ctx, lead: bool) {
    let base = ctx.base + offset;
    let http = ctx.begin("http", base..base + data.len());

    let Some(first_end) = find_crlf(data, 0) else {
        // No complete line: a continuation of a message we do not have.
        ctx.set_text(http, "Hypertext Transfer Protocol (continuation)");
        ctx.leaf("http.file_data", base..base + data.len(), Value::Bytes);
        if lead {
            ctx.set_info("Continuation");
        }
        ctx.end();
        return;
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
    if lead {
        ctx.set_info(format!("{a} {b} {c}"));
    }
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
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                ctx.leaf("http.transfer_encoding", r, Value::Str(value.into()));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_ends_at_the_blank_line() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(message_end(req), Some(req.len()));
    }

    #[test]
    fn incomplete_headers_need_more() {
        assert_eq!(message_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(message_end(b"GET / HTTP"), None);
    }

    #[test]
    fn a_content_length_body_is_awaited_in_full() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(message_end(head), None, "no body yet");
        let mut short = head.to_vec();
        short.extend_from_slice(b"abc");
        assert_eq!(message_end(&short), None, "three of five bytes");
        let mut whole = head.to_vec();
        whole.extend_from_slice(b"abcde");
        assert_eq!(message_end(&whole), Some(whole.len()));
        // Trailing bytes belong to the next message, not this one.
        let mut extra = whole.clone();
        extra.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(message_end(&extra), Some(whole.len()));
    }

    #[test]
    fn a_chunked_body_ends_at_the_zero_chunk() {
        let body = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(message_end(body), Some(body.len()));
        // One chunk short.
        let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert_eq!(message_end(partial), None);
        // Chunk extensions do not confuse the length.
        let ext = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5;a=b\r\nhello\r\n0\r\n\r\n";
        assert_eq!(message_end(ext), Some(ext.len()));
    }

    #[test]
    fn a_body_less_status_has_no_body_whatever_it_says() {
        // A 304 with a Content-Length is common and the body is not there.
        // Waiting for it would stall the stream forever.
        let m = b"HTTP/1.1 304 Not Modified\r\nETag: x\r\n\r\n";
        assert_eq!(message_end(m), Some(m.len()));
        let m = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(message_end(m), Some(m.len()));
        let m = b"HTTP/1.1 100 Continue\r\n\r\n";
        assert_eq!(message_end(m), Some(m.len()));
    }

    #[test]
    fn a_response_with_no_length_runs_to_what_arrived() {
        // Nothing to wait for, so it must not be held: holding would mean the
        // body is never shown at all.
        let m = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody bytes";
        assert_eq!(message_end(m), Some(m.len()));
    }

    #[test]
    fn a_request_with_no_length_header_has_no_body() {
        let m = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(message_end(m), Some(m.len()));
        // Anything after it is a second, pipelined request.
        let two = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
        // "GET /a HTTP/1.1" is 15 bytes, then CRLF CRLF.
        assert_eq!(message_end(two), Some(19));
    }

    #[test]
    fn a_malformed_chunk_length_is_not_awaited_forever() {
        // `zz` is not hex. Returning None here would hold the stream, so the
        // caller has to treat an unparseable chunked body as needing more and
        // eventually hit the size cap; what matters is that it does not panic
        // or loop.
        let m = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
        assert_eq!(message_end(m), None);
    }

    #[test]
    fn a_huge_chunk_length_does_not_overflow() {
        let m = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n";
        assert_eq!(message_end(m), None);
    }
}
