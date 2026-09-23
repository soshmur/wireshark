//! Evaluating a compiled filter over a stored frame.
//!
//! This never re-dissects: it walks the flat tree the frame already carries.
//! Multi-occurrence semantics follow Wireshark — a comparison is true when
//! ANY occurrence of the field in the frame satisfies it. So
//! `tcp.port == 443` is true for a segment from 50000 to 443, and
//! `ip.src != 10.0.0.1` is true when any `ip.src` in the frame differs,
//! which for a frame carrying one IPv4 header is the intuitive reading, and
//! for a frame carrying two (an ICMP error quoting the offending header) is
//! the surprising one. `!(ip.src == 10.0.0.1)` is the way to say "no
//! occurrence matches".

use crate::dissect::node::{NodeRef, Value};
use crate::dissect::registry::Kind;
use crate::dissect::Frame;

use super::ast::CmpOp;
use super::types::{Operand, Target, Test};

/// Does `frame` match?
pub fn matches(test: &Test, frame: &Frame) -> bool {
    match test {
        Test::And(parts) => parts.iter().all(|t| matches(t, frame)),
        Test::Or(parts) => parts.iter().any(|t| matches(t, frame)),
        Test::Not(a) => !matches(a, frame),
        Test::Present(target) => frame
            .tree
            .iter()
            .any(|n| target.ids.contains(&n.field_id())),
        Test::Compare { target, op, value } => any_occurrence(target, frame, |node, bytes| {
            compare(node, bytes, target, *op, value)
        }),
        Test::In { target, values } => any_occurrence(target, frame, |node, bytes| {
            values
                .iter()
                .any(|v| compare(node, bytes, target, CmpOp::Eq, v))
        }),
        Test::Regex {
            target,
            text,
            bytes: re,
        } => any_occurrence(target, frame, |node, bytes| {
            if target.slice.is_some() {
                return slice_bytes(node, bytes, target).is_some_and(|b| re.is_match(b));
            }
            match node.value() {
                Value::Str(s) => text.is_match(&s),
                Value::Bytes | Value::None => {
                    search_bytes(node, bytes, target).is_some_and(|b| re.is_match(b))
                }
                other => text.is_match(&other.to_string()),
            }
        }),
    }
}

/// Run `f` over each occurrence of the target's fields, stopping at the
/// first that matches.
fn any_occurrence(
    target: &Target,
    frame: &Frame,
    mut f: impl FnMut(&NodeRef<'_>, &[u8]) -> bool,
) -> bool {
    for node in frame.tree.iter() {
        if !target.ids.contains(&node.field_id()) {
            continue;
        }
        let Some(bytes) = frame.source(node.source()) else {
            continue;
        };
        if f(&node, bytes) {
            return true;
        }
    }
    false
}

/// The bytes a node covers in its data source.
fn field_bytes<'a>(node: &NodeRef<'_>, source: &'a [u8]) -> Option<&'a [u8]> {
    source.get(node.range())
}

/// The bytes `contains` and `matches` search for a target. A protocol layer
/// node covers only its own header (so that selecting it highlights the
/// header), but a filter asking whether TCP contains some text means the
/// segment and everything it encapsulates, so searching runs from the
/// layer's start to the end of its data source. Groups and ordinary fields
/// search exactly their own bytes.
fn search_bytes<'a>(node: &NodeRef<'_>, source: &'a [u8], target: &Target) -> Option<&'a [u8]> {
    if matches!(target.kind, Kind::Protocol) && target.slice.is_none() {
        return source.get(node.range().start..);
    }
    field_bytes(node, source)
}

/// The bytes a slice selects from a node's own bytes.
fn slice_bytes<'a>(node: &NodeRef<'_>, source: &'a [u8], target: &Target) -> Option<&'a [u8]> {
    let slice = target.slice?;
    let whole = field_bytes(node, source)?;
    let start = slice.offset.min(whole.len());
    let end = match slice.len {
        Some(n) => start.saturating_add(n).min(whole.len()),
        None => whole.len(),
    };
    // A slice that runs past the field's bytes does not match, rather than
    // silently comparing a shorter run.
    let wanted = match slice.len {
        Some(n) => n,
        None => end - start,
    };
    let got = whole.get(start..end)?;
    (got.len() == wanted).then_some(got)
}

fn compare(node: &NodeRef<'_>, source: &[u8], target: &Target, op: CmpOp, value: &Operand) -> bool {
    if target.slice.is_some() {
        let Some(got) = slice_bytes(node, source, target) else {
            return false;
        };
        let Operand::Bytes(want) = value else {
            return false;
        };
        return bytes_op(got, want, op);
    }
    match (value, node.value()) {
        (Operand::Unsigned(want), Value::Unsigned(got)) => ord_op(got.cmp(want), op),
        (Operand::Signed(want), Value::Signed(got)) => ord_op(got.cmp(want), op),
        // An unsigned field compared with a signed literal cannot match; the
        // type checker rejects that, so this is only reached for `Signed`
        // fields carrying a non-negative value.
        (Operand::Signed(want), Value::Unsigned(got)) => {
            i64::try_from(got).is_ok_and(|g| ord_op(g.cmp(want), op))
        }
        (Operand::Bool(want), Value::Bool(got)) => ord_op(got.cmp(want), op),
        (Operand::Str(want), Value::Str(got)) => match op {
            CmpOp::Contains => got.contains(want.as_str()),
            _ => ord_op(got.as_str().cmp(want.as_str()), op),
        },
        (Operand::Ipv4(want), Value::Ipv4(got)) => ord_op(got.cmp(want), op),
        (Operand::Ipv4Net(net, mask), Value::Ipv4(got)) => {
            let mut masked = got;
            for i in 0..4 {
                masked[i] &= mask[i];
            }
            let eq = masked == *net;
            match op {
                CmpOp::Eq => eq,
                CmpOp::Ne => !eq,
                _ => false,
            }
        }
        (Operand::Ipv6(want), Value::Ipv6(got)) => ord_op(got.cmp(want), op),
        (Operand::Ipv6Net(net, mask), Value::Ipv6(got)) => {
            let mut masked = got;
            for i in 0..16 {
                masked[i] &= mask[i];
            }
            let eq = masked == *net;
            match op {
                CmpOp::Eq => eq,
                CmpOp::Ne => !eq,
                _ => false,
            }
        }
        (Operand::Bytes(want), Value::Mac(got)) => bytes_op(&got, want, op),
        (Operand::Bytes(want), _) => {
            let got = if op == CmpOp::Contains {
                search_bytes(node, source, target)
            } else {
                field_bytes(node, source)
            };
            got.is_some_and(|got| bytes_op(got, want, op))
        }
        // `Kind::Protocol`/`Group` nodes carry no value; `contains` searches
        // the bytes the layer covers.
        (Operand::Str(want), Value::None)
            if matches!(target.kind, Kind::Protocol | Kind::Group) =>
        {
            search_bytes(node, source, target).is_some_and(|got| bytes_op(got, want.as_bytes(), op))
        }
        _ => false,
    }
}

fn ord_op(ordering: std::cmp::Ordering, op: CmpOp) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match op {
        CmpOp::Eq => ordering == Equal,
        CmpOp::Ne => ordering != Equal,
        CmpOp::Gt => ordering == Greater,
        CmpOp::Ge => ordering != Less,
        CmpOp::Lt => ordering == Less,
        CmpOp::Le => ordering != Greater,
        // Handled before this point.
        CmpOp::Contains | CmpOp::Matches => false,
    }
}

fn bytes_op(got: &[u8], want: &[u8], op: CmpOp) -> bool {
    match op {
        CmpOp::Contains => contains_bytes(got, want),
        _ => ord_op(got.cmp(want), op),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{RawFrame, Timestamp};
    use crate::dissect::{dissect, Reassembly};
    use crate::filter::types::compile;
    use netscope_ffi::LinkType;
    use std::sync::Arc;

    fn frame(bytes: &[u8]) -> Frame {
        let mut r = Reassembly::new();
        dissect(
            LinkType::ETHERNET,
            1,
            RawFrame {
                ts: Timestamp {
                    secs: 1_700_000_000,
                    nanos: 0,
                },
                caplen: bytes.len() as u32,
                orig_len: bytes.len() as u32,
                bytes: Arc::from(bytes),
            },
            &mut r,
        )
    }

    fn synthetic() -> Frame {
        let mut r = Reassembly::new();
        dissect(
            LinkType::ETHERNET,
            1,
            crate::synthetic::raw_frame(5),
            &mut r,
        )
    }

    fn yes(f: &Frame, filter: &str) {
        let t = compile(filter).unwrap_or_else(|e| panic!("{filter}: {e}"));
        assert!(matches(&t, f), "{filter} should match");
    }

    fn no(f: &Frame, filter: &str) {
        let t = compile(filter).unwrap_or_else(|e| panic!("{filter}: {e}"));
        assert!(!matches(&t, f), "{filter} should not match");
    }

    #[test]
    fn presence_and_numbers() {
        let f = synthetic();
        yes(&f, "tcp");
        yes(&f, "eth && ip && tcp");
        no(&f, "udp");
        no(&f, "arp");
        yes(&f, "tcp.dstport == 5001");
        no(&f, "tcp.dstport == 443");
        yes(&f, "ip.ttl == 64");
        yes(&f, "ip.ttl >= 64");
        yes(&f, "ip.ttl > 63");
        no(&f, "ip.ttl > 64");
        yes(&f, "ip.ttl <= 64");
        yes(&f, "frame.len > 50");
        no(&f, "frame.len > 100");
    }

    #[test]
    fn any_occurrence_matches() {
        let f = synthetic();
        // tcp.port is an alias covering srcport and dstport.
        yes(&f, "tcp.port == 5001");
        yes(&f, "tcp.port == 40005");
        no(&f, "tcp.port == 1234");
        yes(&f, "tcp.port in {80, 5001, 443}");
        no(&f, "tcp.port in {80, 443}");
    }

    #[test]
    fn addresses_and_prefixes() {
        let f = synthetic();
        yes(&f, "ip.src == 10.0.0.5");
        yes(&f, "ip.addr == 10.0.0.5");
        yes(&f, "ip.addr == 93.184.216.34");
        yes(&f, "ip.addr == 10.0.0.0/8");
        yes(&f, "ip.src == 10.0.0.0/24");
        no(&f, "ip.src == 10.1.0.0/16");
        no(&f, "ip.addr == 192.168.0.0/16");
        yes(&f, "eth.src == 00:1c:42:00:00:05");
        yes(&f, "eth.addr == 00:1c:42:00:00:01");
        no(&f, "eth.src == aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn slices_read_the_fields_bytes() {
        let f = synthetic();
        yes(&f, "eth.src[0:3] == 00:1c:42");
        no(&f, "eth.src[0:3] == 00:1c:43");
        yes(&f, "eth.src[0] == 0");
        yes(&f, "ip.src[0] == 10");
        yes(&f, "ip.src[0:2] == 0a:00");
        // A slice past the end of the field does not match.
        no(&f, "eth.src[4:8] == 00:00:00:00:00:00:00:00");
    }

    #[test]
    fn booleans_and_flags() {
        let f = synthetic();
        yes(&f, "tcp.flags.ack == true");
        yes(&f, "tcp.flags.push == 1");
        yes(&f, "tcp.flags.syn == false");
        no(&f, "tcp.flags.syn == true");
        yes(&f, "tcp.flags.syn == 0");
        yes(&f, "tcp.flags == 0x018");
    }

    #[test]
    fn strings_contains_and_regex() {
        let mut b = vec![0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        b.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        b.extend_from_slice(&[0x08, 0x00]);
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut ip = vec![
            0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut tcp = vec![
            0xc0, 0x00, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ];
        tcp.extend_from_slice(payload);
        let total = (20 + tcp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&tcp);
        b.extend_from_slice(&ip);
        let f = frame(&b);
        yes(&f, "http");
        yes(&f, "http.request.method == \"GET\"");
        yes(&f, "http.host == \"example.com\"");
        yes(&f, "http.host contains \"example\"");
        no(&f, "http.host contains \"google\"");
        yes(&f, "http.host matches \"^ex.*le\\\\.com$\"");
        no(&f, "http.host matches \"^www\"");
        yes(&f, "http.request.uri matches \"\\\\.html$\"");
        // `contains` on a protocol searches the layer's bytes.
        yes(&f, "tcp contains \"GET\"");
        yes(&f, "frame contains \"index.html\"");
        no(&f, "frame contains \"nowhere\"");
    }

    #[test]
    fn boolean_structure() {
        let f = synthetic();
        yes(&f, "tcp && !udp");
        yes(&f, "udp || tcp");
        no(&f, "udp && tcp");
        yes(&f, "!(udp || arp)");
        yes(&f, "(ip.ttl == 64 || ip.ttl == 1) && tcp");
        no(&f, "!tcp");
    }

    #[test]
    fn ne_is_any_occurrence_and_not_is_the_alternative() {
        let f = synthetic();
        // One ip.src in the frame, so both readings agree.
        yes(&f, "ip.src != 1.2.3.4");
        no(&f, "ip.src != 10.0.0.5");
        // ip.addr covers two fields, so `!=` is true when either differs.
        yes(&f, "ip.addr != 10.0.0.5");
        // The unambiguous way to say "no occurrence matches".
        no(&f, "!(ip.addr == 10.0.0.5)");
    }

    #[test]
    fn enum_values_by_name() {
        let f = synthetic();
        yes(&f, "ip.proto == 6");
        yes(&f, "ip.proto == \"TCP\"");
        no(&f, "ip.proto == \"UDP\"");
        yes(&f, "ip.checksum.status == \"Good\"");
    }

    #[test]
    fn missing_fields_never_match() {
        let f = synthetic();
        for filter in [
            "dns.qry.name == \"x\"",
            "dns",
            "arp.opcode == 1",
            "icmp.type == 8",
            "udp.port == 53",
        ] {
            no(&f, filter);
        }
        // Negation of a missing field is true.
        yes(&f, "!dns");
    }
}
