//! Type checking against the field registry, and compilation of the checked
//! AST into a form the evaluator can run without further decisions.
//!
//! Everything that can be wrong with a filter is decided here: unknown
//! fields, operators a field's type does not support, literals of the wrong
//! type, malformed regexes, slices on fields that have no bytes. Evaluation
//! is then total.

use std::ops::Range;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;

use super::ast::{CmpOp, Expr, FieldRef, Literal, Slice};
use super::lex::{FilterError, Result};
use crate::dissect::registry::{self, Kind};

/// What a comparison compares against, once the literal has been matched to
/// the field's type.
#[derive(Debug, Clone)]
pub enum Operand {
    Unsigned(u64),
    Signed(i64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4([u8; 4]),
    /// Address and mask, pre-computed.
    Ipv4Net([u8; 4], [u8; 4]),
    Ipv6([u8; 16]),
    Ipv6Net([u8; 16], [u8; 16]),
    Bool(bool),
}

/// A field resolved to the registry: one or more concrete field ids, plus
/// the slice to apply to each occurrence's bytes.
#[derive(Debug, Clone)]
pub struct Target {
    /// Field ids to look for. An alias like `ip.addr` has several.
    pub ids: Vec<u16>,
    pub kind: Kind,
    pub slice: Option<Slice>,
    pub name: String,
}

/// What the evaluator runs. Every decision has already been made.
#[derive(Debug, Clone)]
pub enum Test {
    Present(Target),
    Compare {
        target: Target,
        op: CmpOp,
        value: Operand,
    },
    Regex {
        target: Target,
        /// Applied to text values.
        text: Box<Regex>,
        /// Applied to byte values.
        bytes: Box<BytesRegex>,
    },
    In {
        target: Target,
        values: Vec<Operand>,
    },
    And(Box<Test>, Box<Test>),
    Or(Box<Test>, Box<Test>),
    Not(Box<Test>),
}

/// Type-check `expr` and compile it.
pub fn check(expr: &Expr) -> Result<Test> {
    match expr {
        Expr::Present(f) => Ok(Test::Present(resolve(f)?)),
        Expr::Compare { field, op, value } => {
            let target = resolve(field)?;
            if *op == CmpOp::Matches {
                let Literal::Str(pattern) = &value.value else {
                    return Err(FilterError::new(
                        format!(
                            "`matches` needs a quoted regular expression, found {}",
                            value.value.kind_name()
                        ),
                        value.span.clone(),
                    ));
                };
                if !can_match(target.kind, target.slice.is_some()) {
                    return Err(FilterError::new(
                        format!(
                            "`matches` cannot be used on {} ({})",
                            target.name,
                            kind_name(target.kind)
                        ),
                        field.span.clone(),
                    ));
                }
                let text = Regex::new(pattern)
                    .map_err(|e| FilterError::new(regex_message(&e), value.span.clone()))?;
                let bytes = BytesRegex::new(pattern)
                    .map_err(|e| FilterError::new(regex_message(&e), value.span.clone()))?;
                return Ok(Test::Regex {
                    target,
                    text: Box::new(text),
                    bytes: Box::new(bytes),
                });
            }
            if *op == CmpOp::Contains && !can_contain(target.kind, target.slice.is_some()) {
                return Err(FilterError::new(
                    format!(
                        "`contains` cannot be used on {} ({})",
                        target.name,
                        kind_name(target.kind)
                    ),
                    field.span.clone(),
                ));
            }
            if op.is_ordering() && !is_ordered(target.kind, target.slice.is_some()) {
                return Err(FilterError::new(
                    format!(
                        "`{}` cannot be used on {} ({}); only `==` and `!=` apply",
                        op.name(),
                        target.name,
                        kind_name(target.kind)
                    ),
                    field.span.clone(),
                ));
            }
            let value = coerce(&target, &value.value, &value.span, *op)?;
            Ok(Test::Compare {
                target,
                op: *op,
                value,
            })
        }
        Expr::In { field, values } => {
            let target = resolve(field)?;
            let mut out = Vec::with_capacity(values.len());
            for v in values {
                out.push(coerce(&target, &v.value, &v.span, CmpOp::Eq)?);
            }
            Ok(Test::In {
                target,
                values: out,
            })
        }
        Expr::And(a, b) => Ok(Test::And(Box::new(check(a)?), Box::new(check(b)?))),
        Expr::Or(a, b) => Ok(Test::Or(Box::new(check(a)?), Box::new(check(b)?))),
        Expr::Not(a) => Ok(Test::Not(Box::new(check(a)?))),
    }
}

/// Compile a filter from text in one step.
pub fn compile(input: &str) -> Result<Test> {
    check(&super::parse::parse(input)?)
}

fn regex_message(e: &regex::Error) -> String {
    // The crate's messages are multi-line with a caret diagram; the filter
    // bar has one line, so keep the first meaningful sentence.
    let text = e.to_string();
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with("regex parse error"))
        .unwrap_or("invalid regular expression");
    format!("invalid regular expression: {}", first.trim())
}

fn resolve(field: &FieldRef) -> Result<Target> {
    let Some(def) = registry::lookup(&field.name) else {
        let hint = match registry::closest(&field.name) {
            Some(near) => format!("; did you mean `{near}`?"),
            None => String::new(),
        };
        return Err(FilterError::new(
            format!("unknown field `{}`{hint}", field.name),
            field.span.clone(),
        ));
    };
    let ids: Vec<u16> = if def.members.is_empty() {
        registry::field_id_if_known(&field.name)
            .into_iter()
            .collect()
    } else {
        def.members
            .iter()
            .filter_map(|m| registry::field_id_if_known(m))
            .collect()
    };
    if ids.is_empty() {
        return Err(FilterError::new(
            format!("field `{}` cannot be filtered on", field.name),
            field.span.clone(),
        ));
    }
    if field.slice.is_some() && !has_bytes(def.kind) {
        return Err(FilterError::new(
            format!(
                "`{}` ({}) has no bytes to slice",
                field.name,
                kind_name(def.kind)
            ),
            field.span.clone(),
        ));
    }
    Ok(Target {
        ids,
        kind: def.kind,
        slice: field.slice,
        name: format!("`{}`", field.name),
    })
}

/// Whether a field's value occupies bytes a slice can address.
fn has_bytes(kind: Kind) -> bool {
    !matches!(kind, Kind::Bool | Kind::Protocol | Kind::Group)
}

fn can_contain(kind: Kind, sliced: bool) -> bool {
    sliced || matches!(kind, Kind::Str | Kind::Bytes | Kind::Protocol | Kind::Group)
}

fn can_match(kind: Kind, sliced: bool) -> bool {
    can_contain(kind, sliced)
}

fn is_ordered(kind: Kind, sliced: bool) -> bool {
    if sliced {
        return true;
    }
    matches!(
        kind,
        Kind::Unsigned(_) | Kind::Signed | Kind::Enum(..) | Kind::Str | Kind::Bytes
    )
}

pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Protocol => "a protocol",
        Kind::Group => "a group",
        Kind::Bool => "a flag",
        Kind::Unsigned(_) => "an unsigned number",
        Kind::Signed => "a signed number",
        Kind::Str => "text",
        Kind::Bytes => "bytes",
        Kind::Ipv4 => "an IPv4 address",
        Kind::Ipv6 => "an IPv6 address",
        Kind::Mac => "a MAC address",
        Kind::Enum(..) => "an enumerated number",
    }
}

fn mask_v4(bits: u8) -> [u8; 4] {
    let m: u32 = if bits >= 32 {
        u32::MAX
    } else {
        u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0)
    };
    m.to_be_bytes()
}

fn mask_v6(bits: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bits = usize::from(bits.min(128));
    for (i, byte) in out.iter_mut().enumerate() {
        let lo = i * 8;
        *byte = if bits >= lo + 8 {
            0xff
        } else if bits > lo {
            0xffu8 << (8 - (bits - lo))
        } else {
            0
        };
    }
    out
}

/// Match a literal to the field's type, or explain why it cannot be.
fn coerce(target: &Target, lit: &Literal, span: &Range<usize>, op: CmpOp) -> Result<Operand> {
    let wrong = |expected: &str| {
        FilterError::new(
            format!(
                "{} is {}, so it cannot be compared with {}; expected {expected}",
                target.name,
                kind_name(target.kind),
                lit.kind_name()
            ),
            span.clone(),
        )
    };
    // A slice is always a byte string, whatever the field's own type is.
    if target.slice.is_some() {
        return match lit {
            Literal::Bytes(b) => Ok(Operand::Bytes(b.clone())),
            Literal::Str(s) => Ok(Operand::Bytes(s.clone().into_bytes())),
            Literal::Unsigned(n) if *n <= u64::from(u8::MAX) => Ok(Operand::Bytes(vec![*n as u8])),
            Literal::Ipv4(a) => Ok(Operand::Bytes(a.to_vec())),
            Literal::Ipv6(a) => Ok(Operand::Bytes(a.to_vec())),
            _ => Err(FilterError::new(
                format!(
                    "a slice is a byte string, so it cannot be compared with {}; \
                     expected bytes like aa:bb:cc or a quoted string",
                    lit.kind_name()
                ),
                span.clone(),
            )),
        };
    }
    match (target.kind, lit) {
        (Kind::Protocol | Kind::Group, Literal::Str(s)) if op == CmpOp::Contains => {
            Ok(Operand::Bytes(s.clone().into_bytes()))
        }
        (Kind::Protocol | Kind::Group, Literal::Bytes(b)) if op == CmpOp::Contains => {
            Ok(Operand::Bytes(b.clone()))
        }
        (Kind::Protocol | Kind::Group, _) => Err(FilterError::new(
            format!(
                "{} is {}; write it on its own to test that the frame has it",
                target.name,
                kind_name(target.kind)
            ),
            span.clone(),
        )),
        (Kind::Bool, Literal::Bool(b)) => Ok(Operand::Bool(*b)),
        (Kind::Bool, Literal::Unsigned(n)) if *n <= 1 => Ok(Operand::Bool(*n == 1)),
        (Kind::Bool, _) => Err(wrong("`true`, `false`, 0 or 1")),

        (Kind::Unsigned(_) | Kind::Enum(..), Literal::Unsigned(n)) => Ok(Operand::Unsigned(*n)),
        (Kind::Unsigned(_) | Kind::Enum(..), Literal::Signed(n)) => Err(FilterError::new(
            format!(
                "{} is unsigned, so it cannot be compared with {n}",
                target.name
            ),
            span.clone(),
        )),
        (Kind::Unsigned(_), _) => Err(wrong("a number")),
        (Kind::Enum(table, _), Literal::Str(s)) => {
            // Allow the symbolic name: tcp.flags == "SYN" style lookups.
            match table
                .iter()
                .find(|(_, name)| name.eq_ignore_ascii_case(s))
                .map(|(v, _)| *v)
            {
                Some(v) => Ok(Operand::Unsigned(v)),
                None => Err(FilterError::new(
                    format!("`{s}` is not a known value for {}", target.name),
                    span.clone(),
                )),
            }
        }
        (Kind::Enum(..), _) => Err(wrong("a number or a known value name")),

        (Kind::Signed, Literal::Signed(n)) => Ok(Operand::Signed(*n)),
        (Kind::Signed, Literal::Unsigned(n)) => i64::try_from(*n)
            .map(Operand::Signed)
            .map_err(|_| FilterError::new("number is too large", span.clone())),
        (Kind::Signed, _) => Err(wrong("a number")),

        (Kind::Str, Literal::Str(s)) => Ok(Operand::Str(s.clone())),
        (Kind::Str, _) => Err(wrong("a quoted string")),

        (Kind::Bytes, Literal::Bytes(b)) => Ok(Operand::Bytes(b.clone())),
        (Kind::Bytes, Literal::Str(s)) => Ok(Operand::Bytes(s.clone().into_bytes())),
        (Kind::Bytes, _) => Err(wrong("bytes like aa:bb:cc or a quoted string")),

        (Kind::Ipv4, Literal::Ipv4(a)) => Ok(Operand::Ipv4(*a)),
        (Kind::Ipv4, Literal::Ipv4Cidr(a, bits)) => {
            let mask = mask_v4(*bits);
            let mut net = *a;
            for i in 0..4 {
                net[i] &= mask[i];
            }
            Ok(Operand::Ipv4Net(net, mask))
        }
        (Kind::Ipv4, _) => Err(wrong("an IPv4 address like 10.0.0.1 or 10.0.0.0/8")),

        (Kind::Ipv6, Literal::Ipv6(a)) => Ok(Operand::Ipv6(*a)),
        (Kind::Ipv6, Literal::Ipv6Cidr(a, bits)) => {
            let mask = mask_v6(*bits);
            let mut net = *a;
            for i in 0..16 {
                net[i] &= mask[i];
            }
            Ok(Operand::Ipv6Net(net, mask))
        }
        (Kind::Ipv6, _) => Err(wrong("an IPv6 address like 2001:db8::1 or fe80::/10")),

        (Kind::Mac, Literal::Bytes(b)) if b.len() == 6 => Ok(Operand::Bytes(b.clone())),
        (Kind::Mac, _) => Err(wrong("a MAC address like aa:bb:cc:dd:ee:ff")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(input: &str) -> FilterError {
        compile(input).expect_err("should not compile")
    }

    #[test]
    fn well_typed_filters_compile() {
        for f in [
            "tcp",
            "tcp.port == 443",
            "ip.addr == 10.0.0.0/8",
            "ipv6.addr == fe80::/10",
            "eth.src == aa:bb:cc:dd:ee:ff",
            "eth.src[0:3] == aa:bb:cc",
            "dns.qry.name contains \"example\"",
            "dns.qry.name matches \"^www\\\\.\"",
            "tcp.flags.syn == true",
            "tcp.flags.syn == 1",
            "udp.port in {53, 5353}",
            "!(arp || icmp) && frame.len > 100",
            "ip.checksum.status == \"Good\"",
        ] {
            compile(f).unwrap_or_else(|e| panic!("{f}: {e}"));
        }
    }

    #[test]
    fn unknown_fields_are_rejected_with_a_suggestion() {
        let e = err("tcp.prot == 443");
        assert!(e.message.contains("unknown field"), "{}", e.message);
        assert!(e.message.contains("tcp.port"), "{}", e.message);
        assert_eq!(e.column, 0);
    }

    #[test]
    fn operators_are_checked_against_the_field_type() {
        let e = err("tcp.flags.syn > 0");
        assert!(e.message.contains("cannot be used"), "{}", e.message);
        let e = err("ip.src contains \"10\"");
        assert!(e.message.contains("contains"), "{}", e.message);
        let e = err("ip.ttl matches \"6\"");
        assert!(e.message.contains("matches"), "{}", e.message);
        let e = err("ip.src > 10.0.0.1");
        assert!(e.message.contains("only `==` and `!=`"), "{}", e.message);
    }

    #[test]
    fn literals_are_checked_against_the_field_type() {
        let e = err("tcp.port == \"http\"");
        assert!(e.message.contains("expected a number"), "{}", e.message);
        assert_eq!(e.column, 12);
        let e = err("ip.src == aa:bb:cc:dd:ee:ff");
        assert!(e.message.contains("IPv4"), "{}", e.message);
        let e = err("eth.src == 10.0.0.1");
        assert!(e.message.contains("MAC"), "{}", e.message);
        let e = err("tcp.port == -1");
        assert!(e.message.contains("unsigned"), "{}", e.message);
        let e = err("tcp.flags.syn == 7");
        assert!(e.message.contains("`true`"), "{}", e.message);
    }

    #[test]
    fn protocols_cannot_be_compared() {
        let e = err("tcp == 1");
        assert!(e.message.contains("on its own"), "{}", e.message);
    }

    #[test]
    fn slices_need_bytes_and_byte_literals() {
        let e = err("tcp.flags.syn[0] == aa:bb");
        assert!(e.message.contains("no bytes to slice"), "{}", e.message);
        let e = err("eth.src[0:3] == 443");
        assert!(e.message.contains("byte string"), "{}", e.message);
    }

    #[test]
    fn bad_regexes_are_reported_at_the_pattern() {
        let e = err("dns.qry.name matches \"(\"");
        assert!(
            e.message.contains("invalid regular expression"),
            "{}",
            e.message
        );
        assert_eq!(e.column, 21);
        let e = err("dns.qry.name matches 5");
        assert!(
            e.message.contains("quoted regular expression"),
            "{}",
            e.message
        );
    }

    #[test]
    fn cidr_masks_are_precomputed() {
        match compile("ip.addr == 10.1.2.3/8").expect("compile") {
            Test::Compare {
                value: Operand::Ipv4Net(net, mask),
                target,
                ..
            } => {
                assert_eq!(net, [10, 0, 0, 0], "host bits must be cleared");
                assert_eq!(mask, [255, 0, 0, 0]);
                assert_eq!(target.ids.len(), 2, "ip.addr covers src and dst");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(mask_v6(10)[..2], [0xff, 0xc0]);
        assert_eq!(mask_v4(0), [0, 0, 0, 0]);
        assert_eq!(mask_v4(32), [255, 255, 255, 255]);
    }
}
