//! Display-filter tokeniser. Every token carries the column span it came
//! from, so the parser and type checker can point at the exact text.

use std::fmt;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A field name: `tcp.srcport`, `ip`, `dns.flags.response`.
    Field(String),
    /// An unsigned literal, decimal or hex.
    Number(u64),
    /// A negative decimal literal.
    Signed(i64),
    Str(String),
    /// Colon-separated hex pairs: a MAC when six of them, a byte string
    /// otherwise (`eth.src[0:3] == aa:bb:cc`).
    Bytes(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv4Cidr([u8; 4], u8),
    Ipv6([u8; 16]),
    Ipv6Cidr([u8; 16], u8),
    Bool(bool),

    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
    Matches,
    In,

    And,
    Or,
    Not,

    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Colon,
    Comma,
}

impl Tok {
    /// How the token is written, for error messages.
    pub fn describe(&self) -> String {
        match self {
            Tok::Field(f) => format!("field `{f}`"),
            Tok::Number(n) => format!("number {n}"),
            Tok::Signed(n) => format!("number {n}"),
            Tok::Str(s) => format!("string \"{s}\""),
            Tok::Bytes(b) => format!("{}-byte literal", b.len()),
            Tok::Ipv4(_) | Tok::Ipv4Cidr(..) => "IPv4 literal".into(),
            Tok::Ipv6(_) | Tok::Ipv6Cidr(..) => "IPv6 literal".into(),
            Tok::Bool(b) => format!("`{b}`"),
            Tok::Eq => "`==`".into(),
            Tok::Ne => "`!=`".into(),
            Tok::Gt => "`>`".into(),
            Tok::Ge => "`>=`".into(),
            Tok::Lt => "`<`".into(),
            Tok::Le => "`<=`".into(),
            Tok::Contains => "`contains`".into(),
            Tok::Matches => "`matches`".into(),
            Tok::In => "`in`".into(),
            Tok::And => "`&&`".into(),
            Tok::Or => "`||`".into(),
            Tok::Not => "`!`".into(),
            Tok::LParen => "`(`".into(),
            Tok::RParen => "`)`".into(),
            Tok::LBrace => "`{`".into(),
            Tok::RBrace => "`}`".into(),
            Tok::LBracket => "`[`".into(),
            Tok::RBracket => "`]`".into(),
            Tok::Colon => "`:`".into(),
            Tok::Comma => "`,`".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned {
    pub tok: Tok,
    pub span: Range<usize>,
}

/// A filter that could not be compiled, with the column it failed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    pub message: String,
    /// Byte offset into the filter text where the problem starts.
    pub column: usize,
    /// Length of the offending text, for underlining.
    pub len: usize,
}

impl FilterError {
    pub fn new(message: impl Into<String>, span: Range<usize>) -> FilterError {
        FilterError {
            message: message.into(),
            column: span.start,
            len: span.len().max(1),
        }
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (column {})", self.message, self.column + 1)
    }
}

impl std::error::Error for FilterError {}

pub type Result<T> = std::result::Result<T, FilterError>;

/// Characters that may appear inside an unquoted word. Operators and
/// brackets are excluded, so `tcp.port==443` lexes without spaces.
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-' | '/' | '*' | '$')
}

pub fn lex(input: &str) -> Result<Vec<Spanned>> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let two = input.get(i..i + 2);
        let simple = match (c, two) {
            (_, Some("==")) => Some((Tok::Eq, 2)),
            (_, Some("!=")) => Some((Tok::Ne, 2)),
            (_, Some(">=")) => Some((Tok::Ge, 2)),
            (_, Some("<=")) => Some((Tok::Le, 2)),
            (_, Some("&&")) => Some((Tok::And, 2)),
            (_, Some("||")) => Some((Tok::Or, 2)),
            ('>', _) => Some((Tok::Gt, 1)),
            ('<', _) => Some((Tok::Lt, 1)),
            ('!', _) => Some((Tok::Not, 1)),
            ('(', _) => Some((Tok::LParen, 1)),
            (')', _) => Some((Tok::RParen, 1)),
            ('{', _) => Some((Tok::LBrace, 1)),
            ('}', _) => Some((Tok::RBrace, 1)),
            ('[', _) => Some((Tok::LBracket, 1)),
            (']', _) => Some((Tok::RBracket, 1)),
            (':', _) => Some((Tok::Colon, 1)),
            (',', _) => Some((Tok::Comma, 1)),
            ('=', _) => {
                return Err(FilterError::new(
                    "`=` is not an operator; use `==` to compare",
                    start..start + 1,
                ))
            }
            ('&', _) | ('|', _) => {
                return Err(FilterError::new(
                    format!("single `{c}` is not an operator; use `{c}{c}`"),
                    start..start + 1,
                ))
            }
            _ => None,
        };
        if let Some((tok, len)) = simple {
            out.push(Spanned {
                tok,
                span: start..start + len,
            });
            i += len;
            continue;
        }
        if c == '"' || c == '\'' {
            let (s, len) = lex_string(input, i, c)?;
            out.push(Spanned {
                tok: Tok::Str(s),
                span: start..start + len,
            });
            i += len;
            continue;
        }
        if !is_word_char(c) {
            return Err(FilterError::new(
                format!("unexpected character `{c}`"),
                start..start + c.len_utf8(),
            ));
        }
        // A word: an operand or a keyword. Classify it once complete.
        let mut end = i;
        while end < bytes.len() && is_word_char(bytes[end] as char) {
            end += 1;
        }
        let word = input.get(start..end).unwrap_or_default();
        // A `:` here belongs to a slice (`[0:3]`) rather than to the word
        // when the word before it ends the field name.
        let (word, end) = trim_slice_colon(word, start, end, &out);
        let tok = classify(word, start..end, &out)?;
        out.push(Spanned {
            tok,
            span: start..end,
        });
        i = end;
    }
    Ok(out)
}

/// Inside a slice, `3]` must not swallow the `:` of `0:3`. A word that starts
/// right after `[` or `:` and is a plain number keeps only its digits.
fn trim_slice_colon<'a>(
    word: &'a str,
    start: usize,
    end: usize,
    prev: &[Spanned],
) -> (&'a str, usize) {
    let in_slice = matches!(
        prev.last().map(|s| &s.tok),
        Some(Tok::LBracket) | Some(Tok::Colon)
    );
    if !in_slice {
        return (word, end);
    }
    match word.find(':') {
        Some(cut) => (&word[..cut], start + cut),
        None => (word, end),
    }
}

fn lex_string(input: &str, at: usize, quote: char) -> Result<(String, usize)> {
    let bytes = input.as_bytes();
    let mut s = String::new();
    let mut i = at + 1;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == quote {
            return Ok((s, i + 1 - at));
        }
        if c == '\\' {
            let Some(&next) = bytes.get(i + 1) else {
                return Err(FilterError::new(
                    "string ends with a trailing backslash",
                    i..i + 1,
                ));
            };
            match next as char {
                'n' => s.push('\n'),
                't' => s.push('\t'),
                'r' => s.push('\r'),
                '0' => s.push('\0'),
                '\\' => s.push('\\'),
                '"' => s.push('"'),
                '\'' => s.push('\''),
                'x' => {
                    let hex = input.get(i + 2..i + 4).unwrap_or("");
                    let Ok(b) = u8::from_str_radix(hex, 16) else {
                        return Err(FilterError::new(
                            "`\\x` needs two hex digits",
                            i..i + 2.min(bytes.len() - i),
                        ));
                    };
                    s.push(b as char);
                    i += 4;
                    continue;
                }
                other => {
                    return Err(FilterError::new(
                        format!("unknown escape `\\{other}`"),
                        i..i + 2,
                    ))
                }
            }
            i += 2;
            continue;
        }
        s.push(c);
        i += 1;
    }
    Err(FilterError::new("unterminated string", at..at + 1))
}

/// Decide what a word is. Literal forms are tried before field names so
/// `aa:bb:cc:dd:ee:ff` is a MAC rather than a (nonexistent) field.
fn classify(word: &str, span: Range<usize>, prev: &[Spanned]) -> Result<Tok> {
    if word.is_empty() {
        return Err(FilterError::new("expected a value", span));
    }
    match word {
        "contains" => return Ok(Tok::Contains),
        "matches" => return Ok(Tok::Matches),
        "in" => return Ok(Tok::In),
        "and" => return Ok(Tok::And),
        "or" => return Ok(Tok::Or),
        "not" => return Ok(Tok::Not),
        "true" => return Ok(Tok::Bool(true)),
        "false" => return Ok(Tok::Bool(false)),
        _ => {}
    }
    if let Some(t) = parse_ipv4(word) {
        return Ok(t);
    }
    if let Some(t) = parse_ipv6(word) {
        return Ok(t);
    }
    if let Some(t) = parse_hex_bytes(word) {
        return Ok(t);
    }
    if let Some(t) = parse_number(word, &span, prev)? {
        return Ok(t);
    }
    if is_field_name(word) {
        return Ok(Tok::Field(word.to_string()));
    }
    Err(FilterError::new(
        format!("`{word}` is not a field name or a literal"),
        span,
    ))
}

fn is_field_name(word: &str) -> bool {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    word.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && !word.ends_with('.')
}

fn parse_number(word: &str, span: &Range<usize>, prev: &[Spanned]) -> Result<Option<Tok>> {
    let negative = word.starts_with('-');
    let body = word.strip_prefix('-').unwrap_or(word);
    if negative {
        // Only an operand position may start with a minus.
        let ok = matches!(
            prev.last().map(|s| &s.tok),
            None | Some(Tok::Eq)
                | Some(Tok::Ne)
                | Some(Tok::Gt)
                | Some(Tok::Ge)
                | Some(Tok::Lt)
                | Some(Tok::Le)
                | Some(Tok::LParen)
                | Some(Tok::LBrace)
                | Some(Tok::Comma)
        );
        if !ok {
            return Ok(None);
        }
    }
    let value = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(None);
        }
        u64::from_str_radix(hex, 16)
            .map_err(|_| FilterError::new("hex number is too large", span.clone()))?
    } else {
        if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit()) {
            return Ok(None);
        }
        body.parse::<u64>()
            .map_err(|_| FilterError::new("number is too large", span.clone()))?
    };
    if negative {
        let signed = i64::try_from(value)
            .map(|v| -v)
            .map_err(|_| FilterError::new("number is too large", span.clone()))?;
        return Ok(Some(Tok::Signed(signed)));
    }
    Ok(Some(Tok::Number(value)))
}

fn parse_ipv4(word: &str) -> Option<Tok> {
    let (addr, prefix) = split_prefix(word);
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        out[i] = p.parse::<u8>().ok()?;
    }
    match prefix {
        None => Some(Tok::Ipv4(out)),
        Some(bits) => {
            let bits: u8 = bits.parse().ok()?;
            (bits <= 32).then_some(Tok::Ipv4Cidr(out, bits))
        }
    }
}

fn parse_ipv6(word: &str) -> Option<Tok> {
    let (addr, prefix) = split_prefix(word);
    if !addr.contains(':') {
        return None;
    }
    let out: [u8; 16] = addr.parse::<std::net::Ipv6Addr>().ok()?.octets();
    match prefix {
        None => Some(Tok::Ipv6(out)),
        Some(bits) => {
            let bits: u8 = bits.parse().ok()?;
            (bits <= 128).then_some(Tok::Ipv6Cidr(out, bits))
        }
    }
}

fn split_prefix(word: &str) -> (&str, Option<&str>) {
    match word.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (word, None),
    }
}

/// `aa:bb:cc` and friends: two-hex-digit groups separated by colons.
fn parse_hex_bytes(word: &str) -> Option<Tok> {
    if !word.contains(':') || word.contains('/') {
        return None;
    }
    let groups: Vec<&str> = word.split(':').collect();
    if groups.len() < 2 {
        return None;
    }
    let mut out = Vec::with_capacity(groups.len());
    for g in groups {
        if g.len() != 2 || !g.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u8::from_str_radix(g, 16).ok()?);
    }
    Some(Tok::Bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).expect("lex").into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn fields_operators_and_numbers() {
        assert_eq!(
            toks("tcp.port==443"),
            [Tok::Field("tcp.port".into()), Tok::Eq, Tok::Number(443)]
        );
        assert_eq!(
            toks("ip.ttl >= 0x40 && !tcp"),
            [
                Tok::Field("ip.ttl".into()),
                Tok::Ge,
                Tok::Number(0x40),
                Tok::And,
                Tok::Not,
                Tok::Field("tcp".into())
            ]
        );
        assert_eq!(
            toks("frame.len < -1"),
            [Tok::Field("frame.len".into()), Tok::Lt, Tok::Signed(-1)]
        );
    }

    #[test]
    fn address_literals() {
        assert_eq!(toks("10.0.0.1"), [Tok::Ipv4([10, 0, 0, 1])]);
        assert_eq!(toks("10.0.0.0/8"), [Tok::Ipv4Cidr([10, 0, 0, 0], 8)]);
        assert_eq!(
            toks("aa:bb:cc:dd:ee:ff"),
            [Tok::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])]
        );
        assert_eq!(toks("aa:bb:cc"), [Tok::Bytes(vec![0xaa, 0xbb, 0xcc])]);
        let Tok::Ipv6(a) = &toks("2001:db8::1")[0] else {
            panic!("expected IPv6");
        };
        assert_eq!(a[0..2], [0x20, 0x01]);
        assert!(matches!(toks("fe80::/10")[0], Tok::Ipv6Cidr(_, 10)));
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(toks(r#""hello""#), [Tok::Str("hello".into())]);
        assert_eq!(toks(r#"'a b'"#), [Tok::Str("a b".into())]);
        assert_eq!(toks(r#""a\nb""#), [Tok::Str("a\nb".into())]);
        assert_eq!(toks(r#""\x41""#), [Tok::Str("A".into())]);
        assert_eq!(toks(r#""say \"hi\"""#), [Tok::Str("say \"hi\"".into())]);
    }

    #[test]
    fn slices_and_sets() {
        assert_eq!(
            toks("eth.src[0:3]"),
            [
                Tok::Field("eth.src".into()),
                Tok::LBracket,
                Tok::Number(0),
                Tok::Colon,
                Tok::Number(3),
                Tok::RBracket
            ]
        );
        assert_eq!(
            toks("tcp.port in {80,443}"),
            [
                Tok::Field("tcp.port".into()),
                Tok::In,
                Tok::LBrace,
                Tok::Number(80),
                Tok::Comma,
                Tok::Number(443),
                Tok::RBrace
            ]
        );
    }

    #[test]
    fn errors_carry_a_column() {
        let e = lex("tcp.port = 443").expect_err("should fail");
        assert_eq!(e.column, 9);
        assert!(e.message.contains("=="), "{}", e.message);
        let e = lex("tcp && \"unterminated").expect_err("should fail");
        assert_eq!(e.column, 7);
        let e = lex("ip.src == 10.0.0.1 & 1").expect_err("should fail");
        assert_eq!(e.column, 19);
        let e = lex("tcp.port == 99999999999999999999999").expect_err("should fail");
        assert!(e.message.contains("too large"), "{}", e.message);
    }
}
