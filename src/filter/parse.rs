//! Recursive-descent parser for the display filter grammar.
//!
//! Precedence, loosest first: `||`, `&&`, `!`, then a comparison or a bare
//! field. Parentheses group. The parser is only concerned with shape; the
//! type checker decides whether a comparison makes sense.

use super::ast::{CmpOp, Expr, FieldRef, Literal, Slice, SpannedLiteral};
use super::lex::{lex, FilterError, Result, Spanned, Tok};

pub fn parse(input: &str) -> Result<Expr> {
    let tokens = lex(input)?;
    if tokens.is_empty() {
        return Err(FilterError::new("the filter is empty", 0..1));
    }
    let mut p = Parser {
        tokens: &tokens,
        pos: 0,
        end: input.len(),
        depth: 0,
    };
    let expr = p.or_expr()?;
    if let Some(t) = p.peek_spanned() {
        return Err(FilterError::new(
            format!(
                "unexpected {} after the end of the filter",
                t.tok.describe()
            ),
            t.span.clone(),
        ));
    }
    Ok(expr)
}

/// How deeply `!` and parentheses may nest. Every level is a stack frame in
/// the parser and again in whatever later walks the tree, so it is capped
/// and reported as an ordinary error rather than left to overflow the stack.
/// Real filters do not come close; the fuzzer reached it immediately.
const MAX_DEPTH: u32 = 64;

struct Parser<'a> {
    tokens: &'a [Spanned],
    pos: usize,
    /// Offset just past the input, for errors that point at "the end".
    end: usize,
    /// Current nesting of `!` and parentheses.
    depth: u32,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Tok> {
        self.tokens.get(self.pos).map(|s| &s.tok)
    }

    fn peek_spanned(&self) -> Option<&'a Spanned> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&'a Spanned> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, want: &Tok) -> bool {
        if self.peek() == Some(want) {
            self.pos += 1;
            return true;
        }
        false
    }

    /// The span to blame when input runs out.
    fn eof_span(&self) -> std::ops::Range<usize> {
        self.tokens
            .last()
            .map(|s| s.span.end..s.span.end + 1)
            .unwrap_or(self.end..self.end + 1)
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<&'a Spanned> {
        match self.peek_spanned() {
            Some(s) if s.tok == *want => {
                self.pos += 1;
                Ok(s)
            }
            Some(s) => Err(FilterError::new(
                format!("expected {what}, found {}", s.tok.describe()),
                s.span.clone(),
            )),
            None => Err(FilterError::new(
                format!("expected {what}, but the filter ends here"),
                self.eof_span(),
            )),
        }
    }

    /// Enter one level of nesting, or refuse. `span` is blamed in the error.
    fn descend(&mut self, span: std::ops::Range<usize>) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FilterError::new(
                format!("the filter nests more than {MAX_DEPTH} levels deep"),
                span,
            ));
        }
        Ok(())
    }

    fn or_expr(&mut self) -> Result<Expr> {
        let first = self.and_expr()?;
        if self.peek() != Some(&Tok::Or) {
            return Ok(first);
        }
        let mut parts = vec![first];
        while self.eat(&Tok::Or) {
            parts.push(self.and_expr()?);
        }
        Ok(Expr::Or(parts))
    }

    fn and_expr(&mut self) -> Result<Expr> {
        let first = self.unary()?;
        if self.peek() != Some(&Tok::And) {
            return Ok(first);
        }
        let mut parts = vec![first];
        while self.eat(&Tok::And) {
            parts.push(self.unary()?);
        }
        Ok(Expr::And(parts))
    }

    fn unary(&mut self) -> Result<Expr> {
        if let Some(s) = self.peek_spanned() {
            if s.tok == Tok::Not {
                let span = s.span.clone();
                self.pos += 1;
                self.descend(span)?;
                let inner = self.unary()?;
                self.depth -= 1;
                return Ok(Expr::Not(Box::new(inner)));
            }
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr> {
        let Some(s) = self.peek_spanned() else {
            return Err(FilterError::new(
                "expected a field or `(`, but the filter ends here",
                self.eof_span(),
            ));
        };
        if s.tok == Tok::LParen {
            let span = s.span.clone();
            self.pos += 1;
            self.descend(span)?;
            let inner = self.or_expr()?;
            self.expect(&Tok::RParen, "`)` to close the group")?;
            self.depth -= 1;
            return Ok(inner);
        }
        let Tok::Field(name) = &s.tok else {
            let hint = match &s.tok {
                Tok::Number(_) | Tok::Signed(_) | Tok::Str(_) | Tok::Bytes(_) => {
                    " (a comparison starts with a field name, not a value)"
                }
                _ => "",
            };
            return Err(FilterError::new(
                format!("expected a field name, found {}{hint}", s.tok.describe()),
                s.span.clone(),
            ));
        };
        let field_span = s.span.clone();
        self.pos += 1;
        let slice = self.slice()?;
        let end = self
            .tokens
            .get(self.pos.wrapping_sub(1))
            .map_or(field_span.end, |t| t.span.end);
        let field = FieldRef {
            name: name.clone(),
            slice,
            span: field_span.start..end,
        };

        let op = match self.peek() {
            Some(Tok::Eq) => Some(CmpOp::Eq),
            Some(Tok::Ne) => Some(CmpOp::Ne),
            Some(Tok::Gt) => Some(CmpOp::Gt),
            Some(Tok::Ge) => Some(CmpOp::Ge),
            Some(Tok::Lt) => Some(CmpOp::Lt),
            Some(Tok::Le) => Some(CmpOp::Le),
            Some(Tok::Contains) => Some(CmpOp::Contains),
            Some(Tok::Matches) => Some(CmpOp::Matches),
            _ => None,
        };
        if let Some(op) = op {
            self.pos += 1;
            let value = self.literal()?;
            return Ok(Expr::Compare { field, op, value });
        }
        if self.eat(&Tok::In) {
            self.expect(&Tok::LBrace, "`{` to open the set")?;
            let mut values = Vec::new();
            loop {
                values.push(self.literal()?);
                if self.eat(&Tok::Comma) {
                    continue;
                }
                self.expect(&Tok::RBrace, "`,` or `}` to close the set")?;
                break;
            }
            return Ok(Expr::In { field, values });
        }
        Ok(Expr::Present(field))
    }

    /// An optional `[offset]`, `[offset:len]`, `[offset:]` or `[:len]`.
    fn slice(&mut self) -> Result<Option<Slice>> {
        if !self.eat(&Tok::LBracket) {
            return Ok(None);
        }
        let offset = match self.peek() {
            Some(Tok::Number(n)) => {
                let n = *n as usize;
                self.pos += 1;
                n
            }
            Some(Tok::Colon) => 0,
            _ => {
                return Err(match self.peek_spanned() {
                    Some(s) => FilterError::new(
                        format!("expected a slice offset, found {}", s.tok.describe()),
                        s.span.clone(),
                    ),
                    None => FilterError::new(
                        "expected a slice offset, but the filter ends here",
                        self.eof_span(),
                    ),
                })
            }
        };
        let len = if self.eat(&Tok::Colon) {
            match self.peek() {
                Some(Tok::Number(n)) => {
                    let n = *n as usize;
                    self.pos += 1;
                    Some(n)
                }
                // `[2:]` runs to the end of the field.
                _ => None,
            }
        } else {
            Some(1)
        };
        if let Some(0) = len {
            if let Some(s) = self.peek_spanned() {
                return Err(FilterError::new(
                    "a slice cannot have length 0",
                    s.span.clone(),
                ));
            }
        }
        self.expect(&Tok::RBracket, "`]` to close the slice")?;
        Ok(Some(Slice { offset, len }))
    }

    fn literal(&mut self) -> Result<SpannedLiteral> {
        let Some(s) = self.next() else {
            return Err(FilterError::new(
                "expected a value, but the filter ends here",
                self.eof_span(),
            ));
        };
        let value = match &s.tok {
            Tok::Number(n) => Literal::Unsigned(*n),
            Tok::Signed(n) => Literal::Signed(*n),
            Tok::Str(v) => Literal::Str(v.clone()),
            Tok::Bytes(b) => Literal::Bytes(b.clone()),
            Tok::Ipv4(a) => Literal::Ipv4(*a),
            Tok::Ipv4Cidr(a, b) => Literal::Ipv4Cidr(*a, *b),
            Tok::Ipv6(a) => Literal::Ipv6(*a),
            Tok::Ipv6Cidr(a, b) => Literal::Ipv6Cidr(*a, *b),
            Tok::Bool(b) => Literal::Bool(*b),
            Tok::Field(name) => {
                return Err(FilterError::new(
                    format!(
                        "expected a value, found field `{name}`; \
                         comparing two fields is not supported"
                    ),
                    s.span.clone(),
                ))
            }
            other => {
                return Err(FilterError::new(
                    format!("expected a value, found {}", other.describe()),
                    s.span.clone(),
                ))
            }
        };
        Ok(SpannedLiteral {
            value,
            span: s.span.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(e: &Expr) -> &FieldRef {
        match e {
            Expr::Present(f) | Expr::Compare { field: f, .. } | Expr::In { field: f, .. } => f,
            _ => panic!("not a leaf"),
        }
    }

    #[test]
    fn presence_and_comparison() {
        let e = parse("tcp").expect("parse");
        assert_eq!(field(&e).name, "tcp");
        let e = parse("tcp.port == 443").expect("parse");
        match &e {
            Expr::Compare { field, op, value } => {
                assert_eq!(field.name, "tcp.port");
                assert_eq!(*op, CmpOp::Eq);
                assert_eq!(value.value, Literal::Unsigned(443));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn precedence_is_or_then_and_then_not() {
        // a || b && c parses as a || (b && c)
        let e = parse("arp || tcp && udp").expect("parse");
        match &e {
            Expr::Or(parts) => {
                assert_eq!(parts.len(), 2);
                assert_eq!(field(&parts[0]).name, "arp");
                assert!(matches!(parts[1], Expr::And(..)));
            }
            other => panic!("{other:?}"),
        }
        // !a && b parses as (!a) && b
        let e = parse("!arp && tcp").expect("parse");
        match &e {
            Expr::And(parts) => {
                assert_eq!(parts.len(), 2);
                assert!(matches!(parts[0], Expr::Not(_)));
                assert_eq!(field(&parts[1]).name, "tcp");
            }
            other => panic!("{other:?}"),
        }
        // Parentheses override.
        let e = parse("(arp || tcp) && udp").expect("parse");
        assert!(matches!(e, Expr::And(..)));
        // `!` binds tighter than a comparison's operands are consumed.
        let e = parse("!(tcp.port == 443)").expect("parse");
        assert!(matches!(e, Expr::Not(_)));
    }

    #[test]
    fn a_chain_of_the_same_operator_is_one_flat_node() {
        // Not a left-leaning tree: the depth of `a || b || ... ` must not
        // grow with the number of operands, because every walk of the tree
        // is recursive.
        match parse("arp || tcp || udp || dns || icmp").expect("parse") {
            Expr::Or(parts) => assert_eq!(parts.len(), 5),
            other => panic!("{other:?}"),
        }
        match parse("arp && tcp && udp").expect("parse") {
            Expr::And(parts) => assert_eq!(parts.len(), 3),
            other => panic!("{other:?}"),
        }
        // Mixed operators still nest, at one level per precedence change.
        match parse("a.b || c.d && e.f || g.h").expect("parse") {
            Expr::Or(parts) => {
                assert_eq!(parts.len(), 3);
                assert!(matches!(parts[1], Expr::And(..)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nesting_is_capped_rather_than_overflowing_the_stack() {
        // The fuzzer reached this in seconds with `!!!!...` and `((((...`.
        let deep_not = "!".repeat(MAX_DEPTH as usize + 1) + "tcp";
        let e = parse(&deep_not).expect_err("should be refused");
        assert!(e.message.contains("nests more than"), "{}", e.message);
        assert!(e.column < deep_not.len());

        let depth = MAX_DEPTH as usize + 1;
        let deep_paren = "(".repeat(depth) + "tcp" + &")".repeat(depth);
        let e = parse(&deep_paren).expect_err("should be refused");
        assert!(e.message.contains("nests more than"), "{}", e.message);

        // Just inside the cap still parses, so the limit is not off by one
        // in the direction that rejects real filters.
        let ok = "!".repeat(MAX_DEPTH as usize) + "tcp";
        assert!(parse(&ok).is_ok());

        // Nesting is depth, not count: a long flat chain is fine.
        let long_chain = (0..500)
            .map(|_| "tcp")
            .collect::<Vec<_>>()
            .join(" || ");
        assert!(parse(&long_chain).is_ok());

        // And parentheses closed before the next one opens do not accumulate.
        let wide = (0..500)
            .map(|_| "(tcp)")
            .collect::<Vec<_>>()
            .join(" || ");
        assert!(parse(&wide).is_ok());
    }

    #[test]
    fn word_operators_are_accepted() {
        assert!(matches!(parse("arp or tcp").expect("parse"), Expr::Or(_)));
        assert!(matches!(
            parse("arp and tcp").expect("parse"),
            Expr::And(_)
        ));
        assert!(matches!(parse("not arp").expect("parse"), Expr::Not(_)));
    }

    #[test]
    fn slices_parse_in_every_form() {
        let s = |text: &str| field(&parse(text).expect("parse")).slice;
        assert_eq!(
            s("eth.src[0]"),
            Some(Slice {
                offset: 0,
                len: Some(1)
            })
        );
        assert_eq!(
            s("eth.src[0:3]"),
            Some(Slice {
                offset: 0,
                len: Some(3)
            })
        );
        assert_eq!(
            s("eth.src[2:]"),
            Some(Slice {
                offset: 2,
                len: None
            })
        );
        assert_eq!(
            s("eth.src[:4]"),
            Some(Slice {
                offset: 0,
                len: Some(4)
            })
        );
        assert_eq!(s("eth.src"), None);
    }

    #[test]
    fn sets_parse() {
        let e = parse("tcp.port in {80, 443, 8080}").expect("parse");
        match e {
            Expr::In { field, values } => {
                assert_eq!(field.name, "tcp.port");
                assert_eq!(values.len(), 3);
                assert_eq!(values[2].value, Literal::Unsigned(8080));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn errors_point_at_the_right_column() {
        let e = parse("tcp.port ==").expect_err("should fail");
        assert!(e.message.contains("ends here"), "{}", e.message);
        assert_eq!(e.column, 11);

        let e = parse("(tcp").expect_err("should fail");
        assert!(e.message.contains("`)`"), "{}", e.message);

        let e = parse("443 == tcp.port").expect_err("should fail");
        assert_eq!(e.column, 0);
        assert!(e.message.contains("field name"), "{}", e.message);

        let e = parse("tcp.port == udp.port").expect_err("should fail");
        assert_eq!(e.column, 12);
        assert!(e.message.contains("two fields"), "{}", e.message);

        let e = parse("tcp udp").expect_err("should fail");
        assert_eq!(e.column, 4);
        assert!(e.message.contains("after the end"), "{}", e.message);

        let e = parse("tcp.port in 80").expect_err("should fail");
        assert!(e.message.contains("`{`"), "{}", e.message);

        let e = parse("").expect_err("should fail");
        assert!(e.message.contains("empty"), "{}", e.message);
    }
}
