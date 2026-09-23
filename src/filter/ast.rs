//! The display-filter syntax tree, as the parser produces it and the type
//! checker annotates it.

use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
    Matches,
}

impl CmpOp {
    pub fn name(self) -> &'static str {
        match self {
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Contains => "contains",
            CmpOp::Matches => "matches",
        }
    }

    /// Ordering comparisons need a field type with a total order.
    pub fn is_ordering(self) -> bool {
        matches!(self, CmpOp::Gt | CmpOp::Ge | CmpOp::Lt | CmpOp::Le)
    }
}

/// A byte range taken from a field's own bytes: `eth.src[0:3]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slice {
    pub offset: usize,
    /// `None` means "to the end of the field".
    pub len: Option<usize>,
}

/// The left side of a comparison: a field, optionally sliced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    pub name: String,
    pub slice: Option<Slice>,
    pub span: Range<usize>,
}

/// A literal value, before type checking has matched it to a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    Unsigned(u64),
    Signed(i64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv4Cidr([u8; 4], u8),
    Ipv6([u8; 16]),
    Ipv6Cidr([u8; 16], u8),
    Bool(bool),
}

impl Literal {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Literal::Unsigned(_) => "a number",
            Literal::Signed(_) => "a signed number",
            Literal::Str(_) => "a string",
            Literal::Bytes(b) if b.len() == 6 => "a MAC or byte string",
            Literal::Bytes(_) => "a byte string",
            Literal::Ipv4(_) => "an IPv4 address",
            Literal::Ipv4Cidr(..) => "an IPv4 prefix",
            Literal::Ipv6(_) => "an IPv6 address",
            Literal::Ipv6Cidr(..) => "an IPv6 prefix",
            Literal::Bool(_) => "a boolean",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpannedLiteral {
    pub value: Literal,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A bare field name: true when the frame contains that field.
    Present(FieldRef),
    /// `field op literal`.
    Compare {
        field: FieldRef,
        op: CmpOp,
        value: SpannedLiteral,
    },
    /// `field in { a, b, c }`.
    In {
        field: FieldRef,
        values: Vec<SpannedLiteral>,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}
