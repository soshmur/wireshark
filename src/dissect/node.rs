//! The dissection tree. Every node carries the byte range it was decoded from;
//! the hex pane highlights from it and the filter engine reads from it.

use std::fmt;
use std::ops::Range;

/// A typed field value. `Bytes` has no payload because the bytes are the
/// node's `range` within the frame; evaluators read them from the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A pure container (protocol or group) with no value of its own.
    None,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Str(String),
    Bytes,
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Mac([u8; 6]),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None | Value::Bytes => Ok(()),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Unsigned(u) => write!(f, "{u}"),
            Value::Signed(i) => write!(f, "{i}"),
            Value::Str(s) => f.write_str(s),
            Value::Ipv4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Value::Ipv6(a) => f.write_str(&std::net::Ipv6Addr::from(*a).to_string()),
            Value::Mac(m) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Text shown in the detail tree.
    pub label: String,
    /// Filter field name (`tcp.srcport`); protocols use their bare name (`tcp`).
    pub abbrev: &'static str,
    /// Byte range within the frame this node was decoded from.
    pub range: Range<usize>,
    pub value: Value,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(
        abbrev: &'static str,
        label: impl Into<String>,
        range: Range<usize>,
        value: Value,
    ) -> Node {
        Node {
            label: label.into(),
            abbrev,
            range,
            value,
            children: Vec::new(),
        }
    }

    pub fn with_children(mut self, children: Vec<Node>) -> Node {
        self.children = children;
        self
    }

    /// Rough heap footprint, used for the ring buffer's byte accounting.
    pub fn approx_size(&self) -> usize {
        let own = std::mem::size_of::<Node>()
            + self.label.len()
            + match &self.value {
                Value::Str(s) => s.len(),
                _ => 0,
            };
        own + self.children.iter().map(Node::approx_size).sum::<usize>()
    }

    /// Depth-first walk of this node and all descendants.
    pub fn walk<'a>(&'a self, f: &mut impl FnMut(&'a Node, usize)) {
        fn go<'a>(n: &'a Node, depth: usize, f: &mut impl FnMut(&'a Node, usize)) {
            f(n, depth);
            for c in &n.children {
                go(c, depth + 1, f);
            }
        }
        go(self, 0, f);
    }

    /// The innermost node whose range covers `offset`, preferring deeper nodes.
    pub fn innermost_at(&self, offset: usize) -> Option<&Node> {
        if !self.range.contains(&offset) {
            return None;
        }
        self.children
            .iter()
            .find_map(|c| c.innermost_at(offset))
            .or(Some(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn innermost_prefers_deepest_child() {
        let leaf = Node::new("a.b.c", "leaf", 4..6, Value::Unsigned(1));
        let mid = Node::new("a.b", "mid", 2..8, Value::None).with_children(vec![leaf]);
        let root = Node::new("a", "root", 0..10, Value::None).with_children(vec![mid]);
        assert_eq!(root.innermost_at(5).map(|n| n.abbrev), Some("a.b.c"));
        assert_eq!(root.innermost_at(7).map(|n| n.abbrev), Some("a.b"));
        assert_eq!(root.innermost_at(1).map(|n| n.abbrev), Some("a"));
        assert_eq!(root.innermost_at(10), None);
    }

    #[test]
    fn value_display() {
        assert_eq!(
            Value::Mac([0xde, 0xad, 0xbe, 0xef, 0, 1]).to_string(),
            "de:ad:be:ef:00:01"
        );
        assert_eq!(Value::Ipv4([10, 0, 0, 1]).to_string(), "10.0.0.1");
        assert_eq!(Value::Ipv6([0; 16]).to_string(), "::");
    }
}
