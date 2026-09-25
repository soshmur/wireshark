//! The dissection tree.
//!
//! Dissectors write nodes straight into a `TreeBuilder`: a flat, depth-first
//! array of 28-byte records plus a byte arena for strings. There is no
//! intermediate pointer tree, so a frame costs two allocations rather than one
//! per protocol subtree. Every node carries the byte range it was decoded
//! from; the hex pane highlights from it and the filter engine reads from it.
//!
//! Labels are not stored: a node holds its field id and typed value, and the
//! display label is formatted on demand from the field registry
//! (`registry::label`). Nodes that need free text (malformed reasons, option
//! summaries) carry it in `text`, which overrides the formatted label.

use std::fmt::{self, Write as _};
use std::ops::Range;

use super::registry;

/// Index of the byte buffer a node's `range` refers to.
/// `0` is always the captured frame; reassembly adds further sources.
pub type SourceId = u8;

/// A typed field value. `Bytes` has no payload because the bytes are the
/// node's `range` within its data source; evaluators read them from there.
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
            Value::Ipv4(a) => f.write_str(&fmt_ipv4(*a)),
            Value::Ipv6(a) => f.write_str(&std::net::Ipv6Addr::from(*a).to_string()),
            Value::Mac(m) => f.write_str(&fmt_mac(*m)),
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `aa:bb:cc:dd:ee:ff` without going through `fmt`.
pub fn fmt_mac(m: [u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in m.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0xf)] as char);
    }
    s
}

/// Dotted quad without going through `fmt`.
pub fn fmt_ipv4(a: [u8; 4]) -> String {
    let mut s = String::with_capacity(15);
    for (i, b) in a.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        let b = *b;
        if b >= 100 {
            s.push((b'0' + b / 100) as char);
        }
        if b >= 10 {
            s.push((b'0' + (b / 10) % 10) as char);
        }
        s.push((b'0' + b % 10) as char);
    }
    s
}

pub fn fmt_ipv6(a: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(a).to_string()
}

// ---- storage --------------------------------------------------------------

const TAG_NONE: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_UNSIGNED: u8 = 2;
const TAG_SIGNED: u8 = 3;
const TAG_STR: u8 = 4;
const TAG_BYTES: u8 = 5;
const TAG_IPV4: u8 = 6;
const TAG_IPV6: u8 = 7;
const TAG_MAC: u8 = 8;

/// One flattened node. 28 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TreeNode {
    field: u16,
    depth: u8,
    source: SourceId,
    tag: u8,
    _pad: u8,
    text_len: u16,
    start: u32,
    len: u32,
    text_off: u32,
    /// Inline scalar, or `(offset, len)` into the arena for `Str`/`Ipv6`.
    payload: [u8; 8],
}

/// Handle to a node already written, so its range, text or value can be
/// corrected once the dissector knows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId(u32);

/// A frame's dissection tree in flattened, depth-first form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tree {
    nodes: Box<[TreeNode]>,
    arena: Box<[u8]>,
}

/// A view of one node in a `Tree`.
#[derive(Debug, Clone, Copy)]
pub struct NodeRef<'a> {
    tree: &'a Tree,
    index: usize,
}

// ---- building -------------------------------------------------------------

/// Lets `write!` append UTF-8 straight into the arena.
struct ArenaWriter<'a>(&'a mut Vec<u8>);

impl fmt::Write for ArenaWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Writes nodes in depth-first order. `begin`/`end` bracket a container;
/// `leaf` adds a field at the current depth.
#[derive(Debug, Default)]
pub struct TreeBuilder {
    nodes: Vec<TreeNode>,
    arena: Vec<u8>,
    depth: u8,
    /// Largest `range.end` written for data source 0, so the driver can tell
    /// which trailing bytes no layer claimed.
    max_end_source0: usize,
}

impl TreeBuilder {
    pub fn new() -> TreeBuilder {
        TreeBuilder {
            // A typical Ethernet/IPv4/TCP frame is ~66 nodes.
            nodes: Vec::with_capacity(80),
            arena: Vec::with_capacity(128),
            depth: 0,
            max_end_source0: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Handle of the node that will be written next.
    pub fn next_id(&self) -> NodeId {
        NodeId(self.nodes.len() as u32)
    }

    /// The furthest byte of data source 0 any node covers.
    pub fn max_end(&self) -> usize {
        self.max_end_source0
    }

    /// Set a node's range to span every node written at or after it, in the
    /// same data source. The driver uses this on a layer whose dissector
    /// returned early, so the layer still covers the fields it did parse.
    pub fn fit_range(&mut self, id: NodeId) {
        let i = id.0 as usize;
        let Some(node) = self.nodes.get(i) else {
            return;
        };
        let source = node.source;
        let end = self.nodes[i..]
            .iter()
            .filter(|n| n.source == source)
            .map(|n| n.start as usize + n.len as usize)
            .max()
            .unwrap_or(0);
        self.set_end(id, end);
    }

    /// Forget the watermark. The driver calls this after writing the `frame`
    /// pseudo-layer, whose range spans the whole frame by definition and
    /// would otherwise hide unclaimed trailing bytes.
    pub fn reset_max_end(&mut self) {
        self.max_end_source0 = 0;
    }

    fn push(
        &mut self,
        abbrev: &'static str,
        source: SourceId,
        range: Range<usize>,
        value: &Value,
    ) -> NodeId {
        let mut payload = [0u8; 8];
        let tag = match value {
            Value::None => TAG_NONE,
            Value::Bool(b) => {
                payload[0] = u8::from(*b);
                TAG_BOOL
            }
            Value::Unsigned(u) => {
                payload = u.to_le_bytes();
                TAG_UNSIGNED
            }
            Value::Signed(i) => {
                payload = i.to_le_bytes();
                TAG_SIGNED
            }
            Value::Str(s) => {
                payload = self.intern(s.as_bytes());
                TAG_STR
            }
            Value::Bytes => TAG_BYTES,
            Value::Ipv4(a) => {
                payload[..4].copy_from_slice(a);
                TAG_IPV4
            }
            Value::Ipv6(a) => {
                payload = self.intern(a);
                TAG_IPV6
            }
            Value::Mac(m) => {
                payload[..6].copy_from_slice(m);
                TAG_MAC
            }
        };
        if source == 0 {
            self.max_end_source0 = self.max_end_source0.max(range.end);
        }
        let id = NodeId(self.nodes.len() as u32);
        self.nodes.push(TreeNode {
            field: registry::field_id(abbrev),
            depth: self.depth,
            source,
            tag,
            _pad: 0,
            text_len: 0,
            start: range.start.min(u32::MAX as usize) as u32,
            len: range.len().min(u32::MAX as usize) as u32,
            text_off: 0,
            payload,
        });
        id
    }

    fn intern(&mut self, bytes: &[u8]) -> [u8; 8] {
        let off = self.arena.len() as u32;
        self.arena.extend_from_slice(bytes);
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&off.to_le_bytes());
        p[4..].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        p
    }

    /// Add a field at the current depth.
    pub fn leaf(
        &mut self,
        abbrev: &'static str,
        source: SourceId,
        range: Range<usize>,
        value: Value,
    ) -> NodeId {
        self.push(abbrev, source, range, &value)
    }

    /// Open a container; nodes added until `end` are its children.
    pub fn begin(&mut self, abbrev: &'static str, source: SourceId, range: Range<usize>) -> NodeId {
        self.begin_value(abbrev, source, range, Value::None)
    }

    /// Open a container that also carries a value of its own, such as a flags
    /// byte whose bits are its children.
    pub fn begin_value(
        &mut self,
        abbrev: &'static str,
        source: SourceId,
        range: Range<usize>,
        value: Value,
    ) -> NodeId {
        let id = self.push(abbrev, source, range, &value);
        self.depth = self.depth.saturating_add(1);
        id
    }

    /// Close the most recently opened container.
    pub fn end(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Restore the nesting depth, after a dissector returned early from
    /// inside one or more open containers.
    pub fn set_depth(&mut self, depth: u8) {
        self.depth = depth;
    }

    /// Close a container and correct its range to what it actually covered.
    pub fn end_at(&mut self, id: NodeId, end: usize) {
        self.end();
        self.set_end(id, end);
    }

    /// Correct a node's range end (its start is unchanged).
    pub fn set_end(&mut self, id: NodeId, end: usize) {
        if let Some(n) = self.nodes.get_mut(id.0 as usize) {
            let start = n.start as usize;
            n.len = end.saturating_sub(start).min(u32::MAX as usize) as u32;
            if n.source == 0 {
                self.max_end_source0 = self.max_end_source0.max(end);
            }
        }
    }

    /// Give a node a free-text label, overriding the registry's format.
    pub fn set_text(&mut self, id: NodeId, text: &str) {
        let p = self.intern(text.as_bytes());
        if let Some(n) = self.nodes.get_mut(id.0 as usize) {
            n.text_off = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
            n.text_len = text.len().min(u16::MAX as usize) as u16;
        }
    }

    /// Format a label directly into the arena, with no intermediate `String`.
    pub fn set_text_args(&mut self, id: NodeId, args: fmt::Arguments<'_>) {
        let off = self.arena.len();
        let _ = ArenaWriter(&mut self.arena).write_fmt(args);
        let len = self.arena.len() - off;
        if let Some(n) = self.nodes.get_mut(id.0 as usize) {
            n.text_off = off.min(u32::MAX as usize) as u32;
            n.text_len = len.min(u16::MAX as usize) as u16;
        }
    }

    /// Replace a node's string value with `parts` joined by `sep`, written
    /// straight into the arena. Used to patch `frame.protocols`, which is
    /// known only once every layer has run.
    pub fn set_str_joined(&mut self, id: NodeId, parts: &[&str], sep: u8) {
        let off = self.arena.len() as u32;
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                self.arena.push(sep);
            }
            self.arena.extend_from_slice(part.as_bytes());
        }
        let len = self.arena.len() as u32 - off;
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&off.to_le_bytes());
        p[4..].copy_from_slice(&len.to_le_bytes());
        if let Some(n) = self.nodes.get_mut(id.0 as usize) {
            n.tag = TAG_STR;
            n.payload = p;
        }
    }

    pub fn finish(self) -> Tree {
        Tree {
            nodes: self.nodes.into_boxed_slice(),
            arena: self.arena.into_boxed_slice(),
        }
    }
}

impl Tree {
    /// Build a tree with a closure, for tests and small fixtures.
    pub fn build(f: impl FnOnce(&mut TreeBuilder)) -> Tree {
        let mut b = TreeBuilder::new();
        f(&mut b);
        b.finish()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Approximate heap footprint.
    pub fn approx_size(&self) -> usize {
        self.nodes.len() * std::mem::size_of::<TreeNode>() + self.arena.len()
    }

    pub fn get(&self, index: usize) -> Option<NodeRef<'_>> {
        (index < self.nodes.len()).then_some(NodeRef { tree: self, index })
    }

    /// All nodes in depth-first order.
    pub fn iter(&self) -> impl Iterator<Item = NodeRef<'_>> + '_ {
        (0..self.nodes.len()).map(move |index| NodeRef { tree: self, index })
    }

    /// Top-level nodes (depth 0).
    pub fn roots(&self) -> impl Iterator<Item = NodeRef<'_>> + '_ {
        self.iter().filter(|n| n.depth() == 0)
    }

    /// The innermost node in `source` whose non-empty range covers `offset`.
    pub fn innermost_at(&self, source: SourceId, offset: usize) -> Option<NodeRef<'_>> {
        let mut best: Option<(u8, usize, usize)> = None; // (depth, len, index)
        for (i, n) in self.nodes.iter().enumerate() {
            if n.source != source || n.len == 0 {
                continue;
            }
            let (s, e) = (n.start as usize, n.start as usize + n.len as usize);
            if offset < s || offset >= e {
                continue;
            }
            let better = match best {
                None => true,
                Some((d, l, _)) => n.depth > d || (n.depth == d && (n.len as usize) < l),
            };
            if better {
                best = Some((n.depth, n.len as usize, i));
            }
        }
        best.map(|(_, _, index)| NodeRef { tree: self, index })
    }

    /// Nodes whose field is `abbrev`, in tree order.
    pub fn find<'a>(&'a self, abbrev: &str) -> impl Iterator<Item = NodeRef<'a>> + 'a {
        let id = registry::field_id_if_known(abbrev);
        self.iter().filter(move |n| Some(n.node().field) == id)
    }
}

impl<'a> NodeRef<'a> {
    fn node(&self) -> &'a TreeNode {
        &self.tree.nodes[self.index]
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn abbrev(&self) -> &'static str {
        registry::field_abbrev(self.node().field)
    }

    pub fn field_id(&self) -> u16 {
        self.node().field
    }

    pub fn depth(&self) -> u8 {
        self.node().depth
    }

    pub fn source(&self) -> SourceId {
        self.node().source
    }

    pub fn range(&self) -> Range<usize> {
        let n = self.node();
        n.start as usize..n.start as usize + n.len as usize
    }

    pub fn text(&self) -> Option<&'a str> {
        let n = self.node();
        if n.text_len == 0 {
            return None;
        }
        let r = n.text_off as usize..n.text_off as usize + n.text_len as usize;
        self.tree
            .arena
            .get(r)
            .and_then(|b| std::str::from_utf8(b).ok())
    }

    fn arena_slice(&self) -> &'a [u8] {
        let p = self.node().payload;
        let off = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
        let len = u32::from_le_bytes([p[4], p[5], p[6], p[7]]) as usize;
        self.tree.arena.get(off..off + len).unwrap_or(&[])
    }

    /// The value, reconstructed (strings are copied).
    pub fn value(&self) -> Value {
        let n = self.node();
        let p = n.payload;
        match n.tag {
            TAG_BOOL => Value::Bool(p[0] != 0),
            TAG_UNSIGNED => Value::Unsigned(u64::from_le_bytes(p)),
            TAG_SIGNED => Value::Signed(i64::from_le_bytes(p)),
            TAG_STR => Value::Str(String::from_utf8_lossy(self.arena_slice()).into_owned()),
            TAG_BYTES => Value::Bytes,
            TAG_IPV4 => Value::Ipv4([p[0], p[1], p[2], p[3]]),
            TAG_IPV6 => {
                let mut a = [0u8; 16];
                let s = self.arena_slice();
                if s.len() == 16 {
                    a.copy_from_slice(s);
                }
                Value::Ipv6(a)
            }
            TAG_MAC => Value::Mac([p[0], p[1], p[2], p[3], p[4], p[5]]),
            _ => Value::None,
        }
    }

    /// The string value without copying, if this is a `Str`.
    pub fn str_value(&self) -> Option<&'a str> {
        (self.node().tag == TAG_STR)
            .then(|| std::str::from_utf8(self.arena_slice()).ok())
            .flatten()
    }

    pub fn unsigned(&self) -> Option<u64> {
        let n = self.node();
        (n.tag == TAG_UNSIGNED).then(|| u64::from_le_bytes(n.payload))
    }

    pub fn is_container(&self) -> bool {
        self.node().tag == TAG_NONE
    }

    /// `true` when the next node is a child of this one.
    pub fn has_children(&self) -> bool {
        self.tree
            .nodes
            .get(self.index + 1)
            .is_some_and(|n| n.depth > self.node().depth)
    }

    /// Direct children, in order.
    pub fn children(&self) -> impl Iterator<Item = NodeRef<'a>> + 'a {
        let tree = self.tree;
        let depth = self.node().depth;
        let start = self.index + 1;
        tree.nodes[start..]
            .iter()
            .enumerate()
            .take_while(move |(_, n)| n.depth > depth)
            .filter(move |(_, n)| n.depth == depth + 1)
            .map(move |(i, _)| NodeRef {
                tree,
                index: start + i,
            })
    }

    /// Index one past the last descendant.
    pub fn subtree_end(&self) -> usize {
        let depth = self.node().depth;
        let mut i = self.index + 1;
        while i < self.tree.nodes.len() && self.tree.nodes[i].depth > depth {
            i += 1;
        }
        i
    }

    /// First direct child with field `abbrev`.
    pub fn child(&self, abbrev: &str) -> Option<NodeRef<'a>> {
        let id = registry::field_id_if_known(abbrev)?;
        self.children().find(|c| c.node().field == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Tree {
        Tree::build(|b| {
            let eth = b.begin("eth", 0, 0..14);
            b.leaf("eth.src", 0, 6..12, Value::Mac([1, 2, 3, 4, 5, 6]));
            b.end_at(eth, 14);
            let tcp = b.begin("tcp", 0, 0..10);
            b.leaf("tcp.srcport", 0, 4..6, Value::Unsigned(443));
            let flags = b.begin("tcp.flags", 0, 2..4);
            b.leaf("tcp.flags.syn", 0, 2..4, Value::Bool(true));
            b.end();
            let _ = flags;
            b.end_at(tcp, 10);
        })
    }

    #[test]
    fn builds_depth_first_with_structure() {
        let t = sample();
        let order: Vec<(&str, u8)> = t.iter().map(|n| (n.abbrev(), n.depth())).collect();
        assert_eq!(
            order,
            [
                ("eth", 0),
                ("eth.src", 1),
                ("tcp", 0),
                ("tcp.srcport", 1),
                ("tcp.flags", 1),
                ("tcp.flags.syn", 2)
            ]
        );
        let tcp = t.get(2).unwrap();
        let kids: Vec<&str> = tcp.children().map(|c| c.abbrev()).collect();
        assert_eq!(kids, ["tcp.srcport", "tcp.flags"]);
        assert_eq!(tcp.subtree_end(), 6);
        assert!(tcp.has_children());
        assert!(!t.get(3).unwrap().has_children());
        assert_eq!(
            tcp.child("tcp.srcport").and_then(|n| n.unsigned()),
            Some(443)
        );
        assert_eq!(tcp.range(), 0..10);
    }

    #[test]
    fn values_round_trip() {
        let t = Tree::build(|b| {
            let id = b.leaf("dns.qry.name", 0, 0..3, Value::Str("example.com".into()));
            b.set_text(id, "hello");
            b.leaf("ipv6.src", 0, 0..16, Value::Ipv6([1; 16]));
            b.leaf("ip.ttl", 0, 0..1, Value::Signed(-5));
            b.leaf("data.data", 0, 0..4, Value::Bytes);
        });
        assert_eq!(t.get(0).unwrap().value(), Value::Str("example.com".into()));
        assert_eq!(t.get(0).unwrap().str_value(), Some("example.com"));
        assert_eq!(t.get(0).unwrap().text(), Some("hello"));
        assert_eq!(t.get(1).unwrap().value(), Value::Ipv6([1; 16]));
        assert_eq!(t.get(2).unwrap().value(), Value::Signed(-5));
        assert_eq!(t.get(3).unwrap().value(), Value::Bytes);
        assert_eq!(t.get(3).unwrap().range(), 0..4);
        assert_eq!(std::mem::size_of::<TreeNode>(), 28);
    }

    #[test]
    fn end_at_and_set_end_correct_ranges() {
        let t = Tree::build(|b| {
            let id = b.begin("tcp", 0, 5..5);
            b.leaf("tcp.srcport", 0, 5..7, Value::Unsigned(1));
            b.end_at(id, 25);
            assert_eq!(b.depth(), 0);
            assert_eq!(b.max_end(), 25);
        });
        assert_eq!(t.get(0).unwrap().range(), 5..25);
    }

    #[test]
    fn innermost_prefers_deepest_then_smallest() {
        let t = sample();
        assert_eq!(
            t.innermost_at(0, 3).map(|n| n.abbrev()),
            Some("tcp.flags.syn")
        );
        assert_eq!(
            t.innermost_at(0, 5).map(|n| n.abbrev()),
            Some("tcp.srcport")
        );
        assert_eq!(t.innermost_at(0, 8).map(|n| n.abbrev()), Some("eth.src"));
        assert_eq!(t.innermost_at(0, 13).map(|n| n.abbrev()), Some("eth"));
        assert!(t.innermost_at(0, 14).is_none());
        assert!(t.innermost_at(1, 3).is_none());
    }

    #[test]
    fn address_formatters() {
        assert_eq!(fmt_mac([0xde, 0xad, 0xbe, 0xef, 0, 1]), "de:ad:be:ef:00:01");
        assert_eq!(fmt_ipv4([10, 0, 0, 1]), "10.0.0.1");
        assert_eq!(fmt_ipv4([255, 100, 9, 0]), "255.100.9.0");
        assert_eq!(Value::Ipv6([0; 16]).to_string(), "::");
    }
}
