//! The protocol hierarchy: what the capture is made of.
//!
//! Every frame carries the chain of layers it was dissected as —
//! `eth:ip:tcp:http` — and this folds those chains into a tree with counts
//! at every node. A frame contributes to each protocol on its own chain, so
//! the totals at any one depth add up to the capture, and `eth` is always
//! 100% of an Ethernet capture rather than the small remainder left after
//! its children.
//!
//! Two counts per node, and the difference between them is the useful part:
//! *packets* is every frame passing through the protocol, *end packets* is
//! the frames where it was the last one. A high `tcp` with a low `tcp` end
//! count means the payloads were recognised; the reverse means they were
//! not.

use crate::dissect::Frame;

use super::Snapshot;

/// One protocol in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Protocol abbrev, e.g. `tcp`.
    pub name: String,
    /// How deep in the chain, for indenting.
    pub depth: usize,
    /// Frames whose chain includes this protocol at this position.
    pub packets: u64,
    pub bytes: u64,
    /// Frames where this was the last protocol in the chain.
    pub end_packets: u64,
    pub end_bytes: u64,
    /// The full chain up to and including this row, for filtering.
    pub chain: Vec<String>,
}

impl Row {
    /// A display filter selecting the frames this row counts.
    ///
    /// Naming every protocol in the chain, not just the last: `http` alone
    /// would also match HTTP over a different transport, which is not what
    /// the row counted.
    pub fn filter(&self) -> String {
        self.chain.join(" && ")
    }
}

/// The chain a frame was dissected as.
fn chain_of(frame: &Frame) -> Vec<&str> {
    frame
        .tree
        .find("frame.protocols")
        .next()
        .and_then(|n| n.str_value())
        .map(|s| s.split(':').filter(|p| !p.is_empty()).collect())
        .unwrap_or_default()
}

/// Build the hierarchy, depth-first, in first-seen order at each level.
pub fn hierarchy(snapshot: &Snapshot) -> Vec<Row> {
    // A trie built as a flat vector: each node knows its parent, so the
    // depth-first order is produced by one walk at the end.
    #[derive(Debug)]
    struct Node {
        name: String,
        parent: Option<usize>,
        depth: usize,
        packets: u64,
        bytes: u64,
        end_packets: u64,
        end_bytes: u64,
        children: Vec<usize>,
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();

    for frame in snapshot.iter() {
        let chain = chain_of(frame);
        if chain.is_empty() {
            continue;
        }
        let bytes = u64::from(frame.orig_len);
        let mut parent: Option<usize> = None;
        for (depth, name) in chain.iter().enumerate() {
            let siblings = match parent {
                Some(p) => &nodes[p].children,
                None => &roots,
            };
            let found = siblings.iter().copied().find(|i| nodes[*i].name == *name);
            let idx = match found {
                Some(i) => i,
                None => {
                    let i = nodes.len();
                    nodes.push(Node {
                        name: (*name).to_string(),
                        parent,
                        depth,
                        packets: 0,
                        bytes: 0,
                        end_packets: 0,
                        end_bytes: 0,
                        children: Vec::new(),
                    });
                    match parent {
                        Some(p) => nodes[p].children.push(i),
                        None => roots.push(i),
                    }
                    i
                }
            };
            nodes[idx].packets += 1;
            nodes[idx].bytes += bytes;
            if depth + 1 == chain.len() {
                nodes[idx].end_packets += 1;
                nodes[idx].end_bytes += bytes;
            }
            parent = Some(idx);
        }
    }

    // Depth-first, so a row's children follow it and indenting reads as a
    // tree.
    let mut out = Vec::with_capacity(nodes.len());
    let mut stack: Vec<usize> = roots.into_iter().rev().collect();
    while let Some(i) = stack.pop() {
        let mut chain = Vec::new();
        let mut at = Some(i);
        while let Some(j) = at {
            chain.push(nodes[j].name.clone());
            at = nodes[j].parent;
        }
        chain.reverse();
        out.push(Row {
            name: nodes[i].name.clone(),
            depth: nodes[i].depth,
            packets: nodes[i].packets,
            bytes: nodes[i].bytes,
            end_packets: nodes[i].end_packets,
            end_bytes: nodes[i].end_bytes,
            chain,
        });
        for child in nodes[i].children.iter().rev() {
            stack.push(*child);
        }
    }
    out
}

/// Totals for the percentage columns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
}

pub fn totals(snapshot: &Snapshot) -> Totals {
    let mut t = Totals::default();
    for frame in snapshot.iter() {
        t.packets += 1;
        t.bytes += u64::from(frame.orig_len);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, State};
    use crate::store::{Limits, Store};
    use netscope_ffi::LinkType;
    use std::sync::Arc;

    fn store_of(count: u64) -> Arc<Store> {
        let store = Store::new(Limits::default());
        let mut state = State::new();
        let batch: Vec<Arc<crate::dissect::Frame>> = (0..count)
            .map(|i| {
                Arc::new(dissect(
                    LinkType::ETHERNET,
                    i as u32 + 1,
                    crate::synthetic::raw_frame(i),
                    &mut state,
                ))
            })
            .collect();
        store.append(batch);
        store
    }

    #[test]
    fn the_root_accounts_for_every_frame() {
        // If `eth` is not 100% of an Ethernet capture, the tree is counting
        // the remainder after its children rather than the frames through it.
        let store = store_of(20);
        let snap = store.snapshot();
        let rows = hierarchy(&snap);
        let t = totals(&snap);
        assert_eq!(t.packets, 20);
        let eth = rows.iter().find(|r| r.name == "eth").expect("eth");
        assert_eq!(eth.packets, 20);
        assert_eq!(eth.bytes, t.bytes);
        assert_eq!(eth.depth, 0);
    }

    #[test]
    fn a_frame_counts_at_every_layer_of_its_chain() {
        let store = store_of(10);
        let snap = store.snapshot();
        let rows = hierarchy(&snap);
        for name in ["eth", "ip", "tcp"] {
            let row = rows.iter().find(|r| r.name == name).expect(name);
            assert_eq!(row.packets, 10, "{name}");
        }
    }

    #[test]
    fn end_counts_say_where_dissection_stopped() {
        // The generated frames are eth:ip:tcp:data, so tcp is never the end
        // and data always is. That distinction is the point of the column.
        let store = store_of(10);
        let snap = store.snapshot();
        let rows = hierarchy(&snap);
        let tcp = rows.iter().find(|r| r.name == "tcp").expect("tcp");
        let data = rows.iter().find(|r| r.name == "data");
        assert_eq!(tcp.packets, 10);
        assert_eq!(
            tcp.end_packets + data.map_or(0, |d| d.end_packets),
            10,
            "every frame ends somewhere below tcp"
        );
    }

    #[test]
    fn rows_are_depth_first_so_indenting_reads_as_a_tree() {
        let store = store_of(5);
        let snap = store.snapshot();
        let rows = hierarchy(&snap);
        assert!(!rows.is_empty());
        assert_eq!(rows[0].depth, 0);
        // A child never precedes its parent, and depth grows by at most one.
        for pair in rows.windows(2) {
            assert!(
                pair[1].depth <= pair[0].depth + 1,
                "{:?} then {:?}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn the_filter_names_the_whole_chain() {
        // `http` alone would also match HTTP reached another way, which is
        // not the set of frames the row counted.
        let store = store_of(5);
        let snap = store.snapshot();
        let rows = hierarchy(&snap);
        let deep = rows.iter().max_by_key(|r| r.depth).expect("some row");
        assert!(deep.depth > 0);
        let f = deep.filter();
        assert!(f.contains(" && "), "{f}");
        assert!(f.starts_with("eth"), "{f}");
        assert!(crate::filter::compile(&f).is_ok(), "{f}");
    }

    #[test]
    fn an_empty_capture_has_an_empty_hierarchy() {
        let store = Store::new(Limits::default());
        let snap = store.snapshot();
        assert!(hierarchy(&snap).is_empty());
        assert_eq!(totals(&snap), Totals::default());
    }
}
