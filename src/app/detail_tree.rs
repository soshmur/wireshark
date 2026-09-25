//! The packet detail tree: the flattened dissection tree rendered as an
//! expandable outline. Expansion state is remembered per field name, so
//! opening `tcp.flags` once keeps it open for every frame.

use std::collections::HashSet;

use crate::dissect::{registry, Frame, NodeRef};

#[derive(Debug)]
pub struct TreeState {
    /// Field abbrevs whose subtree is shown expanded.
    expanded: HashSet<&'static str>,
    /// Selected node index within the current frame's tree.
    pub selected: Option<usize>,
    /// Frame number the selection belongs to; a different frame resets it.
    frame_number: Option<u32>,
    /// One-shot request to scroll the selected node into view.
    scroll_to_selected: bool,
}

impl Default for TreeState {
    fn default() -> Self {
        // Layers open, `frame` and nested groups closed, like Wireshark.
        let expanded = [
            "eth",
            "vlan",
            "llc",
            "arp",
            "ip",
            "ipv6",
            "icmp",
            "icmpv6",
            "udp",
            "tcp",
            "dns",
            "dhcp",
            "http",
            "tls",
            "null",
            "data",
            "_ws.malformed",
        ]
        .into_iter()
        .collect();
        Self {
            expanded,
            selected: None,
            frame_number: None,
            scroll_to_selected: false,
        }
    }
}

impl TreeState {
    fn sync_frame(&mut self, number: u32) {
        if self.frame_number != Some(number) {
            self.frame_number = Some(number);
            self.selected = None;
        }
    }

    pub fn is_expanded(&self, node: &NodeRef<'_>) -> bool {
        self.expanded.contains(node.abbrev())
    }

    pub fn toggle(&mut self, node: &NodeRef<'_>) {
        if !self.expanded.remove(node.abbrev()) {
            self.expanded.insert(node.abbrev());
        }
    }

    /// Toggle expansion of the selected node (Enter).
    pub fn toggle_selected(&mut self, frame: &Frame) {
        if let Some(node) = self.selected.and_then(|i| frame.tree.get(i)) {
            if node.has_children() {
                self.toggle(&node);
            }
        }
    }

    /// Select `index` and expand every ancestor so it is visible.
    pub fn select_and_reveal(&mut self, frame: &Frame, index: usize) {
        self.sync_frame(frame.number);
        let Some(target) = frame.tree.get(index) else {
            return;
        };
        let mut depth = target.depth();
        // Ancestors are the nearest preceding nodes with strictly smaller depth.
        for i in (0..index).rev() {
            if depth == 0 {
                break;
            }
            if let Some(n) = frame.tree.get(i) {
                if n.depth() < depth {
                    self.expanded.insert(n.abbrev());
                    depth = n.depth();
                }
            }
        }
        self.selected = Some(index);
        self.scroll_to_selected = true;
    }

    /// Indices of the nodes currently visible (ancestors all expanded).
    fn visible(&self, frame: &Frame) -> Vec<usize> {
        let mut out = Vec::with_capacity(frame.tree.len());
        let mut hide_below: Option<u8> = None;
        for n in frame.tree.iter() {
            if let Some(d) = hide_below {
                if n.depth() > d {
                    continue;
                }
                hide_below = None;
            }
            out.push(n.index());
            if n.has_children() && !self.is_expanded(&n) {
                hide_below = Some(n.depth());
            }
        }
        out
    }

    /// Move the selection up or down among visible nodes.
    pub fn navigate(&mut self, frame: &Frame, delta: isize) {
        self.sync_frame(frame.number);
        let visible = self.visible(frame);
        if visible.is_empty() {
            return;
        }
        let pos = self
            .selected
            .and_then(|s| visible.iter().position(|&i| i == s));
        let next = match pos {
            Some(p) => (p as isize + delta).clamp(0, visible.len() as isize - 1) as usize,
            None => 0,
        };
        self.selected = Some(visible[next]);
        self.scroll_to_selected = true;
    }
}

/// Draws the tree for `frame`. Returns `true` when the selection changed by
/// a click (so the caller can move keyboard focus here).
pub fn show(ui: &mut egui::Ui, frame: Option<&Frame>, state: &mut TreeState) -> bool {
    let Some(frame) = frame else {
        ui.weak("Select a packet to see its dissection.");
        return false;
    };
    state.sync_frame(frame.number);
    let mut clicked = false;
    let visible = state.visible(frame);
    let row_height = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
    let scroll_to = state.scroll_to_selected.then_some(()).and(state.selected);
    state.scroll_to_selected = false;
    egui::ScrollArea::both()
        .id_salt("detail")
        .auto_shrink([false, false])
        .show_rows(ui, row_height, visible.len(), |ui, range| {
            for vi in range {
                let Some(node) = frame.tree.get(visible[vi]) else {
                    continue;
                };
                let data = frame.source(node.source()).unwrap_or(&[]);
                let label = registry::label(&node, data);
                let is_selected = state.selected == Some(node.index());
                let marker = if node.has_children() {
                    if state.is_expanded(&node) {
                        "▼ "
                    } else {
                        "▶ "
                    }
                } else {
                    "   "
                };
                let text = format!(
                    "{}{marker}{label}",
                    "    ".repeat(usize::from(node.depth()))
                );
                let resp = ui.selectable_label(is_selected, text);
                if resp.clicked() {
                    state.selected = Some(node.index());
                    clicked = true;
                }
                if resp.double_clicked() && node.has_children() {
                    state.toggle(&node);
                }
                if scroll_to == Some(node.index()) {
                    resp.scroll_to_me(Some(egui::Align::Center));
                }
                if is_selected && resp.hovered() {
                    resp.on_hover_text(format!(
                        "{}  [{}..{})",
                        node.abbrev(),
                        node.range().start,
                        node.range().end
                    ));
                }
            }
        });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, State};
    use netscope_ffi::LinkType;

    fn frame() -> Frame {
        let mut r = State::new();
        dissect(
            LinkType::ETHERNET,
            1,
            crate::synthetic::raw_frame(5),
            &mut r,
        )
    }

    #[test]
    fn collapsed_groups_hide_their_children() {
        let f = frame();
        let st = TreeState::default();
        let visible = st.visible(&f);
        let abbrevs: Vec<&str> = visible
            .iter()
            .filter_map(|&i| f.tree.get(i))
            .map(|n| n.abbrev())
            .collect();
        // `frame` is collapsed by default: its fields are hidden.
        assert!(abbrevs.contains(&"frame"));
        assert!(!abbrevs.contains(&"frame.number"));
        // `tcp` is expanded, `tcp.flags` is not.
        assert!(abbrevs.contains(&"tcp.srcport"));
        assert!(abbrevs.contains(&"tcp.flags"));
        assert!(!abbrevs.contains(&"tcp.flags.syn"));
    }

    #[test]
    fn navigation_moves_through_visible_nodes_only() {
        let f = frame();
        let mut st = TreeState::default();
        st.navigate(&f, 1);
        assert_eq!(st.selected, Some(0)); // first visible: frame
        st.navigate(&f, 1);
        let n = f.tree.get(st.selected.unwrap()).unwrap();
        assert_eq!(n.abbrev(), "eth"); // frame's children are hidden
        st.navigate(&f, -10);
        assert_eq!(st.selected, Some(0));
    }

    #[test]
    fn reveal_expands_ancestors_and_enter_toggles() {
        let f = frame();
        let mut st = TreeState::default();
        let syn = f
            .tree
            .iter()
            .find(|n| n.abbrev() == "tcp.flags.syn")
            .unwrap();
        st.select_and_reveal(&f, syn.index());
        assert_eq!(st.selected, Some(syn.index()));
        assert!(st.expanded.contains("tcp.flags"));
        assert!(st.visible(&f).contains(&syn.index()));
        // Enter on the flags group collapses it again.
        let flags = f.tree.iter().find(|n| n.abbrev() == "tcp.flags").unwrap();
        st.selected = Some(flags.index());
        st.toggle_selected(&f);
        assert!(!st.expanded.contains("tcp.flags"));
        assert!(!st.visible(&f).contains(&syn.index()));
    }

    #[test]
    fn hex_offset_maps_to_innermost_node() {
        let f = frame();
        // Byte 34 is the first TCP byte (source port).
        let n = f.tree.innermost_at(0, 34).unwrap();
        assert_eq!(n.abbrev(), "tcp.srcport");
        // Byte 26 is the IPv4 source address.
        assert_eq!(f.tree.innermost_at(0, 26).unwrap().abbrev(), "ip.src");
        // Byte 47 is the flags byte: the deepest node is a flag bit.
        assert!(f
            .tree
            .innermost_at(0, 47)
            .unwrap()
            .abbrev()
            .starts_with("tcp.flags."));
    }
}
