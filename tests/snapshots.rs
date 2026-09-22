//! Snapshot tests: the full dissection tree of every fixture frame, rendered
//! as text, compared with `tests/snapshots/*.snap` via insta.
//! Review changes with `cargo insta review` (or `INSTA_UPDATE=always`).

mod common;

use std::fmt::Write as _;

use netscope::dissect::{dissect, registry, Frame, Reassembly};
use netscope_ffi::LinkType;

/// One line per node: indent, label, then `[abbrev source:start-end]`.
pub fn render(frame: &Frame) -> String {
    let mut out = String::new();
    let s = &frame.summary;
    let _ = writeln!(
        out,
        "#{} {} -> {} {} | {}",
        frame.number, s.source, s.destination, s.protocol, s.info
    );
    for n in frame.tree.iter() {
        let data = frame.source(n.source()).unwrap_or(&[]);
        let r = n.range();
        let _ = writeln!(
            out,
            "{}{}  [{} {}:{}-{}]",
            "  ".repeat(usize::from(n.depth()) + 1),
            registry::label(&n, data),
            n.abbrev(),
            n.source(),
            r.start,
            r.end
        );
    }
    out
}

#[test]
fn dissection_trees() {
    for fx in common::fixtures::all() {
        let bytes = common::pcapng_with_link(fx.link_type, &fx.frames);
        let section = netscope::pcapng::read(&bytes).expect("parse");
        let link = LinkType(i32::from(fx.link_type));
        let mut reassembly = Reassembly::new();
        let mut text = String::new();
        for (i, p) in section.packets.into_iter().enumerate() {
            let frame = dissect(link, i as u32 + 1, p.frame, &mut reassembly);
            text.push_str(&render(&frame));
            text.push('\n');
        }
        insta::assert_snapshot!(fx.name, text);
    }
}
