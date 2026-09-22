//! Keeps the checked-in fixture captures in sync with their generators.
//! `NETSCOPE_REGEN=1 cargo test --test fixtures` rewrites them.

mod common;

use std::path::PathBuf;

use common::fixtures;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.pcapng"))
}

#[test]
fn fixture_files_match_generators() {
    let regen = std::env::var("NETSCOPE_REGEN").is_ok();
    let mut stale = Vec::new();
    for fx in fixtures::all() {
        let bytes = common::pcapng_with_link(fx.link_type, &fx.frames);
        let path = fixture_path(fx.name);
        if regen {
            std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
            std::fs::write(&path, &bytes).expect("write fixture");
            continue;
        }
        match std::fs::read(&path) {
            Ok(existing) if existing == bytes => {}
            _ => stale.push(fx.name),
        }
    }
    assert!(
        stale.is_empty(),
        "fixtures out of date: {stale:?}; run NETSCOPE_REGEN=1 cargo test --test fixtures"
    );
}

#[test]
fn fixtures_parse_back() {
    for fx in fixtures::all() {
        let bytes = common::pcapng_with_link(fx.link_type, &fx.frames);
        let section = netscope::pcapng::read(&bytes).expect("parse");
        assert_eq!(section.packets.len(), fx.frames.len(), "{}", fx.name);
        assert_eq!(section.interfaces[0].link_type, fx.link_type);
        for (i, p) in section.packets.iter().enumerate() {
            assert_eq!(&*p.frame.bytes, &fx.frames[i][..], "{} frame {i}", fx.name);
            assert_eq!(p.frame.ts, common::ts(i as u32));
        }
    }
}
