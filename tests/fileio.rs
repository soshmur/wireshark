//! File I/O: reading captures, writing them back, and refusing the ones
//! that cannot be read without saying something untrue about them.

mod common;

use std::sync::Arc;

use netscope::capture::file::{self, SaveFormat};
use netscope::dissect::{Frame, Options};
use netscope::pcap::{Format, Precision};
use netscope_ffi::LinkType;

/// Dissect a fixture the way the application would.
fn frames(name: &str) -> Vec<Arc<Frame>> {
    let fx = common::fixtures::all()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no fixture named {name}"));
    let bytes = common::pcapng_fixture(&fx);
    let loaded = file::load(&bytes).expect("load the fixture");
    loaded.dissect_all(Options::default())
}

#[test]
fn every_fixture_round_trips_through_pcapng() {
    // Bytes, wire lengths and timestamps must all survive. pcapng carries
    // nanoseconds, so nothing should be rounded.
    for fx in common::fixtures::all() {
        let original = common::pcapng_fixture(&fx);
        let loaded = file::load(&original).expect(fx.name);
        let dissected = loaded.dissect_all(Options::default());
        let (written, saved) = file::encode(&dissected, SaveFormat::Pcapng).expect("encode");
        assert_eq!(saved.frames, fx.frames.len(), "{}", fx.name);

        let again = file::load(&written).expect("reread");
        assert_eq!(again.packets.len(), loaded.packets.len(), "{}", fx.name);
        for (i, ((_, a), (_, b))) in loaded.packets.iter().zip(&again.packets).enumerate() {
            assert_eq!(a.bytes, b.bytes, "{} frame {i}: bytes", fx.name);
            assert_eq!(a.orig_len, b.orig_len, "{} frame {i}: wire length", fx.name);
            assert_eq!(a.ts, b.ts, "{} frame {i}: timestamp", fx.name);
        }
    }
}

#[test]
fn every_fixture_round_trips_through_pcap() {
    for fx in common::fixtures::all() {
        let dissected = frames(fx.name);
        let (written, saved) = file::encode(&dissected, SaveFormat::Pcap).expect("encode");
        let again = file::load(&written).expect("reread");
        assert_eq!(again.format, Format::Pcap);
        assert_eq!(again.packets.len(), saved.frames, "{}", fx.name);
        // The link type is carried in the file header, so it has to come
        // back or every frame dissects as something else.
        assert_eq!(
            again.link_type_of(0),
            LinkType(i32::from(fx.link_type)),
            "{}",
            fx.name
        );
        for (i, (_, b)) in again.packets.iter().enumerate() {
            assert_eq!(&*b.bytes, &fx.frames[i][..], "{} frame {i}", fx.name);
        }
    }
}

#[test]
fn a_reread_file_dissects_identically() {
    // The point of the round trip: not just that the bytes survive, but
    // that they mean the same thing afterwards.
    for name in ["tcp_analysis", "desegment", "streams", "malformed"] {
        let before = frames(name);
        let (written, _) = file::encode(&before, SaveFormat::Pcapng).expect("encode");
        let after = file::load(&written)
            .expect("reread")
            .dissect_all(Options::default());
        assert_eq!(before.len(), after.len(), "{name}");
        for (a, b) in before.iter().zip(&after) {
            assert_eq!(a.summary.info, b.summary.info, "{name} frame {}", a.number);
            assert_eq!(a.summary.protocol, b.summary.protocol, "{name}");
            assert_eq!(a.tree.len(), b.tree.len(), "{name} frame {}", a.number);
            assert_eq!(
                a.summary.expert.map(|e| e.severity),
                b.summary.expert.map(|e| e.severity),
                "{name} frame {}",
                a.number
            );
        }
    }
}

#[test]
fn pcap_precision_follows_the_data() {
    // The fixtures' timestamps end in 123_456_789 ns, which microseconds
    // cannot hold, so the writer must choose the nanosecond magic.
    let dissected = frames("streams");
    let (_, saved) = file::encode(&dissected, SaveFormat::Pcap).expect("encode");
    assert_eq!(saved.precision, Some(Precision::Nano));
    assert!(
        saved.notes.iter().any(|n| n.contains("libpcap 1.5")),
        "and say so, because old tools cannot read it: {:?}",
        saved.notes
    );
}

#[test]
fn a_microsecond_aligned_capture_stays_microsecond() {
    // Nothing is lost, so the more compatible magic is used.
    let mut dissected = frames("streams");
    for f in &mut dissected {
        Arc::make_mut(f).ts.nanos = 1000;
    }
    let (written, saved) = file::encode(&dissected, SaveFormat::Pcap).expect("encode");
    assert_eq!(saved.precision, Some(Precision::Micro));
    assert!(saved.notes.is_empty(), "{:?}", saved.notes);
    let again = file::load(&written).expect("reread");
    assert_eq!(again.packets[0].1.ts.nanos, 1000);
}

#[test]
fn saving_a_subset_writes_only_that_subset() {
    // "Export displayed" is the whole point of having a frame set.
    let all = frames("streams");
    let subset: Vec<Arc<Frame>> = all.iter().take(3).cloned().collect();
    let (written, saved) = file::encode(&subset, SaveFormat::Pcapng).expect("encode");
    assert_eq!(saved.frames, 3);
    let again = file::load(&written).expect("reread");
    assert_eq!(again.packets.len(), 3);
    assert_eq!(&*again.packets[0].1.bytes, &*all[0].bytes);
}

#[test]
fn an_empty_selection_still_writes_a_valid_file() {
    let (written, saved) = file::encode(&[], SaveFormat::Pcapng).expect("encode");
    assert_eq!(saved.frames, 0);
    let again = file::load(&written).expect("an empty capture is still a capture");
    assert!(again.packets.is_empty());
    // And the same for pcap, which needs a link type it cannot get from the
    // frames.
    let (written, _) = file::encode(&[], SaveFormat::Pcap).expect("encode");
    assert!(file::load(&written).expect("reread").packets.is_empty());
}

#[test]
fn a_capture_mixing_link_types_survives_pcapng_and_warns_in_pcap() {
    // pcapng describes an interface per link type; pcap has one field for
    // the whole file, so the frames that disagree cannot be written under
    // it without making them dissect as something else.
    let mut mixed = frames("streams");
    for f in mixed.iter_mut().skip(10) {
        Arc::make_mut(f).link_type = LinkType::RAW;
    }
    let (written, saved) = file::encode(&mixed, SaveFormat::Pcapng).expect("encode");
    assert_eq!(saved.frames, mixed.len());
    let again = file::load(&written).expect("reread");
    assert_eq!(again.interfaces.len(), 2, "one interface per link type");
    assert!(
        again.warnings.iter().any(|w| w.contains("mixes")),
        "{:?}",
        again.warnings
    );

    let (_, saved) = file::encode(&mixed, SaveFormat::Pcap).expect("encode");
    assert!(saved.frames < mixed.len());
    assert!(
        saved.notes.iter().any(|n| n.contains("save as pcapng")),
        "and say how to keep them: {:?}",
        saved.notes
    );
}

#[test]
fn the_format_is_read_from_the_bytes_not_the_name() {
    // A .pcap that is really pcapng is common; picking the parser by name
    // turns that into a parse error or a misparse.
    let dissected = frames("streams");
    let (ng, _) = file::encode(&dissected, SaveFormat::Pcapng).expect("encode");
    let (pc, _) = file::encode(&dissected, SaveFormat::Pcap).expect("encode");
    assert_eq!(file::load(&ng).expect("ng").format, Format::Pcapng);
    assert_eq!(file::load(&pc).expect("pc").format, Format::Pcap);
}

#[test]
fn unreadable_files_say_what_is_wrong() {
    let cases: &[(&[u8], &str)] = &[
        (b"", "empty"),
        (b"not a capture at all, just text", "neither format"),
        (b"\x00\x01\x02\x03plausible length though", "neither format"),
    ];
    for (bytes, expect) in cases {
        let e = file::load(bytes).expect_err("should be refused");
        let msg = e.to_string();
        assert!(
            msg.contains(expect),
            "{:?} gave {msg:?}, expected to mention {expect:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    // The modified format is named rather than misread.
    let mut modified = netscope::pcap::MAGIC_MODIFIED.to_le_bytes().to_vec();
    modified.extend_from_slice(&[0; 40]);
    let msg = file::load(&modified).expect_err("refused").to_string();
    assert!(msg.contains("modified-format"), "{msg}");
    assert!(msg.contains("editcap"), "and suggest a way out: {msg}");
}

#[test]
fn a_truncated_file_yields_its_readable_prefix_with_a_warning() {
    // A capture killed mid-write is ordinary and its packets are still
    // worth showing.
    let dissected = frames("streams");
    let (full, _) = file::encode(&dissected, SaveFormat::Pcap).expect("encode");
    let cut = &full[..full.len() - 20];
    let loaded = file::load(cut).expect("the readable prefix");
    assert!(loaded.packets.len() < dissected.len());
    assert!(
        loaded.warnings.iter().any(|w| w.contains("truncated")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn a_pcapng_packet_naming_a_missing_interface_is_shown_not_dropped() {
    // Malformed, but the bytes are there. Dropping them silently would
    // lose packets a user can see in a hex editor.
    let dissected = frames("streams");
    let (mut bytes, _) = file::encode(&dissected, SaveFormat::Pcapng).expect("encode");
    // The first EPB's interface id is the first four bytes of its body.
    let epb = netscope::pcapng::BLOCK_EPB.to_le_bytes();
    let at = bytes
        .windows(4)
        .position(|w| w == epb)
        .expect("an EPB somewhere");
    bytes[at + 8..at + 12].copy_from_slice(&99u32.to_le_bytes());
    let loaded = file::load(&bytes).expect("still loads");
    assert_eq!(loaded.packets.len(), dissected.len());
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.contains("does not describe")),
        "{:?}",
        loaded.warnings
    );
}
