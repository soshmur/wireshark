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

/// libpcap reading what netscope wrote.
///
/// Everything above validates the writer against netscope's own reader,
/// which cannot catch a mistake both halves share — a format validated only
/// by its own reader is validated against its own misreadings. libpcap is
/// the reference implementation and is already linked, so it can be asked.
///
/// It only reads classic pcap here. pcapng has no equivalent check available
/// on this machine, which is stated plainly rather than papered over.
mod against_libpcap {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("netscope-test-{name}"))
    }

    #[test]
    fn libpcap_agrees_about_a_file_netscope_wrote() {
        let dissected = frames("streams");
        let path = temp_path("streams.pcap");
        let saved = file::save_path(&path, &dissected, SaveFormat::Pcap).expect("write the file");

        let (link, packets) = match netscope_ffi::verify_savefile(&path.to_string_lossy()) {
            Ok(v) => v,
            Err(e) => {
                // libpcap is loaded lazily on Windows; without Npcap there is
                // nothing to compare against, and saying so beats failing.
                eprintln!("skipping: libpcap unavailable ({e})");
                return;
            }
        };
        assert_eq!(link, LinkType::ETHERNET, "libpcap read the link type");
        assert_eq!(
            packets.len(),
            saved.frames,
            "libpcap found a different number of packets"
        );
        for (i, ((_secs, _nanos, orig_len, bytes), ours)) in
            packets.iter().zip(&dissected).enumerate()
        {
            assert_eq!(bytes, &ours.bytes.to_vec(), "frame {i}: bytes");
            assert_eq!(*orig_len, ours.orig_len, "frame {i}: wire length");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn libpcap_reads_a_microsecond_file_too() {
        // The two magics are different code paths in both implementations.
        let mut dissected = frames("streams");
        for f in &mut dissected {
            Arc::make_mut(f).ts.nanos = 2000;
        }
        let path = temp_path("micros.pcap");
        let saved = file::save_path(&path, &dissected, SaveFormat::Pcap).expect("write");
        assert_eq!(saved.precision, Some(Precision::Micro));
        match netscope_ffi::verify_savefile(&path.to_string_lossy()) {
            Ok((_, packets)) => {
                assert_eq!(packets.len(), dissected.len());
                assert_eq!(packets[0].1, 2, "libpcap reports 2 microseconds");
            }
            Err(e) => eprintln!("skipping: libpcap unavailable ({e})"),
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// pcapng options that change what a timestamp means, or that carry metadata
/// a round trip should keep.
mod pcapng_options {
    use netscope::pcapng;

    /// Build a pcapng file by hand so an option can be set that netscope's
    /// own writer does not emit.
    struct Build {
        out: Vec<u8>,
    }

    impl Build {
        fn new() -> Build {
            let mut b = Build { out: Vec::new() };
            let mut body = Vec::new();
            body.extend_from_slice(&pcapng::BYTE_ORDER_MAGIC.to_le_bytes());
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&u64::MAX.to_le_bytes());
            b.block(pcapng::BLOCK_SHB, &body);
            b
        }

        fn block(&mut self, kind: u32, body: &[u8]) {
            let padded = pcapng::pad4(body.len());
            let total = (12 + padded) as u32;
            self.out.extend_from_slice(&kind.to_le_bytes());
            self.out.extend_from_slice(&total.to_le_bytes());
            self.out.extend_from_slice(body);
            self.out.resize(self.out.len() + padded - body.len(), 0);
            self.out.extend_from_slice(&total.to_le_bytes());
        }

        fn option(body: &mut Vec<u8>, code: u16, value: &[u8]) {
            body.extend_from_slice(&code.to_le_bytes());
            body.extend_from_slice(&(value.len() as u16).to_le_bytes());
            body.extend_from_slice(value);
            body.resize(pcapng::pad4(body.len()), 0);
        }

        /// An IDB with `if_tsresol` 6 and an optional `if_tsoffset`.
        fn interface(&mut self, offset: Option<i64>, description: Option<&str>) {
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&65535u32.to_le_bytes());
            Self::option(&mut body, pcapng::OPT_IF_NAME, b"eth0");
            if let Some(d) = description {
                Self::option(&mut body, pcapng::OPT_IF_DESCRIPTION, d.as_bytes());
            }
            Self::option(&mut body, pcapng::OPT_IF_TSRESOL, &[6]);
            if let Some(o) = offset {
                Self::option(&mut body, pcapng::OPT_IF_TSOFFSET, &o.to_le_bytes());
            }
            Self::option(&mut body, pcapng::OPT_ENDOFOPT, &[]);
            self.block(pcapng::BLOCK_IDB, &body);
        }

        /// An EPB whose timestamp counts `units` of the interface's
        /// resolution.
        fn packet(&mut self, units: u64) {
            let data = [0u8; 14];
            let mut body = Vec::new();
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&((units >> 32) as u32).to_le_bytes());
            body.extend_from_slice(&(units as u32).to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&data);
            body.resize(pcapng::pad4(body.len()), 0);
            self.block(pcapng::BLOCK_EPB, &body);
        }
    }

    #[test]
    fn if_tsoffset_shifts_the_timestamps() {
        // A writer may store small timestamps against a base held in the
        // option. Ignoring it reports times decades adrift, with nothing to
        // say something was missed.
        let base = 1_700_000_000i64;
        let mut b = Build::new();
        b.interface(Some(base), None);
        b.packet(5_000_000); // five seconds at microsecond resolution
        let section = pcapng::read(&b.out).expect("read");
        assert_eq!(section.interfaces[0].ts_offset, base);
        assert_eq!(section.packets[0].frame.ts.secs, base + 5);
    }

    #[test]
    fn without_the_option_nothing_is_shifted() {
        let mut b = Build::new();
        b.interface(None, None);
        b.packet(5_000_000);
        let section = pcapng::read(&b.out).expect("read");
        assert_eq!(section.interfaces[0].ts_offset, 0);
        assert_eq!(section.packets[0].frame.ts.secs, 5);
    }

    #[test]
    fn a_negative_offset_works_and_an_absurd_one_does_not_wrap() {
        let mut b = Build::new();
        b.interface(Some(-10), None);
        b.packet(20_000_000);
        let section = pcapng::read(&b.out).expect("read");
        assert_eq!(section.packets[0].frame.ts.secs, 10);

        // An offset near the limit must saturate, not wrap into the past.
        let mut b = Build::new();
        b.interface(Some(i64::MAX), None);
        b.packet(5_000_000);
        let section = pcapng::read(&b.out).expect("read");
        assert_eq!(section.packets[0].frame.ts.secs, i64::MAX);
    }

    #[test]
    fn an_interface_description_is_read_and_round_trips() {
        let mut b = Build::new();
        b.interface(None, Some("Corporate uplink"));
        b.packet(1_000_000);
        let section = pcapng::read(&b.out).expect("read");
        assert_eq!(
            section.interfaces[0].description.as_deref(),
            Some("Corporate uplink")
        );

        // And the writer can emit one, so a description survives a save.
        let mut w = pcapng::Writer::new(Vec::new(), "netscope").expect("shb");
        w.interface_described(1, 65535, "eth0", "Corporate uplink")
            .expect("idb");
        let bytes = w.finish().expect("finish");
        let back = pcapng::read(&bytes).expect("reread");
        assert_eq!(back.interfaces[0].name.as_deref(), Some("eth0"));
        assert_eq!(
            back.interfaces[0].description.as_deref(),
            Some("Corporate uplink")
        );
    }

    #[test]
    fn a_truncated_tsoffset_option_is_ignored_rather_than_read_short() {
        // Four bytes where eight are required. Reading what is there would
        // produce a plausible-looking wrong answer.
        let mut b = Build::new();
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&65535u32.to_le_bytes());
        Build::option(&mut body, pcapng::OPT_IF_TSRESOL, &[6]);
        Build::option(&mut body, pcapng::OPT_IF_TSOFFSET, &[1, 2, 3, 4]);
        Build::option(&mut body, pcapng::OPT_ENDOFOPT, &[]);
        b.block(pcapng::BLOCK_IDB, &body);
        b.packet(1_000_000);
        let section = pcapng::read(&b.out).expect("read");
        assert_eq!(section.interfaces[0].ts_offset, 0);
        assert_eq!(section.packets[0].frame.ts.secs, 1);
    }
}

#[test]
fn interface_names_and_descriptions_survive_a_save() {
    // The brief asks for interface metadata to be preserved. Without it the
    // names are replaced by the link type's, which throws away information
    // the file had for no reason.
    let dissected = frames("streams");
    let source = vec![netscope::capture::file::Iface {
        link_type: LinkType::ETHERNET,
        snaplen: 1514,
        name: Some("enp3s0".into()),
        description: Some("Office uplink".into()),
        stats: netscope::pcapng::Stats::default(),
        ts_per_sec: 1_000_000_000,
    }];
    let (written, _) =
        file::encode_preserving(&dissected, SaveFormat::Pcapng, &source).expect("encode");
    let back = file::load(&written).expect("reread");
    assert_eq!(back.interfaces.len(), 1);
    assert_eq!(back.interfaces[0].name.as_deref(), Some("enp3s0"));
    assert_eq!(
        back.interfaces[0].description.as_deref(),
        Some("Office uplink")
    );
    assert_eq!(back.interfaces[0].snaplen, 1514, "the snaplen too");

    // With nothing to preserve, the link type's name is a reasonable default
    // rather than an empty field.
    let (written, _) = file::encode(&dissected, SaveFormat::Pcapng).expect("encode");
    let back = file::load(&written).expect("reread");
    assert!(back.interfaces[0].name.is_some());
}

#[test]
fn an_opened_file_saved_again_keeps_its_interface_metadata() {
    // The round trip the brief is really asking about: open, save, open.
    let mut w = netscope::pcapng::Writer::new(Vec::new(), "test").expect("shb");
    w.interface_described(1, 2048, "wlan0", "Wireless")
        .expect("idb");
    w.packet(
        0,
        netscope::capture::Timestamp {
            secs: 1_700_000_000,
            nanos: 500,
        },
        14,
        &[0u8; 14],
    )
    .expect("packet");
    let original = w.finish().expect("finish");

    let first = file::load(&original).expect("load");
    let dissected = first.dissect_all(Options::default());
    let (resaved, _) =
        file::encode_preserving(&dissected, SaveFormat::Pcapng, &first.interfaces).expect("encode");
    let second = file::load(&resaved).expect("reload");
    assert_eq!(second.interfaces[0].name.as_deref(), Some("wlan0"));
    assert_eq!(
        second.interfaces[0].description.as_deref(),
        Some("Wireless")
    );
    assert_eq!(second.interfaces[0].snaplen, 2048);
    assert_eq!(second.packets[0].1.ts.nanos, 500, "and the nanoseconds");
}

/// Interface Statistics Blocks: what the capture says it missed.
mod interface_statistics {
    use netscope::pcapng;

    /// A file with an ISB carrying the counts given.
    fn with_isb(received: Option<u64>, dropped: Option<u64>, os_dropped: Option<u64>) -> Vec<u8> {
        let mut out = Vec::new();
        let block = |out: &mut Vec<u8>, kind: u32, body: &[u8]| {
            let padded = pcapng::pad4(body.len());
            let total = (12 + padded) as u32;
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&total.to_le_bytes());
            out.extend_from_slice(body);
            out.resize(out.len() + padded - body.len(), 0);
            out.extend_from_slice(&total.to_le_bytes());
        };
        let option = |body: &mut Vec<u8>, code: u16, value: &[u8]| {
            body.extend_from_slice(&code.to_le_bytes());
            body.extend_from_slice(&(value.len() as u16).to_le_bytes());
            body.extend_from_slice(value);
            body.resize(pcapng::pad4(body.len()), 0);
        };

        let mut shb = Vec::new();
        shb.extend_from_slice(&pcapng::BYTE_ORDER_MAGIC.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&u64::MAX.to_le_bytes());
        block(&mut out, pcapng::BLOCK_SHB, &shb);

        let mut idb = Vec::new();
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&65535u32.to_le_bytes());
        option(&mut idb, pcapng::OPT_IF_NAME, b"eth0");
        option(&mut idb, pcapng::OPT_ENDOFOPT, &[]);
        block(&mut out, pcapng::BLOCK_IDB, &idb);

        let mut isb = Vec::new();
        isb.extend_from_slice(&0u32.to_le_bytes()); // interface 0
        isb.extend_from_slice(&0u32.to_le_bytes()); // ts high
        isb.extend_from_slice(&0u32.to_le_bytes()); // ts low
        if let Some(v) = received {
            option(&mut isb, pcapng::OPT_ISB_IFRECV, &v.to_le_bytes());
        }
        if let Some(v) = dropped {
            option(&mut isb, pcapng::OPT_ISB_IFDROP, &v.to_le_bytes());
        }
        if let Some(v) = os_dropped {
            option(&mut isb, pcapng::OPT_ISB_OSDROP, &v.to_le_bytes());
        }
        option(&mut isb, pcapng::OPT_ENDOFOPT, &[]);
        block(&mut out, pcapng::BLOCK_ISB, &isb);
        out
    }

    #[test]
    fn the_counts_are_read_onto_the_interface() {
        let bytes = with_isb(Some(5000), Some(42), None);
        let section = pcapng::read(&bytes).expect("read");
        let s = section.interfaces[0].stats;
        assert_eq!(s.received, Some(5000));
        assert_eq!(s.dropped, Some(42));
        assert_eq!(s.os_dropped, None, "absent options stay absent");
        assert_eq!(s.total_lost(), 42);
    }

    #[test]
    fn both_kinds_of_drop_count_as_lost() {
        let bytes = with_isb(Some(100), Some(3), Some(4));
        let section = pcapng::read(&bytes).expect("read");
        assert_eq!(section.interfaces[0].stats.total_lost(), 7);
    }

    #[test]
    fn a_file_reporting_drops_says_so_on_load() {
        // A capture that dropped packets is incomplete. Letting a user draw
        // conclusions from it with no sign of that is the failure here.
        let bytes = with_isb(Some(5000), Some(42), None);
        let loaded = netscope::capture::file::load(&bytes).expect("load");
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.contains("42 packets dropped") && w.contains("incomplete")),
            "{:?}",
            loaded.warnings
        );
        assert!(
            loaded.warnings.iter().any(|w| w.contains("eth0")),
            "and name the interface: {:?}",
            loaded.warnings
        );
    }

    #[test]
    fn a_clean_capture_says_nothing_about_drops() {
        let bytes = with_isb(Some(5000), Some(0), Some(0));
        let loaded = netscope::capture::file::load(&bytes).expect("load");
        assert!(
            !loaded.warnings.iter().any(|w| w.contains("dropped")),
            "{:?}",
            loaded.warnings
        );
        // And a file with no ISB at all is equally quiet.
        let none = netscope::capture::file::load(&with_isb(None, None, None)).expect("load");
        assert!(!none.warnings.iter().any(|w| w.contains("dropped")));
    }

    #[test]
    fn an_isb_naming_an_interface_that_does_not_exist_is_ignored() {
        let mut bytes = with_isb(Some(1), Some(1), None);
        // The ISB's interface id is the first four bytes of its body. Find it
        // by its block type rather than by a fixed offset.
        let isb = pcapng::BLOCK_ISB.to_le_bytes();
        let at = bytes
            .windows(4)
            .position(|w| w == isb)
            .expect("the ISB is in there");
        bytes[at + 8..at + 12].copy_from_slice(&77u32.to_le_bytes());
        let section = pcapng::read(&bytes).expect("still reads");
        assert!(section.interfaces[0].stats.is_empty());
    }
}
