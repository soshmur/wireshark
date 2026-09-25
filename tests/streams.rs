//! Conversation tracking: which frames belong to which stream.
//!
//! The interesting cases are the ones where the answer is not "group by
//! 5-tuple": both directions must collapse to one stream, and a reused port
//! must not.

mod common;

use netscope::dissect::{dissect, Frame, State};
use netscope::filter::{compile, matches};
use netscope_ffi::LinkType;

fn load(name: &str) -> Vec<Frame> {
    let fx = common::fixtures::all()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no fixture named {name}"));
    let bytes = common::pcapng_fixture(&fx);
    let section = netscope::pcapng::read(&bytes).expect("read fixture");
    let link = LinkType(i32::from(fx.link_type));
    let mut state = State::new();
    section
        .packets
        .into_iter()
        .enumerate()
        .map(|(i, p)| dissect(link, i as u32 + 1, p.frame, &mut state))
        .collect()
}

#[track_caller]
fn expect(frames: &[Frame], filter: &str, want: &[u32]) {
    let test = compile(filter).unwrap_or_else(|e| panic!("{filter}: {e}"));
    let got: Vec<u32> = frames
        .iter()
        .filter(|f| matches(&test, f))
        .map(|f| f.number)
        .collect();
    assert_eq!(got, want, "filter `{filter}` selected the wrong frames");
}

#[test]
fn both_directions_of_a_connection_are_one_stream() {
    let f = load("streams");
    // Frames 1-5 and 9-10 are one connection on client port 40000: SYN,
    // SYN/ACK, ACK, data out, data back, FIN, FIN. Five of those seven run
    // client to server and two run the other way.
    expect(&f, "tcp.stream == 0", &[1, 2, 3, 4, 5, 9, 10]);
    expect(
        &f,
        "tcp.stream == 0 && ip.src == 192.168.1.10",
        &[1, 3, 4, 9],
    );
    expect(
        &f,
        "tcp.stream == 0 && ip.src == 93.184.216.34",
        &[2, 5, 10],
    );
}

#[test]
fn concurrent_connections_are_separate_streams() {
    let f = load("streams");
    // Interleaved in the capture, but a different client port.
    expect(&f, "tcp.stream == 1", &[6, 7, 8]);
}

#[test]
fn a_reused_port_starts_a_new_stream() {
    let f = load("streams");
    // Frames 11-13 have exactly the same 5-tuple as stream 0, after it
    // closed. Grouping by 5-tuple alone would splice them onto stream 0 and
    // Follow Stream would show two unrelated conversations as one.
    expect(&f, "tcp.stream == 2", &[11, 12, 13]);
    expect(
        &f,
        "tcp.srcport == 40000 || tcp.dstport == 40000",
        &[1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 17, 18],
    );
}

#[test]
fn udp_flows_are_streams_too() {
    let f = load("streams");
    expect(&f, "udp.stream == 3", &[14, 15]);
    expect(&f, "udp.stream == 4", &[16]);
    // TCP and UDP ids come from one sequence, so a udp.stream value never
    // collides with a tcp.stream value.
    expect(&f, "tcp.stream == 3", &[]);
    expect(&f, "udp.stream == 0", &[]);
}

#[test]
fn ipv6_conversations_are_tracked_the_same_way() {
    let f = load("streams");
    expect(&f, "tcp.stream == 5", &[17, 18]);
    expect(&f, "ipv6 && tcp", &[17, 18]);
}

#[test]
fn every_transport_frame_has_a_stream() {
    let f = load("streams");
    let transport = compile("tcp || udp").expect("compile");
    let has_id = compile("tcp.stream || udp.stream").expect("compile");
    for frame in &f {
        if matches(&transport, frame) {
            assert!(
                matches(&has_id, frame),
                "frame {} has a transport layer but no stream id",
                frame.number
            );
        }
    }
}

#[test]
fn stream_ids_are_dense_and_start_at_zero() {
    // Ids are handed out in first-seen order with no gaps, so they read as
    // "the nth conversation in this capture" rather than as opaque handles.
    let f = load("streams");
    let mut seen: Vec<u64> = Vec::new();
    for frame in &f {
        for node in frame.tree.iter() {
            if matches!(node.abbrev(), "tcp.stream" | "udp.stream") {
                if let Some(v) = node.unsigned() {
                    if !seen.contains(&v) {
                        seen.push(v);
                    }
                }
            }
        }
    }
    seen.sort_unstable();
    assert_eq!(seen, vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn a_frame_with_no_network_layer_has_no_stream() {
    // The ICMP fixtures quote a transport header inside an error. The quoted
    // header is dissected, but it belongs to the original datagram, not to a
    // conversation this capture is tracking either end of.
    let f = load("link_layer");
    let has_id = compile("tcp.stream || udp.stream").expect("compile");
    assert!(
        !f.iter().any(|fr| matches(&has_id, fr)),
        "link-layer fixture has no transport conversations"
    );
}

/// The `tcp_analysis` fixture is one connection built so that each finding
/// lands on exactly one known frame. Its frames carry explicit microsecond
/// times, because telling an out-of-order segment from a retransmission is a
/// question of milliseconds.
mod analysis {
    use super::{expect, load};

    #[test]
    fn each_finding_lands_on_the_frame_built_for_it() {
        let f = load("tcp_analysis");
        // Frame 5 resends frame 4's bytes after 490 ms, before the server has
        // acknowledged them.
        expect(&f, "tcp.analysis.retransmission", &[5]);
        // Frame 7 resends bytes the server acknowledged in frame 6.
        expect(&f, "tcp.analysis.spurious_retransmission", &[7]);
        // Frame 9 fills the hole frame 8 skipped, half a millisecond later:
        // the network reordered them rather than the sender resending.
        expect(&f, "tcp.analysis.out_of_order", &[9]);
        // Frame 8 jumps ahead of the gap frame 9 later fills; frame 10 jumps
        // over bytes the capture never sees at all.
        expect(&f, "tcp.analysis.lost_segment", &[8, 10]);
        // Frame 15 resends 2 ms after the server's third duplicate ACK.
        expect(&f, "tcp.analysis.fast_retransmission", &[15]);
        expect(&f, "tcp.analysis.duplicate_ack", &[12, 13, 14]);
        expect(&f, "tcp.analysis.overlap", &[16]);
        expect(&f, "tcp.analysis.zero_window", &[17]);
        expect(&f, "tcp.analysis.keep_alive", &[18]);
        expect(&f, "tcp.analysis.window_full", &[20]);
        expect(&f, "tcp.analysis.ack_lost_segment", &[21]);
    }

    #[test]
    fn duplicate_acks_are_numbered_and_point_back() {
        let f = load("tcp_analysis");
        expect(&f, "tcp.analysis.duplicate_ack_num == 1", &[12]);
        expect(&f, "tcp.analysis.duplicate_ack_num == 2", &[13]);
        expect(&f, "tcp.analysis.duplicate_ack_num == 3", &[14]);
        // All three repeat the ACK first sent in frame 11.
        expect(&f, "tcp.analysis.duplicate_ack_frame == 11", &[12, 13, 14]);
    }

    #[test]
    fn ordinary_frames_carry_no_analysis_subtree() {
        let f = load("tcp_analysis");
        // The handshake and the first data segment are unremarkable. Frame 4
        // does have bytes in flight, which is a measurement rather than a
        // finding, so it is excluded here by naming the findings.
        expect(
            &f,
            "tcp && !tcp.analysis.retransmission && !tcp.analysis.spurious_retransmission \
             && !tcp.analysis.out_of_order && !tcp.analysis.lost_segment \
             && !tcp.analysis.fast_retransmission && !tcp.analysis.duplicate_ack \
             && !tcp.analysis.overlap && !tcp.analysis.zero_window \
             && !tcp.analysis.keep_alive && !tcp.analysis.window_full \
             && !tcp.analysis.ack_lost_segment",
            &[1, 2, 3, 4, 6, 11, 19, 22, 23],
        );
    }

    #[test]
    fn a_clean_conversation_produces_no_findings_at_all() {
        // The `streams` fixture is ordinary traffic. If any analysis field
        // fires there, a heuristic is too eager - which is how the fixture's
        // own sequence numbers were found to be wrong.
        let f = load("streams");
        for field in [
            "tcp.analysis.retransmission",
            "tcp.analysis.spurious_retransmission",
            "tcp.analysis.out_of_order",
            "tcp.analysis.lost_segment",
            "tcp.analysis.fast_retransmission",
            "tcp.analysis.duplicate_ack",
            "tcp.analysis.overlap",
            "tcp.analysis.zero_window",
            "tcp.analysis.keep_alive",
            "tcp.analysis.window_full",
            "tcp.analysis.ack_lost_segment",
        ] {
            expect(&f, field, &[]);
        }
    }
}

/// Every fixture except the one built for it must be free of analysis
/// findings. A fixture that accidentally looks like a retransmission storm
/// makes its snapshot unreadable and can hide a real regression behind noise
/// that was always there. Three fixtures were in exactly that state when the
/// analyser was first wired in.
#[test]
fn no_other_fixture_produces_analysis_findings() {
    const FINDINGS: &[&str] = &[
        "tcp.analysis.retransmission",
        "tcp.analysis.spurious_retransmission",
        "tcp.analysis.out_of_order",
        "tcp.analysis.lost_segment",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.overlap",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.zero_window",
        "tcp.analysis.window_full",
        "tcp.analysis.keep_alive",
        "tcp.analysis.ack_lost_segment",
    ];
    let mut noise = Vec::new();
    for fx in common::fixtures::all() {
        if fx.name == "tcp_analysis" {
            continue;
        }
        let frames = load(fx.name);
        for field in FINDINGS {
            let test = compile(field).expect("compile");
            let hits: Vec<u32> = frames
                .iter()
                .filter(|f| matches(&test, f))
                .map(|f| f.number)
                .collect();
            if !hits.is_empty() {
                noise.push(format!("{}: {field} on {hits:?}", fx.name));
            }
        }
    }
    assert!(noise.is_empty(), "fixtures are not clean:\n{noise:#?}");
}
