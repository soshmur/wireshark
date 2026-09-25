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

/// Expert info: the severity and group attached to each finding, and the
/// worst-of summary the packet list renders.
mod expert {
    use super::{expect, load};
    use netscope::dissect::Severity;

    #[test]
    fn findings_carry_a_severity_and_a_group() {
        let f = load("tcp_analysis");
        // A resend is normal on any real network.
        expect(
            &f,
            "tcp.analysis.retransmission && _ws.expert.severity == \"Note\"",
            &[5],
        );
        // A gap or an overlap misleads anyone reading the stream.
        expect(
            &f,
            "tcp.analysis.lost_segment && _ws.expert.severity == \"Warning\"",
            &[8, 10],
        );
        expect(
            &f,
            "tcp.analysis.overlap && _ws.expert.severity == \"Warning\"",
            &[16],
        );
        // Everything the analyser raises is in the Sequence group.
        expect(&f, "_ws.expert && _ws.expert.group != \"Sequence\"", &[]);
    }

    #[test]
    fn severity_is_comparable_so_a_filter_can_rank_frames() {
        // The point of an ordered severity: one filter finds everything worth
        // looking at, without naming each finding.
        let f = load("tcp_analysis");
        expect(
            &f,
            "_ws.expert.severity >= \"Warning\"",
            &[8, 10, 16, 17, 21],
        );
    }

    #[test]
    fn a_bad_checksum_is_an_error_in_the_checksum_group() {
        // The ipv4 fixture's third frame has a deliberately wrong header
        // checksum. Validation is on by default in the library.
        let f = load("ipv4");
        expect(&f, "_ws.checksum.bad", &[3]);
        expect(
            &f,
            "_ws.checksum.bad && _ws.expert.severity == \"Error\" \
             && _ws.expert.group == \"Checksum\"",
            &[3],
        );
    }

    #[test]
    fn a_malformed_frame_is_an_error_in_the_malformed_group() {
        let f = load("malformed");
        let malformed: Vec<u32> = f
            .iter()
            .filter(|fr| fr.tree.find("_ws.malformed").next().is_some())
            .map(|fr| fr.number)
            .collect();
        assert!(!malformed.is_empty(), "the fixture should have some");
        expect(&f, "_ws.malformed", &malformed);
        expect(
            &f,
            "_ws.malformed && _ws.expert.group == \"Malformed\"",
            &malformed,
        );
    }

    #[test]
    fn the_summary_keeps_the_worst_finding() {
        let f = load("tcp_analysis");
        for frame in &f {
            let worst = frame
                .tree
                .find("_ws.expert.severity")
                .filter_map(|n| n.unsigned())
                .map(Severity::from_u64)
                .max();
            assert_eq!(
                frame.summary.expert.map(|e| e.severity),
                worst,
                "frame {} summary disagrees with its tree",
                frame.number
            );
        }
    }

    #[test]
    fn a_clean_frame_has_no_expert_summary() {
        let f = load("streams");
        for frame in &f {
            assert!(
                frame.summary.expert.is_none(),
                "frame {} of an ordinary capture has an expert finding: {:?}",
                frame.number,
                frame.summary.expert
            );
        }
    }
}

/// Desegmentation: messages that do not fit in one segment.
mod desegment {
    use super::{expect, load};

    #[test]
    fn a_split_response_is_dissected_once_it_is_whole() {
        let f = load("desegment");
        // Frames 2 and 3 carry part of a response; frame 4 completes it and
        // is where the message appears.
        expect(&f, "http.segment", &[2, 3, 6, 9]);
        expect(&f, "http.response.code == 200", &[4, 7]);
        expect(&f, "http.response.code == 404", &[10]);
        // The content length is only readable because the headers and body
        // were joined; before desegmentation frame 2 showed a truncated body
        // and frames 3 and 4 showed nothing at all.
        expect(&f, "http.content_length == 30", &[4]);
    }

    #[test]
    fn the_reassembled_body_is_complete() {
        let f = load("desegment");
        let frame = f.iter().find(|fr| fr.number == 4).expect("frame 4");
        let data = frame
            .tree
            .find("http.file_data")
            .next()
            .expect("the body node");
        // 30 bytes, from three segments of ten.
        assert_eq!(data.range().len(), 30);
        let source = frame.source(data.source()).expect("its data source");
        assert_eq!(
            &source[data.range()],
            b"0123456789abcdefghijABCDEFGHIJ",
            "the body should be the three segments joined, in order"
        );
        assert_ne!(
            data.source(),
            0,
            "a reassembled body cannot live in the captured frame, which only \
             holds the last ten bytes"
        );
    }

    #[test]
    fn a_chunked_body_is_awaited_to_its_final_chunk() {
        let f = load("desegment");
        // Frame 6 ends mid-chunk: the length said 16 bytes and 14 arrived.
        expect(&f, "http.transfer_encoding", &[7]);
        expect(&f, "http.segment && tcp.stream == 0", &[2, 3, 6, 9]);
    }

    #[test]
    fn pipelined_messages_in_one_segment_are_all_dissected() {
        let f = load("desegment");
        let frame = f.iter().find(|fr| fr.number == 8).expect("frame 8");
        let uris: Vec<&str> = frame
            .tree
            .find("http.request.uri")
            .filter_map(|n| n.str_value())
            .collect();
        assert_eq!(
            uris,
            vec!["/one", "/two"],
            "both requests sharing the segment must appear"
        );
    }

    #[test]
    fn an_incomplete_first_line_is_held_too() {
        // Frame 9 is "HTTP/1.1 404 Not " - not even a whole status line.
        // Holding it is what lets frame 10 produce a 404.
        let f = load("desegment");
        expect(&f, "http.segment && frame.number == 9", &[9]);
        expect(&f, "http.response.phrase == \"Not Found\"", &[10]);
    }

    #[test]
    fn a_held_frame_stays_tcp_in_the_protocol_column() {
        // It carries no message, so calling it HTTP would claim one.
        let f = load("desegment");
        for n in [2u32, 3, 6, 9] {
            let frame = f.iter().find(|fr| fr.number == n).expect("frame");
            assert_eq!(
                frame.summary.protocol, "tcp",
                "frame {n} carries part of a message, not a message"
            );
            assert_eq!(frame.summary.info, "[TCP segment of a reassembled PDU]");
        }
    }

    #[test]
    fn body_bytes_with_no_message_start_are_shown_not_held() {
        // The http fixture's last frame is body data continuing a response
        // whose start this capture never saw. Holding it would wait for a
        // message that is already over, and the bytes would never appear.
        let f = load("http");
        expect(&f, "http", &[1, 2, 3, 4]);
        expect(&f, "http.segment", &[]);
    }
}

/// TLS records split across segments.
mod tls_desegment {
    use super::{expect, load};

    #[test]
    fn a_split_client_hello_is_parsed_once_whole() {
        let f = load("tls_desegment");
        // Frame 1 carries three bytes - not even a whole record header.
        // Frame 2 carries more of the same record. Frame 3 completes it.
        expect(&f, "tls.segment", &[1, 2, 4]);
        expect(&f, "tls", &[3, 4, 5]);
        // The SNI is the point: before desegmentation a ClientHello split
        // across segments showed a fragment with no fields at all.
        expect(
            &f,
            "tls.handshake.extensions_server_name == \"split.example.com\"",
            &[3],
        );
    }

    #[test]
    fn a_frame_holding_only_a_fragment_stays_tcp() {
        let f = load("tls_desegment");
        for n in [1u32, 2] {
            let frame = f.iter().find(|fr| fr.number == n).expect("frame");
            assert_eq!(frame.summary.protocol, "tcp");
            assert_eq!(frame.summary.info, "[TCP segment of a reassembled PDU]");
        }
    }

    #[test]
    fn a_complete_record_and_a_partial_one_can_share_a_segment() {
        // Frame 4 carries a whole ServerHello followed by the first ten
        // bytes of the next record. The complete one must be dissected now
        // and the partial one held, not one or the other.
        let f = load("tls_desegment");
        expect(&f, "tls.handshake.type == 2", &[4]);
        expect(&f, "tls.segment && tls.record", &[4]);
        let frame = f.iter().find(|fr| fr.number == 4).expect("frame 4");
        assert_eq!(frame.summary.protocol, "tls");
        assert!(
            frame.summary.info.starts_with("Server Hello"),
            "info was {:?}",
            frame.summary.info
        );
    }

    #[test]
    fn the_reassembled_record_lives_in_its_own_data_source() {
        let f = load("tls_desegment");
        let frame = f.iter().find(|fr| fr.number == 3).expect("frame 3");
        let sni = frame
            .tree
            .find("tls.handshake.extensions_server_name")
            .next()
            .expect("the SNI node");
        assert_ne!(
            sni.source(),
            0,
            "the name spans segments, so it cannot be in the captured frame"
        );
        let source = frame.source(sni.source()).expect("its data source");
        assert_eq!(&source[sni.range()], b"split.example.com");
    }
}

/// Follow Stream: rebuilding a conversation's bytes from the stored frames.
mod follow {
    use super::load;
    use netscope::dissect::stream::Direction;
    use netscope::store::{follow, Limits, Store};
    use std::sync::Arc;

    /// Put a fixture's frames into a store and follow a stream from it.
    fn followed(fixture: &str, id: u32) -> netscope::store::Stream {
        let store = Store::new(Limits::default());
        let frames: Vec<Arc<netscope::dissect::Frame>> =
            load(fixture).into_iter().map(Arc::new).collect();
        store.append(frames);
        follow::follow(&store.snapshot(), id)
    }

    #[test]
    fn a_conversation_comes_back_in_order_and_by_direction() {
        // Stream 0 of the desegment fixture: a request out, a response back
        // in three segments, then more.
        let s = followed("desegment", 0);
        let client = s.joined(Direction::Forward);
        let server = s.joined(Direction::Reverse);
        assert!(
            client.starts_with(b"GET /split HTTP/1.1\r\n"),
            "client side starts with the request"
        );
        assert!(
            server.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "server side starts with the response"
        );
        // The split body is contiguous in the reassembled server side.
        let text = String::from_utf8_lossy(&server);
        assert!(
            text.contains("0123456789abcdefghijABCDEFGHIJ"),
            "the three-segment body should be joined"
        );
        assert_eq!(s.missing, 0, "nothing was dropped in this capture");
    }

    #[test]
    fn retransmissions_do_not_appear_twice() {
        // The tcp_analysis fixture resends the same ten bytes three times.
        // A transcript showing them three times would be a lie about what
        // the application received.
        let s = followed("tcp_analysis", 0);
        let client = s.joined(Direction::Forward);
        let text = String::from_utf8_lossy(&client);
        assert_eq!(
            text.matches("0123456789").count(),
            text.len() / 10,
            "every ten-byte run should be distinct data, not a repeat"
        );
    }

    #[test]
    fn gaps_that_are_later_filled_are_not_reported_as_missing() {
        // The fixture skips bytes twice and fills both holes: once by an
        // out-of-order segment and once by a fast retransmission. A capture
        // that recovered everything must not claim to be missing anything.
        let s = followed("tcp_analysis", 0);
        assert_eq!(s.missing, 0);
        assert!(s.chunks.iter().all(|c| c.gap_before == 0));
    }

    #[test]
    fn both_directions_are_counted_separately() {
        let s = followed("desegment", 0);
        assert!(s.frames[0] > 0 && s.frames[1] > 0);
        assert!(s.bytes[0] > 0 && s.bytes[1] > 0);
        assert_ne!(s.bytes[0], s.bytes[1]);
    }

    #[test]
    fn a_udp_flow_follows_in_capture_order() {
        // Stream 3 of the streams fixture is a UDP exchange. Datagrams have
        // no sequence space, so capture order is the only order there is.
        let s = followed("streams", 3);
        assert_eq!(s.joined(Direction::Forward), b"q");
        assert_eq!(s.joined(Direction::Reverse), b"a");
        assert_eq!(s.missing, 0);
    }

    #[test]
    fn following_a_stream_that_is_not_there_gives_nothing() {
        let s = followed("streams", 999);
        assert!(s.is_empty());
        assert_eq!(s.frames, [0, 0]);
    }

    #[test]
    fn a_handshake_only_stream_has_no_bytes_to_show() {
        // Stream 5 of the streams fixture is a SYN and a SYN/ACK over IPv6.
        // Neither carries payload, so there is nothing to follow.
        let s = followed("streams", 5);
        assert!(s.is_empty());
    }
}

/// The conversations table.
mod conversations {
    use super::load;
    use netscope::store::conversations::{conversations, filter_for, Kind};
    use netscope::store::{Limits, Store};
    use std::sync::Arc;

    fn rows(fixture: &str, kind: Kind) -> Vec<netscope::store::Row> {
        let store = Store::new(Limits::default());
        let frames: Vec<Arc<netscope::dissect::Frame>> =
            load(fixture).into_iter().map(Arc::new).collect();
        store.append(frames);
        conversations(&store.snapshot(), kind)
    }

    #[test]
    fn both_directions_total_into_one_row() {
        // The streams fixture's first connection is 7 frames, 4 from the
        // client and 3 from the server. Two rows each knowing half would be
        // the classic failure.
        let tcp = rows("streams", Kind::Tcp);
        let first = tcp
            .iter()
            .find(|r| r.stream == Some(0))
            .expect("stream 0 should have a row");
        assert_eq!(first.total_packets(), 7);
        // Endpoints are stored in a canonical order, which is not the order
        // they were seen in, so the client is found by its port rather than
        // assumed to be first.
        let (client, server) = if first.port_a == 40000 {
            (first.packets[0], first.packets[1])
        } else {
            (first.packets[1], first.packets[0])
        };
        assert_eq!((client, server), (4, 3));
        assert!(first.bytes[0] > 0 && first.bytes[1] > 0);
    }

    #[test]
    fn a_reused_port_is_its_own_conversation() {
        // Streams 0 and 2 share a 5-tuple exactly. They must not share a
        // row: adding a later connection's totals to an earlier one's would
        // describe traffic that never shared a conversation.
        let tcp = rows("streams", Kind::Tcp);
        // Stream 5 also uses port 40000, over IPv6, so narrow to the two
        // that share the exact IPv4 five-tuple.
        let reused: Vec<_> = tcp
            .iter()
            .filter(|r| matches!(r.stream, Some(0) | Some(2)))
            .collect();
        assert_eq!(reused.len(), 2, "one row each for streams 0 and 2");
        let mut totals: Vec<u64> = reused.iter().map(|r| r.total_packets()).collect();
        totals.sort_unstable();
        assert_eq!(totals, vec![3, 7]);
        for row in reused {
            let f = filter_for(row, Kind::Tcp);
            assert!(
                f.starts_with("tcp.stream == "),
                "a row with a stream id filters by it: {f}"
            );
        }
    }

    #[test]
    fn the_layers_group_differently() {
        // Every frame shares one pair of MACs, so Ethernet collapses to one
        // row while TCP has several.
        let eth = rows("streams", Kind::Ethernet);
        let tcp = rows("streams", Kind::Tcp);
        assert_eq!(eth.len(), 1, "one MAC pair: {eth:#?}");
        assert!(tcp.len() > 1, "several TCP conversations");
        // And the Ethernet row accounts for every frame.
        assert_eq!(eth[0].total_packets(), 18);
    }

    #[test]
    fn udp_and_tcp_are_counted_separately() {
        let udp = rows("streams", Kind::Udp);
        let tcp = rows("streams", Kind::Tcp);
        assert_eq!(udp.iter().map(|r| r.total_packets()).sum::<u64>(), 3);
        assert_eq!(tcp.iter().map(|r| r.total_packets()).sum::<u64>(), 15);
    }

    #[test]
    fn rows_are_busiest_first() {
        let tcp = rows("desegment", Kind::Tcp);
        for pair in tcp.windows(2) {
            assert!(
                pair[0].total_bytes() >= pair[1].total_bytes(),
                "the reason to open this table is to find what is using the link"
            );
        }
    }

    #[test]
    fn ipv6_conversations_appear_at_the_ip_layer() {
        let ip = rows("streams", Kind::Ip);
        let v6 = ip
            .iter()
            .filter(|r| matches!(r.a, netscope::dissect::Addr::Ipv6(_)))
            .count();
        assert_eq!(v6, 1, "the fixture has one IPv6 conversation");
        let row = ip
            .iter()
            .find(|r| matches!(r.a, netscope::dissect::Addr::Ipv6(_)))
            .expect("row");
        assert!(filter_for(row, Kind::Ip).starts_with("ipv6.addr == "));
    }

    #[test]
    fn every_generated_filter_compiles() {
        // The table's "apply as filter" action is only useful if what it
        // produces is a filter the engine accepts.
        for fixture in ["streams", "desegment", "tcp_analysis", "ipv6"] {
            for kind in Kind::ALL {
                for row in rows(fixture, kind) {
                    let f = filter_for(&row, kind);
                    assert!(
                        netscope::filter::compile(&f).is_ok(),
                        "{fixture}/{}: {f}",
                        kind.name()
                    );
                }
            }
        }
    }
}
