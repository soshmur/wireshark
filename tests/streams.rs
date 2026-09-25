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
    let bytes = common::pcapng_with_link(fx.link_type, &fx.frames);
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
