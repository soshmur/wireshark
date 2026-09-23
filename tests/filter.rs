//! The display filter language, exercised against the checked-in fixture
//! captures.
//!
//! Each valid case names a fixture and the exact set of frame numbers the
//! filter must select, so a change in either the language or a dissector
//! shows up as a specific difference rather than a count. Each invalid case
//! asserts the message and the column it points at.

mod common;

use netscope::dissect::{dissect, Frame, Reassembly};
use netscope::filter::{compile, matches};
use netscope_ffi::LinkType;

/// Dissect a fixture once, in frame order, as a capture would.
fn load(name: &str) -> Vec<Frame> {
    let fx = common::fixtures::all()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no fixture named {name}"));
    let bytes = common::pcapng_with_link(fx.link_type, &fx.frames);
    let section = netscope::pcapng::read(&bytes).expect("read fixture");
    let link = LinkType(i32::from(fx.link_type));
    let mut reassembly = Reassembly::new();
    section
        .packets
        .into_iter()
        .enumerate()
        .map(|(i, p)| dissect(link, i as u32 + 1, p.frame, &mut reassembly))
        .collect()
}

fn selected(frames: &[Frame], filter: &str) -> Vec<u32> {
    let test = compile(filter).unwrap_or_else(|e| panic!("{filter}: {e}"));
    frames
        .iter()
        .filter(|f| matches(&test, f))
        .map(|f| f.number)
        .collect()
}

/// Assert a filter selects exactly these frame numbers.
#[track_caller]
fn expect(frames: &[Frame], filter: &str, want: &[u32]) {
    let got = selected(frames, filter);
    assert_eq!(got, want, "filter `{filter}` selected the wrong frames");
}

#[test]
fn link_layer_filters() {
    let f = load("link_layer");
    // 12 frames: 4 ARP, VLAN, QinQ, 4 LLC/802.3, unknown ethertype, odd ARP.
    expect(&f, "arp", &[1, 2, 3, 4, 6, 12]);
    expect(&f, "vlan", &[5, 6]);
    expect(&f, "llc", &[7, 8, 9, 10]);
    expect(&f, "eth", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    expect(&f, "!eth", &[]);
    expect(&f, "arp.opcode == 1", &[1, 3, 4, 6, 12]);
    expect(&f, "arp.opcode == 2", &[2]);
    expect(&f, "arp.opcode == \"reply\"", &[2]);
    expect(&f, "arp.src.proto_ipv4 == 192.168.1.10", &[1, 4, 6]);
    expect(&f, "arp.addr == 192.168.1.10", &[1, 2, 3, 4, 6]);
    expect(&f, "arp.addr == 192.168.1.0/24", &[1, 2, 3, 4, 6]);
    expect(&f, "eth.dst == ff:ff:ff:ff:ff:ff", &[1, 3, 4]);
    // Frame 2 is the reply, sent from the other host.
    expect(
        &f,
        "eth.src == 00:11:22:33:44:55",
        &[1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    );
    expect(
        &f,
        "eth.src[0:3] == 00:11:22",
        &[1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    );
    expect(&f, "eth.src[0:3] == 00:11:23", &[]);
    expect(&f, "vlan.id == 100", &[5]);
    expect(&f, "vlan.id == 5 || vlan.id == 200", &[6]);
    expect(&f, "vlan.priority == 3", &[5]);
    expect(&f, "vlan.dei == true", &[6]);
    expect(&f, "llc.dsap == 0xaa", &[7, 9]);
    expect(&f, "eth.type == 0x0806", &[1, 2, 3, 4, 12]);
    expect(&f, "eth.type == \"ARP\"", &[1, 2, 3, 4, 12]);
    expect(&f, "eth.len", &[7, 8, 9, 10]);
    expect(&f, "arp && vlan", &[6]);
    expect(&f, "arp && !vlan", &[1, 2, 3, 4, 12]);
    expect(&f, "eth.padding", &[1]);
}

#[test]
fn ipv4_filters() {
    let f = load("ipv4");
    expect(&f, "ip", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    expect(&f, "icmp", &[1, 2, 3, 7, 8, 9, 10, 11]);
    // Frames 7-10 quote this host's datagram inside an ICMP error, so its
    // address appears in them too; see the multi-occurrence test.
    expect(
        &f,
        "ip.src == 192.168.1.10",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
    expect(
        &f,
        "ip.addr == 93.184.216.34",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
    expect(
        &f,
        "ip.src == 192.168.1.0/24",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
    expect(&f, "ip.src == 10.0.0.0/8", &[]);
    expect(&f, "ip.ttl == 1", &[2]);
    expect(&f, "ip.ttl < 64", &[2]);
    expect(
        &f,
        "ip.ttl >= 64",
        &[1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
    expect(&f, "ip.proto == 1", &[1, 2, 3, 7, 8, 9, 10, 11]);
    expect(&f, "ip.proto == \"ICMP\"", &[1, 2, 3, 7, 8, 9, 10, 11]);
    // Frames 7-10 quote a UDP datagram inside an ICMP error, so they carry a
    // second IPv4 header whose protocol is UDP.
    expect(&f, "ip.proto == 17", &[4, 5, 6, 7, 8, 9, 10]);
    expect(&f, "ip.flags.mf == true", &[4, 5]);
    expect(&f, "ip.frag_offset > 0", &[4, 6]);
    expect(&f, "ip.id == 0x4242", &[4, 5, 6]);
    expect(&f, "ip.options", &[2]);
    expect(&f, "ip.opt.type == 148", &[2]);
    expect(&f, "ip.checksum.status == \"Bad\"", &[3]);
    expect(
        &f,
        "ip.checksum.status == \"Good\"",
        &[1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    );
    expect(&f, "icmp.type == 8", &[1, 2]);
    expect(&f, "icmp.type == 0", &[3, 11]);
    expect(&f, "icmp.type in {3, 11}", &[7, 8, 9]);
    expect(&f, "icmp.code == 4", &[8]);
    expect(&f, "icmp.mtu == 1500", &[8]);
    expect(&f, "icmp.gateway == 192.168.1.254", &[10]);
    // Frame 6 completes the reassembly, so the datagram's UDP header appears
    // there; frames 7-10 carry a quoted UDP header inside an ICMP error.
    expect(&f, "udp", &[6, 7, 8, 9, 10]);
    expect(&f, "udp.srcport == 4000", &[6, 7, 8, 9, 10]);
    expect(&f, "ip.fragments", &[6]);
    // TSO frame: total length zero with a payload.
    expect(&f, "ip.len_tso", &[13]);
    expect(&f, "ip.len == 0", &[13]);
    expect(&f, "tcp", &[13]);
}

#[test]
fn ipv6_filters() {
    let f = load("ipv6");
    expect(&f, "ipv6", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    expect(&f, "icmpv6", &[1, 6, 7, 8, 9, 10]);
    expect(&f, "udp", &[2, 3, 5]);
    expect(
        &f,
        "ipv6.src == fe80::211:22ff:fe33:4455",
        &[1, 2, 3, 4, 5, 6, 11],
    );
    expect(
        &f,
        "ipv6.addr == 2001:db8::1",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    );
    expect(&f, "ipv6.src == fe80::/10", &[1, 2, 3, 4, 5, 6, 11]);
    expect(&f, "ipv6.src == 2001:db8::/32", &[7, 8, 9, 10]);
    expect(&f, "ipv6.hlim == 255", &[6, 7, 8, 9]);
    expect(&f, "ipv6.hopopts", &[2]);
    expect(&f, "ipv6.dstopts", &[2]);
    expect(&f, "ipv6.routing", &[3]);
    expect(&f, "ipv6.routing.type == 0", &[3]);
    expect(&f, "ipv6.fraghdr", &[4, 5]);
    expect(&f, "ipv6.fraghdr.more == true", &[4]);
    expect(&f, "icmpv6.type == 135", &[6]);
    expect(&f, "icmpv6.type in {133, 134, 135, 136}", &[6, 7, 8]);
    expect(&f, "icmpv6.nd.na.flag.s == true", &[7]);
    expect(&f, "icmpv6.opt.mtu == 1500", &[8]);
    expect(&f, "icmpv6.mtu == 1280", &[10]);
    expect(&f, "ipv6.nxt == 59", &[11]);
}

#[test]
fn tcp_and_udp_filters() {
    let f = load("tcp_udp");
    expect(&f, "tcp", &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(&f, "udp", &[10, 11]);
    expect(&f, "tcp.flags.syn == true", &[1, 2, 5]);
    expect(&f, "tcp.flags.syn == true && tcp.flags.ack == false", &[1]);
    expect(&f, "tcp.flags.reset == true", &[5, 8]);
    expect(&f, "tcp.flags == 0x002", &[1]);
    expect(&f, "tcp.srcport == 51000", &[1, 3, 5, 6, 7, 9]);
    expect(&f, "tcp.port == 5001", &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(
        &f,
        "tcp.port in {5001, 51000}",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9],
    );
    expect(&f, "tcp.len > 0", &[3]);
    expect(&f, "tcp.seq == 1001", &[3]);
    expect(&f, "tcp.options.mss", &[1, 2, 6]);
    expect(&f, "tcp.options.mss_val == 1460", &[1, 2, 6]);
    expect(&f, "tcp.options.wscale", &[1, 2]);
    expect(&f, "tcp.options.wscale.shift == 7", &[1]);
    expect(&f, "tcp.options.sack_perm", &[1, 2]);
    expect(&f, "tcp.options.sack", &[4]);
    expect(&f, "tcp.options.timestamp", &[1, 3]);
    expect(&f, "tcp.options.timestamp.tsval == 2", &[3]);
    // Frame 7's options are padded to a 32-bit boundary, which the parser
    // reads as End of Option List followed by padding.
    expect(&f, "tcp.options.eol", &[6, 7]);
    expect(&f, "tcp.options.unknown", &[7]);
    expect(&f, "tcp.window_size_value == 0", &[5]);
    expect(&f, "tcp.urgent_pointer > 0", &[5]);
    expect(&f, "udp.port == 9", &[10, 11]);
    expect(&f, "udp.checksum.status == \"Not present\"", &[11]);
    expect(&f, "udp.length == 19", &[10, 11]);
    expect(&f, "tcp contains \"payload\"", &[3]);
    expect(&f, "udp contains \"udp payload\"", &[10]);
}

#[test]
fn dns_filters() {
    let f = load("dns");
    expect(&f, "dns", &[1, 2, 3, 4, 5, 6]);
    expect(&f, "dns.flags.response == true", &[2, 3, 4, 5]);
    expect(&f, "dns.flags.response == false", &[1, 6]);
    expect(&f, "dns.qry.name == \"www.example.com\"", &[1, 2]);
    expect(&f, "dns.qry.name contains \"example\"", &[1, 2, 3, 4]);
    expect(&f, "dns.qry.name matches \"^www\\\\.\"", &[1, 2]);
    expect(
        &f,
        "dns.qry.name matches \"\\\\.(com|invalid)$\"",
        &[1, 2, 3, 4, 5],
    );
    expect(&f, "dns.qry.type == 1", &[1, 2, 5]);
    expect(&f, "dns.qry.type == \"ANY\"", &[3, 6]);
    expect(&f, "dns.a == 93.184.216.34", &[2]);
    expect(&f, "dns.aaaa == 2001:db8::1", &[3]);
    expect(&f, "dns.cname == \"cdn.example.com\"", &[2]);
    expect(&f, "dns.flags.rcode == 3", &[5]);
    expect(&f, "dns.count.answers > 1", &[2, 3]);
    expect(&f, "dns.resp.ttl < 100", &[2, 3, 4]);
    expect(&f, "dns.ns", &[4]);
    expect(&f, "dns.soa.serial_number == 2024010101", &[3]);
    expect(&f, "dns.srv.port == 5060", &[3]);
    expect(&f, "dns.mx.preference == 10", &[3]);
    expect(&f, "dns.txt contains \"spf1\"", &[3]);
    expect(&f, "udp.port == 5353", &[6]);
    expect(&f, "dns.id == 0x1a2b", &[1, 2]);
}

#[test]
fn dhcp_http_and_tls_filters() {
    let d = load("dhcp");
    expect(&d, "dhcp", &[1, 2, 3, 4]);
    expect(&d, "dhcp.option.dhcp == 1", &[1]);
    expect(&d, "dhcp.option.dhcp == \"Request\"", &[3]);
    expect(&d, "dhcp.ip.your == 192.168.1.10", &[2, 4]);
    expect(&d, "dhcp.hw.mac_addr == 00:11:22:33:44:55", &[1, 2, 3, 4]);
    expect(&d, "dhcp.option.hostname == \"laptop\"", &[1]);
    expect(&d, "dhcp.option.domain_name_server == 8.8.8.8", &[2]);
    expect(&d, "dhcp.option.ip_address_lease_time == 86400", &[2, 4]);
    expect(&d, "dhcp.option.vendor_class_id contains \"MSFT\"", &[3]);
    expect(&d, "dhcp.id == 0xabcd1234", &[1, 2, 3, 4]);

    let h = load("http");
    expect(&h, "http", &[1, 2, 3, 4]);
    expect(&h, "http.request", &[1, 3]);
    expect(&h, "http.response", &[2]);
    expect(&h, "http.request.method == \"GET\"", &[1]);
    expect(&h, "http.request.method == \"POST\"", &[3]);
    expect(&h, "http.response.code == 200", &[2]);
    expect(&h, "http.host == \"example.com\"", &[1, 3]);
    expect(&h, "http.user_agent contains \"netscope\"", &[1]);
    expect(&h, "http.content_type contains \"html\"", &[2]);
    expect(&h, "http.content_length == 13", &[2]);
    expect(&h, "http.request.uri matches \"^/(index|api)\"", &[1, 3]);
    expect(&h, "tcp.port == 8081", &[3]);

    let t = load("tls");
    expect(&t, "tls", &[1, 2, 3, 4, 5, 6]);
    expect(&t, "tls.handshake.type == 1", &[1]);
    expect(&t, "tls.handshake.type == 2", &[2]);
    expect(
        &t,
        "tls.handshake.extensions_server_name == \"example.com\"",
        &[1],
    );
    expect(
        &t,
        "tls.handshake.extensions_server_name contains \"example\"",
        &[1],
    );
    expect(&t, "tls.handshake.ciphersuite == 0x1301", &[1, 2]);
    expect(&t, "tls.record.content_type == 21", &[3]);
    expect(&t, "tls.alert_message.desc == 0", &[3]);
    expect(&t, "tls.handshake.certificate", &[4]);
    expect(&t, "tls.record.version == 0x0301", &[1]);
    expect(&t, "tls.handshake.extensions_alpn_str == \"h2\"", &[1]);
    expect(&t, "tls.app_data", &[2]);
    expect(&t, "tls.continuation_data", &[5, 6]);
}

#[test]
fn boolean_structure_and_precedence() {
    let f = load("ipv4");
    // || is looser than &&: this is icmp OR (udp AND ip.frag_offset > 0).
    expect(
        &f,
        "icmp || udp && ip.frag_offset > 0",
        &[1, 2, 3, 6, 7, 8, 9, 10, 11],
    );
    expect(&f, "(icmp || udp) && ip.frag_offset > 0", &[6]);
    expect(&f, "!icmp && ip", &[4, 5, 6, 12, 13]);
    expect(&f, "!(icmp || udp)", &[4, 5, 12, 13]);
    // An ICMP error quotes the datagram that caused it, so frames 7-10 do
    // carry a UDP header and `not udp` excludes them.
    expect(&f, "icmp and not udp", &[1, 2, 3, 11]);
    expect(&f, "!!icmp", &[1, 2, 3, 7, 8, 9, 10, 11]);
    expect(&f, "ip && !ip", &[]);
    expect(
        &f,
        "ip || !ip",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
}

#[test]
fn multi_occurrence_semantics_are_any_match() {
    // Frame 7 is an ICMP port-unreachable quoting the offending header, so
    // it carries two IPv4 headers with the addresses reversed.
    let f = load("ipv4");
    let quoting = &f[6];
    assert_eq!(quoting.number, 7);
    let count = quoting
        .tree
        .iter()
        .filter(|n| n.abbrev() == "ip.src")
        .count();
    assert_eq!(count, 2, "the fixture must carry a quoted header");

    // The outer header of frames 7-10 comes from the far host.
    expect(&f, "ip.src == 93.184.216.34", &[7, 8, 9, 10]);
    // The quoted header inside those errors came from this host, so an
    // any-occurrence match selects every frame, including the four whose
    // outer source is the far host.
    expect(
        &f,
        "ip.src == 192.168.1.10",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
    // `!=` is likewise any-occurrence: true when some occurrence differs,
    // which for frames carrying two headers is true of both addresses.
    expect(
        &f,
        "ip.src != 93.184.216.34",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    );
    // Negating the equality is the way to say "no occurrence matches".
    expect(&f, "!(ip.src == 192.168.1.10)", &[]);
}

#[test]
fn malformed_frames_are_filterable() {
    let f = load("malformed");
    let bad = selected(&f, "_ws.malformed");
    assert!(
        bad.len() > 10,
        "expected many malformed frames, got {bad:?}"
    );
    // A frame whose IPv4 header could not be read at all has no `ip` layer;
    // one that failed later keeps the fields it did parse.
    expect(&f, "eth && !ip", &[1, 2, 3, 5, 18, 19, 20, 21]);
    expect(
        &f,
        "ip",
        &[4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 23],
    );
    // Partially parsed layers are still filterable.
    expect(&f, "dns.flags.response == true", &[13]);
    expect(&f, "tcp", &[4, 7, 8, 16, 17]);
}

#[test]
fn invalid_filters_report_message_and_column() {
    // (filter, substring of the message, column it points at)
    let cases: &[(&str, &str, usize)] = &[
        ("", "empty", 0),
        ("tcp.port = 443", "use `==`", 9),
        ("tcp.prot == 443", "did you mean `tcp.port`", 0),
        ("nosuch.field", "unknown field", 0),
        ("tcp.port ==", "ends here", 11),
        ("tcp.port == \"http\"", "expected a number", 12),
        ("ip.src == aa:bb:cc:dd:ee:ff", "IPv4", 10),
        ("eth.src == 10.0.0.1", "MAC", 11),
        ("tcp.port == -1", "unsigned", 12),
        ("tcp.flags.syn > 0", "cannot be used", 0),
        ("ip.src contains \"10\"", "contains", 0),
        ("ip.ttl matches \"6\"", "matches", 0),
        ("tcp == 1", "on its own", 7),
        ("tcp.flags.syn[0] == aa:bb", "no bytes to slice", 0),
        ("eth.src[0:3] == 443", "byte string", 16),
        (
            "dns.qry.name matches \"(\"",
            "invalid regular expression",
            21,
        ),
        ("443 == tcp.port", "field name", 0),
        ("tcp.port == udp.port", "two fields", 12),
        ("(tcp", "`)`", 4),
        ("tcp udp", "after the end", 4),
        ("tcp.port in 80", "`{`", 12),
        ("ip.src == 10.0.0.1 & 1", "use `&&`", 19),
        ("tcp && \"unterminated", "unterminated", 7),
    ];
    for (filter, want_message, want_column) in cases {
        let err = compile(filter)
            .err()
            .unwrap_or_else(|| panic!("`{filter}` should not compile"));
        assert!(
            err.message.contains(want_message),
            "`{filter}`: message `{}` should contain `{want_message}`",
            err.message
        );
        assert_eq!(
            err.column, *want_column,
            "`{filter}`: column of `{}`",
            err.message
        );
    }
}

#[test]
fn every_registered_field_can_be_compiled() {
    // A filter naming any registered field must at least type-check with a
    // literal of its own kind, so the registry and the type checker cannot
    // drift apart.
    use netscope::dissect::registry::{self, Kind};
    let mut failures = Vec::new();
    for def in registry::all() {
        let filter = match def.kind {
            Kind::Protocol | Kind::Group => def.abbrev.to_string(),
            Kind::Bool => format!("{} == true", def.abbrev),
            Kind::Unsigned(_) | Kind::Enum(..) => format!("{} == 1", def.abbrev),
            Kind::Signed => format!("{} == -1", def.abbrev),
            Kind::Str => format!("{} == \"x\"", def.abbrev),
            Kind::Bytes => format!("{} == aa:bb", def.abbrev),
            Kind::Ipv4 => format!("{} == 10.0.0.1", def.abbrev),
            Kind::Ipv6 => format!("{} == 2001:db8::1", def.abbrev),
            Kind::Mac => format!("{} == aa:bb:cc:dd:ee:ff", def.abbrev),
        };
        if let Err(e) = compile(&filter) {
            failures.push(format!("{filter}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The default colour rules are display filters, so they belong in this
/// suite. What they assert is *ordering*: the first match wins and most
/// frames match several rules, so the interesting property is which one
/// claims each frame, not whether any does.
mod colour_rules {
    use super::load;
    use netscope::app::colour_rules::{defaults, Rules};

    /// The name of the rule that claims each frame, or `-` for none.
    #[track_caller]
    fn expect_claims(fixture: &str, want: &[&str]) {
        let rules = Rules::new(defaults());
        let got: Vec<&str> = load(fixture)
            .iter()
            .map(|f| match rules.matching(f) {
                Some(i) => rules.rules()[i].name.as_str(),
                None => "-",
            })
            .collect();
        assert_eq!(
            got, want,
            "colour rules claimed the wrong frames in {fixture}"
        );
    }

    #[test]
    fn every_default_rule_compiles() {
        let rules = Rules::new(defaults());
        for (i, rule) in rules.rules().iter().enumerate() {
            assert!(
                rules.error(i).is_none(),
                "default rule `{}` (`{}`) does not compile: {:?}",
                rule.name,
                rule.filter,
                rules.error(i)
            );
        }
    }

    #[test]
    fn link_layer_frames_are_claimed_by_their_innermost_protocol() {
        // Frames 5 and 7 are VLAN and LLC/SNAP carrying ICMP, so the ICMP
        // rule claims them ahead of anything link-layer. Frames 8-11 are
        // LLC without an IP payload and match no rule at all.
        expect_claims(
            "link_layer",
            &[
                "ARP", "ARP", "ARP", "ARP", "ICMP", "ARP", "ICMP", "-", "-", "-", "-", "ARP",
            ],
        );
    }

    #[test]
    fn a_bad_checksum_outranks_the_protocol() {
        // Frame 3 has a deliberately wrong IPv4 header checksum; without the
        // checksum rule sitting above them, ICMP would have claimed it.
        // Frames 4, 5 and 12 are fragments with no transport layer to name.
        expect_claims(
            "ipv4",
            &[
                "ICMP",
                "ICMP",
                "Bad checksum",
                "-",
                "-",
                "UDP",
                "ICMP",
                "ICMP",
                "ICMP",
                "ICMP",
                "ICMP",
                "-",
                "TLS",
            ],
        );
    }

    #[test]
    fn handshake_and_reset_outrank_plain_tcp() {
        expect_claims(
            "tcp_udp",
            &[
                "TCP handshake",
                "TCP handshake",
                "TCP",
                "TCP",
                "TCP reset",
                "TCP",
                "TCP",
                "TCP reset",
                "TCP",
                "UDP",
                "UDP",
            ],
        );
    }

    #[test]
    fn dns_outranks_the_udp_carrying_it() {
        expect_claims("dns", &["DNS", "DNS", "DNS", "DNS", "DNS", "DNS"]);
    }

    #[test]
    fn malformed_outranks_everything() {
        // Frame 4 is a well-formed segment and frame 17 a well-formed TLS
        // record; every other frame in this fixture fails to dissect
        // somewhere and the malformed rule takes it.
        let rules = Rules::new(defaults());
        let frames = load("malformed");
        let claimed: Vec<&str> = frames
            .iter()
            .map(|f| match rules.matching(f) {
                Some(i) => rules.rules()[i].name.as_str(),
                None => "-",
            })
            .collect();
        assert_eq!(claimed[3], "TCP");
        assert_eq!(claimed[16], "TLS");
        for (i, name) in claimed.iter().enumerate() {
            if i != 3 && i != 16 {
                assert_eq!(*name, "Malformed", "frame {} of malformed", i + 1);
            }
        }
    }

    #[test]
    fn a_disabled_rule_hands_the_frame_to_the_next_one() {
        let mut rules = Rules::new(defaults());
        let frames = load("dns");
        assert_eq!(
            rules.rules()[rules.matching(&frames[1]).expect("rule")].name,
            "DNS"
        );
        let dns = rules.matching(&frames[1]).expect("rule");
        rules.rules_mut()[dns].enabled = false;
        rules.recompile();
        let next = rules.matching(&frames[1]).expect("rule");
        assert_eq!(rules.rules()[next].name, "UDP");
    }
}
