//! The fixture captures, defined as code. Regenerate the checked-in files
//! with `NETSCOPE_REGEN=1 cargo test --test fixtures`.

use super::*;

pub struct Fixture {
    pub name: &'static str,
    pub link_type: u16,
    pub frames: Vec<Vec<u8>>,
}

fn f(name: &'static str, frames: Vec<Vec<u8>>) -> Fixture {
    Fixture {
        name,
        link_type: 1,
        frames,
    }
}

fn eth_ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
    eth(MAC_B, MAC_A, 0x0800, &ipv4(IP_A, IP_B, proto, payload))
}

fn link_layer() -> Fixture {
    let arp_req = arp(1, MAC_A, IP_A, [0; 6], [192, 168, 1, 1]);
    let mut arp_frame = eth(MAC_BCAST, MAC_A, 0x0806, &arp_req);
    arp_frame.resize(60, 0); // Ethernet minimum with padding
    let arp_reply = eth(
        MAC_A,
        MAC_B,
        0x0806,
        &arp(2, MAC_B, [192, 168, 1, 1], MAC_A, IP_A),
    );
    let arp_probe = eth(
        MAC_BCAST,
        MAC_A,
        0x0806,
        &arp(1, MAC_A, [0; 4], [0; 6], IP_A),
    );
    let arp_announce = eth(MAC_BCAST, MAC_A, 0x0806, &arp(1, MAC_A, IP_A, [0; 6], IP_A));
    let vlan_ip = eth(
        MAC_B,
        MAC_A,
        0x8100,
        &vlan(
            3,
            false,
            100,
            0x0800,
            &ipv4(IP_A, IP_B, 1, &icmp_echo(true, 1, 1, b"vlan")),
        ),
    );
    let qinq = eth(
        MAC_B,
        MAC_A,
        0x88a8,
        &vlan(
            0,
            true,
            5,
            0x8100,
            &vlan(1, false, 200, 0x0806, &arp(1, MAC_A, IP_A, [0; 6], IP_B)),
        ),
    );
    let llc_snap = eth_802_3(
        MAC_B,
        MAC_A,
        &snap(
            0,
            0x0800,
            &ipv4(IP_A, IP_B, 1, &icmp_echo(false, 1, 1, b"snap")),
        ),
    );
    let llc_stp = eth_802_3(
        [0x01, 0x80, 0xc2, 0, 0, 0],
        MAC_A,
        &[0x42, 0x42, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let llc_snap_other_oui = eth_802_3(MAC_B, MAC_A, &snap(0x00000c, 0x2000, &[1, 2, 3, 4]));
    // 802.3 length shorter than the frame: the rest is a trailer.
    let mut with_trailer = eth_802_3(MAC_B, MAC_A, &[0x42, 0x42, 0x03, 0, 0]);
    with_trailer.extend_from_slice(&[0xee; 8]);
    with_trailer[12..14].copy_from_slice(&5u16.to_be_bytes());
    let unknown_ethertype = eth(MAC_B, MAC_A, 0x88b5, &[0xde, 0xad, 0xbe, 0xef]);
    let arp_other_hw = eth(
        MAC_B,
        MAC_A,
        0x0806,
        &[
            0, 6, 0x08, 0x00, 2, 4, 0, 1, 0xaa, 0xbb, 1, 2, 3, 4, 0xcc, 0xdd, 5, 6, 7, 8,
        ],
    );
    f(
        "link_layer",
        vec![
            arp_frame,
            arp_reply,
            arp_probe,
            arp_announce,
            vlan_ip,
            qinq,
            llc_snap,
            llc_stp,
            llc_snap_other_oui,
            with_trailer,
            unknown_ethertype,
            arp_other_hw,
        ],
    )
}

fn ipv4_fixture() -> Fixture {
    let plain = eth_ipv4(1, &icmp_echo(true, 0x1234, 1, b"hello world, this is ping"));
    let mut with_opts = Ipv4::new(IP_A, IP_B, 1);
    with_opts.options = vec![148, 4, 0, 0, 1, 7, 3, 4, 130, 4, 0xab, 0xcd, 0];
    with_opts.dscp_ecn = 0xb8; // EF, ECN 0
    with_opts.ttl = 1;
    let opts_frame = eth(
        MAC_B,
        MAC_A,
        0x0800,
        &with_opts.build(&icmp_echo(true, 2, 2, b"opts")),
    );
    let mut bad = Ipv4::new(IP_A, IP_B, 1);
    bad.bad_checksum = true;
    let bad_frame = eth(
        MAC_B,
        MAC_A,
        0x0800,
        &bad.build(&icmp_echo(false, 2, 2, b"bad")),
    );
    // Three fragments of a 40-byte UDP datagram, sent out of order.
    let udp_whole = udp4(IP_A, IP_B, 4000, 5000, &[0xab; 32]);
    let frag = |off: u16, mf: bool, slice: &[u8]| {
        let mut h = Ipv4::new(IP_A, IP_B, 17);
        h.id = 0x4242;
        h.df = false;
        h.mf = mf;
        h.frag_off = off / 8;
        eth(MAC_B, MAC_A, 0x0800, &h.build(slice))
    };
    let frag2 = frag(16, true, &udp_whole[16..32]);
    let frag1 = frag(0, true, &udp_whole[..16]);
    let frag3 = frag(32, false, &udp_whole[32..]);
    // Unreachable carrying the offending header. A real ICMP error quotes the
    // datagram that caused it, which travelled the other way: the host sent
    // IP_A -> IP_B, and the error comes back IP_B -> IP_A.
    let inner = ipv4(IP_A, IP_B, 17, &udp4(IP_A, IP_B, 4000, 5000, &[1, 2, 3, 4]));
    let mut rest = vec![0, 0, 0, 0];
    rest.extend_from_slice(&inner[..28]);
    let unreach = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 1, &icmp(3, 3, &rest)),
    );
    let mut rest = vec![0, 0, 0x05, 0xdc];
    rest.extend_from_slice(&inner[..28]);
    let frag_needed = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 1, &icmp(3, 4, &rest)),
    );
    let mut rest = vec![0, 0, 0, 0];
    rest.extend_from_slice(&inner[..28]);
    let ttl_exceeded = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 1, &icmp(11, 0, &rest)),
    );
    let redirect = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            IP_B,
            IP_A,
            1,
            &icmp(
                5,
                1,
                &[[192, 168, 1, 254].as_slice(), &inner[..28]].concat(),
            ),
        ),
    );
    let mut padded = eth_ipv4(1, &icmp_echo(false, 0x1234, 1, b""));
    padded.resize(60, 0);
    let unknown_proto = eth_ipv4(0x63, &[1, 2, 3, 4, 5, 6, 7, 8]);
    // TCP segmentation offload: the NIC fills in total length and checksum
    // per segment, so a captured frame carries zero in both.
    let mut tso = Ipv4::new(IP_A, IP_B, 6);
    tso.total_len = Some(0);
    tso.bad_checksum = false;
    let mut t = Tcp::new(52100, 443, PSH | ACK);
    t.seq = 1;
    let mut tso_frame = eth(
        MAC_B,
        MAC_A,
        0x0800,
        &tso.build(&tcp4(IP_A, IP_B, &t, &[0xcd; 120])),
    );
    // Zero the header checksum the way an offloading NIC leaves it.
    tso_frame[24] = 0;
    tso_frame[25] = 0;
    f(
        "ipv4",
        vec![
            plain,
            opts_frame,
            bad_frame,
            frag2,
            frag1,
            frag3,
            unreach,
            frag_needed,
            ttl_exceeded,
            redirect,
            padded,
            unknown_proto,
            tso_frame,
        ],
    )
}

fn ipv6_fixture() -> Fixture {
    let echo = icmpv6(
        IP6_A,
        IP6_B,
        128,
        0,
        &[0x00, 0x2a, 0x00, 0x01, b'p', b'i', b'n', b'g'],
    );
    let plain = eth(MAC_B, MAC_A, 0x86dd, &ipv6(IP6_A, IP6_B, 58, 64, &echo));
    // Hop-by-hop (router alert) then destination options then UDP.
    let udp = udp6(IP6_A, IP6_B, 1234, 5678, b"ext headers");
    let mut chain = vec![60, 0, 5, 2, 0, 0, 1, 0]; // hopopts: next=dstopts, RA option, PadN
    chain.extend_from_slice(&[17, 0, 0x1e, 2, 0xaa, 0xbb, 1, 0]); // dstopts: next=udp, unknown opt, PadN
    chain.extend_from_slice(&udp);
    let exts = eth(MAC_B, MAC_A, 0x86dd, &ipv6(IP6_A, IP6_B, 0, 64, &chain));
    // Routing header type 0 with one address, then UDP.
    let mut chain = vec![17, 2, 0, 1, 0, 0, 0, 0];
    chain.extend_from_slice(&IP6_B);
    chain.extend_from_slice(&udp);
    let routing = eth(MAC_B, MAC_A, 0x86dd, &ipv6(IP6_A, IP6_B, 43, 64, &chain));
    // Fragment header: first fragment (offset 0, more) and an atomic fragment.
    let mut chain = vec![17, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef];
    chain.extend_from_slice(&udp[..8]);
    let frag = eth(MAC_B, MAC_A, 0x86dd, &ipv6(IP6_A, IP6_B, 44, 64, &chain));
    let mut chain = vec![17, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
    chain.extend_from_slice(&udp);
    let atomic = eth(MAC_B, MAC_A, 0x86dd, &ipv6(IP6_A, IP6_B, 44, 64, &chain));
    // NDP: solicitation with source link-layer option, advertisement, RA.
    let mut ns = vec![0; 4];
    ns.extend_from_slice(&IP6_B);
    ns.extend_from_slice(&[1, 1]);
    ns.extend_from_slice(&MAC_A);
    let ns_frame = eth(
        [0x33, 0x33, 0xff, 0, 0, 1],
        MAC_A,
        0x86dd,
        &ipv6(IP6_A, IP6_B, 58, 255, &icmpv6(IP6_A, IP6_B, 135, 0, &ns)),
    );
    let mut na = 0x6000_0000u32.to_be_bytes().to_vec();
    na.extend_from_slice(&IP6_B);
    na.extend_from_slice(&[2, 1]);
    na.extend_from_slice(&MAC_B);
    let na_frame = eth(
        MAC_A,
        MAC_B,
        0x86dd,
        &ipv6(IP6_B, IP6_A, 58, 255, &icmpv6(IP6_B, IP6_A, 136, 0, &na)),
    );
    let mut ra = vec![64, 0x80, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
    ra.extend_from_slice(&[5, 1, 0, 0, 0, 0, 0x05, 0xdc]); // MTU 1500
    ra.extend_from_slice(&[3, 4, 64, 0xc0]); // prefix info
    ra.extend_from_slice(&86400u32.to_be_bytes());
    ra.extend_from_slice(&14400u32.to_be_bytes());
    ra.extend_from_slice(&[0; 4]);
    ra.extend_from_slice(&IP6_B);
    ra.extend_from_slice(&[1, 1]);
    ra.extend_from_slice(&MAC_B);
    let ra_frame = eth(
        [0x33, 0x33, 0, 0, 0, 1],
        MAC_B,
        0x86dd,
        &ipv6(IP6_B, IP6_A, 58, 255, &icmpv6(IP6_B, IP6_A, 134, 0, &ra)),
    );
    let mut rd = vec![0; 4];
    rd.extend_from_slice(&IP6_B);
    rd.extend_from_slice(&IP6_A);
    rd.extend_from_slice(&[25, 3, 0, 0, 0, 0, 0x0e, 0x10]);
    rd.extend_from_slice(&IP6_B);
    let redirect6 = eth(
        MAC_A,
        MAC_B,
        0x86dd,
        &ipv6(IP6_B, IP6_A, 58, 255, &icmpv6(IP6_B, IP6_A, 137, 0, &rd)),
    );
    let too_big = eth(
        MAC_A,
        MAC_B,
        0x86dd,
        &ipv6(
            IP6_B,
            IP6_A,
            58,
            64,
            &icmpv6(IP6_B, IP6_A, 2, 0, &[0, 0, 0x05, 0x00, 0x60, 0, 0, 0]),
        ),
    );
    let no_next = eth(MAC_B, MAC_A, 0x86dd, &ipv6(IP6_A, IP6_B, 59, 64, &[]));
    f(
        "ipv6",
        vec![
            plain, exts, routing, frag, atomic, ns_frame, na_frame, ra_frame, redirect6, too_big,
            no_next,
        ],
    )
}

fn tcp_udp_fixture() -> Fixture {
    let mut syn = Tcp::new(51000, 5001, SYN);
    syn.options = vec![
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let syn_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &syn, &[]));
    let mut synack = Tcp::new(5001, 51000, SYN | ACK);
    synack.seq = 5000;
    synack.ack = 1001;
    synack.options = vec![2, 4, 0x05, 0xb4, 1, 1, 4, 2, 1, 3, 3, 5];
    let synack_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 6, &tcp4(IP_B, IP_A, &synack, &[])),
    );
    let mut data = Tcp::new(51000, 5001, PSH | ACK);
    data.seq = 1001;
    data.ack = 5001;
    data.options = vec![1, 1, 8, 10, 0, 0, 0, 2, 0, 0, 0, 9];
    let data_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &data, b"payload bytes"));
    let mut sack = Tcp::new(5001, 51000, ACK);
    sack.seq = 5001;
    sack.ack = 1001;
    sack.options = vec![
        1, 1, 5, 18, 0, 0, 0x04, 0x00, 0, 0, 0x08, 0x00, 0, 0, 0x0c, 0x00, 0, 0, 0x10, 0x00,
    ];
    let sack_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 6, &tcp4(IP_B, IP_A, &sack, &[])),
    );
    let mut all = Tcp::new(
        51000,
        5001,
        FIN | SYN | RST | PSH | ACK | URG | ECE | CWR | 0x100,
    );
    all.urgent = 7;
    all.window = 0;
    let all_flags = eth_ipv4(6, &tcp4(IP_A, IP_B, &all, &[]));
    let mut eol = Tcp::new(51000, 5001, ACK);
    eol.options = vec![2, 4, 0x05, 0xb4, 0, 0, 0, 0];
    let eol_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &eol, &[]));
    let mut unknown_opt = Tcp::new(51000, 5001, ACK);
    unknown_opt.options = vec![254, 6, 1, 2, 3, 4, 30, 4, 0, 0];
    let unknown_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &unknown_opt, &[]));
    let rst = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            IP_B,
            IP_A,
            6,
            &tcp4(IP_B, IP_A, &Tcp::new(5001, 51000, RST), &[]),
        ),
    );
    let mut short = eth_ipv4(6, &tcp4(IP_A, IP_B, &Tcp::new(51000, 5001, ACK), &[]));
    short.resize(60, 0); // padding must not become payload
    let udp_frame = eth_ipv4(17, &udp4(IP_A, IP_B, 40000, 9, b"udp payload"));
    let udp_nocksum = {
        let mut u = udp4(IP_A, IP_B, 40000, 9, b"no checksum");
        u[6] = 0;
        u[7] = 0;
        eth_ipv4(17, &u)
    };
    f(
        "tcp_udp",
        vec![
            syn_frame,
            synack_frame,
            data_frame,
            sack_frame,
            all_flags,
            eol_frame,
            unknown_frame,
            rst,
            short,
            udp_frame,
            udp_nocksum,
        ],
    )
}

fn dns_fixture() -> Fixture {
    let q = dns_question(&dns_name("www.example.com"), 1, 1);
    let query = [dns_header(0x1a2b, 0x0100, 1, 0, 0, 0), q.clone()].concat();
    let query_frame = eth_ipv4(17, &udp4(IP_A, [192, 168, 1, 1], 53123, 53, &query));
    // Response: CNAME to a compressed name, then A for the target, all using pointers.
    let mut resp = dns_header(0x1a2b, 0x8180, 1, 2, 0, 0);
    resp.extend_from_slice(&q);
    // CNAME www.example.com -> cdn.example.com (label + pointer to "example.com" at 12+4)
    let mut cname_rdata = vec![3, b'c', b'd', b'n'];
    cname_rdata.extend_from_slice(&dns_ptr(16));
    resp.extend_from_slice(&dns_rr(&dns_ptr(12), 5, 1, 300, &cname_rdata));
    let target_off = (12 + q.len() + 12) as u16; // start of rdata of the CNAME RR
    resp.extend_from_slice(&dns_rr(&dns_ptr(target_off), 1, 1, 60, &[93, 184, 216, 34]));
    let resp_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            IP_A,
            17,
            &udp4([192, 168, 1, 1], IP_A, 53, 53123, &resp),
        ),
    );
    // AAAA + MX + TXT + SOA + PTR + SRV answers.
    let q6 = dns_question(&dns_name("example.com"), 255, 1);
    let mut any = dns_header(0x0002, 0x8180, 1, 6, 0, 0);
    any.extend_from_slice(&q6);
    any.extend_from_slice(&dns_rr(&dns_ptr(12), 28, 1, 60, &IP6_B));
    let mut mx = 10u16.to_be_bytes().to_vec();
    mx.extend_from_slice(&[4, b'm', b'a', b'i', b'l']);
    mx.extend_from_slice(&dns_ptr(12));
    any.extend_from_slice(&dns_rr(&dns_ptr(12), 15, 1, 60, &mx));
    any.extend_from_slice(&dns_rr(
        &dns_ptr(12),
        16,
        1,
        60,
        &[
            11, b'v', b'=', b's', b'p', b'f', b'1', b' ', b'-', b'a', b'l', b'l',
        ],
    ));
    let mut soa = [2, b'n', b's'].to_vec();
    soa.extend_from_slice(&dns_ptr(12));
    soa.extend_from_slice(&[5, b'a', b'd', b'm', b'i', b'n']);
    soa.extend_from_slice(&dns_ptr(12));
    for v in [2024010101u32, 7200, 3600, 1209600, 300] {
        soa.extend_from_slice(&v.to_be_bytes());
    }
    any.extend_from_slice(&dns_rr(&dns_ptr(12), 6, 1, 60, &soa));
    any.extend_from_slice(&dns_rr(
        &dns_name("34.216.184.93.in-addr.arpa"),
        12,
        1,
        60,
        &dns_ptr(12),
    ));
    let mut srv = Vec::new();
    for v in [10u16, 20, 5060] {
        srv.extend_from_slice(&v.to_be_bytes());
    }
    srv.extend_from_slice(&[3, b's', b'i', b'p']);
    srv.extend_from_slice(&dns_ptr(12));
    any.extend_from_slice(&dns_rr(&dns_name("_sip._udp.example.com"), 33, 1, 60, &srv));
    let any_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            IP_A,
            17,
            &udp4([192, 168, 1, 1], IP_A, 53, 53124, &any),
        ),
    );
    // Referral: authority NS records and an additional A glue record, plus an
    // unknown record type (HTTPS) as raw data.
    let mut ref_msg = dns_header(0x0009, 0x8180, 1, 1, 1, 1);
    ref_msg.extend_from_slice(&dns_question(&dns_name("example.com"), 65, 1));
    ref_msg.extend_from_slice(&dns_rr(
        &dns_ptr(12),
        65,
        1,
        60,
        &[0, 1, 0, 1, 0, 6, 2, b'h', b'2', 2, b'h', b'3'],
    ));
    let mut ns_rdata = vec![3, b'n', b's', b'1'];
    ns_rdata.extend_from_slice(&dns_ptr(12));
    ref_msg.extend_from_slice(&dns_rr(&dns_ptr(12), 2, 1, 3600, &ns_rdata));
    ref_msg.extend_from_slice(&dns_rr(
        &[[3u8, b'n', b's', b'1'].as_slice(), &dns_ptr(12)].concat(),
        1,
        1,
        3600,
        &[192, 0, 2, 53],
    ));
    let ref_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            IP_A,
            17,
            &udp4([192, 168, 1, 1], IP_A, 53, 53126, &ref_msg),
        ),
    );
    // NXDOMAIN with no answers.
    let nx = [
        dns_header(0x0003, 0x8183, 1, 0, 0, 0),
        dns_question(&dns_name("nope.invalid"), 1, 1),
    ]
    .concat();
    let nx_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            IP_A,
            17,
            &udp4([192, 168, 1, 1], IP_A, 53, 53125, &nx),
        ),
    );
    // mDNS on 5353 with a root query.
    let mdns = [
        dns_header(0, 0, 1, 0, 0, 0),
        dns_question(&[0], 255, 0x8001),
    ]
    .concat();
    let mdns_frame = eth(
        [0x01, 0x00, 0x5e, 0, 0, 0xfb],
        MAC_A,
        0x0800,
        &ipv4(
            IP_A,
            [224, 0, 0, 251],
            17,
            &udp4(IP_A, [224, 0, 0, 251], 5353, 5353, &mdns),
        ),
    );
    f(
        "dns",
        vec![
            query_frame,
            resp_frame,
            any_frame,
            ref_frame,
            nx_frame,
            mdns_frame,
        ],
    )
}

fn dhcp_fixture() -> Fixture {
    let discover = [
        dhcp_opt(53, &[1]),
        dhcp_opt(61, &[[1u8].as_slice(), &MAC_A].concat()),
        dhcp_opt(12, b"laptop"),
        dhcp_opt(55, &[1, 3, 6, 15, 28]),
        dhcp_opt(57, &[0x05, 0xdc]),
        vec![255],
    ]
    .concat();
    let discover_frame = eth(
        MAC_BCAST,
        MAC_A,
        0x0800,
        &ipv4(
            [0; 4],
            [255; 4],
            17,
            &udp4(
                [0; 4],
                [255; 4],
                68,
                67,
                &dhcp(1, 0xabcd1234, MAC_A, [0; 4], &discover),
            ),
        ),
    );
    let offer = [
        dhcp_opt(53, &[2]),
        dhcp_opt(54, &[192, 168, 1, 1]),
        dhcp_opt(51, &86400u32.to_be_bytes()),
        dhcp_opt(1, &[255, 255, 255, 0]),
        dhcp_opt(3, &[192, 168, 1, 1]),
        dhcp_opt(6, &[8, 8, 8, 8, 1, 1, 1, 1]),
        dhcp_opt(15, b"lan"),
        dhcp_opt(58, &43200u32.to_be_bytes()),
        dhcp_opt(59, &75600u32.to_be_bytes()),
        dhcp_opt(28, &[192, 168, 1, 255]),
        vec![255, 0, 0, 0],
    ]
    .concat();
    let offer_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            [255; 4],
            17,
            &udp4(
                [192, 168, 1, 1],
                [255; 4],
                67,
                68,
                &dhcp(2, 0xabcd1234, MAC_A, IP_A, &offer),
            ),
        ),
    );
    let request = [
        dhcp_opt(53, &[3]),
        dhcp_opt(50, &IP_A),
        dhcp_opt(54, &[192, 168, 1, 1]),
        dhcp_opt(60, b"MSFT 5.0"),
        dhcp_opt(42, &[192, 168, 1, 1]),
        dhcp_opt(43, &[1, 4, 0xde, 0xad, 0xbe, 0xef]),
        vec![255],
    ]
    .concat();
    let request_frame = eth(
        MAC_BCAST,
        MAC_A,
        0x0800,
        &ipv4(
            [0; 4],
            [255; 4],
            17,
            &udp4(
                [0; 4],
                [255; 4],
                68,
                67,
                &dhcp(1, 0xabcd1234, MAC_A, [0; 4], &request),
            ),
        ),
    );
    let ack = [
        dhcp_opt(53, &[5]),
        dhcp_opt(54, &[192, 168, 1, 1]),
        dhcp_opt(51, &86400u32.to_be_bytes()),
        vec![255],
    ]
    .concat();
    let ack_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            IP_A,
            17,
            &udp4(
                [192, 168, 1, 1],
                IP_A,
                67,
                68,
                &dhcp(2, 0xabcd1234, MAC_A, IP_A, &ack),
            ),
        ),
    );
    f(
        "dhcp",
        vec![discover_frame, offer_frame, request_frame, ack_frame],
    )
}

fn http_fixture() -> Fixture {
    let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netscope-test/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";
    let mut t = Tcp::new(52000, 80, PSH | ACK);
    t.seq = 1;
    t.ack = 1;
    let req_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, req));
    let resp = b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 13\r\n\r\n<html></html>";
    let mut t = Tcp::new(80, 52000, PSH | ACK);
    t.seq = 1;
    t.ack = 1 + req.len() as u32;
    let resp_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 6, &tcp4(IP_B, IP_A, &t, resp)),
    );
    // POST on a non-standard port, detected by heuristic.
    let post = b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\n{}";
    let mut t = Tcp::new(52001, 8081, PSH | ACK);
    t.seq = 1;
    t.ack = 1;
    let post_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, post));
    // Continuation: port 80 but no request line.
    let mut t = Tcp::new(80, 52000, ACK);
    t.seq = 100;
    t.ack = 200;
    let cont_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            IP_B,
            IP_A,
            6,
            &tcp4(IP_B, IP_A, &t, b"more body bytes without headers"),
        ),
    );
    f("http", vec![req_frame, resp_frame, post_frame, cont_frame])
}

fn tls_fixture() -> Fixture {
    let ch = tls_client_hello(
        0x0303,
        &[0x5a; 32],
        &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x00ff],
        &[
            tls_sni("example.com"),
            tls_ext(43, &[4, 0x03, 0x04, 0x03, 0x03]),
            tls_alpn(&["h2", "http/1.1"]),
            tls_ext(10, &[0, 4, 0, 0x1d, 0, 0x17]),
        ],
    );
    let mut t = Tcp::new(53000, 443, PSH | ACK);
    t.seq = 1;
    t.ack = 1;
    let ch_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, &tls_record(22, 0x0301, &ch)));
    let sh = tls_server_hello(
        0x0303,
        0x1301,
        &[
            tls_ext(43, &[0x03, 0x04]),
            tls_ext(51, &[0, 0x1d, 0, 1, 0x42]),
        ],
    );
    let mut server = tls_record(22, 0x0303, &sh);
    server.extend_from_slice(&tls_record(20, 0x0303, &[1]));
    server.extend_from_slice(&tls_record(23, 0x0303, &[0x99; 40]));
    let mut t = Tcp::new(443, 53000, PSH | ACK);
    t.seq = 1;
    t.ack = 200;
    let sh_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 6, &tcp4(IP_B, IP_A, &t, &server)),
    );
    let alert = tls_record(21, 0x0303, &[1, 0]);
    let mut t = Tcp::new(53000, 443, PSH | ACK);
    t.seq = 200;
    t.ack = 300;
    let alert_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, &alert));
    // TLS 1.2 style: certificate handshake, then an encrypted handshake message.
    let cert = tls_handshake(11, &[0, 0, 7, 0, 0, 4, 0x30, 0x82, 0x01, 0x02]);
    let mut v12 = tls_record(22, 0x0303, &cert);
    v12.extend_from_slice(&tls_record(22, 0x0303, &[0xaa; 16]));
    let mut t = Tcp::new(443, 53000, PSH | ACK);
    t.seq = 300;
    t.ack = 210;
    let v12_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 6, &tcp4(IP_B, IP_A, &t, &v12)),
    );
    // Record split across segments: header says 1000 bytes, only 30 present.
    let mut partial = tls_record(23, 0x0303, &[0; 30]);
    partial[3] = 0x03;
    partial[4] = 0xe8;
    let mut t = Tcp::new(443, 53000, ACK);
    t.seq = 400;
    t.ack = 210;
    let partial_frame = eth(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(IP_B, IP_A, 6, &tcp4(IP_B, IP_A, &t, &partial)),
    );
    // Non-TLS bytes on 443.
    let mut t = Tcp::new(53000, 443, PSH | ACK);
    t.seq = 500;
    t.ack = 500;
    let junk_frame = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, b"not tls at all"));
    f(
        "tls",
        vec![
            ch_frame,
            sh_frame,
            alert_frame,
            v12_frame,
            partial_frame,
            junk_frame,
        ],
    )
}

fn malformed_fixture() -> Fixture {
    // Ethernet header only, claims IPv4.
    let eth_only = eth(MAC_B, MAC_A, 0x0800, &[]);
    // IPv4 with IHL = 3.
    let mut ihl3 = eth_ipv4(1, &icmp_echo(true, 1, 1, b"x"));
    ihl3[14] = 0x43;
    // IPv4 version 5.
    let mut v5 = eth_ipv4(1, &icmp_echo(true, 1, 1, b"x"));
    v5[14] = 0x55;
    // IPv4 total length larger than the frame.
    let mut long = Ipv4::new(IP_A, IP_B, 6);
    long.total_len = Some(9000);
    let ip_len_too_big = eth(
        MAC_B,
        MAC_A,
        0x0800,
        &long.build(&tcp4(IP_A, IP_B, &Tcp::new(1, 2, ACK), b"abc")),
    );
    // IPv4 header truncated mid-address.
    let mut trunc = eth_ipv4(6, &tcp4(IP_A, IP_B, &Tcp::new(1, 2, ACK), &[]));
    trunc.truncate(14 + 17);
    // TCP data offset 3.
    let mut bad_off = Tcp::new(1, 2, ACK);
    bad_off.data_offset = Some(3);
    let tcp_off = eth_ipv4(6, &tcp4(IP_A, IP_B, &bad_off, &[]));
    // TCP option with length 0.
    let mut opt0 = Tcp::new(1, 2, ACK);
    opt0.options = vec![2, 0, 0, 0];
    let tcp_opt0 = eth_ipv4(6, &tcp4(IP_A, IP_B, &opt0, &[]));
    // TCP option running past the header.
    let mut optlong = Tcp::new(1, 2, ACK);
    optlong.options = vec![8, 10, 0, 0];
    let tcp_optlong = eth_ipv4(6, &tcp4(IP_A, IP_B, &optlong, &[]));
    // UDP length < 8.
    let mut udp_short = udp4(IP_A, IP_B, 1, 2, b"");
    udp_short[4] = 0;
    udp_short[5] = 3;
    let udp_len = eth_ipv4(17, &udp_short);
    // DNS: pointer loop.
    let mut loop_q = dns_header(1, 0x0100, 1, 0, 0, 0);
    loop_q.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    let dns_loop = eth_ipv4(17, &udp4(IP_A, IP_B, 1234, 53, &loop_q));
    // DNS: forward pointer.
    let mut fwd = dns_header(2, 0x0100, 1, 0, 0, 0);
    fwd.extend_from_slice(&[
        0xc0, 0x20, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let dns_fwd = eth_ipv4(17, &udp4(IP_A, IP_B, 1234, 53, &fwd));
    // DNS: label runs off the end.
    let mut runoff = dns_header(3, 0x0100, 1, 0, 0, 0);
    runoff.extend_from_slice(&[63, b'a', b'b']);
    let dns_runoff = eth_ipv4(17, &udp4(IP_A, IP_B, 1234, 53, &runoff));
    // DNS: claims 65535 answers.
    let mut counts = dns_header(4, 0x8180, 1, 0xffff, 0xffff, 0xffff);
    counts.extend_from_slice(&dns_question(&dns_name("a.b"), 1, 1));
    let dns_counts = eth_ipv4(17, &udp4(IP_A, IP_B, 1234, 53, &counts));
    // DHCP: truncated fixed header.
    let dhcp_short = eth_ipv4(17, &udp4(IP_A, IP_B, 68, 67, &[1, 1, 6, 0, 1, 2, 3]));
    // DHCP: option length past end.
    let dhcp_opt_over = eth_ipv4(
        17,
        &udp4(IP_A, IP_B, 68, 67, &dhcp(1, 1, MAC_A, [0; 4], &[53, 9, 1])),
    );
    // TLS: handshake length beyond record; extension length beyond hello.
    let mut bad_hs = tls_record(22, 0x0303, &[1, 0xff, 0xff, 0xff, 3, 3]);
    bad_hs.truncate(11);
    let mut t = Tcp::new(1, 443, PSH | ACK);
    t.seq = 1;
    let tls_hs = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, &bad_hs));
    let mut ch = tls_client_hello(0x0303, &[], &[0x1301], &[tls_ext(0, &[0xff, 0xff, 0, 0])]);
    let ch_len = ch.len();
    ch[ch_len - 3] = 0xff; // corrupt extension length
    let tls_ext_bad = eth_ipv4(6, &tcp4(IP_A, IP_B, &t, &tls_record(22, 0x0303, &ch)));
    // ICMPv6 option with length 0.
    let mut ns = vec![0; 4];
    ns.extend_from_slice(&IP6_B);
    ns.extend_from_slice(&[1, 0, 1, 2, 3, 4, 5, 6]);
    let icmpv6_opt0 = eth(
        MAC_B,
        MAC_A,
        0x86dd,
        &ipv6(IP6_A, IP6_B, 58, 255, &icmpv6(IP6_A, IP6_B, 135, 0, &ns)),
    );
    // IPv6 extension header chain that runs off the end.
    let ipv6_ext_trunc = eth(
        MAC_B,
        MAC_A,
        0x86dd,
        &ipv6(IP6_A, IP6_B, 0, 64, &[17, 5, 0]),
    );
    // ARP truncated.
    let arp_trunc = eth(
        MAC_BCAST,
        MAC_A,
        0x0806,
        &[0, 1, 0x08, 0x00, 6, 4, 0, 1, 1, 2, 3],
    );
    // VLAN tag with nothing after it.
    let vlan_trunc = eth(MAC_B, MAC_A, 0x8100, &[0x00, 0x64]);
    // Empty frame.
    let empty = Vec::new();
    // IPv4 fragment exceeding the maximum datagram size.
    let mut huge = Ipv4::new(IP_A, IP_B, 17);
    huge.id = 0x9999;
    huge.df = false;
    huge.mf = false;
    huge.frag_off = 0x1fff;
    let frag_huge = eth(MAC_B, MAC_A, 0x0800, &huge.build(&[0; 16]));
    f(
        "malformed",
        vec![
            eth_only,
            ihl3,
            v5,
            ip_len_too_big,
            trunc,
            tcp_off,
            tcp_opt0,
            tcp_optlong,
            udp_len,
            dns_loop,
            dns_fwd,
            dns_runoff,
            dns_counts,
            dhcp_short,
            dhcp_opt_over,
            tls_hs,
            tls_ext_bad,
            icmpv6_opt0,
            ipv6_ext_trunc,
            arp_trunc,
            vlan_trunc,
            empty,
            frag_huge,
        ],
    )
}

fn null_fixture() -> Fixture {
    let mut frames = Vec::new();
    let mut f4 = 2u32.to_le_bytes().to_vec();
    f4.extend_from_slice(&ipv4(
        [127, 0, 0, 1],
        [127, 0, 0, 1],
        1,
        &icmp_echo(true, 9, 9, b"lo"),
    ));
    frames.push(f4);
    let mut f6 = 24u32.to_le_bytes().to_vec();
    let lo6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    f6.extend_from_slice(&ipv6(
        lo6,
        lo6,
        58,
        64,
        &icmpv6(lo6, lo6, 128, 0, &[0, 1, 0, 1]),
    ));
    frames.push(f6);
    Fixture {
        name: "null_loopback",
        link_type: 0,
        frames,
    }
}

pub fn all() -> Vec<Fixture> {
    vec![
        link_layer(),
        ipv4_fixture(),
        ipv6_fixture(),
        tcp_udp_fixture(),
        dns_fixture(),
        dhcp_fixture(),
        http_fixture(),
        tls_fixture(),
        malformed_fixture(),
        null_fixture(),
    ]
}
