//! Packet builders for fixtures. Every fixture capture is produced from these
//! programmatically (never from live traffic) so the byte layout is known.

#![allow(dead_code)]

pub mod fixtures;

use netscope::capture::Timestamp;
use netscope::dissect::proto::inet_checksum;
use netscope::pcapng::Writer;

pub const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
pub const MAC_B: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
pub const MAC_BCAST: [u8; 6] = [0xff; 6];
pub const IP_A: [u8; 4] = [192, 168, 1, 10];
pub const IP_B: [u8; 4] = [93, 184, 216, 34];
pub const IP6_A: [u8; 16] = [
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55,
];
pub const IP6_B: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

pub fn ts(n: u32) -> Timestamp {
    Timestamp {
        secs: 1_700_000_000 + i64::from(n),
        nanos: (n % 1000) * 1_000_000 + 123_456,
    }
}

pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(14 + payload.len());
    b.extend_from_slice(&dst);
    b.extend_from_slice(&src);
    b.extend_from_slice(&ethertype.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

/// IEEE 802.3 frame with a length field and LLC payload.
pub fn eth_802_3(dst: [u8; 6], src: [u8; 6], llc: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&dst);
    b.extend_from_slice(&src);
    b.extend_from_slice(&(llc.len() as u16).to_be_bytes());
    b.extend_from_slice(llc);
    b
}

pub fn vlan(pcp: u8, dei: bool, id: u16, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let tci = (u16::from(pcp) << 13) | (u16::from(dei) << 12) | (id & 0x0fff);
    let mut b = Vec::new();
    b.extend_from_slice(&tci.to_be_bytes());
    b.extend_from_slice(&ethertype.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

pub fn snap(oui: u32, pid: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0xaa, 0xaa, 0x03];
    b.extend_from_slice(&oui.to_be_bytes()[1..]);
    b.extend_from_slice(&pid.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

pub fn arp(opcode: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0, 1, 0x08, 0x00, 6, 4];
    b.extend_from_slice(&opcode.to_be_bytes());
    b.extend_from_slice(&sha);
    b.extend_from_slice(&spa);
    b.extend_from_slice(&tha);
    b.extend_from_slice(&tpa);
    b
}

#[derive(Clone)]
pub struct Ipv4 {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub id: u16,
    pub df: bool,
    pub mf: bool,
    pub frag_off: u16,
    pub ttl: u8,
    pub dscp_ecn: u8,
    pub options: Vec<u8>,
    /// Override the total length field (for malformed cases).
    pub total_len: Option<u16>,
    pub bad_checksum: bool,
}

impl Ipv4 {
    pub fn new(src: [u8; 4], dst: [u8; 4], proto: u8) -> Ipv4 {
        Ipv4 {
            src,
            dst,
            proto,
            id: 0x1234,
            df: true,
            mf: false,
            frag_off: 0,
            ttl: 64,
            dscp_ecn: 0,
            options: Vec::new(),
            total_len: None,
            bad_checksum: false,
        }
    }

    pub fn build(&self, payload: &[u8]) -> Vec<u8> {
        let mut opts = self.options.clone();
        while !opts.len().is_multiple_of(4) {
            opts.push(0);
        }
        let ihl = 5 + opts.len() / 4;
        let total = self
            .total_len
            .unwrap_or((20 + opts.len() + payload.len()) as u16);
        let mut b = Vec::with_capacity(20 + opts.len() + payload.len());
        b.push(0x40 | ihl as u8);
        b.push(self.dscp_ecn);
        b.extend_from_slice(&total.to_be_bytes());
        b.extend_from_slice(&self.id.to_be_bytes());
        let flags_off =
            (u16::from(self.df) << 14) | (u16::from(self.mf) << 13) | (self.frag_off & 0x1fff);
        b.extend_from_slice(&flags_off.to_be_bytes());
        b.push(self.ttl);
        b.push(self.proto);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.src);
        b.extend_from_slice(&self.dst);
        b.extend_from_slice(&opts);
        let ck = inet_checksum(&[&b]);
        let ck = if self.bad_checksum { ck ^ 0x00ff } else { ck };
        b[10..12].copy_from_slice(&ck.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    Ipv4::new(src, dst, proto).build(payload)
}

/// IPv6 header with an optional chain of extension headers already built
/// (each ext header's own next-header field must be filled by the caller).
pub fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, hlim: u8, ext_and_payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(40 + ext_and_payload.len());
    b.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    b.extend_from_slice(&(ext_and_payload.len() as u16).to_be_bytes());
    b.push(next);
    b.push(hlim);
    b.extend_from_slice(&src);
    b.extend_from_slice(&dst);
    b.extend_from_slice(ext_and_payload);
    b
}

fn pseudo_v4(src: [u8; 4], dst: [u8; 4], proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[0, proto]);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p
}

fn pseudo_v6(src: [u8; 16], dst: [u8; 16], proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(40);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&(len as u32).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, proto]);
    p
}

#[derive(Clone)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
    pub urgent: u16,
    pub options: Vec<u8>,
    /// Override the data offset nibble (for malformed cases).
    pub data_offset: Option<u8>,
}

pub const FIN: u16 = 0x001;
pub const SYN: u16 = 0x002;
pub const RST: u16 = 0x004;
pub const PSH: u16 = 0x008;
pub const ACK: u16 = 0x010;
pub const URG: u16 = 0x020;
pub const ECE: u16 = 0x040;
pub const CWR: u16 = 0x080;

impl Tcp {
    pub fn new(sport: u16, dport: u16, flags: u16) -> Tcp {
        Tcp {
            sport,
            dport,
            seq: 1000,
            ack: 0,
            flags,
            window: 65535,
            urgent: 0,
            options: Vec::new(),
            data_offset: None,
        }
    }

    pub fn build(&self, pseudo: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut opts = self.options.clone();
        while !opts.len().is_multiple_of(4) {
            opts.push(0);
        }
        let off = self.data_offset.unwrap_or((5 + opts.len() / 4) as u8);
        let mut b = Vec::with_capacity(20 + opts.len() + payload.len());
        b.extend_from_slice(&self.sport.to_be_bytes());
        b.extend_from_slice(&self.dport.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.extend_from_slice(&((u16::from(off) << 12) | (self.flags & 0x0fff)).to_be_bytes());
        b.extend_from_slice(&self.window.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.urgent.to_be_bytes());
        b.extend_from_slice(&opts);
        b.extend_from_slice(payload);
        let mut p = pseudo.to_vec();
        let len = b.len();
        if p.len() == 12 {
            p[10..12].copy_from_slice(&(len as u16).to_be_bytes());
        } else if p.len() == 40 {
            p[32..36].copy_from_slice(&(len as u32).to_be_bytes());
        }
        let ck = inet_checksum(&[&p, &b]);
        b[16..18].copy_from_slice(&ck.to_be_bytes());
        b
    }
}

/// TCP over IPv4 with correct checksum.
pub fn tcp4(src: [u8; 4], dst: [u8; 4], t: &Tcp, payload: &[u8]) -> Vec<u8> {
    t.build(&pseudo_v4(src, dst, 6, 0), payload)
}

pub fn udp_raw(sport: u16, dport: u16, pseudo: &[u8], payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut b = Vec::with_capacity(len);
    b.extend_from_slice(&sport.to_be_bytes());
    b.extend_from_slice(&dport.to_be_bytes());
    b.extend_from_slice(&(len as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(payload);
    let mut p = pseudo.to_vec();
    if p.len() == 12 {
        p[10..12].copy_from_slice(&(len as u16).to_be_bytes());
    } else if p.len() == 40 {
        p[32..36].copy_from_slice(&(len as u32).to_be_bytes());
    }
    let ck = inet_checksum(&[&p, &b]);
    b[6..8].copy_from_slice(&(if ck == 0 { 0xffff } else { ck }).to_be_bytes());
    b
}

pub fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    udp_raw(sport, dport, &pseudo_v4(src, dst, 17, 0), payload)
}

pub fn udp6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    udp_raw(sport, dport, &pseudo_v6(src, dst, 17, 0), payload)
}

pub fn icmp(ty: u8, code: u8, rest: &[u8]) -> Vec<u8> {
    let mut b = vec![ty, code, 0, 0];
    b.extend_from_slice(rest);
    let ck = inet_checksum(&[&b]);
    b[2..4].copy_from_slice(&ck.to_be_bytes());
    b
}

pub fn icmp_echo(request: bool, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut rest = Vec::new();
    rest.extend_from_slice(&ident.to_be_bytes());
    rest.extend_from_slice(&seq.to_be_bytes());
    rest.extend_from_slice(data);
    icmp(if request { 8 } else { 0 }, 0, &rest)
}

pub fn icmpv6(src: [u8; 16], dst: [u8; 16], ty: u8, code: u8, rest: &[u8]) -> Vec<u8> {
    let mut b = vec![ty, code, 0, 0];
    b.extend_from_slice(rest);
    let p = pseudo_v6(src, dst, 58, b.len());
    let ck = inet_checksum(&[&p, &b]);
    b[2..4].copy_from_slice(&ck.to_be_bytes());
    b
}

/// DNS name in wire format (no compression).
pub fn dns_name(name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b
}

pub fn dns_header(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(12);
    for v in [id, flags, qd, an, ns, ar] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b
}

pub fn dns_question(name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut b = name.to_vec();
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&qclass.to_be_bytes());
    b
}

pub fn dns_rr(name: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut b = name.to_vec();
    b.extend_from_slice(&rtype.to_be_bytes());
    b.extend_from_slice(&class.to_be_bytes());
    b.extend_from_slice(&ttl.to_be_bytes());
    b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    b.extend_from_slice(rdata);
    b
}

/// A compression pointer to `offset`.
pub fn dns_ptr(offset: u16) -> Vec<u8> {
    (0xc000 | offset).to_be_bytes().to_vec()
}

pub fn dhcp(op: u8, xid: u32, chaddr: [u8; 6], yiaddr: [u8; 4], options: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(240 + options.len());
    b.extend_from_slice(&[op, 1, 6, 0]);
    b.extend_from_slice(&xid.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0x80, 0]);
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&yiaddr);
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(&chaddr);
    b.extend_from_slice(&[0; 10]);
    b.extend_from_slice(&[0; 64]);
    b.extend_from_slice(&[0; 128]);
    b.extend_from_slice(&0x6382_5363u32.to_be_bytes());
    b.extend_from_slice(options);
    b
}

pub fn dhcp_opt(code: u8, value: &[u8]) -> Vec<u8> {
    let mut b = vec![code, value.len() as u8];
    b.extend_from_slice(value);
    b
}

pub fn tls_record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut b = vec![content_type];
    b.extend_from_slice(&version.to_be_bytes());
    b.extend_from_slice(&(body.len() as u16).to_be_bytes());
    b.extend_from_slice(body);
    b
}

pub fn tls_handshake(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut b = vec![ty];
    b.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    b.extend_from_slice(body);
    b
}

pub fn tls_ext(ty: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&ty.to_be_bytes());
    b.extend_from_slice(&(data.len() as u16).to_be_bytes());
    b.extend_from_slice(data);
    b
}

pub fn tls_sni(host: &str) -> Vec<u8> {
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    entry.extend_from_slice(host.as_bytes());
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    tls_ext(0, &list)
}

pub fn tls_alpn(protos: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protos {
        list.push(p.len() as u8);
        list.extend_from_slice(p.as_bytes());
    }
    let mut body = (list.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&list);
    tls_ext(16, &body)
}

pub fn tls_client_hello(
    version: u16,
    session_id: &[u8],
    suites: &[u16],
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&version.to_be_bytes());
    b.extend_from_slice(&[0x11; 32]);
    b.push(session_id.len() as u8);
    b.extend_from_slice(session_id);
    b.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        b.extend_from_slice(&s.to_be_bytes());
    }
    b.extend_from_slice(&[1, 0]); // compression methods: null
    let ext: Vec<u8> = extensions.concat();
    b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    b.extend_from_slice(&ext);
    tls_handshake(1, &b)
}

pub fn tls_server_hello(version: u16, suite: u16, extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&version.to_be_bytes());
    b.extend_from_slice(&[0x22; 32]);
    b.push(0);
    b.extend_from_slice(&suite.to_be_bytes());
    b.push(0);
    let ext: Vec<u8> = extensions.concat();
    b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    b.extend_from_slice(&ext);
    tls_handshake(2, &b)
}

/// Write frames to a pcapng byte buffer on one Ethernet interface.
pub fn pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new(Vec::new(), "netscope fixture generator").expect("write");
    let id = w.interface(1, 262_144, "fixture0").expect("idb");
    for (i, f) in frames.iter().enumerate() {
        w.packet(id, ts(i as u32), f.len() as u32, f).expect("epb");
    }
    w.finish().expect("finish")
}

/// Write frames to a pcapng buffer with the given link type.
pub fn pcapng_with_link(link_type: u16, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new(Vec::new(), "netscope fixture generator").expect("write");
    let id = w.interface(link_type, 262_144, "fixture0").expect("idb");
    for (i, f) in frames.iter().enumerate() {
        w.packet(id, ts(i as u32), f.len() as u32, f).expect("epb");
    }
    w.finish().expect("finish")
}
