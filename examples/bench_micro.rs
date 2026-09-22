//! Micro-costs behind the dissection path.
#![forbid(unsafe_code)]
use netscope::dissect::node::{Node, Tree, Value};
use netscope::dissect::{dissect, registry, Reassembly};
use std::time::Instant;

fn time<F: FnMut()>(name: &str, n: u32, mut f: F) {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    println!(
        "{name:<44} {:>9.1} ns",
        t.elapsed().as_nanos() as f64 / f64::from(n)
    );
}

fn main() {
    let n = 200_000;
    let lt = netscope_ffi::LinkType::ETHERNET;
    let raw = netscope::synthetic::raw_frame(5);
    let mut r = Reassembly::new();
    let frame = dissect(lt, 1, raw.clone(), &mut r);
    let nodes = frame.tree.len();
    println!(
        "frame has {nodes} nodes, {} bytes payload",
        frame.bytes.len()
    );

    time("registry::field_id (one lookup)", n, || {
        std::hint::black_box(registry::field_id("tcp.options.timestamp.tsval"));
    });
    time("dissect() whole frame", n / 4, || {
        let mut r = Reassembly::new();
        std::hint::black_box(dissect(lt, 1, raw.clone(), &mut r));
    });
    // Rebuild the same shape of Node tree without flattening.
    time("build Node tree only (66 nodes)", n / 4, || {
        let mut root = Node::new("tcp", 0..20, Value::None).reserve(14);
        for _ in 0..13 {
            root.push(Node::new("tcp.srcport", 0..2, Value::Unsigned(1)));
        }
        let mut flags = Node::new("tcp.flags", 0..2, Value::Unsigned(1)).reserve(10);
        for _ in 0..10 {
            flags.push(Node::new("tcp.flags.syn", 0..2, Value::Bool(true)));
        }
        root.push(flags);
        let mut ip = Node::new("ip", 0..20, Value::None).reserve(16);
        for _ in 0..16 {
            ip.push(Node::new("ip.ttl", 0..1, Value::Unsigned(64)));
        }
        let mut eth = Node::new("eth", 0..14, Value::None).reserve(3);
        for _ in 0..3 {
            eth.push(Node::new("eth.src", 0..6, Value::Mac([0; 6])));
        }
        std::hint::black_box((root, ip, eth));
    });
    let layers: Vec<Node> = {
        let mut v = Vec::new();
        let mut root = Node::new("tcp", 0..20, Value::None).reserve(14);
        for _ in 0..30 {
            root.push(Node::new("tcp.srcport", 0..2, Value::Unsigned(1)));
        }
        v.push(root);
        let mut ip = Node::new("ip", 0..20, Value::None).reserve(16);
        for _ in 0..35 {
            ip.push(Node::new("ip.ttl", 0..1, Value::Unsigned(64)));
        }
        v.push(ip);
        v
    };
    time("Tree::from_layers (67 nodes)", n / 4, || {
        std::hint::black_box(Tree::from_layers(&layers));
    });
    per_layer();
    time("format! info string", n, || {
        std::hint::black_box(format!(
            "{} → {} [{}] Seq={} Ack={} Win={} Len={}",
            51000u16, 5001u16, "PSH, ACK", 1000u32, 5001u32, 65535u16, 13usize
        ));
    });
}

// Per-layer breakdown: run each dissector alone on the same synthetic frame.

fn per_layer() {
    use netscope::capture::Timestamp;
    use netscope::dissect::ctx::{Ctx, NetAddrs};
    use netscope::dissect::proto;
    let raw = netscope::synthetic::raw_frame(5);
    let bytes = raw.bytes.clone();
    let n = 200_000u32;
    let mut r = Reassembly::new();
    let cases: [(&str, usize); 3] = [("eth", 0), ("ipv4", 14), ("tcp", 34)];
    for (name, off) in cases {
        let t = Instant::now();
        for _ in 0..n {
            let mut ctx = Ctx::new(
                netscope_ffi::LinkType::ETHERNET,
                1,
                Timestamp::default(),
                &mut r,
            );
            ctx.base = off;
            ctx.net_addrs = Some(NetAddrs::V4([10, 0, 0, 1], [93, 184, 216, 34]));
            let slice = &bytes[off..];
            let res = match name {
                "eth" => proto::eth::dissect(slice, &mut ctx),
                "ipv4" => proto::ipv4::dissect(slice, &mut ctx),
                _ => proto::tcp::dissect(slice, &mut ctx),
            };
            std::hint::black_box(&res);
        }
        println!(
            "{:<44} {:>9.1} ns",
            format!("{name}::dissect alone"),
            t.elapsed().as_nanos() as f64 / f64::from(n)
        );
    }
    // Ctx construction alone.
    let t = Instant::now();
    for _ in 0..n {
        let ctx = Ctx::new(
            netscope_ffi::LinkType::ETHERNET,
            1,
            Timestamp::default(),
            &mut r,
        );
        std::hint::black_box(&ctx.base);
    }
    println!(
        "{:<44} {:>9.1} ns",
        "Ctx::new",
        t.elapsed().as_nanos() as f64 / f64::from(n)
    );
}
