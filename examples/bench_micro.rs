//! Micro-costs behind the dissection path.
#![forbid(unsafe_code)]
use std::time::Instant;

use netscope::capture::Timestamp;
use netscope::dissect::ctx::{Ctx, NetAddrs};
use netscope::dissect::node::{Tree, Value};
use netscope::dissect::{dissect, proto, registry, Reassembly};

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

fn per_layer() {
    let raw = netscope::synthetic::raw_frame(5);
    let bytes = raw.bytes.clone();
    let n = 200_000u32;
    let mut r = Reassembly::new();
    for (name, off) in [("eth", 0usize), ("ipv4", 14), ("tcp", 34)] {
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
            std::hint::black_box((&res, ctx.tree.len()));
        }
        println!(
            "{:<44} {:>9.1} ns",
            format!("{name}::dissect alone"),
            t.elapsed().as_nanos() as f64 / f64::from(n)
        );
    }
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
        "Ctx::new (allocates the builder)",
        t.elapsed().as_nanos() as f64 / f64::from(n)
    );
}

fn main() {
    let n = 200_000;
    let lt = netscope_ffi::LinkType::ETHERNET;
    let raw = netscope::synthetic::raw_frame(5);
    let mut r = Reassembly::new();
    let frame = dissect(lt, 1, raw.clone(), &mut r);
    println!(
        "frame has {} nodes, {} bytes payload",
        frame.tree.len(),
        frame.bytes.len()
    );

    time("registry::field_id (memo hit)", n, || {
        std::hint::black_box(registry::field_id("tcp.options.timestamp.tsval"));
    });
    time("dissect() whole frame", n / 4, || {
        let mut r = Reassembly::new();
        std::hint::black_box(dissect(lt, 1, raw.clone(), &mut r));
    });
    time("TreeBuilder: 66 flat nodes", n / 4, || {
        std::hint::black_box(Tree::build(|b| {
            b.begin("tcp", 0, 0..20);
            for _ in 0..13 {
                b.leaf("tcp.srcport", 0, 0..2, Value::Unsigned(1));
            }
            b.begin("tcp.flags", 0, 0..2);
            for _ in 0..10 {
                b.leaf("tcp.flags.syn", 0, 0..2, Value::Bool(true));
            }
            b.end();
            b.end();
            b.begin("ip", 0, 0..20);
            for _ in 0..16 {
                b.leaf("ip.ttl", 0, 0..1, Value::Unsigned(64));
            }
            b.end();
            b.begin("eth", 0, 0..14);
            for _ in 0..3 {
                b.leaf("eth.src", 0, 0..6, Value::Mac([0; 6]));
            }
            b.end();
        }));
    });
    per_layer();
    time("format! info string", n, || {
        std::hint::black_box(format!(
            "{} → {} [{}] Seq={} Ack={} Win={} Len={}",
            51000u16, 5001u16, "PSH, ACK", 1000u32, 5001u32, 65535u16, 13usize
        ));
    });
}
