#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope::dissect::{ctx::Ctx, proto, State};
use netscope::capture::Timestamp;

fuzz_target!(|data: &[u8]| {
    let mut state = State::new();
    let mut ctx = Ctx::new(netscope_ffi::LinkType::ETHERNET, 1, Timestamp::default(), &mut state);
    ctx.net_addrs = Some(netscope::dissect::ctx::NetAddrs::V4([1, 2, 3, 4], [5, 6, 7, 8]));
    let _ = proto::icmp::dissect(data, &mut ctx);
});
