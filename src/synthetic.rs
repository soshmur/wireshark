//! Generated Ethernet/IPv4/TCP frames for benchmarks and the `--synthetic`
//! developer flag. Deterministic in `i`.

use std::sync::Arc;

use crate::capture::{RawFrame, Timestamp};
use crate::dissect::proto::inet_checksum;

/// One synthetic frame: Ethernet II + IPv4 (no options) + TCP (with
/// timestamps option) + `i % 1400` payload bytes, with valid checksums.
pub fn raw_frame(i: u64) -> RawFrame {
    let payload_len = (i % 1400) as usize;
    let tcp_len = 32 + payload_len;
    let ip_len = 20 + tcp_len;
    let mut b = Vec::with_capacity(14 + ip_len);
    // Ethernet
    b.extend_from_slice(&[0x00, 0x1c, 0x42, 0x00, 0x00, 0x01]);
    b.extend_from_slice(&[0x00, 0x1c, 0x42, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
    b.extend_from_slice(&[0x08, 0x00]);
    // IPv4
    let ip_start = b.len();
    b.extend_from_slice(&[0x45, 0x00]);
    b.extend_from_slice(&(ip_len as u16).to_be_bytes());
    b.extend_from_slice(&(i as u16).to_be_bytes());
    b.extend_from_slice(&[0x40, 0x00, 64, 6, 0, 0]);
    b.extend_from_slice(&[10, 0, (i >> 8) as u8, i as u8]);
    b.extend_from_slice(&[93, 184, 216, 34]);
    let ck = inet_checksum(&[&b[ip_start..]]);
    b[ip_start + 10..ip_start + 12].copy_from_slice(&ck.to_be_bytes());
    // TCP: sport varies, dport 5001 (no upper-layer dissector), data offset 8
    // (32 bytes), PSH+ACK. This is exactly the Ethernet/IPv4/TCP benchmark path.
    let tcp_start = b.len();
    b.extend_from_slice(&(40000 + (i % 20000) as u16).to_be_bytes());
    b.extend_from_slice(&5001u16.to_be_bytes());
    b.extend_from_slice(&((i * 1400) as u32).to_be_bytes());
    b.extend_from_slice(&(1u32).to_be_bytes());
    b.extend_from_slice(&[0x80, 0x18]);
    b.extend_from_slice(&501u16.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]);
    // Options: NOP NOP Timestamps(10)
    b.extend_from_slice(&[1, 1, 8, 10]);
    b.extend_from_slice(&((i as u32).wrapping_mul(7)).to_be_bytes());
    b.extend_from_slice(&((i as u32).wrapping_mul(3)).to_be_bytes());
    b.extend((0..payload_len).map(|k| (k as u8).wrapping_add(i as u8)));
    let src = [10, 0, (i >> 8) as u8, i as u8];
    let dst = [93, 184, 216, 34];
    let pseudo = [0u8, 6, (tcp_len >> 8) as u8, tcp_len as u8];
    let ck = inet_checksum(&[&src, &dst, &pseudo, &b[tcp_start..]]);
    b[tcp_start + 16..tcp_start + 18].copy_from_slice(&ck.to_be_bytes());
    let len = b.len() as u32;
    RawFrame {
        ts: Timestamp {
            secs: 1_700_000_000 + (i / 1000) as i64,
            nanos: ((i % 1000) * 1_000_000) as u32,
        },
        caplen: len,
        orig_len: len,
        bytes: Arc::from(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, Reassembly};
    use netscope_ffi::LinkType;

    #[test]
    fn synthetic_frames_dissect_with_good_checksums() {
        let mut r = Reassembly::new();
        for i in [0u64, 1, 1399, 1400, 123_456] {
            let f = dissect(LinkType::ETHERNET, 1, raw_frame(i), &mut r);
            assert_eq!(f.summary.protocol, "tcp", "{}", f.summary.info);
            let statuses: Vec<String> = f
                .tree
                .iter()
                .filter(|n| n.abbrev().ends_with("checksum.status"))
                .map(|n| crate::dissect::registry::value_text(&n, &f.bytes))
                .collect();
            assert_eq!(statuses, ["Good", "Good"], "frame {i}: {}", f.summary.info);
        }
    }
}
