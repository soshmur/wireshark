//! User Datagram Protocol (RFC 768).

use crate::dissect::ctx::{Ctx, Proto};
use crate::dissect::cursor::{Cursor, DissectError, Result};
use crate::dissect::node::Value;

use super::{transport_checksum, CK_BAD, CK_GOOD, CK_NOT_PRESENT, CK_UNVERIFIED};

pub fn dissect(data: &[u8], ctx: &mut Ctx) -> Result<()> {
    let mut c = Cursor::new(data, ctx.base, ctx.source);
    let start = c.abs();
    let (sport, sport_r) = c.u16()?;
    let (dport, dport_r) = c.u16()?;
    let (len, len_r) = c.u16()?;
    let (checksum, checksum_r) = c.u16()?;
    if len < 8 {
        return Err(DissectError::Invalid {
            at: len_r.start,
            what: "UDP length (< 8)",
        });
    }

    ctx.set_protocol("udp");
    ctx.set_info(format!("{sport} → {dport} Len={}", len - 8));
    let udp = ctx.begin("udp", start..c.abs());
    ctx.leaf("udp.srcport", sport_r, Value::Unsigned(u64::from(sport)));
    ctx.leaf("udp.dstport", dport_r, Value::Unsigned(u64::from(dport)));
    ctx.leaf("udp.length", len_r, Value::Unsigned(u64::from(len)));
    ctx.leaf(
        "udp.checksum",
        checksum_r.clone(),
        Value::Unsigned(u64::from(checksum)),
    );
    let status = if checksum == 0 {
        CK_NOT_PRESENT
    } else if data.len() < usize::from(len) {
        // Truncated (snaplen or an ICMP-quoted header): cannot be verified.
        CK_UNVERIFIED
    } else {
        let datagram = data.get(..usize::from(len)).unwrap_or(data);
        match transport_checksum(ctx, 17, datagram) {
            Some(0) => CK_GOOD,
            Some(_) => CK_BAD,
            None => CK_UNVERIFIED,
        }
    };
    ctx.leaf("udp.checksum.status", checksum_r, Value::Unsigned(status));
    ctx.end();
    let _ = udp;

    // The payload is the next layer; it is not repeated as a child here, so
    // selecting the UDP row highlights the header it actually describes.
    let payload_len = (usize::from(len) - 8).min(c.remaining());
    let next = match (sport, dport) {
        (53, _) | (_, 53) | (5353, _) | (_, 5353) => Proto::Dns,
        (67, _) | (_, 67) | (68, _) | (_, 68) => Proto::Dhcp,
        _ => Proto::Data,
    };
    if payload_len > 0 {
        ctx.call_next_bounded(next, c.pos(), payload_len);
    }
    Ok(())
}
