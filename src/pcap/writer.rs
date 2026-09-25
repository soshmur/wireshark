//! Classic pcap writer. Always little-endian, which every reader handles;
//! the reader here accepts both because files arrive from anywhere.

use std::io::{self, Write};

use super::Precision;
use crate::capture::Timestamp;

pub struct Writer<W: Write> {
    out: W,
    precision: Precision,
    snaplen: u32,
}

impl<W: Write> Writer<W> {
    /// Write the file header. One link type applies to the whole file —
    /// that is the format's limitation, and why pcapng is the default for
    /// saving.
    pub fn new(
        mut out: W,
        link_type: u32,
        snaplen: u32,
        precision: Precision,
    ) -> io::Result<Writer<W>> {
        out.write_all(&precision.magic().to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?; // version major
        out.write_all(&4u16.to_le_bytes())?; // version minor
        out.write_all(&0i32.to_le_bytes())?; // thiszone: always UTC
        out.write_all(&0u32.to_le_bytes())?; // sigfigs: unused everywhere
        out.write_all(&snaplen.to_le_bytes())?;
        out.write_all(&link_type.to_le_bytes())?;
        Ok(Writer {
            out,
            precision,
            snaplen,
        })
    }

    /// Append one packet.
    ///
    /// `orig_len` is the length on the wire, which may exceed the bytes
    /// given when the capture was snapped short.
    pub fn packet(&mut self, ts: Timestamp, orig_len: u32, bytes: &[u8]) -> io::Result<()> {
        let frac = match self.precision {
            // Truncating, not rounding: rounding 999_999_999 ns up gives
            // 1_000_000 us, a whole second in a field that cannot hold one.
            Precision::Micro => ts.nanos / 1000,
            Precision::Nano => ts.nanos,
        };
        let caplen = bytes.len().min(self.snaplen as usize) as u32;
        // Negative epoch seconds cannot be represented; the format's field is
        // unsigned. Clamping keeps a nonsense timestamp from becoming a
        // gigantic one.
        let secs = u32::try_from(ts.secs.max(0)).unwrap_or(u32::MAX);
        self.out.write_all(&secs.to_le_bytes())?;
        self.out.write_all(&frac.to_le_bytes())?;
        self.out.write_all(&caplen.to_le_bytes())?;
        self.out.write_all(&orig_len.max(caplen).to_le_bytes())?;
        self.out.write_all(&bytes[..caplen as usize])?;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

/// The precision a set of timestamps needs.
///
/// Microsecond unless something carries sub-microsecond detail, in which
/// case writing microseconds would silently discard it.
pub fn precision_for<'a>(times: impl Iterator<Item = &'a Timestamp>) -> Precision {
    for ts in times {
        if ts.nanos % 1000 != 0 {
            return Precision::Nano;
        }
    }
    Precision::Micro
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::read;

    fn ts(secs: i64, nanos: u32) -> Timestamp {
        Timestamp { secs, nanos }
    }

    #[test]
    fn precision_is_chosen_by_what_the_data_needs() {
        // Every timestamp a whole number of microseconds: nothing is lost by
        // writing microseconds, and the file stays readable by old tools.
        let micros = [ts(1, 0), ts(2, 1000), ts(3, 999_999_000)];
        assert_eq!(precision_for(micros.iter()), Precision::Micro);
        // One value with sub-microsecond detail forces nanoseconds, because
        // the alternative is discarding it without saying so.
        let nanos = [ts(1, 0), ts(2, 1001)];
        assert_eq!(precision_for(nanos.iter()), Precision::Nano);
        assert_eq!(precision_for([].iter()), Precision::Micro);
    }

    #[test]
    fn a_snapped_packet_records_its_wire_length() {
        let mut w = Writer::new(Vec::new(), 1, 10, Precision::Micro).expect("header");
        w.packet(ts(1, 0), 1500, &[0xcd; 40]).expect("packet");
        let f = read(&w.finish().expect("finish")).expect("read");
        assert_eq!(f.frames[0].caplen, 10, "snaplen bounds what is stored");
        assert_eq!(f.frames[0].orig_len, 1500, "the wire length is kept");
        assert_eq!(f.frames[0].bytes.len(), 10);
    }

    #[test]
    fn sub_microsecond_detail_truncates_rather_than_rounding_up() {
        // Rounding 999_999_999 ns up would give 1_000_000 us, which is a
        // whole second in a field that cannot hold one.
        let mut w = Writer::new(Vec::new(), 1, 65535, Precision::Micro).expect("header");
        w.packet(ts(5, 999_999_999), 1, &[0]).expect("packet");
        let f = read(&w.finish().expect("finish")).expect("read");
        assert_eq!(f.frames[0].ts.secs, 5);
        assert_eq!(f.frames[0].ts.nanos, 999_999_000);
    }

    #[test]
    fn a_negative_timestamp_does_not_become_an_enormous_one() {
        // The format's seconds field is unsigned; a negative value cast
        // straight to u32 would read back as 2106.
        let mut w = Writer::new(Vec::new(), 1, 65535, Precision::Micro).expect("header");
        w.packet(ts(-1, 0), 1, &[0]).expect("packet");
        let f = read(&w.finish().expect("finish")).expect("read");
        assert_eq!(f.frames[0].ts.secs, 0);
    }

    #[test]
    fn an_orig_len_smaller_than_the_bytes_is_corrected() {
        // A frame claiming to be 1 byte on the wire while carrying 40 would
        // be refused by the reader as caplen > orig_len, so the writer must
        // not produce one.
        let mut w = Writer::new(Vec::new(), 1, 65535, Precision::Micro).expect("header");
        w.packet(ts(1, 0), 1, &[0xcd; 40]).expect("packet");
        let f = read(&w.finish().expect("finish")).expect("read");
        assert_eq!(f.frames[0].orig_len, 40);
    }

    #[test]
    fn an_empty_file_is_still_a_valid_file() {
        let w = Writer::new(Vec::new(), 1, 65535, Precision::Nano).expect("header");
        let bytes = w.finish().expect("finish");
        assert_eq!(bytes.len(), 24);
        let f = read(&bytes).expect("read");
        assert!(f.frames.is_empty());
        assert_eq!(f.header.ts_per_sec, 1_000_000_000);
    }
}
