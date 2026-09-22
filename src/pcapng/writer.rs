//! Minimal pcapng writer: one section, one or more interfaces, EPBs.
//! Little-endian; nanosecond timestamps (`if_tsresol = 9`).

use std::io::{self, Write};

use super::*;
use crate::capture::Timestamp;

pub struct Writer<W: Write> {
    out: W,
    interfaces: u32,
}

fn option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    buf.resize(pad4(buf.len()), 0);
}

fn block(out: &mut impl Write, block_type: u32, body: &[u8]) -> io::Result<()> {
    let total = (12 + pad4(body.len())) as u32;
    out.write_all(&block_type.to_le_bytes())?;
    out.write_all(&total.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&vec![0u8; pad4(body.len()) - body.len()])?;
    out.write_all(&total.to_le_bytes())
}

impl<W: Write> Writer<W> {
    /// Write the Section Header Block.
    pub fn new(mut out: W, user_appl: &str) -> io::Result<Writer<W>> {
        let mut body = Vec::new();
        body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // major
        body.extend_from_slice(&0u16.to_le_bytes()); // minor
        body.extend_from_slice(&u64::MAX.to_le_bytes()); // section length unknown
        option(&mut body, OPT_SHB_USERAPPL, user_appl.as_bytes());
        option(&mut body, OPT_ENDOFOPT, &[]);
        block(&mut out, BLOCK_SHB, &body)?;
        Ok(Writer { out, interfaces: 0 })
    }

    /// Write an Interface Description Block; returns its interface id.
    pub fn interface(&mut self, link_type: u16, snaplen: u32, name: &str) -> io::Result<u32> {
        let mut body = Vec::new();
        body.extend_from_slice(&link_type.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&snaplen.to_le_bytes());
        if !name.is_empty() {
            option(&mut body, OPT_IF_NAME, name.as_bytes());
        }
        option(&mut body, OPT_IF_TSRESOL, &[9]);
        option(&mut body, OPT_ENDOFOPT, &[]);
        block(&mut self.out, BLOCK_IDB, &body)?;
        let id = self.interfaces;
        self.interfaces += 1;
        Ok(id)
    }

    /// Write an Enhanced Packet Block.
    pub fn packet(
        &mut self,
        interface: u32,
        ts: Timestamp,
        orig_len: u32,
        data: &[u8],
    ) -> io::Result<()> {
        let ts_ns = (ts.secs as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(u64::from(ts.nanos));
        let mut body = Vec::with_capacity(20 + pad4(data.len()));
        body.extend_from_slice(&interface.to_le_bytes());
        body.extend_from_slice(&((ts_ns >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(ts_ns as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&orig_len.to_le_bytes());
        body.extend_from_slice(data);
        body.resize(pad4(body.len()), 0);
        block(&mut self.out, BLOCK_EPB, &body)
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}
