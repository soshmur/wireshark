//! Bounds-checked reader over a packet slice. Every read returns the absolute
//! byte range it consumed so nodes can be built without offset arithmetic.
//!
//! No method here can panic: every access goes through `get`, and lengths
//! from the packet are treated as adversarial.

use std::fmt;
use std::ops::Range;

use super::node::SourceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DissectError {
    /// Needed `need` bytes at absolute offset `at`; only `have` remained.
    Truncated { at: usize, need: usize, have: usize },
    /// A length or value field is impossible (e.g. IHL < 5).
    Invalid { at: usize, what: &'static str },
}

impl fmt::Display for DissectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DissectError::Truncated { at, need, have } => {
                write!(
                    f,
                    "truncated at offset {at}: need {need} bytes, {have} left"
                )
            }
            DissectError::Invalid { at, what } => write!(f, "invalid {what} at offset {at}"),
        }
    }
}

impl std::error::Error for DissectError {}

pub type Result<T> = std::result::Result<T, DissectError>;

/// A read position within `data`, whose first byte sits at absolute offset
/// `base` within the data source.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
    source: SourceId,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8], base: usize, source: SourceId) -> Cursor<'a> {
        Cursor {
            data,
            pos: 0,
            base,
            source,
        }
    }

    pub fn source(&self) -> SourceId {
        self.source
    }

    /// Absolute offset of the next unread byte.
    pub fn abs(&self) -> usize {
        self.base + self.pos
    }

    /// Relative position within the slice this cursor was created over.
    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Everything not yet consumed.
    pub fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    /// Absolute range from `start_abs` to the current position.
    pub fn since(&self, start_abs: usize) -> Range<usize> {
        start_abs..self.abs().max(start_abs)
    }

    /// Absolute range covering everything not yet consumed.
    pub fn rest_range(&self) -> Range<usize> {
        self.abs()..self.abs() + self.remaining()
    }

    /// Peek `n` bytes without consuming.
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        self.data
            .get(self.pos..self.pos.saturating_add(n))
            .ok_or(DissectError::Truncated {
                at: self.abs(),
                need: n,
                have: self.remaining(),
            })
    }

    /// Consume `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<(&'a [u8], Range<usize>)> {
        let slice = self.peek(n)?;
        let range = self.abs()..self.abs() + n;
        self.pos += n;
        Ok((slice, range))
    }

    pub fn skip(&mut self, n: usize) -> Result<Range<usize>> {
        self.take(n).map(|(_, r)| r)
    }

    pub fn u8(&mut self) -> Result<(u8, Range<usize>)> {
        let (b, r) = self.take(1)?;
        Ok((b[0], r))
    }

    pub fn u16(&mut self) -> Result<(u16, Range<usize>)> {
        let (b, r) = self.take(2)?;
        Ok((u16::from_be_bytes([b[0], b[1]]), r))
    }

    pub fn u32(&mut self) -> Result<(u32, Range<usize>)> {
        let (b, r) = self.take(4)?;
        Ok((u32::from_be_bytes([b[0], b[1], b[2], b[3]]), r))
    }

    pub fn u64(&mut self) -> Result<(u64, Range<usize>)> {
        let (b, r) = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok((u64::from_be_bytes(a), r))
    }

    pub fn u16_le(&mut self) -> Result<(u16, Range<usize>)> {
        let (b, r) = self.take(2)?;
        Ok((u16::from_le_bytes([b[0], b[1]]), r))
    }

    pub fn u32_le(&mut self) -> Result<(u32, Range<usize>)> {
        let (b, r) = self.take(4)?;
        Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]), r))
    }

    /// 24-bit big-endian.
    pub fn u24(&mut self) -> Result<(u32, Range<usize>)> {
        let (b, r) = self.take(3)?;
        Ok((u32::from_be_bytes([0, b[0], b[1], b[2]]), r))
    }

    pub fn mac(&mut self) -> Result<([u8; 6], Range<usize>)> {
        let (b, r) = self.take(6)?;
        let mut a = [0u8; 6];
        a.copy_from_slice(b);
        Ok((a, r))
    }

    pub fn ipv4(&mut self) -> Result<([u8; 4], Range<usize>)> {
        let (b, r) = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok((a, r))
    }

    pub fn ipv6(&mut self) -> Result<([u8; 16], Range<usize>)> {
        let (b, r) = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok((a, r))
    }

    /// A sub-cursor over the next `n` bytes, consumed from this one.
    pub fn sub(&mut self, n: usize) -> Result<Cursor<'a>> {
        let base = self.abs();
        let (slice, _) = self.take(n)?;
        Ok(Cursor {
            data: slice,
            pos: 0,
            base,
            source: self.source,
        })
    }

    pub fn invalid(&self, what: &'static str) -> DissectError {
        DissectError::Invalid {
            at: self.abs(),
            what,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked_and_ranged() {
        let data = [1u8, 2, 3, 4, 5];
        let mut c = Cursor::new(&data, 100, 0);
        assert_eq!(c.u8().unwrap(), (1, 100..101));
        assert_eq!(c.u16().unwrap(), (0x0203, 101..103));
        assert_eq!(c.remaining(), 2);
        assert_eq!(
            c.u32(),
            Err(DissectError::Truncated {
                at: 103,
                need: 4,
                have: 2
            })
        );
        // A failed read consumes nothing.
        assert_eq!(c.abs(), 103);
        assert_eq!(c.rest_range(), 103..105);
    }

    #[test]
    fn huge_lengths_do_not_overflow() {
        let data = [0u8; 4];
        let mut c = Cursor::new(&data, usize::MAX - 2, 0);
        assert!(c.take(usize::MAX).is_err());
        assert!(c.peek(usize::MAX).is_err());
        assert!(c.sub(usize::MAX).is_err());
    }

    #[test]
    fn sub_cursor_keeps_absolute_offsets() {
        let data = [9u8; 10];
        let mut c = Cursor::new(&data, 0, 0);
        c.skip(3).unwrap();
        let mut s = c.sub(4).unwrap();
        assert_eq!(s.abs(), 3);
        assert_eq!(s.u8().unwrap().1, 3..4);
        assert_eq!(s.remaining(), 3);
        assert_eq!(c.abs(), 7);
    }
}
