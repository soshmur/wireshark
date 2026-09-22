//! IPv4 fragment reassembly with a per-datagram size cap, an age timeout and
//! a cap on the number of pending datagrams (oldest evicted first).

use std::collections::HashMap;

use crate::capture::Timestamp;

/// (src, dst, id, protocol) identifies a datagram being reassembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub id: u16,
    pub proto: u8,
}

/// One fragment as seen in a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragInfo {
    pub frame: u32,
    /// Byte offset within the reassembled datagram.
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug)]
struct Pending {
    buf: Vec<u8>,
    /// Byte ranges received, kept sorted and merged.
    have: Vec<(usize, usize)>,
    /// Total length once the last fragment (MF=0) has been seen.
    total: Option<usize>,
    frags: Vec<FragInfo>,
    first_seen: Timestamp,
    last_seen: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragResult {
    /// Stored; the datagram is still incomplete.
    Pending { received: usize },
    /// This fragment completed the datagram.
    Complete { data: Vec<u8>, frags: Vec<FragInfo> },
    /// Rejected (over the size cap or inconsistent); not stored.
    Rejected(&'static str),
}

#[derive(Debug)]
pub struct Reassembly {
    pending: HashMap<FragKey, Pending>,
    pub max_datagram: usize,
    pub max_pending: usize,
    pub timeout_secs: i64,
}

impl Default for Reassembly {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembly {
    pub fn new() -> Reassembly {
        Reassembly {
            pending: HashMap::new(),
            max_datagram: 65_535,
            max_pending: 1024,
            timeout_secs: 30,
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drop datagrams whose last fragment is older than the timeout.
    pub fn expire(&mut self, now: Timestamp) {
        let cutoff = now.secs - self.timeout_secs;
        self.pending.retain(|_, p| p.last_seen.secs >= cutoff);
    }

    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .pending
            .iter()
            .min_by_key(|(_, p)| p.first_seen)
            .map(|(k, _)| *k)
        {
            self.pending.remove(&key);
        }
    }

    /// Add a fragment. `offset` is in bytes (already multiplied by 8).
    pub fn add(
        &mut self,
        key: FragKey,
        offset: usize,
        more: bool,
        payload: &[u8],
        frame: u32,
        ts: Timestamp,
    ) -> FragResult {
        self.expire(ts);
        let end = offset.saturating_add(payload.len());
        if end > self.max_datagram {
            return FragResult::Rejected("fragment exceeds maximum datagram size");
        }
        if !self.pending.contains_key(&key) {
            while self.pending.len() >= self.max_pending {
                self.evict_oldest();
            }
            self.pending.insert(
                key,
                Pending {
                    buf: Vec::new(),
                    have: Vec::new(),
                    total: None,
                    frags: Vec::new(),
                    first_seen: ts,
                    last_seen: ts,
                },
            );
        }
        let Some(p) = self.pending.get_mut(&key) else {
            return FragResult::Rejected("no pending slot");
        };
        p.last_seen = ts;
        if !more {
            match p.total {
                Some(t) if t != end => {
                    self.pending.remove(&key);
                    return FragResult::Rejected("conflicting total length");
                }
                _ => p.total = Some(end),
            }
        }
        if let Some(t) = p.total {
            if end > t {
                self.pending.remove(&key);
                return FragResult::Rejected("fragment beyond datagram end");
            }
        }
        if p.buf.len() < end {
            p.buf.resize(end, 0);
        }
        if let Some(dst) = p.buf.get_mut(offset..end) {
            dst.copy_from_slice(payload);
        }
        p.frags.push(FragInfo {
            frame,
            offset,
            len: payload.len(),
        });
        merge_range(&mut p.have, (offset, end));

        let complete = matches!(p.total, Some(t) if p.have.len() == 1 && p.have[0] == (0, t));
        if complete {
            let Some(p) = self.pending.remove(&key) else {
                return FragResult::Rejected("no pending slot");
            };
            FragResult::Complete {
                data: p.buf,
                frags: p.frags,
            }
        } else {
            FragResult::Pending {
                received: p.frags.len(),
            }
        }
    }
}

/// Insert `r` into a sorted list of disjoint ranges, merging neighbours.
fn merge_range(have: &mut Vec<(usize, usize)>, r: (usize, usize)) {
    have.push(r);
    have.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(have.len());
    for &(s, e) in have.iter() {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    *have = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FragKey {
        FragKey {
            src: [1, 1, 1, 1],
            dst: [2, 2, 2, 2],
            id: 7,
            proto: 17,
        }
    }

    fn ts(secs: i64) -> Timestamp {
        Timestamp { secs, nanos: 0 }
    }

    #[test]
    fn reassembles_out_of_order() {
        let mut r = Reassembly::new();
        assert!(matches!(
            r.add(key(), 8, false, &[3, 3, 3, 3], 2, ts(1)),
            FragResult::Pending { received: 1 }
        ));
        match r.add(key(), 0, true, &[1; 8], 1, ts(1)) {
            FragResult::Complete { data, frags } => {
                assert_eq!(data, vec![1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3]);
                assert_eq!(frags.len(), 2);
                assert_eq!(frags[0].frame, 2);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn overlapping_fragments_do_not_break_completion() {
        let mut r = Reassembly::new();
        r.add(key(), 0, true, &[1; 8], 1, ts(1));
        r.add(key(), 4, true, &[2; 8], 2, ts(1));
        match r.add(key(), 12, false, &[3; 4], 3, ts(1)) {
            FragResult::Complete { data, .. } => assert_eq!(data.len(), 16),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_oversize_and_conflicting() {
        let mut r = Reassembly::new();
        assert!(matches!(
            r.add(key(), 65_530, false, &[0; 16], 1, ts(1)),
            FragResult::Rejected(_)
        ));
        r.add(key(), 8, false, &[0; 8], 1, ts(1));
        assert!(matches!(
            r.add(key(), 0, true, &[0; 32], 2, ts(1)),
            FragResult::Rejected(_)
        ));
    }

    #[test]
    fn times_out_and_caps_pending() {
        let mut r = Reassembly::new();
        r.max_pending = 2;
        r.timeout_secs = 5;
        for i in 0..3u16 {
            let mut k = key();
            k.id = i;
            r.add(k, 0, true, &[0; 8], 1, ts(10));
        }
        assert_eq!(r.pending_count(), 2);
        r.expire(ts(16));
        assert_eq!(r.pending_count(), 0);
    }
}
