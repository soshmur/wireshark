//! The I/O graph: traffic over time, bucketed into intervals.
//!
//! Each series is a display filter, so the graph answers whatever the filter
//! language can express — retransmissions against throughput, one
//! conversation against the rest — rather than a fixed set of lines chosen
//! in advance.
//!
//! Buckets are counted relative to the capture's first frame, not to the
//! wall clock, so the x axis reads as "seconds into the capture" and two
//! captures taken at different times can be compared.

use crate::capture::Timestamp;
use crate::filter::{matches, Test};

use super::Snapshot;

/// What a series counts in each bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Unit {
    #[default]
    Packets,
    Bytes,
    /// Bytes per second, which is bytes scaled by the interval. Kept
    /// separate so the axis can be labelled honestly.
    Bits,
}

impl Unit {
    pub fn name(self) -> &'static str {
        match self {
            Unit::Packets => "Packets",
            Unit::Bytes => "Bytes",
            Unit::Bits => "Bits/s",
        }
    }
}

/// One line on the graph.
#[derive(Debug, Clone)]
pub struct Series {
    pub name: String,
    /// Empty means every frame.
    pub filter: String,
    pub colour: [u8; 3],
    pub enabled: bool,
}

/// A series with its filter compiled, or the reason it could not be.
#[derive(Debug)]
pub struct Compiled {
    pub test: Option<Test>,
    pub error: Option<String>,
}

pub fn compile(series: &Series) -> Compiled {
    if series.filter.trim().is_empty() {
        return Compiled {
            test: None,
            error: None,
        };
    }
    match crate::filter::compile(&series.filter) {
        Ok(t) => Compiled {
            test: Some(t),
            error: None,
        },
        Err(e) => Compiled {
            test: None,
            error: Some(format!("column {}: {}", e.column + 1, e.message)),
        },
    }
}

/// The series netscope starts with.
pub fn defaults() -> Vec<Series> {
    vec![
        Series {
            name: "All packets".into(),
            filter: String::new(),
            colour: [140, 190, 230],
            enabled: true,
        },
        Series {
            name: "TCP".into(),
            filter: "tcp".into(),
            colour: [150, 210, 160],
            enabled: true,
        },
        Series {
            name: "Problems".into(),
            filter: "_ws.expert.severity >= \"Warning\"".into(),
            colour: [240, 150, 110],
            enabled: true,
        },
    ]
}

/// Bucketed counts for one series.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    /// Value per bucket, in the series' unit.
    pub points: Vec<f64>,
}

/// The whole graph.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    /// Seconds per bucket.
    pub interval: f64,
    /// Capture time of the first frame, which bucket 0 starts at.
    pub start: Option<Timestamp>,
    pub buckets: usize,
    pub lines: Vec<Line>,
}

impl Graph {
    /// The x value at the centre of bucket `i`, in seconds into the capture.
    pub fn x(&self, i: usize) -> f64 {
        (i as f64 + 0.5) * self.interval
    }

    pub fn max_y(&self) -> f64 {
        self.lines
            .iter()
            .flat_map(|l| l.points.iter().copied())
            .fold(0.0, f64::max)
    }
}

/// Seconds between two timestamps.
fn seconds_between(a: Timestamp, b: Timestamp) -> f64 {
    let secs = (b.secs - a.secs) as f64;
    secs + (f64::from(b.nanos) - f64::from(a.nanos)) / 1e9
}

/// The most buckets worth computing. A one-millisecond interval over an
/// hour-long capture is 3.6 million points, which no screen can show and no
/// one can read; the caller is told so it can widen the interval.
pub const MAX_BUCKETS: usize = 100_000;

/// Bucket the snapshot.
///
/// `tests` parallels `series`: `None` means the series has no filter (every
/// frame) or its filter does not compile, which the caller distinguishes.
pub fn build(
    snapshot: &Snapshot,
    series: &[Series],
    compiled: &[Compiled],
    interval: f64,
    unit: Unit,
) -> Graph {
    let interval = interval.max(0.000_001);
    let Some(first) = snapshot.iter().next() else {
        return Graph {
            interval,
            ..Graph::default()
        };
    };
    let start = first.ts;
    // The snapshot is in capture order, so the last frame is the latest.
    let last = snapshot
        .get(snapshot.len().saturating_sub(1))
        .map_or(start, |f| f.ts);
    let span = seconds_between(start, last).max(0.0);
    let buckets = ((span / interval).floor() as usize + 1).min(MAX_BUCKETS);

    let mut lines: Vec<Line> = series
        .iter()
        .map(|_| Line {
            points: vec![0.0; buckets],
        })
        .collect();

    for frame in snapshot.iter() {
        let at = seconds_between(start, frame.ts);
        if at < 0.0 {
            // A frame earlier than the first is only possible if the capture
            // is not in time order; putting it in bucket 0 keeps it visible.
            continue;
        }
        let idx = (at / interval).floor() as usize;
        if idx >= buckets {
            continue;
        }
        let value = match unit {
            Unit::Packets => 1.0,
            Unit::Bytes | Unit::Bits => f64::from(frame.orig_len),
        };
        for (i, s) in series.iter().enumerate() {
            if !s.enabled {
                continue;
            }
            let include = match compiled.get(i) {
                Some(Compiled { test: Some(t), .. }) => matches(t, frame),
                // No filter: every frame. A filter that does not compile
                // contributes nothing, and the editor shows why.
                Some(Compiled { error: None, .. }) => s.filter.trim().is_empty(),
                _ => false,
            };
            if include {
                if let Some(p) = lines[i].points.get_mut(idx) {
                    *p += value;
                }
            }
        }
    }
    if unit == Unit::Bits {
        for line in &mut lines {
            for p in &mut line.points {
                *p = *p * 8.0 / interval;
            }
        }
    }
    Graph {
        interval,
        start: Some(start),
        buckets,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{RawFrame, Timestamp};
    use crate::dissect::{dissect, State};
    use crate::store::{Limits, Store};
    use netscope_ffi::LinkType;
    use std::sync::Arc;

    /// Frames at given second offsets from a fixed start.
    fn store_at(offsets: &[f64]) -> Arc<Store> {
        let store = Store::new(Limits::default());
        let mut state = State::new();
        let batch: Vec<Arc<crate::dissect::Frame>> = offsets
            .iter()
            .enumerate()
            .map(|(i, off)| {
                let raw = crate::synthetic::raw_frame(i as u64);
                let secs = off.floor() as i64;
                let nanos = ((off - off.floor()) * 1e9) as u32;
                let raw = RawFrame {
                    ts: Timestamp {
                        secs: 1_700_000_000 + secs,
                        nanos,
                    },
                    ..raw
                };
                Arc::new(dissect(LinkType::ETHERNET, i as u32 + 1, raw, &mut state))
            })
            .collect();
        store.append(batch);
        store
    }

    fn one_series(filter: &str) -> (Vec<Series>, Vec<Compiled>) {
        let s = vec![Series {
            name: "s".into(),
            filter: filter.into(),
            colour: [0, 0, 0],
            enabled: true,
        }];
        let c = s.iter().map(compile).collect();
        (s, c)
    }

    #[test]
    fn frames_land_in_the_bucket_their_time_falls_in() {
        let store = store_at(&[0.0, 0.5, 1.2, 1.7, 5.0]);
        let (s, c) = one_series("");
        let g = build(&store.snapshot(), &s, &c, 1.0, Unit::Packets);
        assert_eq!(g.buckets, 6, "zero through five seconds inclusive");
        assert_eq!(g.lines[0].points[0], 2.0);
        assert_eq!(g.lines[0].points[1], 2.0);
        assert_eq!(g.lines[0].points[2], 0.0);
        assert_eq!(g.lines[0].points[5], 1.0);
    }

    #[test]
    fn the_interval_changes_the_buckets_not_the_total() {
        let store = store_at(&[0.0, 0.5, 1.2, 1.7, 5.0]);
        let (s, c) = one_series("");
        let snap = store.snapshot();
        for interval in [0.5, 1.0, 2.0] {
            let g = build(&snap, &s, &c, interval, Unit::Packets);
            let total: f64 = g.lines[0].points.iter().sum();
            assert_eq!(total, 5.0, "interval {interval} lost frames");
        }
    }

    #[test]
    fn a_filtered_series_counts_only_what_matches() {
        let store = store_at(&[0.0, 1.0, 2.0]);
        let snap = store.snapshot();
        let (s, c) = one_series("tcp");
        let all = build(&snap, &s, &c, 1.0, Unit::Packets);
        assert_eq!(all.lines[0].points.iter().sum::<f64>(), 3.0);
        let (s, c) = one_series("arp");
        let none = build(&snap, &s, &c, 1.0, Unit::Packets);
        assert_eq!(none.lines[0].points.iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn a_series_whose_filter_does_not_compile_contributes_nothing() {
        // And the error is available rather than the series silently
        // counting every frame, which would be worse than counting none.
        let store = store_at(&[0.0, 1.0]);
        let (s, c) = one_series("not a filter");
        assert!(c[0].error.is_some());
        let g = build(&store.snapshot(), &s, &c, 1.0, Unit::Packets);
        assert_eq!(g.lines[0].points.iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn bytes_and_bits_differ_by_the_interval() {
        let store = store_at(&[0.0, 0.1]);
        let snap = store.snapshot();
        let (s, c) = one_series("");
        let bytes = build(&snap, &s, &c, 1.0, Unit::Bytes);
        let bits = build(&snap, &s, &c, 1.0, Unit::Bits);
        assert_eq!(bits.lines[0].points[0], bytes.lines[0].points[0] * 8.0);
        // Halving the interval doubles the rate for the same bytes.
        let bits_half = build(&snap, &s, &c, 0.5, Unit::Bits);
        assert_eq!(bits_half.lines[0].points[0], bits.lines[0].points[0] * 2.0);
    }

    #[test]
    fn a_disabled_series_is_not_counted() {
        let store = store_at(&[0.0, 1.0]);
        let (mut s, c) = one_series("");
        s[0].enabled = false;
        let g = build(&store.snapshot(), &s, &c, 1.0, Unit::Packets);
        assert_eq!(g.lines[0].points.iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn an_empty_capture_gives_an_empty_graph() {
        let store = Store::new(Limits::default());
        let (s, c) = one_series("");
        let g = build(&store.snapshot(), &s, &c, 1.0, Unit::Packets);
        assert_eq!(g.buckets, 0);
        assert!(g.start.is_none());
        assert_eq!(g.max_y(), 0.0);
    }

    #[test]
    fn a_tiny_interval_over_a_long_capture_is_bounded() {
        // A millisecond interval over an hour is 3.6 million points, which
        // no screen shows and no one reads. Building them all would hang the
        // UI thread for seconds.
        let store = store_at(&[0.0, 3600.0]);
        let (s, c) = one_series("");
        let g = build(&store.snapshot(), &s, &c, 0.001, Unit::Packets);
        assert_eq!(g.buckets, MAX_BUCKETS);
    }

    #[test]
    fn an_interval_of_zero_does_not_divide_by_it() {
        let store = store_at(&[0.0, 1.0]);
        let (s, c) = one_series("");
        let g = build(&store.snapshot(), &s, &c, 0.0, Unit::Packets);
        assert!(g.interval > 0.0);
        assert!(g.buckets > 0);
    }

    #[test]
    fn every_default_series_compiles() {
        for s in defaults() {
            let c = compile(&s);
            assert!(c.error.is_none(), "{}: {:?}", s.name, c.error);
        }
    }
}
