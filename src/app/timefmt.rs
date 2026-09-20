//! Timestamp rendering for the packet list. No time-zone database: absolute
//! times are UTC, which the column header states.

use crate::capture::Timestamp;
use crate::config::TimeMode;

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD HH:MM:SS.ffffff` in UTC.
pub fn absolute(ts: Timestamp) -> String {
    let days = ts.secs.div_euclid(86_400);
    let sod = ts.secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:06}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        ts.nanos / 1000
    )
}

/// Signed difference `a - b` in seconds with microsecond digits.
pub fn delta(a: Timestamp, b: Timestamp) -> String {
    let mut secs = a.secs - b.secs;
    let mut nanos = i64::from(a.nanos) - i64::from(b.nanos);
    if nanos < 0 {
        nanos += 1_000_000_000;
        secs -= 1;
    }
    if secs < 0 {
        // Negative delta (out-of-order timestamps): render as -S.ffffff.
        let total = -(secs * 1_000_000_000 + nanos);
        return format!(
            "-{}.{:06}",
            total / 1_000_000_000,
            (total % 1_000_000_000) / 1000
        );
    }
    format!("{secs}.{:06}", nanos / 1000)
}

/// Render `ts` for the list given the mode, the capture start and the
/// previous displayed frame's timestamp.
pub fn render(
    mode: TimeMode,
    ts: Timestamp,
    start: Option<Timestamp>,
    previous: Option<Timestamp>,
) -> String {
    match mode {
        TimeMode::Absolute => absolute(ts),
        TimeMode::SinceStart => delta(ts, start.unwrap_or(ts)),
        TimeMode::DeltaPrevious => delta(ts, previous.unwrap_or(ts)),
    }
}

pub fn column_title(mode: TimeMode) -> &'static str {
    match mode {
        TimeMode::Absolute => "Time (UTC)",
        TimeMode::SinceStart => "Time",
        TimeMode::DeltaPrevious => "Delta",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_matches_known_epochs() {
        assert_eq!(
            absolute(Timestamp { secs: 0, nanos: 0 }),
            "1970-01-01 00:00:00.000000"
        );
        assert_eq!(
            absolute(Timestamp {
                secs: 1_700_000_000,
                nanos: 123_456_789
            }),
            "2023-11-14 22:13:20.123456"
        );
        assert_eq!(
            absolute(Timestamp {
                secs: 951_782_400,
                nanos: 0
            }),
            "2000-02-29 00:00:00.000000"
        );
    }

    #[test]
    fn deltas_borrow_correctly() {
        let a = Timestamp {
            secs: 10,
            nanos: 100,
        };
        let b = Timestamp {
            secs: 9,
            nanos: 999_999_000,
        };
        assert_eq!(delta(a, b), "0.000001");
        assert_eq!(delta(b, a), "-0.000001");
        assert_eq!(delta(a, a), "0.000000");
    }
}
