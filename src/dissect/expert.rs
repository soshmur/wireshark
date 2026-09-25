//! Expert information: things worth telling the user about a frame.
//!
//! A dissector raises an expert finding when it notices something that is not
//! a field — a checksum that does not verify, a segment that repeats bytes
//! already seen, a header it could not parse. Each carries a severity and a
//! group, so the packet list can rank frames by how much they warrant a look
//! and the user can filter on `_ws.expert.severity >= "Warning"`.
//!
//! Findings are emitted as tree nodes like anything else, which means the
//! filter engine reaches them without knowing they are special. The frame
//! additionally remembers the worst one, because the packet-list column has
//! to render without walking the tree for every visible row.

/// How much attention a finding deserves. Ordered, so the worst one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum Severity {
    /// A note in passing; never the reason to look at a frame.
    #[default]
    Comment = 0,
    /// Normal protocol activity worth pointing out: a handshake, a close.
    Chat = 1,
    /// Unusual but legal.
    Note = 2,
    /// Probably a problem.
    Warn = 3,
    /// Certainly a problem, or something that could not be parsed.
    Error = 4,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Comment => "Comment",
            Severity::Chat => "Chat",
            Severity::Note => "Note",
            Severity::Warn => "Warning",
            Severity::Error => "Error",
        }
    }

    /// Colour for the packet-list column, chosen to read on a dark row.
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Severity::Comment => [150, 150, 150],
            Severity::Chat => [140, 190, 230],
            Severity::Note => [150, 210, 160],
            Severity::Warn => [240, 190, 110],
            Severity::Error => [240, 130, 130],
        }
    }

    pub fn from_u64(v: u64) -> Severity {
        match v {
            1 => Severity::Chat,
            2 => Severity::Note,
            3 => Severity::Warn,
            4 => Severity::Error,
            _ => Severity::Comment,
        }
    }
}

/// What kind of problem it is. Matches the groups Wireshark uses, so someone
/// who knows the tool can guess the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Group {
    #[default]
    Protocol = 0,
    Checksum = 1,
    Sequence = 2,
    Malformed = 3,
    Reassemble = 4,
    Security = 5,
}

impl Group {
    pub fn name(self) -> &'static str {
        match self {
            Group::Protocol => "Protocol",
            Group::Checksum => "Checksum",
            Group::Sequence => "Sequence",
            Group::Malformed => "Malformed",
            Group::Reassemble => "Reassemble",
            Group::Security => "Security",
        }
    }

    pub fn from_u64(v: u64) -> Group {
        match v {
            1 => Group::Checksum,
            2 => Group::Sequence,
            3 => Group::Malformed,
            4 => Group::Reassemble,
            5 => Group::Security,
            _ => Group::Protocol,
        }
    }
}

/// The worst finding on a frame, kept on the summary so the packet list can
/// render a row without walking its tree.
///
/// The message is `&'static str` rather than a `String`: at a million frames
/// a per-frame allocation is 30-odd MB of small heap blocks for text almost
/// nobody reads. Findings that want to interpolate a number put it in a
/// sibling field instead, which the filter engine can compare anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expert {
    pub severity: Severity,
    pub group: Group,
    pub summary: &'static str,
}

pub static SEVERITIES: &[(u64, &str)] = &[
    (0, "Comment"),
    (1, "Chat"),
    (2, "Note"),
    (3, "Warning"),
    (4, "Error"),
];

pub static GROUPS: &[(u64, &str)] = &[
    (0, "Protocol"),
    (1, "Checksum"),
    (2, "Sequence"),
    (3, "Malformed"),
    (4, "Reassemble"),
    (5, "Security"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_ordered_worst_last() {
        // The packet list keeps the maximum, so the ordering is load-bearing.
        assert!(Severity::Error > Severity::Warn);
        assert!(Severity::Warn > Severity::Note);
        assert!(Severity::Note > Severity::Chat);
        assert!(Severity::Chat > Severity::Comment);
        assert_eq!(
            [Severity::Note, Severity::Error, Severity::Chat]
                .into_iter()
                .max(),
            Some(Severity::Error)
        );
    }

    #[test]
    fn the_tables_agree_with_the_enums() {
        // The value tables drive the registry's rendering, and the enums drive
        // the code; a mismatch would label a severity wrongly in the tree.
        for (v, name) in SEVERITIES {
            assert_eq!(Severity::from_u64(*v).name(), *name);
        }
        for (v, name) in GROUPS {
            assert_eq!(Group::from_u64(*v).name(), *name);
        }
    }
}
