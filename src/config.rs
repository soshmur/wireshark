//! User configuration, persisted as TOML in the platform config directory.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::app::colour_rules::{self, Rule};
use crate::dissect::Options;

/// How the packet list's time column is rendered.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TimeMode {
    /// Wall-clock time of day (UTC) with microseconds.
    Absolute,
    /// Seconds since the first frame of the capture.
    #[default]
    SinceStart,
    /// Seconds since the previous displayed frame.
    DeltaPrevious,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    /// Set once the user has dismissed the authorised-use notice.
    pub first_run_acknowledged: bool,
    /// Last device chosen, restored on the next launch when still present.
    pub last_device: Option<String>,
    /// Last BPF capture filter.
    pub capture_filter: String,
    pub promiscuous: bool,
    pub snaplen: i32,
    /// Ring buffer: evict oldest frames beyond this count.
    pub ring_max_frames: u64,
    /// Ring buffer: evict oldest frames beyond this many bytes (approximate).
    pub ring_max_bytes: u64,
    pub time_mode: TimeMode,
    /// Keep the packet list scrolled to the newest frame while capturing.
    pub auto_scroll: bool,
    /// Verify IPv4 header and ICMPv4 checksums. Off by default, as
    /// Wireshark ships: see `validate_transport_checksums`.
    pub validate_ip_checksums: bool,
    /// Verify TCP, UDP and ICMPv6 checksums. Off by default because a NIC
    /// computes them after libpcap has seen the packet, so on a real capture
    /// 20-40% of frames would be reported bad for no reason.
    pub validate_transport_checksums: bool,
    /// Colour packet-list rows by the rules below.
    pub colouring: bool,
    /// Colour rules, in priority order: the first whose display filter
    /// matches a frame colours its row.
    pub colour_rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            first_run_acknowledged: false,
            last_device: None,
            capture_filter: String::new(),
            promiscuous: true,
            snaplen: 262_144,
            ring_max_frames: 1_000_000,
            ring_max_bytes: 2 * 1024 * 1024 * 1024,
            time_mode: TimeMode::SinceStart,
            auto_scroll: true,
            validate_ip_checksums: false,
            validate_transport_checksums: false,
            colouring: true,
            colour_rules: colour_rules::defaults(),
        }
    }
}

impl Config {
    /// The dissection settings these preferences describe.
    pub fn dissect_options(&self) -> Options {
        Options {
            validate_ip_checksums: self.validate_ip_checksums,
            validate_transport_checksums: self.validate_transport_checksums,
        }
    }

    /// `%APPDATA%\netscope\config\config.toml`, `~/.config/netscope/config.toml`,
    /// `~/Library/Application Support/netscope/config.toml`.
    pub fn path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "netscope")
            .map(|d| d.config_dir().join("config.toml"))
    }

    /// Load from disk; any failure yields the defaults (and the caller may
    /// surface `err`).
    pub fn load() -> (Config, Option<String>) {
        let Some(path) = Self::path() else {
            return (
                Config::default(),
                Some("no config directory available".into()),
            );
        };
        match fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(cfg) => (cfg, None),
                Err(e) => (
                    Config::default(),
                    Some(format!("{}: {e}; using defaults", path.display())),
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Config::default(), None),
            Err(e) => (
                Config::default(),
                Some(format!("{}: {e}; using defaults", path.display())),
            ),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::path().ok_or("no config directory available")?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let cfg = Config {
            first_run_acknowledged: true,
            last_device: Some("eth0".into()),
            capture_filter: "tcp port 443".into(),
            promiscuous: false,
            snaplen: 1600,
            ring_max_frames: 10,
            ring_max_bytes: 20,
            time_mode: TimeMode::DeltaPrevious,
            auto_scroll: false,
            validate_ip_checksums: true,
            validate_transport_checksums: true,
            colouring: false,
            colour_rules: colour_rules::defaults(),
        };
        let text = toml::to_string_pretty(&cfg).expect("serialise");
        let back: Config = toml::from_str(&text).expect("parse");
        assert_eq!(cfg, back);
    }

    #[test]
    fn missing_fields_take_defaults() {
        let back: Config = toml::from_str("first_run_acknowledged = true\n").expect("parse");
        assert!(back.first_run_acknowledged);
        assert_eq!(back.snaplen, Config::default().snaplen);
        assert_eq!(back.ring_max_frames, 1_000_000);
        assert_eq!(back.time_mode, TimeMode::SinceStart);
        assert!(back.colouring);
        assert_eq!(back.colour_rules, colour_rules::defaults());
        assert!(
            !back.validate_ip_checksums && !back.validate_transport_checksums,
            "checksum validation ships off, as Wireshark does"
        );
    }

    #[test]
    fn colour_rules_round_trip() {
        let cfg = Config::default();
        let text = toml::to_string_pretty(&cfg).expect("serialise");
        let back: Config = toml::from_str(&text).expect("parse");
        assert_eq!(cfg.colour_rules, back.colour_rules);
        assert!(!back.colour_rules.is_empty());
    }
}
