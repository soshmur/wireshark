//! User configuration, persisted as TOML in the platform config directory.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            first_run_acknowledged: false,
            last_device: None,
            capture_filter: String::new(),
            promiscuous: true,
            snaplen: 262_144,
        }
    }
}

impl Config {
    /// `%APPDATA%\netscope\config.toml`, `~/.config/netscope/config.toml`,
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
    }
}
