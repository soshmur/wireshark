//! Device enumeration, presented in a UI-friendly shape.

use netscope_ffi::DeviceInfo;

/// A capture interface plus a display-oriented view of its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub info: DeviceInfo,
}

impl Device {
    /// What the list shows in the name column: the description when the OS
    /// provides one (Windows names are GUIDs), otherwise the raw name.
    pub fn display_name(&self) -> &str {
        self.info
            .description
            .as_deref()
            .filter(|d| !d.is_empty())
            .unwrap_or(&self.info.name)
    }

    /// Short state tags, e.g. `up, wireless`.
    pub fn state_tags(&self) -> String {
        let mut tags: Vec<&str> = Vec::new();
        if self.info.is_loopback {
            tags.push("loopback");
        }
        if self.info.is_wireless {
            tags.push("wireless");
        }
        if self.info.is_up {
            tags.push("up");
        }
        if self.info.is_running {
            tags.push("running");
        }
        match self.info.connected {
            Some(true) => tags.push("connected"),
            Some(false) => tags.push("disconnected"),
            None => {}
        }
        tags.join(", ")
    }

    /// Heuristic used to pick a sensible default selection: prefer an interface
    /// that is up, connected, has an address and is not loopback.
    pub fn score(&self) -> u32 {
        let mut s: u32 = 0;
        if self.info.is_up {
            s += 4;
        }
        if self.info.connected == Some(true) {
            s += 4;
        }
        if !self.info.addresses.is_empty() {
            s += 2;
        }
        if self.info.is_loopback {
            s = s.saturating_sub(8);
        }
        s
    }
}

/// Enumerate devices, sorted best-first.
pub fn enumerate() -> Result<Vec<Device>, String> {
    let mut devs: Vec<Device> = netscope_ffi::list_devices()
        .map_err(|e| e.0)?
        .into_iter()
        .map(|info| Device { info })
        .collect();
    devs.sort_by(|a, b| {
        b.score()
            .cmp(&a.score())
            .then_with(|| a.display_name().cmp(b.display_name()))
    });
    Ok(devs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, desc: Option<&str>, up: bool, loopback: bool) -> Device {
        Device {
            info: DeviceInfo {
                name: name.into(),
                description: desc.map(String::from),
                addresses: vec![],
                is_up: up,
                is_running: up,
                is_loopback: loopback,
                is_wireless: false,
                connected: None,
            },
        }
    }

    #[test]
    fn display_name_prefers_description() {
        assert_eq!(
            dev(r"\Device\NPF_{x}", Some("Ethernet"), true, false).display_name(),
            "Ethernet"
        );
        assert_eq!(dev("eth0", None, true, false).display_name(), "eth0");
        assert_eq!(dev("eth0", Some(""), true, false).display_name(), "eth0");
    }

    #[test]
    fn loopback_scores_below_real_interfaces() {
        assert!(dev("eth0", None, true, false).score() > dev("lo", None, true, true).score());
    }
}
