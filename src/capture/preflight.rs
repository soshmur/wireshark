//! Privilege and driver preflight, run once at startup and on demand.
//!
//! Each platform answers "can this process capture?" with an actionable message
//! rather than letting the first `open` fail with an opaque libpcap error.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preflight {
    /// Capture should work.
    Ok { detail: String },
    /// Capture may work; the message says what to do if it does not.
    Warn { message: String },
    /// Capture cannot work until the user acts; the message says how.
    Fail { message: String },
}

impl Preflight {
    pub fn is_fail(&self) -> bool {
        matches!(self, Preflight::Fail { .. })
    }
}

impl fmt::Display for Preflight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Preflight::Ok { detail } => write!(f, "OK: {detail}"),
            Preflight::Warn { message } => write!(f, "Warning: {message}"),
            Preflight::Fail { message } => write!(f, "Cannot capture: {message}"),
        }
    }
}

/// Run the platform check.
pub fn run() -> Preflight {
    #[cfg(windows)]
    {
        windows::check()
    }
    #[cfg(target_os = "linux")]
    {
        linux::check()
    }
    #[cfg(target_os = "macos")]
    {
        macos::check()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Preflight::Warn {
            message: "No privilege preflight for this platform; capture may need root.".into(),
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::Preflight;
    use std::process::Command;

    pub const INSTALL_HINT: &str = "Install Npcap from https://npcap.com (any install mode works; \
        WinPcap-compatible mode is not required), then restart netscope.";

    /// Best-effort query of the Npcap driver service via `sc`. `None` when the
    /// query itself failed.
    fn driver_running() -> Option<bool> {
        let out = Command::new("sc").args(["query", "npcap"]).output().ok()?;
        if !out.status.success() {
            return Some(false);
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Some(text.contains("RUNNING"))
    }

    pub fn check() -> Preflight {
        if let Err(reason) = netscope_ffi::wpcap_available() {
            return Preflight::Fail {
                message: format!("Npcap is not installed: {reason}. {INSTALL_HINT}"),
            };
        }
        if driver_running() == Some(false) {
            return Preflight::Fail {
                message: format!(
                    "wpcap.dll is present but the Npcap driver service is not running. \
                     Run `sc start npcap` from an elevated prompt, or reinstall. {INSTALL_HINT}"
                ),
            };
        }
        match netscope_ffi::is_elevated() {
            Some(true) => Preflight::Ok {
                detail: "Npcap present, driver running, process elevated".into(),
            },
            Some(false) => Preflight::Warn {
                message: "netscope is not running as Administrator. Capture still works when \
                          Npcap was installed without \"Restrict driver access to Administrators \
                          only\"; if opening a device fails with access denied, right-click \
                          netscope and choose \"Run as administrator\" or reinstall Npcap \
                          without that restriction."
                    .into(),
            },
            None => Preflight::Warn {
                message: "Npcap present; could not determine whether the process is elevated."
                    .into(),
            },
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Preflight;
    use std::fs;

    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;

    pub fn setcap_hint() -> String {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "$(which netscope)".to_string());
        format!("sudo setcap cap_net_raw,cap_net_admin+eip {exe}")
    }

    /// Parse the effective capability mask from /proc/self/status.
    pub fn effective_caps(status: &str) -> Option<u64> {
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
    }

    pub fn has_caps(mask: u64) -> bool {
        let need = (1u64 << CAP_NET_RAW) | (1u64 << CAP_NET_ADMIN);
        mask & need == need
    }

    pub fn check() -> Preflight {
        let status = match fs::read_to_string("/proc/self/status") {
            Ok(s) => s,
            Err(e) => {
                return Preflight::Warn {
                    message: format!(
                        "Could not read /proc/self/status ({e}); if capture fails, run: {}",
                        setcap_hint()
                    ),
                }
            }
        };
        match effective_caps(&status) {
            Some(mask) if has_caps(mask) => Preflight::Ok {
                detail: "CAP_NET_RAW and CAP_NET_ADMIN are in the effective set".into(),
            },
            Some(_) => Preflight::Fail {
                message: format!(
                    "This process lacks CAP_NET_RAW/CAP_NET_ADMIN. Grant them once with:\n  {}\n\
                     then run netscope normally (no sudo). Alternatively run under sudo.",
                    setcap_hint()
                ),
            },
            None => Preflight::Warn {
                message: format!(
                    "Could not parse capabilities; if capture fails, run: {}",
                    setcap_hint()
                ),
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_capeff() {
            let s = "Name:\tx\nCapInh:\t0000000000000000\nCapEff:\t0000000000003000\n";
            assert_eq!(effective_caps(s), Some(0x3000));
            assert!(has_caps(0x3000));
            assert!(!has_caps(0x2000));
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::Preflight;
    use std::fs::OpenOptions;
    use std::io::ErrorKind;

    pub const HINT: &str =
        "Capture needs read/write access to /dev/bpf*. Either run netscope with \
        `sudo`, or install Wireshark's ChmodBPF helper (creates the `access_bpf` group and \
        makes /dev/bpf* group-writable), or temporarily run `sudo chmod o+rw /dev/bpf*`.";

    pub fn check() -> Preflight {
        // Opening a BPF device is the actual privilege test; libpcap does the same.
        match OpenOptions::new().read(true).write(true).open("/dev/bpf0") {
            Ok(_) => Preflight::Ok {
                detail: "/dev/bpf0 is readable and writable".into(),
            },
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Preflight::Fail {
                message: format!("Permission denied opening /dev/bpf0. {HINT}"),
            },
            // EBUSY means another capture holds bpf0; probe the next one.
            Err(_) => match OpenOptions::new().read(true).write(true).open("/dev/bpf1") {
                Ok(_) => Preflight::Ok {
                    detail: "/dev/bpf1 is readable and writable".into(),
                },
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Preflight::Fail {
                    message: format!("Permission denied opening /dev/bpf1. {HINT}"),
                },
                Err(e) => Preflight::Warn {
                    message: format!("Could not probe /dev/bpf* ({e}). {HINT}"),
                },
            },
        }
    }
}
