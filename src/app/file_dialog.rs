//! An in-app file chooser.
//!
//! Not a native dialog. The usual crate for that, `rfd`, reaches for an
//! async runtime on Linux through its portal backend, and this project has
//! no async runtime by design. A native dialog is nicer, but not at the cost
//! of the one dependency rule the brief was most explicit about — so this is
//! a plain directory listing, which behaves identically on every platform
//! and adds nothing to the dependency tree.

use std::path::{Path, PathBuf};

use crate::capture::file::SaveFormat;

/// Which frames a save should write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FrameSet {
    #[default]
    All,
    /// Only what the display filter is showing.
    Displayed,
    /// Only the selected frame.
    Selected,
}

impl FrameSet {
    pub fn name(self) -> &'static str {
        match self {
            FrameSet::All => "All packets",
            FrameSet::Displayed => "Displayed packets",
            FrameSet::Selected => "Selected packet",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Open,
    Save,
}

pub struct FileDialog {
    pub open: bool,
    pub mode: Mode,
    /// Directory being listed.
    pub dir: PathBuf,
    /// Name typed or chosen.
    pub name: String,
    pub format: SaveFormat,
    pub set: FrameSet,
    /// Show files that are not captures.
    pub show_all: bool,
    /// Why the last listing failed, if it did.
    error: Option<String>,
    entries: Vec<Entry>,
    listed: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    len: u64,
}

impl Default for FileDialog {
    fn default() -> Self {
        FileDialog {
            open: false,
            mode: Mode::Open,
            dir: default_dir(),
            name: String::new(),
            format: SaveFormat::Pcapng,
            set: FrameSet::All,
            show_all: false,
            error: None,
            entries: Vec::new(),
            listed: None,
        }
    }
}

fn default_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Extensions the open list shows by default.
const CAPTURE_EXTENSIONS: [&str; 6] = ["pcap", "pcapng", "cap", "ntar", "pcapng.gz", "dmp"];

fn looks_like_capture(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|e| CAPTURE_EXTENSIONS.contains(&e.as_str()))
}

/// What the dialog decided, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Open(PathBuf),
    Save {
        path: PathBuf,
        format: SaveFormat,
        set: FrameSet,
    },
}

impl FileDialog {
    pub fn open_for(&mut self, mode: Mode, suggested: Option<String>) {
        self.mode = mode;
        self.open = true;
        self.listed = None;
        if let Some(name) = suggested {
            self.name = name;
        }
    }

    fn refresh(&mut self) {
        if self.listed.as_deref() == Some(self.dir.as_path()) {
            return;
        }
        self.entries.clear();
        self.error = None;
        match std::fs::read_dir(&self.dir) {
            Ok(iter) => {
                for entry in iter.flatten() {
                    let path = entry.path();
                    let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    self.entries.push(Entry {
                        name: name.to_string(),
                        path,
                        is_dir,
                        len,
                    });
                }
                // Directories first, then by name, case-insensitively.
                self.entries.sort_by(|a, b| {
                    b.is_dir
                        .cmp(&a.is_dir)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
            }
            Err(e) => self.error = Some(format!("{}: {e}", self.dir.display())),
        }
        self.listed = Some(self.dir.clone());
    }

    /// The path the current name resolves to, with an extension if the save
    /// format needs one.
    fn chosen(&self) -> PathBuf {
        let mut name = self.name.trim().to_string();
        if self.mode == Mode::Save && !name.is_empty() {
            let has_ext = Path::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| {
                    e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng")
                });
            if !has_ext {
                name.push('.');
                name.push_str(self.format.extension());
            }
        }
        self.dir.join(name)
    }
}

pub fn show(ctx: &egui::Context, d: &mut FileDialog) -> Action {
    let mut action = Action::None;
    let mut open = d.open;
    let title = match d.mode {
        Mode::Open => "Open capture",
        Mode::Save => "Save capture as",
    };
    d.refresh();
    egui::Window::new(title)
        .open(&mut open)
        .default_size([680.0, 460.0])
        .collapsible(false)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(d.dir.parent().is_some(), egui::Button::new("⬆ Up"))
                    .clicked()
                {
                    if let Some(parent) = d.dir.parent() {
                        d.dir = parent.to_path_buf();
                    }
                }
                let mut text = d.dir.display().to_string();
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut text)
                            .desired_width(ui.available_width() - 90.0)
                            .id_salt("dialog-path"),
                    )
                    .lost_focus()
                {
                    let candidate = PathBuf::from(&text);
                    if candidate.is_dir() {
                        d.dir = candidate;
                    }
                }
            });
            if let Some(err) = &d.error {
                ui.colored_label(egui::Color32::from_rgb(230, 120, 120), err);
            }
            ui.separator();

            let mut navigate_to: Option<PathBuf> = None;
            let mut pick: Option<PathBuf> = None;
            egui::ScrollArea::vertical()
                .max_height(260.0)
                .show(ui, |ui| {
                    for entry in &d.entries {
                        if !entry.is_dir && !d.show_all && !looks_like_capture(&entry.path) {
                            continue;
                        }
                        let label = if entry.is_dir {
                            format!("📁 {}", entry.name)
                        } else {
                            format!("   {}  ({})", entry.name, human_size(entry.len))
                        };
                        let selected = !entry.is_dir && d.name == entry.name;
                        let resp = ui.selectable_label(selected, label);
                        if resp.clicked() {
                            if entry.is_dir {
                                navigate_to = Some(entry.path.clone());
                            } else {
                                d.name = entry.name.clone();
                            }
                        }
                        if resp.double_clicked() {
                            if entry.is_dir {
                                navigate_to = Some(entry.path.clone());
                            } else {
                                pick = Some(entry.path.clone());
                            }
                        }
                    }
                });
            if let Some(path) = navigate_to {
                d.dir = path;
                d.name.clear();
            }

            ui.separator();
            ui.horizontal(|ui| {
                ui.label("File name:");
                ui.add(
                    egui::TextEdit::singleline(&mut d.name)
                        .desired_width(300.0)
                        .id_salt("dialog-name"),
                );
                ui.checkbox(&mut d.show_all, "Show all files");
            });

            if d.mode == Mode::Save {
                ui.horizontal(|ui| {
                    ui.label("Format:");
                    ui.selectable_value(&mut d.format, SaveFormat::Pcapng, "pcapng")
                        .on_hover_text("Keeps per-interface metadata and nanosecond timestamps.");
                    ui.selectable_value(&mut d.format, SaveFormat::Pcap, "pcap")
                        .on_hover_text(
                            "One link type for the whole file. Timestamp precision is \
                             chosen from the data.",
                        );
                    ui.separator();
                    ui.label("Write:");
                    for set in [FrameSet::All, FrameSet::Displayed, FrameSet::Selected] {
                        ui.selectable_value(&mut d.set, set, set.name());
                    }
                });
            }

            ui.separator();
            ui.horizontal(|ui| {
                let verb = if d.mode == Mode::Open { "Open" } else { "Save" };
                let ready = !d.name.trim().is_empty();
                if ui.add_enabled(ready, egui::Button::new(verb)).clicked() {
                    pick = Some(d.chosen());
                }
                if ui.button("Cancel").clicked() {
                    d.open = false;
                }
                if d.mode == Mode::Save {
                    let target = d.chosen();
                    if target.exists() {
                        ui.colored_label(
                            egui::Color32::from_rgb(240, 190, 110),
                            "a file of that name exists and will be replaced",
                        );
                    }
                }
            });

            if let Some(path) = pick {
                action = match d.mode {
                    Mode::Open => Action::Open(path),
                    Mode::Save => Action::Save {
                        path,
                        format: d.format,
                        set: d.set,
                    },
                };
                d.open = false;
            }
        });
    if !d.open {
        open = false;
    }
    d.open = open;
    action
}

/// A file size that reads at a glance.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit + 1 < UNITS.len() {
        v /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_extensions_are_matched_case_insensitively() {
        assert!(looks_like_capture(Path::new("a.pcap")));
        assert!(looks_like_capture(Path::new("a.PCAPNG")));
        assert!(looks_like_capture(Path::new("/tmp/b.Cap")));
        assert!(!looks_like_capture(Path::new("a.txt")));
        assert!(!looks_like_capture(Path::new("noextension")));
    }

    #[test]
    fn saving_adds_the_format_extension_when_it_is_missing() {
        let mut d = FileDialog {
            mode: Mode::Save,
            dir: PathBuf::from("/captures"),
            name: "session".into(),
            format: SaveFormat::Pcapng,
            ..FileDialog::default()
        };
        assert!(d.chosen().to_string_lossy().ends_with("session.pcapng"));
        d.format = SaveFormat::Pcap;
        assert!(d.chosen().to_string_lossy().ends_with("session.pcap"));
    }

    #[test]
    fn an_extension_the_user_typed_is_respected() {
        // Adding a second extension to "session.pcap" would produce
        // "session.pcap.pcapng", which is nobody's intent.
        let d = FileDialog {
            mode: Mode::Save,
            dir: PathBuf::from("/captures"),
            name: "session.pcap".into(),
            format: SaveFormat::Pcapng,
            ..FileDialog::default()
        };
        assert!(d.chosen().to_string_lossy().ends_with("session.pcap"));
    }

    #[test]
    fn opening_does_not_invent_an_extension() {
        let d = FileDialog {
            mode: Mode::Open,
            dir: PathBuf::from("/captures"),
            name: "whatever".into(),
            ..FileDialog::default()
        };
        assert!(d.chosen().to_string_lossy().ends_with("whatever"));
    }

    #[test]
    fn sizes_read_at_a_glance() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1000), "1.0 kB");
        assert_eq!(human_size(2_500_000), "2.5 MB");
    }
}
