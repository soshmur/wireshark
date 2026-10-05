//! The Expert Information window: everything wrong in the capture, grouped.

use egui_extras::{Column, TableBuilder};

use crate::dissect::Severity;
use crate::store::expert::{counts, Counts, Entry};

#[derive(Debug, Default)]
pub struct ExpertState {
    pub open: bool,
    pub entries: Vec<Entry>,
    pub counts: Counts,
    pub version: Option<u64>,
    /// Hide anything below this.
    pub least: Severity,
}

impl ExpertState {
    pub fn stale(&self, version: u64) -> bool {
        self.version != Some(version)
    }

    pub fn set(&mut self, entries: Vec<Entry>, version: u64) {
        self.counts = counts(&entries);
        self.entries = entries;
        self.version = Some(version);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Narrow the packet list to this finding.
    Filter(String),
    /// Select this frame.
    GoTo(u32),
}

pub fn show(ctx: &egui::Context, state: &mut ExpertState) -> Action {
    let mut action = Action::None;
    let mut open = state.open;
    egui::Window::new("Expert information")
        .open(&mut open)
        .default_size([800.0, 460.0])
        .show(ctx, |ui| {
            let c = state.counts;
            ui.horizontal(|ui| {
                for (sev, n) in [
                    (Severity::Error, c.errors),
                    (Severity::Warn, c.warnings),
                    (Severity::Note, c.notes),
                    (Severity::Chat, c.chats),
                ] {
                    let [r, g, b] = sev.rgb();
                    ui.colored_label(
                        egui::Color32::from_rgb(r, g, b),
                        format!("{}: {n}", sev.name()),
                    );
                    ui.label("·");
                }
                ui.label(format!("{} in total", c.total()));
            });
            ui.horizontal(|ui| {
                ui.label("Show at least:");
                for sev in [
                    Severity::Chat,
                    Severity::Note,
                    Severity::Warn,
                    Severity::Error,
                ] {
                    ui.selectable_value(&mut state.least, sev, sev.name());
                }
            });
            ui.weak(
                "Double-click a row to filter the packet list; click a frame number to go to it.",
            );
            ui.separator();

            let least = state.least;
            let rows: Vec<&Entry> = state
                .entries
                .iter()
                .filter(|e| e.severity >= least)
                .collect();
            if rows.is_empty() {
                ui.weak(if state.entries.is_empty() {
                    "Nothing to report. Every packet dissected cleanly."
                } else {
                    "Nothing at this severity or above."
                });
                return;
            }
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(70.0).at_least(50.0))
                .column(Column::initial(90.0).at_least(60.0))
                .column(Column::initial(70.0).at_least(50.0))
                .column(Column::initial(300.0).at_least(140.0))
                .column(Column::remainder().at_least(140.0))
                .sense(egui::Sense::click())
                .header(20.0, |mut header| {
                    for title in ["Severity", "Group", "Count", "Summary", "Frames"] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(18.0, rows.len(), |mut r| {
                        let Some(entry) = rows.get(r.index()) else {
                            return;
                        };
                        r.col(|ui| {
                            let [red, g, b] = entry.severity.rgb();
                            ui.colored_label(
                                egui::Color32::from_rgb(red, g, b),
                                entry.severity.name(),
                            );
                        });
                        r.col(|ui| {
                            ui.label(entry.group.name());
                        });
                        r.col(|ui| {
                            ui.label(entry.count.to_string());
                        });
                        r.col(|ui| {
                            ui.label(&entry.summary).on_hover_text(entry.field);
                        });
                        r.col(|ui| {
                            // The first few only. A capture with a million
                            // retransmissions cannot list them, and the
                            // filter is how you see them all.
                            for n in entry.first_frames.iter().take(6) {
                                if ui.small_button(n.to_string()).clicked() {
                                    action = Action::GoTo(*n);
                                }
                            }
                            if entry.count as usize > entry.first_frames.len().min(6) {
                                ui.weak("…");
                            }
                        });
                        if r.response().double_clicked() {
                            action = Action::Filter(entry.filter());
                        }
                    });
                });
        });
    state.open = open;
    action
}
