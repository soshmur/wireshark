//! The virtualised packet list. Only visible rows are laid out, so a million
//! rows cost the same as fifty.

use egui_extras::{Column, TableBuilder};

use super::timefmt;
use crate::config::TimeMode;
use crate::store::Snapshot;

pub const ROW_HEIGHT: f32 = 18.0;

#[derive(Debug, Default)]
pub struct ListState {
    /// Selected frame number (not row: rows shift as the ring evicts).
    pub selected: Option<u32>,
    /// One-shot request to bring a row into view.
    pub scroll_to: Option<(usize, egui::Align)>,
    /// Keep the newest frame in view while capturing.
    pub follow: bool,
}

/// Which keyboard navigation happened this frame, resolved by the caller
/// against the current snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Up(usize),
    Down(usize),
    Home,
    End,
}

impl ListState {
    /// Apply a navigation step. `page` is the number of visible rows.
    pub fn navigate(&mut self, nav: Nav, snapshot: &Snapshot) {
        if snapshot.is_empty() {
            return;
        }
        let last = snapshot.len() - 1;
        let current = self.selected.and_then(|n| snapshot.row_of(n));
        let target = match (nav, current) {
            (Nav::Home, _) => 0,
            (Nav::End, _) => last,
            (Nav::Up(n), Some(r)) => r.saturating_sub(n),
            (Nav::Down(n), Some(r)) => (r + n).min(last),
            (Nav::Up(_), None) => last,
            (Nav::Down(_), None) => 0,
        };
        self.follow = false;
        self.selected = snapshot.get(target).map(|f| f.number);
        self.scroll_to = Some((target, egui::Align::Center));
    }
}

pub fn show(ui: &mut egui::Ui, snapshot: &Snapshot, mode: TimeMode, state: &mut ListState) {
    let n = snapshot.len();
    if state.follow && n > 0 {
        state.scroll_to = Some((n - 1, egui::Align::BOTTOM));
    }
    let mut table = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(70.0).at_least(40.0))
        .column(Column::initial(150.0).at_least(60.0))
        .column(Column::initial(150.0).at_least(60.0))
        .column(Column::initial(150.0).at_least(60.0))
        .column(Column::initial(70.0).at_least(40.0))
        .column(Column::initial(60.0).at_least(40.0))
        .column(Column::remainder().at_least(80.0))
        .sense(egui::Sense::click())
        .min_scrolled_height(0.0);
    if let Some((row, align)) = state.scroll_to.take() {
        table = table.scroll_to_row(row, Some(align));
    }
    let start = snapshot.start_ts();
    table
        .header(20.0, |mut header| {
            for title in [
                "No.",
                timefmt::column_title(mode),
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Info",
            ] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, n, |mut row| {
                let i = row.index();
                let Some(frame) = snapshot.get(i) else {
                    return;
                };
                row.set_selected(state.selected == Some(frame.number));
                let previous = if i > 0 {
                    snapshot.get(i - 1).map(|f| f.ts)
                } else {
                    None
                };
                row.col(|ui| {
                    ui.label(frame.number.to_string());
                });
                row.col(|ui| {
                    ui.label(timefmt::render(mode, frame.ts, start, previous));
                });
                row.col(|ui| {
                    ui.label(&frame.summary.source);
                });
                row.col(|ui| {
                    ui.label(&frame.summary.destination);
                });
                row.col(|ui| {
                    ui.label(frame.summary.protocol);
                });
                row.col(|ui| {
                    ui.label(frame.orig_len.to_string());
                });
                row.col(|ui| {
                    ui.label(&frame.summary.info);
                });
                if row.response().clicked() {
                    state.selected = Some(frame.number);
                    state.follow = false;
                }
            });
        });
}
