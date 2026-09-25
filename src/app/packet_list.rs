//! The virtualised packet list. Only visible rows are laid out, so a million
//! rows cost the same as fifty.

use egui_extras::{Column, TableBuilder, TableRow};

use super::colour_rules::{RowColours, Rules};
use super::timefmt;
use crate::config::TimeMode;
use crate::store::View;

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
    pub fn navigate(&mut self, nav: Nav, view: &View) {
        if view.is_empty() {
            return;
        }
        let last = view.len() - 1;
        let current = self.selected.and_then(|n| view.row_of(n));
        let target = match (nav, current) {
            (Nav::Home, _) => 0,
            (Nav::End, _) => last,
            (Nav::Up(n), Some(r)) => r.saturating_sub(n),
            (Nav::Down(n), Some(r)) => (r + n).min(last),
            (Nav::Up(_), None) => last,
            (Nav::Down(_), None) => 0,
        };
        self.follow = false;
        self.selected = view.get(target).map(|f| f.number);
        self.scroll_to = Some((target, egui::Align::Center));
    }
}

/// One cell, tinted by the colour rule that claimed the row. The fill is
/// painted before the text so it sits under it, and is expanded by half the
/// item spacing so neighbouring cells meet without a seam — the same rect
/// `egui_extras` uses for striping.
fn cell(row: &mut TableRow<'_, '_>, tint: Option<RowColours>, text: impl Into<egui::WidgetText>) {
    row.col(|ui| {
        if let Some(c) = tint {
            let pad = 0.5 * ui.spacing().item_spacing;
            ui.painter().rect_filled(
                ui.max_rect().expand2(pad),
                egui::Rounding::ZERO,
                c.background,
            );
            ui.style_mut().visuals.override_text_color = Some(c.foreground);
        }
        ui.label(text);
    });
}

pub fn show(
    ui: &mut egui::Ui,
    view: &View,
    mode: TimeMode,
    colours: Option<&Rules>,
    state: &mut ListState,
) {
    let n = view.len();
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
        .column(Column::initial(70.0).at_least(40.0))
        .column(Column::remainder().at_least(80.0))
        .sense(egui::Sense::click())
        .min_scrolled_height(0.0);
    if let Some((row, align)) = state.scroll_to.take() {
        table = table.scroll_to_row(row, Some(align));
    }
    let start = view.snapshot().start_ts();
    table
        .header(20.0, |mut header| {
            for title in [
                "No.",
                timefmt::column_title(mode),
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Expert",
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
                let Some(frame) = view.get(i) else {
                    return;
                };
                let selected = state.selected == Some(frame.number);
                row.set_selected(selected);
                // A selected row keeps the selection highlight; the rule
                // colour would hide it.
                let tint = if selected {
                    None
                } else {
                    colours.and_then(|c| c.colours(frame))
                };
                let previous = if i > 0 {
                    view.get(i - 1).map(|f| f.ts)
                } else {
                    None
                };
                cell(&mut row, tint, frame.number.to_string());
                cell(
                    &mut row,
                    tint,
                    timefmt::render(mode, frame.ts, start, previous),
                );
                cell(&mut row, tint, frame.summary.source.to_string());
                cell(&mut row, tint, frame.summary.destination.to_string());
                cell(&mut row, tint, frame.summary.protocol_display());
                cell(&mut row, tint, frame.orig_len.to_string());
                // The expert cell keeps its severity colour even on a tinted
                // row: it is the one column whose colour carries meaning of
                // its own rather than repeating the row's protocol.
                let expert = frame.summary.expert;
                row.col(|ui| {
                    if let Some(c) = tint {
                        let pad = 0.5 * ui.spacing().item_spacing;
                        ui.painter().rect_filled(
                            ui.max_rect().expand2(pad),
                            egui::Rounding::ZERO,
                            c.background,
                        );
                    }
                    match expert {
                        Some(e) => {
                            let [r, g, b] = e.severity.rgb();
                            ui.colored_label(egui::Color32::from_rgb(r, g, b), e.severity.name())
                                .on_hover_text(format!("{}: {}", e.group.name(), e.summary));
                        }
                        None => {
                            if let Some(c) = tint {
                                ui.style_mut().visuals.override_text_color = Some(c.foreground);
                            }
                            ui.label("");
                        }
                    }
                });
                cell(&mut row, tint, frame.summary.info.as_str());
                if row.response().clicked() {
                    state.selected = Some(frame.number);
                    state.follow = false;
                }
            });
        });
}
