//! The protocol hierarchy window: what the capture is made of.

use egui_extras::{Column, TableBuilder};

use crate::store::hierarchy::{Row, Totals};

#[derive(Debug, Default)]
pub struct HierarchyState {
    pub open: bool,
    pub rows: Vec<Row>,
    pub totals: Totals,
    /// Store version the rows describe.
    pub version: Option<u64>,
}

impl HierarchyState {
    pub fn stale(&self, version: u64) -> bool {
        self.version != Some(version)
    }

    pub fn set(&mut self, rows: Vec<Row>, totals: Totals, version: u64) {
        self.rows = rows;
        self.totals = totals;
        self.version = Some(version);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Narrow the packet list to this protocol chain.
    Filter(String),
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "—".to_string();
    }
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

pub fn show(ctx: &egui::Context, state: &mut HierarchyState) -> Action {
    let mut action = Action::None;
    let mut open = state.open;
    egui::Window::new("Protocol hierarchy")
        .open(&mut open)
        .default_size([760.0, 460.0])
        .show(ctx, |ui| {
            ui.weak(format!(
                "{} packets, {} bytes · double-click a row to filter the packet list",
                state.totals.packets, state.totals.bytes
            ));
            ui.weak(
                "\"Packets\" counts frames passing through a protocol; \"ends here\" counts \
                 frames where it was the last one recognised.",
            );
            ui.separator();
            if state.rows.is_empty() {
                ui.weak("Nothing captured yet.");
                return;
            }
            let rows = std::mem::take(&mut state.rows);
            let totals = state.totals;
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(240.0).at_least(120.0))
                .column(Column::initial(80.0).at_least(50.0))
                .column(Column::initial(70.0).at_least(50.0))
                .column(Column::initial(100.0).at_least(60.0))
                .column(Column::initial(70.0).at_least(50.0))
                .column(Column::initial(90.0).at_least(60.0))
                .column(Column::initial(90.0).at_least(60.0))
                .column(Column::remainder().at_least(80.0))
                .sense(egui::Sense::click())
                .header(20.0, |mut header| {
                    for title in [
                        "Protocol",
                        "Packets",
                        "%",
                        "Bytes",
                        "% bytes",
                        "Ends here",
                        "Bytes ending",
                        "Bits/s",
                    ] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(18.0, rows.len(), |mut r| {
                        let Some(row) = rows.get(r.index()) else {
                            return;
                        };
                        r.col(|ui| {
                            // Indent by depth so the chain reads as a tree.
                            ui.add_space(row.depth as f32 * 14.0);
                            ui.label(&row.name);
                        });
                        r.col(|ui| {
                            ui.label(row.packets.to_string());
                        });
                        r.col(|ui| {
                            ui.label(percent(row.packets, totals.packets));
                        });
                        r.col(|ui| {
                            ui.label(row.bytes.to_string());
                        });
                        r.col(|ui| {
                            ui.label(percent(row.bytes, totals.bytes));
                        });
                        r.col(|ui| {
                            ui.label(row.end_packets.to_string());
                        });
                        r.col(|ui| {
                            ui.label(row.end_bytes.to_string());
                        });
                        r.col(|ui| {
                            ui.label(match totals.bits_per_second(row.bytes) {
                                Some(bps) => crate::app::io_graph_window::short_number(bps),
                                None => "—".to_string(),
                            });
                        });
                        let resp = r.response();
                        if resp.double_clicked() {
                            action = Action::Filter(row.filter());
                        }
                        resp.on_hover_text(row.filter());
                    });
                });
            state.rows = rows;
        });
    state.open = open;
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentages_do_not_divide_by_zero() {
        assert_eq!(percent(0, 0), "—");
        assert_eq!(percent(5, 0), "—");
        assert_eq!(percent(1, 2), "50.0%");
        assert_eq!(percent(3, 3), "100.0%");
    }
}
