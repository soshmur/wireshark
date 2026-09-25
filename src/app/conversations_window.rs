//! The conversations window: who is talking to whom, and how much.

use egui_extras::{Column, TableBuilder};

use crate::store::conversations::{filter_for, Kind, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Bytes,
    Packets,
    Duration,
    Rate,
}

pub struct ConversationsState {
    pub open: bool,
    pub kind: Kind,
    pub sort: Sort,
    /// Rows for the current layer, rebuilt when the store changes.
    pub rows: Vec<Row>,
    /// Store version the rows were built from.
    pub version: u64,
    /// Layer the rows were built for.
    built_for: Kind,
}

impl Default for ConversationsState {
    fn default() -> Self {
        ConversationsState {
            open: false,
            kind: Kind::Tcp,
            sort: Sort::Bytes,
            rows: Vec::new(),
            version: u64::MAX,
            built_for: Kind::Tcp,
        }
    }
}

impl ConversationsState {
    /// True when the rows no longer describe the store.
    pub fn stale(&self, version: u64) -> bool {
        self.version != version || self.built_for != self.kind
    }

    pub fn set(&mut self, rows: Vec<Row>, version: u64) {
        self.rows = rows;
        self.version = version;
        self.built_for = self.kind;
        self.resort();
    }

    fn resort(&mut self) {
        match self.sort {
            // Reversed keys rather than a reversed comparison, so the
            // ordering stays stable for rows that tie.
            Sort::Bytes => self
                .rows
                .sort_by_key(|r| std::cmp::Reverse(r.total_bytes())),
            Sort::Packets => self
                .rows
                .sort_by_key(|r| std::cmp::Reverse(r.total_packets())),
            Sort::Duration => self.rows.sort_by(|a, b| {
                b.duration()
                    .partial_cmp(&a.duration())
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Sort::Rate => self.rows.sort_by(|a, b| {
                b.bits_per_second()
                    .unwrap_or(0.0)
                    .partial_cmp(&a.bits_per_second().unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Narrow the packet list to this conversation.
    Filter(String),
    /// Follow this stream.
    Follow(u32),
}

fn endpoint(addr: &crate::dissect::Addr, port: u16) -> String {
    if port == 0 {
        addr.to_string()
    } else {
        format!("{addr}:{port}")
    }
}

/// Bytes in a form that reads at a glance.
fn si(bytes: u64) -> String {
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

pub fn show(ctx: &egui::Context, state: &mut ConversationsState) -> Action {
    let mut action = Action::None;
    let mut open = state.open;
    egui::Window::new("Conversations")
        .open(&mut open)
        .default_size([860.0, 480.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                for kind in Kind::ALL {
                    ui.selectable_value(&mut state.kind, kind, kind.name());
                }
                ui.separator();
                ui.label("Sort by:");
                let before = state.sort;
                for (s, name) in [
                    (Sort::Bytes, "Bytes"),
                    (Sort::Packets, "Packets"),
                    (Sort::Duration, "Duration"),
                    (Sort::Rate, "Bit rate"),
                ] {
                    ui.selectable_value(&mut state.sort, s, name);
                }
                if state.sort != before {
                    state.resort();
                }
            });
            ui.weak(format!(
                "{} conversations · double-click a row to filter the packet list",
                state.rows.len()
            ));
            ui.separator();
            if state.rows.is_empty() {
                ui.weak("No conversations at this layer.");
                return;
            }

            let kind = state.kind;
            let rows = std::mem::take(&mut state.rows);
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(180.0).at_least(80.0))
                .column(Column::initial(180.0).at_least(80.0))
                .column(Column::initial(70.0).at_least(40.0))
                .column(Column::initial(80.0).at_least(50.0))
                .column(Column::initial(70.0).at_least(40.0))
                .column(Column::initial(80.0).at_least(50.0))
                .column(Column::initial(80.0).at_least(50.0))
                .column(Column::remainder().at_least(70.0))
                .sense(egui::Sense::click())
                .header(20.0, |mut header| {
                    for title in [
                        "Address A",
                        "Address B",
                        "A → B",
                        "Bytes A → B",
                        "B → A",
                        "Bytes B → A",
                        "Duration",
                        "Bit rate",
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
                            ui.label(endpoint(&row.a, row.port_a));
                        });
                        r.col(|ui| {
                            ui.label(endpoint(&row.b, row.port_b));
                        });
                        r.col(|ui| {
                            ui.label(row.packets[0].to_string());
                        });
                        r.col(|ui| {
                            ui.label(si(row.bytes[0]));
                        });
                        r.col(|ui| {
                            ui.label(row.packets[1].to_string());
                        });
                        r.col(|ui| {
                            ui.label(si(row.bytes[1]));
                        });
                        r.col(|ui| {
                            ui.label(format!("{:.3} s", row.duration()));
                        });
                        r.col(|ui| {
                            ui.label(match row.bits_per_second() {
                                Some(bps) => format!("{:.0} bit/s", bps),
                                None => "—".to_string(),
                            });
                        });
                        let resp = r.response();
                        if resp.double_clicked() {
                            action = Action::Filter(filter_for(row, kind));
                        } else if resp.clicked() {
                            if let Some(id) = row.stream {
                                action = Action::Follow(id);
                            }
                        }
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
    fn byte_counts_read_at_a_glance() {
        assert_eq!(si(0), "0 B");
        assert_eq!(si(999), "999 B");
        assert_eq!(si(1000), "1.0 kB");
        assert_eq!(si(1_500_000), "1.5 MB");
        // And it does not run off the end of the unit table.
        assert!(si(u64::MAX).ends_with(" TB"));
    }

    #[test]
    fn an_endpoint_without_a_port_shows_only_the_address() {
        let a = crate::dissect::Addr::Ipv4([10, 0, 0, 1]);
        assert_eq!(endpoint(&a, 0), "10.0.0.1");
        assert_eq!(endpoint(&a, 443), "10.0.0.1:443");
    }
}
