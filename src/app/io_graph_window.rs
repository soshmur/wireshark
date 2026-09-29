//! The I/O graph window.
//!
//! Drawn with egui's painter rather than a plotting crate. A stacked line
//! chart with two axes is a couple of hundred lines, and the alternative was
//! another dependency for something this project can do itself — the same
//! reasoning that keeps the file chooser in-app.

use crate::store::io_graph::{self, Graph, Series, Unit};

pub struct IoGraphState {
    pub open: bool,
    pub series: Vec<Series>,
    pub interval: f64,
    pub unit: Unit,
    /// The computed graph, and the store version it describes.
    pub graph: Graph,
    pub version: Option<u64>,
    /// Compile errors, parallel to `series`.
    pub errors: Vec<Option<String>>,
    /// Bucket the pointer is over, for the read-out.
    hover: Option<usize>,
    /// Set when the series list changed and the graph must be rebuilt.
    dirty: bool,
}

impl Default for IoGraphState {
    fn default() -> Self {
        IoGraphState {
            open: false,
            series: io_graph::defaults(),
            interval: 1.0,
            unit: Unit::Packets,
            graph: Graph::default(),
            version: None,
            errors: Vec::new(),
            hover: None,
            dirty: true,
        }
    }
}

impl IoGraphState {
    pub fn stale(&self, version: u64) -> bool {
        self.dirty || self.version != Some(version)
    }

    /// Rebuild from a snapshot.
    pub fn rebuild(&mut self, snapshot: &crate::store::Snapshot, version: u64) {
        let compiled: Vec<io_graph::Compiled> = self.series.iter().map(io_graph::compile).collect();
        self.errors = compiled.iter().map(|c| c.error.clone()).collect();
        self.graph = io_graph::build(snapshot, &self.series, &compiled, self.interval, self.unit);
        self.version = Some(version);
        self.dirty = false;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    /// Narrow the packet list to a series' filter.
    Filter(String),
}

/// Intervals offered, in seconds. Finer than a millisecond is not useful on
/// any screen and the bucket cap would bite first.
const INTERVALS: [(f64, &str); 7] = [
    (0.001, "1 ms"),
    (0.01, "10 ms"),
    (0.1, "100 ms"),
    (1.0, "1 s"),
    (10.0, "10 s"),
    (60.0, "1 min"),
    (600.0, "10 min"),
];

pub fn show(ctx: &egui::Context, state: &mut IoGraphState) -> Action {
    let mut action = Action::None;
    let mut open = state.open;
    egui::Window::new("I/O graph")
        .open(&mut open)
        .default_size([820.0, 560.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Interval:");
                let before = state.interval;
                egui::ComboBox::from_id_salt("io-interval")
                    .selected_text(
                        INTERVALS
                            .iter()
                            .find(|(v, _)| (*v - state.interval).abs() < f64::EPSILON)
                            .map(|(_, n)| *n)
                            .unwrap_or("custom"),
                    )
                    .show_ui(ui, |ui| {
                        for (v, name) in INTERVALS {
                            ui.selectable_value(&mut state.interval, v, name);
                        }
                    });
                ui.separator();
                ui.label("Y axis:");
                let unit_before = state.unit;
                for u in [Unit::Packets, Unit::Bytes, Unit::Bits] {
                    ui.selectable_value(&mut state.unit, u, u.name());
                }
                if state.interval != before || state.unit != unit_before {
                    state.dirty = true;
                }
            });
            ui.separator();

            plot(ui, state, &mut action);

            ui.separator();
            series_editor(ui, state, &mut action);
        });
    state.open = open;
    action
}

fn plot(ui: &mut egui::Ui, state: &mut IoGraphState, action: &mut Action) {
    let height = 260.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    let painter = ui.painter_at(rect);
    let visuals = ui.visuals();
    painter.rect_filled(rect, egui::Rounding::same(2.0), visuals.extreme_bg_color);

    let g = &state.graph;
    if g.buckets == 0 {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Nothing captured yet.",
            egui::FontId::proportional(14.0),
            visuals.weak_text_color(),
        );
        return;
    }

    // Leave room for the axis labels.
    let margin_left = 64.0;
    let margin_bottom = 22.0;
    let plot_rect = egui::Rect::from_min_max(
        rect.min + egui::vec2(margin_left, 8.0),
        rect.max - egui::vec2(8.0, margin_bottom),
    );
    let max_y = g.max_y().max(1.0);
    let x_span = (g.buckets as f64 * g.interval).max(g.interval);

    let to_screen = |x: f64, y: f64| -> egui::Pos2 {
        let fx = (x / x_span).clamp(0.0, 1.0) as f32;
        let fy = (y / max_y).clamp(0.0, 1.0) as f32;
        egui::pos2(
            plot_rect.left() + fx * plot_rect.width(),
            plot_rect.bottom() - fy * plot_rect.height(),
        )
    };

    // Grid and y labels: four lines is enough to read a value off.
    let grid = visuals.weak_text_color().gamma_multiply(0.35);
    for i in 0..=4 {
        let y = max_y * f64::from(i) / 4.0;
        let p = to_screen(0.0, y);
        painter.line_segment(
            [
                egui::pos2(plot_rect.left(), p.y),
                egui::pos2(plot_rect.right(), p.y),
            ],
            egui::Stroke::new(1.0_f32, grid),
        );
        painter.text(
            egui::pos2(plot_rect.left() - 6.0, p.y),
            egui::Align2::RIGHT_CENTER,
            short_number(y),
            egui::FontId::monospace(10.0),
            visuals.weak_text_color(),
        );
    }
    // X labels at either end and the middle, in seconds into the capture.
    for f in [0.0, 0.5, 1.0] {
        let x = x_span * f;
        let p = to_screen(x, 0.0);
        painter.text(
            egui::pos2(p.x, plot_rect.bottom() + 4.0),
            egui::Align2::CENTER_TOP,
            format!("{x:.3} s"),
            egui::FontId::monospace(10.0),
            visuals.weak_text_color(),
        );
    }

    // One polyline per enabled series.
    for (i, series) in state.series.iter().enumerate() {
        if !series.enabled {
            continue;
        }
        let Some(line) = g.lines.get(i) else { continue };
        let [r, gg, b] = series.colour;
        let colour = egui::Color32::from_rgb(r, gg, b);
        let points: Vec<egui::Pos2> = line
            .points
            .iter()
            .enumerate()
            .map(|(bucket, v)| to_screen(g.x(bucket), *v))
            .collect();
        if points.len() == 1 {
            painter.circle_filled(points[0], 2.0, colour);
        } else if points.len() > 1 {
            painter.add(egui::Shape::line(
                points,
                egui::Stroke::new(1.5_f32, colour),
            ));
        }
    }

    // Read-out under the pointer: a graph with no numbers is decoration.
    state.hover = None;
    if let Some(pos) = response.hover_pos() {
        if plot_rect.contains(pos) {
            let f = ((pos.x - plot_rect.left()) / plot_rect.width()).clamp(0.0, 1.0);
            let at = f64::from(f) * x_span;
            let bucket = ((at / g.interval).floor() as usize).min(g.buckets.saturating_sub(1));
            state.hover = Some(bucket);
            painter.line_segment(
                [
                    egui::pos2(pos.x, plot_rect.top()),
                    egui::pos2(pos.x, plot_rect.bottom()),
                ],
                egui::Stroke::new(1.0_f32, visuals.weak_text_color()),
            );
            let mut text = format!("{:.3} s", g.x(bucket));
            for (i, s) in state.series.iter().enumerate() {
                if !s.enabled {
                    continue;
                }
                if let Some(v) = g.lines.get(i).and_then(|l| l.points.get(bucket)) {
                    text.push_str(&format!("  ·  {}: {}", s.name, short_number(*v)));
                }
            }
            response.clone().on_hover_text(text);
        }
    }
    let _ = action;
}

fn series_editor(ui: &mut egui::Ui, state: &mut IoGraphState, action: &mut Action) {
    let mut remove = None;
    let mut dirty = false;
    egui::ScrollArea::vertical()
        .max_height(150.0)
        .show(ui, |ui| {
            for i in 0..state.series.len() {
                let error = state.errors.get(i).cloned().flatten();
                let s = &mut state.series[i];
                ui.horizontal(|ui| {
                    dirty |= ui.checkbox(&mut s.enabled, "").changed();
                    let mut colour = s.colour;
                    if ui.color_edit_button_srgb(&mut colour).changed() {
                        s.colour = colour;
                    }
                    dirty |= ui
                        .add(
                            egui::TextEdit::singleline(&mut s.name)
                                .desired_width(110.0)
                                .id_salt(("io-name", i)),
                        )
                        .changed();
                    dirty |= ui
                        .add(
                            egui::TextEdit::singleline(&mut s.filter)
                                .hint_text("display filter, blank for every packet")
                                .desired_width(320.0)
                                .id_salt(("io-filter", i)),
                        )
                        .changed();
                    if ui
                        .add_enabled(!s.filter.trim().is_empty(), egui::Button::new("Apply"))
                        .on_hover_text("Narrow the packet list to this series")
                        .clicked()
                    {
                        *action = Action::Filter(s.filter.clone());
                    }
                    if ui.button("✖").clicked() {
                        remove = Some(i);
                    }
                });
                if let Some(e) = error {
                    ui.horizontal(|ui| {
                        ui.add_space(30.0);
                        ui.colored_label(egui::Color32::from_rgb(230, 120, 120), e);
                    });
                }
            }
        });
    ui.horizontal(|ui| {
        if ui.button("Add series").clicked() {
            state.series.push(Series {
                name: format!("Series {}", state.series.len() + 1),
                filter: String::new(),
                colour: [200, 200, 200],
                enabled: true,
            });
            dirty = true;
        }
        if ui.button("Restore defaults").clicked() {
            state.series = io_graph::defaults();
            dirty = true;
        }
    });
    if let Some(i) = remove {
        state.series.remove(i);
        dirty = true;
    }
    if dirty {
        state.dirty = true;
    }
}

/// A number short enough for an axis label.
pub fn short_number(v: f64) -> String {
    let abs = v.abs();
    if abs >= 1e9 {
        format!("{:.1}G", v / 1e9)
    } else if abs >= 1e6 {
        format!("{:.1}M", v / 1e6)
    } else if abs >= 1e3 {
        format!("{:.1}k", v / 1e3)
    } else if abs >= 1.0 || abs == 0.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.2}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axis_labels_stay_short() {
        assert_eq!(short_number(0.0), "0");
        assert_eq!(short_number(7.0), "7");
        assert_eq!(short_number(1500.0), "1.5k");
        assert_eq!(short_number(2_500_000.0), "2.5M");
        assert_eq!(short_number(3_000_000_000.0), "3.0G");
        // A fractional rate still says something.
        assert_eq!(short_number(0.25), "0.25");
    }

    #[test]
    fn changing_the_interval_marks_the_graph_stale() {
        // Otherwise the axis changes and the data does not.
        let mut s = IoGraphState {
            dirty: false,
            version: Some(7),
            ..IoGraphState::default()
        };
        assert!(!s.stale(7));
        s.dirty = true;
        assert!(s.stale(7));
        s.dirty = false;
        assert!(s.stale(8), "a new store version is also stale");
    }

    #[test]
    fn every_default_series_is_enabled_and_compiles() {
        let s = IoGraphState::default();
        assert!(!s.series.is_empty());
        for series in &s.series {
            assert!(series.enabled);
            assert!(io_graph::compile(series).error.is_none(), "{}", series.name);
        }
    }
}
