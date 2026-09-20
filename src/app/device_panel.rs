//! The interface list.

use crate::capture::Device;

/// Draws the device table. `selected` is updated when the user clicks a row.
/// Returns `true` when the user double-clicked a row (meaning "start").
pub fn show(
    ui: &mut egui::Ui,
    devices: &[Device],
    error: Option<&str>,
    selected: &mut Option<usize>,
    enabled: bool,
) -> bool {
    let mut start_requested = false;
    if let Some(err) = error {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
        return false;
    }
    if devices.is_empty() {
        ui.label("No capture interfaces found.");
        return false;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("devices")
            .striped(true)
            .num_columns(3)
            .min_col_width(60.0)
            .show(ui, |ui| {
                ui.strong("Interface");
                ui.strong("Addresses");
                ui.strong("State");
                ui.end_row();
                for (i, dev) in devices.iter().enumerate() {
                    let is_sel = *selected == Some(i);
                    let resp = ui.add_enabled(
                        enabled,
                        egui::SelectableLabel::new(is_sel, dev.display_name()),
                    );
                    let resp = resp.on_hover_text(&dev.info.name);
                    if resp.clicked() {
                        *selected = Some(i);
                    }
                    if resp.double_clicked() {
                        *selected = Some(i);
                        start_requested = true;
                    }
                    let addrs = if dev.info.addresses.is_empty() {
                        "—".to_string()
                    } else {
                        dev.info.addresses.join(", ")
                    };
                    ui.label(addrs);
                    ui.label(dev.state_tags());
                    ui.end_row();
                }
            });
    });
    start_requested
}
