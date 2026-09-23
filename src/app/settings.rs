//! Capture options dialog: snaplen, promiscuous mode, ring buffer limits and
//! checksum validation.

use crate::config::Config;

/// Returns `true` when a value changed (caller persists and applies).
pub fn show(ctx: &egui::Context, open: &mut bool, config: &mut Config, capturing: bool) -> bool {
    let mut changed = false;
    egui::Window::new("Capture options")
        .open(open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.add_enabled_ui(!capturing, |ui| {
                egui::Grid::new("capture-options")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Snapshot length (bytes)");
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut config.snaplen)
                                    .range(64..=262_144)
                                    .speed(64),
                            )
                            .changed();
                        ui.end_row();

                        ui.label("Promiscuous mode");
                        changed |= ui.checkbox(&mut config.promiscuous, "").changed();
                        ui.end_row();
                    });
                if capturing {
                    ui.weak("Stop the capture to change these.");
                }
            });
            ui.separator();
            ui.label("Ring buffer — oldest frames are evicted beyond either limit:");
            egui::Grid::new("ring-options")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Max frames");
                    changed |= ui
                        .add(
                            egui::DragValue::new(&mut config.ring_max_frames)
                                .range(4_096..=100_000_000)
                                .speed(4_096),
                        )
                        .changed();
                    ui.end_row();

                    ui.label("Max memory (MB)");
                    let mut mb = config.ring_max_bytes / (1024 * 1024);
                    if ui
                        .add(egui::DragValue::new(&mut mb).range(16..=65_536).speed(16))
                        .changed()
                    {
                        config.ring_max_bytes = mb * 1024 * 1024;
                        changed = true;
                    }
                    ui.end_row();
                });
            ui.weak("Limits apply immediately and are honoured to within one 4,096-frame chunk.");
            ui.separator();
            ui.add_enabled_ui(!capturing, |ui| {
                ui.label("Checksum validation:");
                changed |= ui
                    .checkbox(
                        &mut config.validate_ip_checksums,
                        "Validate IPv4 header and ICMPv4 checksums",
                    )
                    .on_hover_text(
                        "These are computed in software, so a bad one usually means \n                         the packet really is damaged.",
                    )
                    .changed();
                changed |= ui
                    .checkbox(
                        &mut config.validate_transport_checksums,
                        "Validate TCP, UDP and ICMPv6 checksums",
                    )
                    .on_hover_text(
                        "Off by default, as Wireshark ships. Your network card computes \n                         these after libpcap has already seen the packet, so frames your \n                         own machine sent will look wrong - typically 20-40% of a \n                         capture. This is called checksum offload and is normal.",
                    )
                    .changed();
                ui.weak(
                    "Changing these dissects the frames already captured again, \n                     which takes about two seconds per million.",
                );
                if capturing {
                    ui.weak("Stop the capture to change these.");
                }
            });
        });
    changed
}
