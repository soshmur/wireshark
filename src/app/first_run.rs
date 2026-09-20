//! The authorised-use notice shown once on first launch.

pub const NOTICE_TITLE: &str = "Before you capture";

pub const NOTICE: &str = "netscope records network traffic on the interface you choose. \
Capture only on networks and hosts you own or are explicitly authorised to monitor. \
Intercepting other people's traffic without permission is illegal in most jurisdictions.\n\n\
Captured data stays on this machine; netscope does not transmit anything.";

/// Draws the modal. Returns `true` when the user acknowledged it this frame.
pub fn show(ctx: &egui::Context) -> bool {
    let mut acknowledged = false;
    egui::Window::new(NOTICE_TITLE)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(480.0);
            ui.label(NOTICE);
            ui.add_space(12.0);
            ui.vertical_centered(|ui| {
                if ui.button("I understand and am authorised").clicked() {
                    acknowledged = true;
                }
            });
        });
    acknowledged
}
