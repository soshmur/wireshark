//! The Follow Stream window: one conversation as a transcript.

use crate::dissect::stream::Direction;
use crate::store::follow::{render, Chunk, Stream, View};

/// Client bytes and server bytes get different colours, because the single
/// most common question about a transcript is "who said this".
const FORWARD: egui::Color32 = egui::Color32::from_rgb(220, 120, 120);
const REVERSE: egui::Color32 = egui::Color32::from_rgb(120, 170, 230);

#[derive(Debug, Default)]
pub struct FollowState {
    /// The stream being shown, and the bytes gathered for it.
    pub stream: Option<Stream>,
    pub view: View,
    /// Show only one end of the conversation.
    pub only: Option<Direction>,
    pub open: bool,
}

/// What the window asks the application to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    /// Show this frame in the packet list.
    GoTo(u32),
    /// Narrow the packet list to this conversation.
    FilterStream(u32),
}

impl FollowState {
    pub fn show(&mut self, stream: Stream, id: u32) {
        let _ = id;
        self.stream = Some(stream);
        self.open = true;
    }

    fn visible<'a>(&self, chunks: &'a [Chunk]) -> Vec<&'a Chunk> {
        chunks
            .iter()
            .filter(|c| self.only.is_none_or(|d| c.direction == d))
            .collect()
    }
}

pub fn show(ctx: &egui::Context, state: &mut FollowState) -> Action {
    let mut action = Action::None;
    let Some(stream) = state.stream.clone() else {
        return action;
    };
    let mut open = state.open;
    egui::Window::new(format!("Follow stream {}", stream.id))
        .open(&mut open)
        .default_size([760.0, 520.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Show:");
                egui::ComboBox::from_id_salt("follow-dir")
                    .selected_text(match state.only {
                        None => "Both directions",
                        Some(Direction::Forward) => "Client to server",
                        Some(Direction::Reverse) => "Server to client",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut state.only, None, "Both directions");
                        ui.selectable_value(
                            &mut state.only,
                            Some(Direction::Forward),
                            "Client to server",
                        );
                        ui.selectable_value(
                            &mut state.only,
                            Some(Direction::Reverse),
                            "Server to client",
                        );
                    });
                ui.separator();
                ui.label("As:");
                for (v, name) in [
                    (View::Ascii, "ASCII"),
                    (View::Utf8, "UTF-8"),
                    (View::Hex, "Hex dump"),
                ] {
                    ui.selectable_value(&mut state.view, v, name);
                }
                ui.separator();
                if ui.button("Filter to this stream").clicked() {
                    action = Action::FilterStream(stream.id);
                }
            });
            ui.horizontal(|ui| {
                ui.colored_label(FORWARD, format!("{} bytes out", stream.bytes[0]));
                ui.label("·");
                ui.colored_label(REVERSE, format!("{} bytes in", stream.bytes[1]));
                ui.label("·");
                ui.label(format!("{} frames", stream.frames[0] + stream.frames[1]));
                if stream.missing > 0 {
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::from_rgb(240, 190, 110),
                        format!("{} bytes missing from the capture", stream.missing),
                    );
                }
            });
            ui.separator();

            let visible = state.visible(&stream.chunks);
            if visible.is_empty() {
                ui.weak("This conversation carried no payload.");
                return;
            }
            egui::ScrollArea::both().show(ui, |ui| {
                for chunk in visible {
                    if chunk.gap_before > 0 {
                        ui.colored_label(
                            egui::Color32::from_rgb(240, 190, 110),
                            format!("[{} bytes missing from the capture]", chunk.gap_before),
                        );
                    }
                    let colour = match chunk.direction {
                        Direction::Forward => FORWARD,
                        Direction::Reverse => REVERSE,
                    };
                    let text = render(&chunk.bytes, state.view);
                    let label = ui.add(
                        egui::Label::new(egui::RichText::new(text).monospace().color(colour))
                            .sense(egui::Sense::click()),
                    );
                    if label
                        .on_hover_text(format!("from frame {}", chunk.frame))
                        .clicked()
                    {
                        action = Action::GoTo(chunk.frame);
                    }
                }
            });
        });
    state.open = open;
    if !open {
        state.stream = None;
    }
    action
}
