//! The display-filter bar: tints as you type, explains what is wrong and
//! where, and completes field names from the registry.

use crate::dissect::registry;
use crate::filter::{compile, complete, FilterError, Test};

/// Compilation state of the text currently in the bar.
#[derive(Debug, Default)]
pub enum Status {
    /// Nothing typed: no filter applied.
    #[default]
    Empty,
    /// Compiles, and is the filter in force.
    Applied,
    /// Compiles, but has not been applied yet (still typing).
    Ready,
    /// Does not compile.
    Invalid(FilterError),
}

pub struct FilterBar {
    pub text: String,
    pub status: Status,
    /// The filter actually being applied to the packet list.
    pub applied: Option<Test>,
    /// Suggestions for the word under the caret, and the span they replace.
    suggestions: Vec<&'static registry::FieldDef>,
    replace: (usize, usize),
    /// Index into `suggestions`, moved with Up/Down.
    highlighted: usize,
    /// Set when the bar should take keyboard focus on the next frame.
    focus_requested: bool,
    /// Caret position as of the last frame, for finding the current word.
    caret: usize,
}

impl Default for FilterBar {
    fn default() -> Self {
        FilterBar {
            text: String::new(),
            status: Status::Empty,
            applied: None,
            suggestions: Vec::new(),
            replace: (0, 0),
            highlighted: 0,
            focus_requested: false,
            caret: 0,
        }
    }
}

/// What the bar asks the application to do after a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    /// The applied filter changed; the view must be rebuilt.
    FilterChanged,
}

impl FilterBar {
    /// Ask for keyboard focus (Ctrl+K).
    pub fn request_focus(&mut self) {
        self.focus_requested = true;
    }

    /// Re-check the text without applying it.
    fn recheck(&mut self) {
        self.status = if self.text.trim().is_empty() {
            Status::Empty
        } else {
            match compile(&self.text) {
                Ok(_) => Status::Ready,
                Err(e) => Status::Invalid(e),
            }
        };
    }

    /// Compile and apply, if it compiles.
    fn apply(&mut self) -> Action {
        if self.text.trim().is_empty() {
            let had = self.applied.take().is_some();
            self.status = Status::Empty;
            return if had {
                Action::FilterChanged
            } else {
                Action::None
            };
        }
        match compile(&self.text) {
            Ok(test) => {
                self.applied = Some(test);
                self.status = Status::Applied;
                Action::FilterChanged
            }
            Err(e) => {
                self.status = Status::Invalid(e);
                Action::None
            }
        }
    }

    fn clear(&mut self) -> Action {
        self.text.clear();
        self.suggestions.clear();
        self.recheck();
        if self.applied.take().is_some() {
            Action::FilterChanged
        } else {
            Action::None
        }
    }

    /// Replace the word under the caret with a suggestion.
    fn accept(&mut self, index: usize) {
        let Some(def) = self.suggestions.get(index) else {
            return;
        };
        let (start, end) = self.replace;
        if start <= end && end <= self.text.len() {
            self.text.replace_range(start..end, def.abbrev);
            self.caret = start + def.abbrev.len();
        }
        self.suggestions.clear();
        self.recheck();
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Action {
        let mut action = Action::None;
        let (tint, hint) = match &self.status {
            Status::Empty => (None, String::new()),
            // Wireshark's colours: green applied, yellow valid-but-risky or
            // not yet applied, red invalid.
            Status::Applied => (Some(egui::Color32::from_rgb(34, 84, 46)), String::new()),
            Status::Ready => (
                Some(egui::Color32::from_rgb(110, 96, 24)),
                "press Enter to apply".to_string(),
            ),
            Status::Invalid(e) => (
                Some(egui::Color32::from_rgb(110, 32, 32)),
                format!("column {}: {}", e.column + 1, e.message),
            ),
        };

        ui.horizontal(|ui| {
            ui.label("Display filter:");
            // egui 0.29 has no background colour on TextEdit, so tint the
            // frame the field is drawn in.
            if let Some(tint) = tint {
                ui.visuals_mut().extreme_bg_color = tint;
            }
            let edit = egui::TextEdit::singleline(&mut self.text)
                .hint_text("e.g. tcp.port == 443 && ip.addr == 10.0.0.0/8")
                .desired_width((ui.available_width() - 190.0).max(120.0))
                .id_salt("display-filter");
            let output = edit.show(ui);
            let resp = output.response;
            if self.focus_requested {
                self.focus_requested = false;
                resp.request_focus();
            }
            if let Some(cursor) = output.state.cursor.char_range() {
                // Byte offset of the caret, which the completer wants.
                let chars = cursor.primary.index;
                self.caret = self
                    .text
                    .char_indices()
                    .nth(chars)
                    .map_or(self.text.len(), |(i, _)| i);
            }
            if resp.changed() {
                self.recheck();
                let (start, end, s) = complete::suggest_at(&self.text, self.caret, 8);
                self.replace = (start, end);
                self.suggestions = s;
                self.highlighted = 0;
            }
            let has_focus = resp.has_focus();
            if has_focus {
                let (enter, esc, tab, up, down) = ui.input(|i| {
                    (
                        i.key_pressed(egui::Key::Enter),
                        i.key_pressed(egui::Key::Escape),
                        i.key_pressed(egui::Key::Tab),
                        i.key_pressed(egui::Key::ArrowUp),
                        i.key_pressed(egui::Key::ArrowDown),
                    )
                });
                if !self.suggestions.is_empty() {
                    if down {
                        self.highlighted = (self.highlighted + 1) % self.suggestions.len();
                    }
                    if up {
                        self.highlighted = (self.highlighted + self.suggestions.len() - 1)
                            % self.suggestions.len();
                    }
                    if tab || (enter && !self.suggestions.is_empty() && self.highlighted > 0) {
                        self.accept(self.highlighted);
                        return;
                    }
                }
                if enter {
                    self.suggestions.clear();
                    action = self.apply();
                }
                if esc {
                    if self.suggestions.is_empty() {
                        action = self.clear();
                    } else {
                        self.suggestions.clear();
                    }
                }
            } else if !self.suggestions.is_empty() {
                self.suggestions.clear();
            }

            let can_apply = !matches!(self.status, Status::Invalid(_) | Status::Empty);
            if ui
                .add_enabled(can_apply, egui::Button::new("Apply"))
                .clicked()
            {
                action = self.apply();
            }
            if ui
                .add_enabled(!self.text.is_empty(), egui::Button::new("Clear"))
                .clicked()
            {
                action = self.clear();
            }
        });

        if !hint.is_empty() {
            let colour = match &self.status {
                Status::Invalid(_) => egui::Color32::from_rgb(230, 120, 120),
                _ => egui::Color32::from_rgb(200, 180, 90),
            };
            ui.horizontal(|ui| {
                ui.add_space(88.0);
                ui.colored_label(colour, hint);
            });
        }
        if !self.suggestions.is_empty() {
            let mut accept = None;
            ui.horizontal_wrapped(|ui| {
                ui.add_space(88.0);
                for (i, def) in self.suggestions.iter().enumerate() {
                    let label = egui::RichText::new(def.abbrev).monospace();
                    let label = if i == self.highlighted {
                        label.strong()
                    } else {
                        label
                    };
                    if ui
                        .selectable_label(i == self.highlighted, label)
                        .on_hover_text(def.name)
                        .clicked()
                    {
                        accept = Some(i);
                    }
                }
            });
            if let Some(i) = accept {
                self.accept(i);
            }
        }
        action
    }
}
