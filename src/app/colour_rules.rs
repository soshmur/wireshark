//! Protocol colour rules: a list of display filters, each with a colour.
//! The first rule whose filter matches a frame colours its row.
//!
//! Rules are display filters, which is why they live in Phase 3 rather than
//! with the rest of the UI: the language has to exist first.

use serde::{Deserialize, Serialize};

use crate::filter::{compile, matches, FilterError, Test};
use crate::dissect::Frame;

/// A colour rule as it is stored in the config file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub filter: String,
    /// Row background, as `[r, g, b]`.
    pub background: [u8; 3],
    /// Row text colour.
    pub foreground: [u8; 3],
    pub enabled: bool,
}

impl Rule {
    fn new(
        name: &str,
        filter: &str,
        background: [u8; 3],
        foreground: [u8; 3],
    ) -> Rule {
        Rule {
            name: name.to_string(),
            filter: filter.to_string(),
            background,
            foreground,
            enabled: true,
        }
    }
}

/// The rules netscope starts with, in priority order. Chosen to read well on
/// a dark background and to distinguish the cases that matter when scanning:
/// something is wrong, something is a name lookup, something is encrypted.
pub fn defaults() -> Vec<Rule> {
    vec![
        Rule::new("Malformed", "_ws.malformed", [90, 22, 22], [255, 220, 220]),
        Rule::new(
            "Bad checksum",
            "ip.checksum.status == \"Bad\" || tcp.checksum.status == \"Bad\" \
             || udp.checksum.status == \"Bad\"",
            [86, 46, 12],
            [255, 226, 196],
        ),
        Rule::new(
            "TCP reset",
            "tcp.flags.reset == true",
            [74, 30, 46],
            [255, 210, 226],
        ),
        Rule::new(
            "TCP handshake",
            "tcp.flags.syn == true || tcp.flags.fin == true",
            [30, 54, 74],
            [206, 230, 255],
        ),
        Rule::new("ICMP", "icmp || icmpv6", [58, 40, 74], [226, 210, 255]),
        Rule::new("ARP", "arp", [28, 58, 58], [200, 240, 240]),
        Rule::new("DNS", "dns", [24, 56, 40], [206, 246, 222]),
        Rule::new("DHCP", "dhcp", [56, 52, 20], [246, 240, 200]),
        Rule::new("TLS", "tls", [36, 44, 68], [214, 222, 250]),
        Rule::new("HTTP", "http", [30, 58, 30], [210, 246, 210]),
        Rule::new("TCP", "tcp", [34, 38, 46], [222, 226, 234]),
        Rule::new("UDP", "udp", [30, 40, 50], [214, 226, 240]),
    ]
}

fn rgb([r, g, b]: [u8; 3]) -> egui::Color32 {
    egui::Color32::from_rgb(r, g, b)
}

/// A rule compiled for use, or the reason it could not be.
#[derive(Debug)]
struct Compiled {
    test: Option<Test>,
    error: Option<FilterError>,
}

/// The rule set in force, compiled once and applied per displayed row.
#[derive(Debug, Default)]
pub struct Rules {
    rules: Vec<Rule>,
    compiled: Vec<Compiled>,
}

/// The colours a row should be drawn in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowColours {
    pub background: egui::Color32,
    pub foreground: egui::Color32,
}

impl Rules {
    pub fn new(rules: Vec<Rule>) -> Rules {
        let mut out = Rules {
            rules,
            compiled: Vec::new(),
        };
        out.recompile();
        out
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn rules_mut(&mut self) -> &mut Vec<Rule> {
        &mut self.rules
    }

    /// The error for rule `index`, if its filter does not compile.
    pub fn error(&self, index: usize) -> Option<&FilterError> {
        self.compiled.get(index).and_then(|c| c.error.as_ref())
    }

    pub fn recompile(&mut self) {
        self.compiled = self
            .rules
            .iter()
            .map(|r| match compile(&r.filter) {
                Ok(test) => Compiled {
                    test: Some(test),
                    error: None,
                },
                Err(e) => Compiled {
                    test: None,
                    error: Some(e),
                },
            })
            .collect();
    }

    /// The index of the first enabled, compiling rule that matches `frame`.
    /// Rules that do not compile are skipped rather than failing the frame,
    /// so one bad rule in the list does not stop the rest colouring.
    pub fn matching(&self, frame: &Frame) -> Option<usize> {
        self.rules
            .iter()
            .zip(&self.compiled)
            .position(|(rule, compiled)| {
                rule.enabled
                    && compiled
                        .test
                        .as_ref()
                        .is_some_and(|test| matches(test, frame))
            })
    }

    /// The colours for `frame`, from the first rule that matches it.
    pub fn colours(&self, frame: &Frame) -> Option<RowColours> {
        let rule = self.rules.get(self.matching(frame)?)?;
        Some(RowColours {
            background: rgb(rule.background),
            foreground: rgb(rule.foreground),
        })
    }
}

/// Draws the rule editor. Returns `true` when a rule changed, so the caller
/// can recompile and persist.
pub fn editor(ctx: &egui::Context, open: &mut bool, rules: &mut Rules) -> bool {
    let mut changed = false;
    let mut remove = None;
    let mut move_up = None;
    egui::Window::new("Colouring rules")
        .open(open)
        .default_size([640.0, 420.0])
        .show(ctx, |ui| {
            ui.label("The first matching rule colours the row. Each rule is a display filter.");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                let count = rules.rules().len();
                for i in 0..count {
                    let error = rules.error(i).map(|e| format!("column {}: {}", e.column + 1, e.message));
                    let rule = &mut rules.rules_mut()[i];
                    ui.horizontal(|ui| {
                        changed |= ui.checkbox(&mut rule.enabled, "").changed();
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut rule.name)
                                    .desired_width(110.0)
                                    .id_salt(("rule-name", i)),
                            )
                            .changed();
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut rule.filter)
                                    .desired_width(300.0)
                                    .id_salt(("rule-filter", i)),
                            )
                            .changed();
                        let mut bg = rule.background;
                        if ui.color_edit_button_srgb(&mut bg).changed() {
                            rule.background = bg;
                            changed = true;
                        }
                        let mut fg = rule.foreground;
                        if ui.color_edit_button_srgb(&mut fg).changed() {
                            rule.foreground = fg;
                            changed = true;
                        }
                        if ui.add_enabled(i > 0, egui::Button::new("↑")).clicked() {
                            move_up = Some(i);
                        }
                        if ui.button("✖").clicked() {
                            remove = Some(i);
                        }
                    });
                    if let Some(error) = error {
                        ui.horizontal(|ui| {
                            ui.add_space(24.0);
                            ui.colored_label(egui::Color32::from_rgb(230, 120, 120), error);
                        });
                    }
                }
            });
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Add rule").clicked() {
                    rules.rules_mut().push(Rule {
                        name: "New rule".into(),
                        filter: "tcp".into(),
                        background: [40, 40, 40],
                        foreground: [230, 230, 230],
                        enabled: true,
                    });
                    changed = true;
                }
                if ui.button("Restore defaults").clicked() {
                    *rules.rules_mut() = defaults();
                    changed = true;
                }
            });
        });
    if let Some(i) = move_up {
        rules.rules_mut().swap(i - 1, i);
        changed = true;
    }
    if let Some(i) = remove {
        rules.rules_mut().remove(i);
        changed = true;
    }
    if changed {
        rules.recompile();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{dissect, Reassembly};
    use netscope_ffi::LinkType;

    fn synthetic() -> Frame {
        let mut r = Reassembly::new();
        dissect(
            LinkType::ETHERNET,
            1,
            crate::synthetic::raw_frame(5),
            &mut r,
        )
    }

    #[test]
    fn every_default_rule_compiles() {
        let rules = Rules::new(defaults());
        for (i, rule) in rules.rules().iter().enumerate() {
            assert!(
                rules.error(i).is_none(),
                "rule `{}` does not compile: {:?}",
                rule.name,
                rules.error(i)
            );
        }
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let rules = Rules::new(defaults());
        let frame = synthetic();
        // The synthetic frame is a plain PSH/ACK segment, so the TCP rule
        // applies rather than the handshake one.
        let tcp = rules
            .rules()
            .iter()
            .position(|r| r.name == "TCP")
            .expect("TCP rule");
        assert_eq!(rules.matching(&frame), Some(tcp));
        let got = rules.colours(&frame).expect("a rule should match");
        assert_eq!(got.background, rgb(rules.rules()[tcp].background));
    }

    #[test]
    fn a_disabled_or_broken_rule_is_skipped() {
        let mut rules = Rules::new(vec![
            Rule::new("Broken", "not a filter", [1, 1, 1], [2, 2, 2]),
            Rule::new("Disabled", "tcp", [3, 3, 3], [4, 4, 4]),
            Rule::new("Works", "tcp", [5, 5, 5], [6, 6, 6]),
        ]);
        rules.rules_mut()[1].enabled = false;
        rules.recompile();
        assert!(rules.error(0).is_some(), "the broken rule must report why");
        let got = rules.colours(&synthetic()).expect("a rule should match");
        assert_eq!(got.background, rgb([5, 5, 5]));
    }

    #[test]
    fn a_frame_matching_nothing_has_no_colours() {
        let rules = Rules::new(vec![Rule::new("ARP", "arp", [1, 1, 1], [2, 2, 2])]);
        assert!(rules.colours(&synthetic()).is_none());
    }
}
