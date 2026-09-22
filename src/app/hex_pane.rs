//! Hex + ASCII dump of the selected frame, 16 bytes per row, virtualised.
//! Highlights the byte range of the selected tree node; clicking a byte
//! reports its offset so the caller can select the innermost covering node.

use std::ops::Range;

use crate::dissect::{Frame, SourceId};

pub const BYTES_PER_ROW: usize = 16;
const HEX_COL: usize = 10;
const ASCII_COL: usize = 60;

/// Render one dump line: `offset  hex bytes  ascii`.
pub fn line(bytes: &[u8], row: usize) -> String {
    let start = row * BYTES_PER_ROW;
    let chunk = bytes.get(start..).unwrap_or(&[]);
    let chunk = &chunk[..chunk.len().min(BYTES_PER_ROW)];
    let mut hex = String::with_capacity(BYTES_PER_ROW * 3 + 1);
    for (i, b) in chunk.iter().enumerate() {
        if i == 8 {
            hex.push(' ');
        }
        hex.push_str(&format!("{b:02x} "));
    }
    let ascii: String = chunk
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{start:08x}  {hex:<49} {ascii}")
}

/// Character column where byte `i` of a row starts in the hex area.
fn hex_col(i: usize) -> usize {
    HEX_COL + 3 * i + usize::from(i >= 8)
}

/// Map a character column back to a byte index within the row.
fn byte_at_col(col: usize) -> Option<usize> {
    if (ASCII_COL..ASCII_COL + BYTES_PER_ROW).contains(&col) {
        return Some(col - ASCII_COL);
    }
    if col < HEX_COL {
        return None;
    }
    let rel = col - HEX_COL;
    // The extra space after byte 7 shifts the second half by one column.
    let rel = if rel >= 25 { rel - 1 } else { rel };
    let i = rel / 3;
    (i < BYTES_PER_ROW && rel % 3 < 2).then_some(i)
}

#[derive(Debug, Default)]
pub struct HexState {
    /// Which data source is shown (0 = frame bytes).
    pub source: SourceId,
    /// Bytes to highlight, in `source`.
    pub highlight: Option<(SourceId, Range<usize>)>,
}

/// Draws the pane. Returns the (source, offset) of a clicked byte.
pub fn show(
    ui: &mut egui::Ui,
    frame: Option<&Frame>,
    state: &mut HexState,
) -> Option<(SourceId, usize)> {
    let Some(frame) = frame else {
        ui.weak("Select a packet to see its bytes.");
        return None;
    };
    if !frame.extra_sources.is_empty() {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut state.source, 0, "Frame");
            for i in 0..frame.extra_sources.len() {
                let id = (i + 1) as SourceId;
                ui.selectable_value(&mut state.source, id, format!("Reassembled #{id}"));
            }
        });
    } else {
        state.source = 0;
    }
    let Some(bytes) = frame.source(state.source) else {
        state.source = 0;
        return None;
    };
    let highlight = state
        .highlight
        .as_ref()
        .filter(|(s, _)| *s == state.source)
        .map(|(_, r)| r.clone());

    let rows = bytes.len().div_ceil(BYTES_PER_ROW);
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
    let char_w = ui.fonts(|f| f.glyph_width(&font, '0'));
    let hl_color = ui.visuals().selection.bg_fill;
    let mut clicked = None;
    let scroll_to = highlight.as_ref().map(|r| r.start / BYTES_PER_ROW);
    egui::ScrollArea::both()
        .id_salt("hex")
        .auto_shrink([false, false])
        .show_rows(ui, row_height, rows, |ui, range| {
            for r in range {
                let text = line(bytes, r);
                let (rect, resp) = ui.allocate_exact_size(
                    egui::vec2((ASCII_COL + BYTES_PER_ROW) as f32 * char_w, row_height),
                    egui::Sense::click(),
                );
                if let Some(hl) = &highlight {
                    let row_start = r * BYTES_PER_ROW;
                    let lo = hl.start.max(row_start);
                    let hi = hl.end.min(row_start + BYTES_PER_ROW);
                    if lo < hi {
                        let (a, b) = (lo - row_start, hi - row_start);
                        let x = |col: usize| rect.left() + col as f32 * char_w;
                        let hex_rect = egui::Rect::from_min_max(
                            egui::pos2(x(hex_col(a)), rect.top()),
                            egui::pos2(x(hex_col(b - 1) + 2), rect.bottom()),
                        );
                        let ascii_rect = egui::Rect::from_min_max(
                            egui::pos2(x(ASCII_COL + a), rect.top()),
                            egui::pos2(x(ASCII_COL + b), rect.bottom()),
                        );
                        ui.painter().rect_filled(hex_rect, 2.0, hl_color);
                        ui.painter().rect_filled(ascii_rect, 2.0, hl_color);
                    }
                }
                ui.painter().text(
                    rect.left_top(),
                    egui::Align2::LEFT_TOP,
                    &text,
                    font.clone(),
                    ui.visuals().text_color(),
                );
                if resp.clicked() {
                    if let Some(pos) = resp.interact_pointer_pos() {
                        let col = ((pos.x - rect.left()) / char_w).floor().max(0.0) as usize;
                        if let Some(i) = byte_at_col(col) {
                            let off = r * BYTES_PER_ROW + i;
                            if off < bytes.len() {
                                clicked = Some((state.source, off));
                            }
                        }
                    }
                }
                if scroll_to == Some(r) {
                    resp.scroll_to_me(Some(egui::Align::Center));
                }
            }
        });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_full_and_partial_rows() {
        let bytes: Vec<u8> = (0u8..20).collect();
        assert_eq!(
            line(&bytes, 0),
            "00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................"
        );
        assert_eq!(
            line(&bytes, 1),
            "00000010  10 11 12 13                                       ...."
        );
        assert_eq!(
            line(&bytes, 5),
            "00000050                                                    "
        );
    }

    #[test]
    fn printable_ascii_is_shown() {
        let l = line(b"Hello, world!!!!", 0);
        assert!(l.ends_with("Hello, world!!!!"), "{l}");
    }

    #[test]
    fn columns_map_to_bytes_and_back() {
        for i in 0..BYTES_PER_ROW {
            assert_eq!(byte_at_col(hex_col(i)), Some(i), "byte {i}");
            assert_eq!(
                byte_at_col(hex_col(i) + 1),
                Some(i),
                "byte {i} second digit"
            );
            assert_eq!(byte_at_col(ASCII_COL + i), Some(i), "ascii {i}");
        }
        assert_eq!(byte_at_col(hex_col(7) + 2), None); // the space after a byte
        assert_eq!(byte_at_col(0), None);
        assert_eq!(byte_at_col(ASCII_COL + 16), None);
        // The line text really puts byte i where hex_col says.
        let l = line(&[0xaa; 16], 0);
        for i in 0..16 {
            assert_eq!(&l[hex_col(i)..hex_col(i) + 2], "aa");
        }
    }
}
