//! Hex + ASCII dump of the selected frame, 16 bytes per row, virtualised.

use crate::dissect::Frame;

pub const BYTES_PER_ROW: usize = 16;

/// Render one dump line: `offset  hex bytes  |ascii|`.
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

pub fn show(ui: &mut egui::Ui, frame: Option<&Frame>) {
    let Some(frame) = frame else {
        ui.weak("Select a packet to see its bytes.");
        return;
    };
    let rows = frame.bytes.len().div_ceil(BYTES_PER_ROW);
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
    egui::ScrollArea::both()
        .id_salt("hex")
        .auto_shrink([false, false])
        .show_rows(ui, row_height, rows, |ui, range| {
            for r in range {
                ui.monospace(line(&frame.bytes, r));
            }
        });
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
}
