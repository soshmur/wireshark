#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    netscope::app::run()
}
