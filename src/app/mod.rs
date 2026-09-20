//! Stage 3: the UI thread. It renders state and issues start/stop; it never
//! parses and never blocks on the capture pipeline.

mod device_panel;
mod first_run;

use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;

use crate::capture::{self, Capture, CaptureConfig, Device, Preflight, RawFrame, StatsSnapshot};
use crate::config::Config;

const REPAINT_INTERVAL: Duration = Duration::from_millis(250);

/// Phase 0 consumer: drains the channel so the capture thread has somewhere to
/// put frames. Replaced by the dissection worker in Phase 1.
struct Sink {
    join: Option<JoinHandle<u64>>,
}

impl Sink {
    fn spawn(rx: Receiver<RawFrame>) -> Sink {
        let join = thread::Builder::new()
            .name("netscope-sink".into())
            .spawn(move || rx.iter().count() as u64)
            .ok();
        Sink { join }
    }
}

/// Smoothed frames-per-second and bytes-per-second, sampled by the UI.
#[derive(Debug)]
struct RateMeter {
    last_sample: Instant,
    last_frames: u64,
    last_bytes: u64,
    frames_per_sec: f64,
    bytes_per_sec: f64,
}

impl RateMeter {
    fn new() -> Self {
        Self {
            last_sample: Instant::now(),
            last_frames: 0,
            last_bytes: 0,
            frames_per_sec: 0.0,
            bytes_per_sec: 0.0,
        }
    }

    fn update(&mut self, s: &StatsSnapshot) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_sample).as_secs_f64();
        if dt < 0.5 {
            return;
        }
        self.frames_per_sec = s.received.saturating_sub(self.last_frames) as f64 / dt;
        self.bytes_per_sec = s.bytes.saturating_sub(self.last_bytes) as f64 / dt;
        self.last_frames = s.received;
        self.last_bytes = s.bytes;
        self.last_sample = now;
    }
}

/// Launch the UI. Blocks until the window closes.
pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 640.0])
            .with_min_inner_size([640.0, 400.0])
            .with_title("netscope"),
        ..Default::default()
    };
    eframe::run_native(
        "netscope",
        options,
        Box::new(|cc| Ok(Box::new(NetscopeApp::new(cc)))),
    )
}

pub struct NetscopeApp {
    config: Config,
    config_error: Option<String>,
    preflight: Preflight,
    devices: Vec<Device>,
    device_error: Option<String>,
    selected: Option<usize>,
    capture: Option<Capture>,
    sink: Option<Sink>,
    capture_error: Option<String>,
    rate: RateMeter,
    last_stats: StatsSnapshot,
    show_first_run: bool,
}

impl NetscopeApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (config, config_error) = Config::load();
        let preflight = capture::preflight::run();
        let mut app = Self {
            show_first_run: !config.first_run_acknowledged,
            config,
            config_error,
            preflight,
            devices: Vec::new(),
            device_error: None,
            selected: None,
            capture: None,
            sink: None,
            capture_error: None,
            rate: RateMeter::new(),
            last_stats: StatsSnapshot::default(),
        };
        app.refresh_devices();
        app
    }

    fn refresh_devices(&mut self) {
        if self.preflight.is_fail() {
            self.devices.clear();
            self.device_error = Some("Fix the problem above, then click Refresh.".into());
            return;
        }
        match capture::device::enumerate() {
            Ok(devs) => {
                self.selected = self
                    .config
                    .last_device
                    .as_deref()
                    .and_then(|name| devs.iter().position(|d| d.info.name == name))
                    .or(if devs.is_empty() { None } else { Some(0) });
                self.devices = devs;
                self.device_error = None;
            }
            Err(e) => {
                self.devices.clear();
                self.device_error = Some(format!("Could not list interfaces: {e}"));
            }
        }
    }

    fn is_capturing(&self) -> bool {
        self.capture.as_ref().is_some_and(Capture::is_running)
    }

    fn start_capture(&mut self) {
        let Some(dev) = self.selected.and_then(|i| self.devices.get(i)) else {
            self.capture_error = Some("Select an interface first.".into());
            return;
        };
        let bpf = self.config.capture_filter.trim();
        let cfg = CaptureConfig {
            device: dev.info.name.clone(),
            snaplen: self.config.snaplen,
            promiscuous: self.config.promiscuous,
            bpf: (!bpf.is_empty()).then(|| bpf.to_string()),
            ..CaptureConfig::default()
        };
        match Capture::start(cfg) {
            Ok((cap, rx)) => {
                self.capture_error = None;
                self.sink = Some(Sink::spawn(rx));
                self.capture = Some(cap);
                self.rate = RateMeter::new();
                self.config.last_device = Some(dev.info.name.clone());
                self.persist_config();
            }
            Err(e) => self.capture_error = Some(format!("Could not start capture: {e}")),
        }
    }

    fn stop_capture(&mut self) {
        if let Some(mut cap) = self.capture.take() {
            cap.stop();
            self.last_stats = cap.stats();
            if let Some(err) = cap.error() {
                self.capture_error = Some(format!("Capture ended: {err}"));
            }
        }
        if let Some(mut sink) = self.sink.take() {
            if let Some(join) = sink.join.take() {
                let _ = join.join();
            }
        }
    }

    fn persist_config(&mut self) {
        if let Err(e) = self.config.save() {
            self.config_error = Some(format!("Could not save config: {e}"));
        }
    }

    fn preflight_banner(&self, ui: &mut egui::Ui) {
        let (fill, text) = match &self.preflight {
            Preflight::Ok { detail } => (
                egui::Color32::from_rgb(34, 84, 46),
                format!("Capture ready — {detail}"),
            ),
            Preflight::Warn { message } => (egui::Color32::from_rgb(120, 90, 20), message.clone()),
            Preflight::Fail { message } => (egui::Color32::from_rgb(120, 30, 30), message.clone()),
        };
        egui::Frame::none()
            .fill(fill)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(egui::RichText::new(text).color(egui::Color32::WHITE)).wrap(),
                );
            });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let capturing = self.is_capturing();
        ui.horizontal(|ui| {
            if capturing {
                if ui.button("⏹ Stop").clicked() {
                    self.stop_capture();
                }
            } else {
                let can_start = !self.preflight.is_fail() && self.selected.is_some();
                if ui
                    .add_enabled(can_start, egui::Button::new("▶ Start"))
                    .clicked()
                {
                    self.start_capture();
                }
            }
            if ui
                .add_enabled(!capturing, egui::Button::new("⟳ Refresh"))
                .clicked()
            {
                self.preflight = capture::preflight::run();
                self.refresh_devices();
            }
            ui.separator();
            ui.label("Capture filter (BPF):");
            let edit = ui.add_enabled(
                !capturing,
                egui::TextEdit::singleline(&mut self.config.capture_filter)
                    .hint_text("e.g. tcp port 443")
                    .desired_width(260.0),
            );
            if edit.lost_focus() {
                self.persist_config();
            }
            if ui
                .add_enabled(
                    !capturing,
                    egui::Checkbox::new(&mut self.config.promiscuous, "Promiscuous"),
                )
                .changed()
            {
                self.persist_config();
            }
        });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            match &self.capture {
                Some(cap) => {
                    let dev = self
                        .devices
                        .iter()
                        .find(|d| d.info.name == cap.device())
                        .map(Device::display_name)
                        .unwrap_or_else(|| cap.device());
                    let lt = cap.link_type();
                    ui.label(format!(
                        "{} {} · link type {} ({}, DLT {})",
                        if cap.is_running() {
                            "Capturing on"
                        } else {
                            "Stopped:"
                        },
                        dev,
                        lt.name(),
                        lt.description(),
                        lt.0
                    ));
                }
                None => {
                    ui.label("Idle");
                }
            }
            ui.separator();
            let s = &self.last_stats;
            ui.label(format!("Frames: {}", s.received));
            ui.label(format!("Bytes: {}", s.bytes));
            ui.label(format!(
                "Rate: {:.0} fps / {:.1} KB/s",
                self.rate.frames_per_sec,
                self.rate.bytes_per_sec / 1024.0
            ));
            let dropped = s.dropped_channel + s.kernel_dropped + s.kernel_if_dropped;
            let drop_text = format!(
                "Dropped: {dropped} (chan {} / drv {} / if {})",
                s.dropped_channel, s.kernel_dropped, s.kernel_if_dropped
            );
            if dropped > 0 {
                ui.colored_label(egui::Color32::from_rgb(230, 150, 60), drop_text);
            } else {
                ui.label(drop_text);
            }
            if let Some(err) = &self.capture_error {
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
            }
        });
    }
}

impl eframe::App for NetscopeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.show_first_run && first_run::show(ctx) {
            self.show_first_run = false;
            self.config.first_run_acknowledged = true;
            self.persist_config();
        }

        if let Some(cap) = &self.capture {
            self.last_stats = cap.stats();
            self.rate.update(&self.last_stats);
            if !cap.is_running() && self.capture_error.is_none() {
                self.capture_error = cap.error().map(|e| format!("Capture ended: {e}"));
            }
            ctx.request_repaint_after(REPAINT_INTERVAL);
        }

        egui::TopBottomPanel::top("banner").show(ctx, |ui| {
            ui.add_enabled_ui(!self.show_first_run, |ui| {
                self.preflight_banner(ui);
                if let Some(err) = &self.config_error {
                    ui.colored_label(egui::Color32::from_rgb(230, 150, 60), err);
                }
                ui.add_space(4.0);
                self.toolbar(ui);
                ui.add_space(4.0);
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.status_bar(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!self.show_first_run, |ui| {
                ui.heading("Interfaces");
                let capturing = self.is_capturing();
                let start = device_panel::show(
                    ui,
                    &self.devices,
                    self.device_error.as_deref(),
                    &mut self.selected,
                    !capturing,
                );
                if start && !capturing && !self.preflight.is_fail() {
                    self.start_capture();
                }
            });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_capture();
    }
}
