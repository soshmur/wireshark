//! Stage 3: the UI thread. It renders from a store snapshot and issues
//! start/stop; it never parses and never blocks on the capture pipeline.

mod device_panel;
mod first_run;
mod hex_pane;
mod packet_list;
mod settings;
pub mod timefmt;

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::capture::{self, Capture, CaptureConfig, Device, Preflight, StatsSnapshot};
use crate::config::{Config, TimeMode};
use crate::dissect::worker::Worker;
use crate::store::{Limits, Snapshot, Store, StoreStats};
use packet_list::{ListState, Nav};

const REPAINT_INTERVAL: Duration = Duration::from_millis(100);

/// Launch-time options (developer flags).
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Preload this many generated frames into the store.
    pub synthetic: u64,
}

/// Launch the UI. Blocks until the window closes.
pub fn run(opts: Options) -> eframe::Result<()> {
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
        Box::new(move |cc| Ok(Box::new(NetscopeApp::new(cc, opts)))),
    )
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

pub struct NetscopeApp {
    config: Config,
    config_error: Option<String>,
    preflight: Preflight,
    devices: Vec<Device>,
    device_error: Option<String>,
    selected_device: Option<usize>,
    capture: Option<Capture>,
    worker: Option<Worker>,
    capture_error: Option<String>,
    rate: RateMeter,
    last_stats: StatsSnapshot,
    store: Arc<Store>,
    snapshot: Snapshot,
    store_stats: StoreStats,
    list: ListState,
    show_first_run: bool,
    show_devices: bool,
    show_settings: bool,
    /// CPU time of the last `update` call.
    ui_frame_time: Duration,
}

impl NetscopeApp {
    pub fn new(_cc: &eframe::CreationContext<'_>, opts: Options) -> Self {
        let (config, config_error) = Config::load();
        let preflight = capture::preflight::run();
        let store = Store::new(Limits {
            max_frames: config.ring_max_frames,
            max_bytes: config.ring_max_bytes,
        });
        let mut app = Self {
            show_first_run: !config.first_run_acknowledged,
            list: ListState {
                follow: config.auto_scroll,
                ..ListState::default()
            },
            config,
            config_error,
            preflight,
            devices: Vec::new(),
            device_error: None,
            selected_device: None,
            capture: None,
            worker: None,
            capture_error: None,
            rate: RateMeter::new(),
            last_stats: StatsSnapshot::default(),
            snapshot: store.snapshot(),
            store_stats: StoreStats::default(),
            store,
            show_devices: true,
            show_settings: false,
            ui_frame_time: Duration::ZERO,
        };
        app.refresh_devices();
        if opts.synthetic > 0 {
            app.preload_synthetic(opts.synthetic);
        }
        app
    }

    /// Developer aid: fill the store with generated Ethernet-shaped frames.
    fn preload_synthetic(&mut self, count: u64) {
        let mut batch = Vec::with_capacity(1024);
        for i in 0..count {
            let len = 60 + (i % 1400) as usize;
            let mut bytes = vec![0u8; len];
            bytes[..6].copy_from_slice(&[0xff; 6]);
            bytes[6..12].copy_from_slice(&[
                0,
                0x1c,
                0x42,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
            ]);
            bytes[12..14].copy_from_slice(&[0x08, 0x00]);
            let raw = crate::capture::RawFrame {
                ts: crate::capture::Timestamp {
                    secs: 1_700_000_000 + (i / 1000) as i64,
                    nanos: ((i % 1000) * 1_000_000) as u32,
                },
                caplen: len as u32,
                orig_len: len as u32,
                bytes: Arc::from(bytes),
            };
            batch.push(Arc::new(crate::dissect::dissect(
                netscope_ffi::LinkType::ETHERNET,
                (i + 1) as u32,
                raw,
            )));
            if batch.len() == 1024 {
                self.store
                    .append(std::mem::replace(&mut batch, Vec::with_capacity(1024)));
            }
        }
        self.store.append(batch);
        self.show_devices = false;
        self.list.follow = false;
    }

    fn refresh_devices(&mut self) {
        if self.preflight.is_fail() {
            self.devices.clear();
            self.device_error = Some("Fix the problem above, then click Refresh.".into());
            return;
        }
        match capture::device::enumerate() {
            Ok(devs) => {
                self.selected_device = self
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
        let Some(dev) = self.selected_device.and_then(|i| self.devices.get(i)) else {
            self.capture_error = Some("Select an interface first.".into());
            return;
        };
        let device_name = dev.info.name.clone();
        let bpf = self.config.capture_filter.trim();
        let cfg = CaptureConfig {
            device: device_name.clone(),
            snaplen: self.config.snaplen,
            promiscuous: self.config.promiscuous,
            bpf: (!bpf.is_empty()).then(|| bpf.to_string()),
            ..CaptureConfig::default()
        };
        match Capture::start(cfg) {
            Ok((cap, rx)) => {
                // A new capture replaces the previous one (Phase 5 adds save prompts).
                self.stop_capture();
                self.store.clear();
                self.list = ListState {
                    follow: self.config.auto_scroll,
                    ..ListState::default()
                };
                self.capture_error = None;
                self.worker = Some(Worker::spawn(rx, Arc::clone(&self.store), cap.link_type()));
                self.capture = Some(cap);
                self.rate = RateMeter::new();
                self.show_devices = false;
                self.config.last_device = Some(device_name);
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
            // Dropping `cap` closes the channel; the worker drains and exits.
            drop(cap);
        }
        if let Some(mut worker) = self.worker.take() {
            worker.join();
        }
        self.list.follow = false;
    }

    fn persist_config(&mut self) {
        if let Err(e) = self.config.save() {
            self.config_error = Some(format!("Could not save config: {e}"));
        }
    }

    fn apply_limits(&mut self) {
        self.store.set_limits(Limits {
            max_frames: self.config.ring_max_frames,
            max_bytes: self.config.ring_max_bytes,
        });
    }

    fn refresh_snapshot(&mut self) {
        if self.store.version() != self.snapshot.version() {
            self.snapshot = self.store.snapshot();
            self.store_stats = self.store.stats();
        }
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        // Keys go to the list only when no text field owns the keyboard.
        if ctx.memory(|m| m.focused().is_some()) || self.show_first_run {
            return;
        }
        let page = 20;
        let nav = ctx.input(|i| {
            if i.key_pressed(egui::Key::ArrowUp) {
                Some(Nav::Up(1))
            } else if i.key_pressed(egui::Key::ArrowDown) {
                Some(Nav::Down(1))
            } else if i.key_pressed(egui::Key::PageUp) {
                Some(Nav::Up(page))
            } else if i.key_pressed(egui::Key::PageDown) {
                Some(Nav::Down(page))
            } else if i.key_pressed(egui::Key::Home) {
                Some(Nav::Home)
            } else if i.key_pressed(egui::Key::End) {
                Some(Nav::End)
            } else {
                None
            }
        });
        if let Some(nav) = nav {
            self.list.navigate(nav, &self.snapshot);
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("View", |ui| {
                ui.label("Time display");
                let mut mode = self.config.time_mode;
                ui.radio_value(&mut mode, TimeMode::Absolute, "Absolute (UTC)");
                ui.radio_value(
                    &mut mode,
                    TimeMode::SinceStart,
                    "Seconds since capture start",
                );
                ui.radio_value(
                    &mut mode,
                    TimeMode::DeltaPrevious,
                    "Delta from previous packet",
                );
                if mode != self.config.time_mode {
                    self.config.time_mode = mode;
                    self.persist_config();
                }
                ui.separator();
                if ui
                    .checkbox(&mut self.config.auto_scroll, "Auto-scroll during capture")
                    .changed()
                {
                    self.list.follow = self.config.auto_scroll && self.is_capturing();
                    self.persist_config();
                }
            });
            ui.menu_button("Capture", |ui| {
                let capturing = self.is_capturing();
                if ui
                    .add_enabled(!capturing, egui::Button::new("Interfaces…"))
                    .clicked()
                {
                    self.show_devices = true;
                    ui.close_menu();
                }
                if ui
                    .add_enabled(!capturing, egui::Button::new("Options…"))
                    .clicked()
                {
                    self.show_settings = true;
                    ui.close_menu();
                }
                ui.separator();
                if capturing {
                    if ui.button("Stop").clicked() {
                        self.stop_capture();
                        ui.close_menu();
                    }
                } else if ui.button("Start").clicked() {
                    self.start_capture();
                    ui.close_menu();
                }
            });
        });
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
                let can_start = !self.preflight.is_fail() && self.selected_device.is_some();
                if ui
                    .add_enabled(can_start, egui::Button::new("▶ Start"))
                    .clicked()
                {
                    self.start_capture();
                }
            }
            if ui
                .add_enabled(!capturing, egui::Button::new("Interfaces"))
                .clicked()
            {
                self.preflight = capture::preflight::run();
                self.refresh_devices();
                self.show_devices = true;
            }
            if ui
                .add_enabled(!capturing, egui::Button::new("Options"))
                .clicked()
            {
                self.show_settings = true;
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
                        "{} {} · {} (DLT {})",
                        if cap.is_running() {
                            "Capturing on"
                        } else {
                            "Stopped:"
                        },
                        dev,
                        lt.name(),
                        lt.0
                    ));
                }
                None => {
                    ui.label("Idle");
                }
            }
            ui.separator();
            let st = &self.store_stats;
            ui.label(format!("Frames: {}", st.frames));
            if st.evicted_frames > 0 {
                ui.label(format!("Evicted: {}", st.evicted_frames));
            }
            ui.label(format!(
                "Mem: {:.1} MB",
                st.bytes as f64 / (1024.0 * 1024.0)
            ));
            ui.separator();
            let s = &self.last_stats;
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
            ui.separator();
            ui.weak(format!(
                "ui {:.1} ms",
                self.ui_frame_time.as_secs_f64() * 1000.0
            ));
            if let Some(err) = &self.capture_error {
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
            }
        });
    }

    fn devices_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_devices;
        let mut start = false;
        egui::Window::new("Interfaces")
            .open(&mut open)
            .default_size([720.0, 360.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("⟳ Refresh").clicked() {
                        self.preflight = capture::preflight::run();
                        self.refresh_devices();
                    }
                    let can_start = !self.preflight.is_fail() && self.selected_device.is_some();
                    if ui
                        .add_enabled(can_start, egui::Button::new("▶ Start"))
                        .clicked()
                    {
                        start = true;
                    }
                    ui.weak("Double-click an interface to start.");
                });
                ui.separator();
                start |= device_panel::show(
                    ui,
                    &self.devices,
                    self.device_error.as_deref(),
                    &mut self.selected_device,
                    true,
                );
            });
        self.show_devices = open;
        if start && !self.preflight.is_fail() {
            self.start_capture();
        }
    }
}

impl eframe::App for NetscopeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let frame_start = Instant::now();
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
        self.refresh_snapshot();
        self.handle_keys(ctx);

        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            ui.add_enabled_ui(!self.show_first_run, |ui| self.menu_bar(ui));
        });
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
        egui::TopBottomPanel::bottom("hex")
            .resizable(true)
            .default_height(220.0)
            .min_height(60.0)
            .show(ctx, |ui| {
                let frame = self
                    .list
                    .selected
                    .and_then(|n| self.snapshot.row_of(n))
                    .and_then(|r| self.snapshot.get(r))
                    .map(Arc::as_ref);
                hex_pane::show(ui, frame);
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!self.show_first_run, |ui| {
                packet_list::show(ui, &self.snapshot, self.config.time_mode, &mut self.list);
            });
        });

        if self.show_devices && !self.show_first_run {
            self.devices_window(ctx);
        }
        if self.show_settings {
            let capturing = self.is_capturing();
            if settings::show(ctx, &mut self.show_settings, &mut self.config, capturing) {
                self.apply_limits();
                self.persist_config();
            }
        }
        self.ui_frame_time = frame_start.elapsed();
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_capture();
    }
}
