//! Stage 3: the UI thread. It renders from a store snapshot and issues
//! start/stop; it never parses and never blocks on the capture pipeline.

pub mod colour_rules;
mod detail_tree;
mod device_panel;
mod filter_bar;
pub mod find;
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
use crate::dissect::Frame;
use crate::store::{Limits, Store, StoreStats, View};
use detail_tree::TreeState;
use hex_pane::HexState;
use packet_list::{ListState, Nav};

/// Which pane keyboard navigation applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    List,
    Tree,
}

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
    /// The rows the packet list shows: every frame, or those a display
    /// filter selects.
    view: View,
    filter: filter_bar::FilterBar,
    /// Compiled colour rules, applied per displayed row.
    colours: colour_rules::Rules,
    find: find::FindBar,
    store_stats: StoreStats,
    list: ListState,
    tree: TreeState,
    hex: HexState,
    focus: Focus,
    show_first_run: bool,
    show_devices: bool,
    show_settings: bool,
    show_colour_rules: bool,
    /// CPU time of the last `update` call.
    ui_frame_time: Duration,
}

impl NetscopeApp {
    pub fn new(_cc: &eframe::CreationContext<'_>, opts: Options) -> Self {
        let (config, config_error) = Config::load();
        let preflight = capture::preflight::run();
        let colours = colour_rules::Rules::new(config.colour_rules.clone());
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
            view: View::all(store.snapshot()),
            filter: filter_bar::FilterBar::default(),
            colours,
            find: find::FindBar::default(),
            store_stats: StoreStats::default(),
            store,
            show_devices: true,
            show_settings: false,
            show_colour_rules: false,
            tree: TreeState::default(),
            hex: HexState::default(),
            focus: Focus::List,
            ui_frame_time: Duration::ZERO,
        };
        app.refresh_devices();
        if opts.synthetic > 0 {
            app.preload_synthetic(opts.synthetic);
        }
        app
    }

    /// Developer aid: fill the store with generated Ethernet/IPv4/TCP frames.
    fn preload_synthetic(&mut self, count: u64) {
        let mut batch = Vec::with_capacity(1024);
        let mut reassembly = crate::dissect::Reassembly::new();
        for i in 0..count {
            batch.push(Arc::new(crate::dissect::dissect(
                netscope_ffi::LinkType::ETHERNET,
                (i + 1) as u32,
                crate::synthetic::raw_frame(i),
                &mut reassembly,
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

    fn refresh_view(&mut self) {
        if self.store.version() != self.view.version() {
            self.rebuild_view();
            self.store_stats = self.store.stats();
        }
    }

    /// Rebuild the displayed rows from the store and the applied filter.
    fn rebuild_view(&mut self) {
        self.view = View::build(self.store.snapshot(), self.filter.applied.as_ref());
    }

    /// The frame currently selected in the list, if still held.
    fn selected_frame(&self) -> Option<Arc<Frame>> {
        self.list
            .selected
            .and_then(|n| self.view.row_of(n))
            .and_then(|r| self.view.get(r))
            .cloned()
    }

    /// Move the selection to the next row satisfying the find query.
    fn run_find(&mut self, direction: find::Direction) {
        let Ok(query) = self.find.compiled() else {
            return;
        };
        let from = self.list.selected.and_then(|n| self.view.row_of(n));
        match find::search(&self.view, from, direction, &query) {
            Some(row) => {
                self.list.follow = false;
                self.list.selected = self.view.get(row).map(|f| f.number);
                self.list.scroll_to = Some((row, egui::Align::Center));
                self.focus = Focus::List;
                self.find.report(true);
            }
            None => self.find.report(false),
        }
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        if self.show_first_run {
            return;
        }
        // Ctrl+K focuses the filter bar from anywhere, Ctrl+F the find bar.
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::K)) {
            self.filter.request_focus();
            return;
        }
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::F)) {
            self.find.open();
            return;
        }
        // F3 repeats the last find without returning to the bar.
        if self.find.open && ctx.input(|i| i.key_pressed(egui::Key::F3)) {
            let backward = ctx.input(|i| i.modifiers.shift);
            self.run_find(if backward {
                find::Direction::Backward
            } else {
                find::Direction::Forward
            });
            return;
        }
        // The rest go to the panes only when no text field owns the keyboard.
        if ctx.memory(|m| m.focused().is_some()) {
            return;
        }
        let page = 20;
        let (up, down, page_up, page_down, home, end, enter) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::ArrowUp),
                i.key_pressed(egui::Key::ArrowDown),
                i.key_pressed(egui::Key::PageUp),
                i.key_pressed(egui::Key::PageDown),
                i.key_pressed(egui::Key::Home),
                i.key_pressed(egui::Key::End),
                i.key_pressed(egui::Key::Enter),
            )
        });
        let frame = self.selected_frame();
        if enter {
            if let Some(f) = &frame {
                self.tree.toggle_selected(f);
            }
            return;
        }
        match (self.focus, frame.as_deref()) {
            (Focus::Tree, Some(f)) => {
                if up {
                    self.tree.navigate(f, -1);
                } else if down {
                    self.tree.navigate(f, 1);
                } else if page_up {
                    self.tree.navigate(f, -page);
                } else if page_down {
                    self.tree.navigate(f, page);
                }
            }
            _ => {
                let nav = if up {
                    Some(Nav::Up(1))
                } else if down {
                    Some(Nav::Down(1))
                } else if page_up {
                    Some(Nav::Up(page as usize))
                } else if page_down {
                    Some(Nav::Down(page as usize))
                } else if home {
                    Some(Nav::Home)
                } else if end {
                    Some(Nav::End)
                } else {
                    None
                };
                if let Some(nav) = nav {
                    self.list.navigate(nav, &self.view);
                }
            }
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Edit", |ui| {
                if ui.button("Find packet…	Ctrl+F").clicked() {
                    self.find.open();
                    ui.close_menu();
                }
                if ui
                    .add_enabled(self.find.open, egui::Button::new("Find next	F3"))
                    .clicked()
                {
                    self.run_find(find::Direction::Forward);
                    ui.close_menu();
                }
                if ui
                    .add_enabled(self.find.open, egui::Button::new("Find previous	Shift+F3"))
                    .clicked()
                {
                    self.run_find(find::Direction::Backward);
                    ui.close_menu();
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
                ui.separator();
                if ui
                    .checkbox(&mut self.config.colouring, "Colourise packet list")
                    .changed()
                {
                    self.persist_config();
                }
                if ui.button("Colouring rules…").clicked() {
                    self.show_colour_rules = true;
                    ui.close_menu();
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
            if self.view.is_filtered() {
                ui.label(format!(
                    "Displayed: {} of {}",
                    self.view.len(),
                    self.view.total()
                ));
            } else {
                ui.label(format!("Frames: {}", st.frames));
            }
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
        self.refresh_view();
        self.handle_keys(ctx);
        let mut find_request = None;

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
                if self.filter.show(ui) == filter_bar::Action::FilterChanged {
                    self.rebuild_view();
                    // Keep the selection if it is still displayed, else move
                    // to the nearest frame after it.
                    if let Some(n) = self.list.selected {
                        if self.view.row_of(n).is_none() {
                            self.list.selected = self
                                .view
                                .row_at_or_after(n)
                                .and_then(|r| self.view.get(r))
                                .map(|f| f.number);
                        }
                    }
                }
                if self.find.open {
                    ui.add_space(4.0);
                    match self.find.show(ui) {
                        find::Action::Find(d) => find_request = Some(d),
                        find::Action::Close => self.find.close(),
                        find::Action::None => {}
                    }
                }
                ui.add_space(4.0);
            });
        });
        if let Some(d) = find_request {
            self.run_find(d);
        }
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.status_bar(ui);
        });
        let frame = self.selected_frame();
        // The selected tree node drives the hex highlight.
        self.hex.highlight = frame.as_ref().and_then(|f| {
            self.tree
                .selected
                .and_then(|i| f.tree.get(i))
                .filter(|n| !n.range().is_empty())
                .map(|n| (n.source(), n.range()))
        });
        let mut hex_click = None;
        egui::TopBottomPanel::bottom("hex")
            .resizable(true)
            .default_height(200.0)
            .min_height(60.0)
            .show(ctx, |ui| {
                hex_click = hex_pane::show(ui, frame.as_deref(), &mut self.hex);
            });
        egui::TopBottomPanel::bottom("detail")
            .resizable(true)
            .default_height(220.0)
            .min_height(60.0)
            .show(ctx, |ui| {
                if detail_tree::show(ui, frame.as_deref(), &mut self.tree) {
                    self.focus = Focus::Tree;
                }
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!self.show_first_run, |ui| {
                let before = self.list.selected;
                let colours = self.config.colouring.then_some(&self.colours);
                packet_list::show(ui, &self.view, self.config.time_mode, colours, &mut self.list);
                if self.list.selected != before {
                    self.focus = Focus::List;
                }
            });
        });
        // Clicking a byte selects the innermost node covering it.
        if let (Some((source, offset)), Some(f)) = (hex_click, frame.as_deref()) {
            if let Some(node) = f.tree.innermost_at(source, offset) {
                self.tree.select_and_reveal(f, node.index());
                self.focus = Focus::Tree;
            }
        }

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
        if self.show_colour_rules
            && colour_rules::editor(ctx, &mut self.show_colour_rules, &mut self.colours)
        {
            self.config.colour_rules = self.colours.rules().to_vec();
            self.persist_config();
        }
        self.ui_frame_time = frame_start.elapsed();
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_capture();
    }
}
