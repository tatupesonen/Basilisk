//! The eframe application: the main window, the detached native windows
//! (deferred viewports), and saving the preferences.
//!
//! All state lives in one [`Tool`] behind a mutex. egui paints every
//! viewport on the main thread, one after another, so each window locks the
//! tool for its frame and nothing contends; detached windows read and write
//! the same navigation and highlight state as the main window. The lock is
//! released before the detached windows are scheduled, because in an
//! embedded context (tests) egui runs their callbacks immediately.

use std::sync::Arc;

use parking_lot::Mutex;

use super::layout::Detached;
use super::overlay::Env;
use super::tool::{Opener, Prefs, Tool};
use super::{chrome, dock, options, welcome};
use crate::actions::ActionId;
use crate::design::{Tokens, theme};
use crate::views::Request;

/// The key the preferences are stored under.
pub const PREFS_KEY: &str = "basilisk-prefs";

/// The basilisk application.
#[derive(Debug)]
pub struct BasiliskApp {
    tool: Arc<Mutex<Tool>>,
    /// The detached windows' viewports, for repainting them when data
    /// arrives or the shared state changes (deferred viewports repaint
    /// only when asked).
    viewports: Arc<Mutex<Vec<egui::ViewportId>>>,
    /// The shared state last frame, to notice changes made in one window.
    seen: u64,
    /// The native-window self-test, when asked for.
    selftest: Option<super::selftest::SelfTest>,
}

/// The demo program's opener.
pub fn demo_opener() -> Opener {
    Arc::new(|| {
        crate::demo::DemoProgram::licd()
            .map(|p| Arc::new(p) as Arc<dyn crate::model::ProgramSource>)
            .map_err(|e| e.to_string())
    })
}

impl BasiliskApp {
    /// An application on `ctx` with `prefs`, opening programs with `opener`.
    pub fn new(ctx: &egui::Context, prefs: Prefs, opener: Opener) -> Self {
        theme::install_fonts(ctx);
        let mac = cfg!(target_os = "macos");
        let tool = Tool::new(prefs, opener, mac);
        let app = Self {
            tool: Arc::new(Mutex::new(tool)),
            viewports: Arc::new(Mutex::new(Vec::new())),
            seen: 0,
            selftest: None,
        };
        app.install_waker(ctx);
        app
    }

    /// The application as eframe creates it: preferences from storage,
    /// the demo program.
    pub fn from_creation_context(cc: &eframe::CreationContext<'_>) -> Self {
        let prefs = cc
            .storage
            .and_then(|s| eframe::get_value::<Prefs>(s, PREFS_KEY))
            .unwrap_or_default();
        Self::new(&cc.egui_ctx, prefs, demo_opener())
    }

    fn install_waker(&self, ctx: &egui::Context) {
        let tool = self.tool.lock();
        if let Some(ws) = &tool.ws {
            let ctx = ctx.clone();
            let viewports = Arc::clone(&self.viewports);
            ws.client.set_waker(Arc::new(move || {
                ctx.request_repaint();
                for v in viewports.lock().iter() {
                    ctx.request_repaint_of(*v);
                }
            }));
        }
    }

    /// Runs the native-window self-test (see `selftest`).
    #[must_use]
    pub fn with_selftest(mut self, st: super::selftest::SelfTest) -> Self {
        self.selftest = Some(st);
        self
    }

    /// The tool (tests and the binary).
    pub fn tool(&self) -> parking_lot::MutexGuard<'_, Tool> {
        self.tool.lock()
    }

    /// Draws one frame of the main window and schedules the detached ones.
    pub fn frame(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        // First frame on this context (eframe's, or a test harness's):
        // fonts, theme and the repaint waker belong to the context.
        let ready = egui::Id::new("bk-ui-ready");
        if !ctx.data(|d| d.get_temp::<bool>(ready).unwrap_or(false)) {
            ctx.data_mut(|d| d.insert_temp(ready, true));
            theme::install_fonts(&ctx);
            self.tool.lock().restyle();
            self.install_waker(&ctx);
            // New fonts take effect from the next frame; draw nothing now.
            ctx.request_repaint();
            return;
        }
        let had_program = self.tool.lock().ws.is_some();
        let windows: Vec<Detached> = {
            let mut tool = self.tool.lock();
            main_window(ui, &mut tool);
            match &mut tool.ws {
                Some(ws) => {
                    let origin = ctx.input(|i| i.viewport().inner_rect.map(|r| r.min));
                    ws.layout.adopt_floating(origin);
                    ws.prune();
                    ws.layout.windows.clone()
                }
                None => Vec::new(),
            }
        };
        if !had_program && self.tool.lock().ws.is_some() {
            self.install_waker(&ctx);
        }
        let ids: Vec<egui::ViewportId> = windows.iter().map(|w| viewport_id(w.id)).collect();
        // Something changed in one window (location, highlight, an edit):
        // the others redraw too.
        let seen = self.tool.lock().ws.as_ref().map_or(0, state_signature);
        if seen != self.seen {
            self.seen = seen;
            for id in &ids {
                ctx.request_repaint_of(*id);
            }
        }
        *self.viewports.lock() = ids;
        if let Some(st) = &mut self.selftest {
            st.tick(&ctx, &mut self.tool.lock());
        }
        for w in windows {
            self.detached(&ctx, &w);
        }
    }

    fn detached(&self, ctx: &egui::Context, w: &Detached) {
        let id = viewport_id(w.id);
        let mut builder = egui::ViewportBuilder::default()
            .with_title(w.title())
            .with_min_inner_size([320.0, 200.0]);
        if let Some(icon) = super::brand::icon() {
            builder = builder.with_icon(Arc::new(icon));
        }
        builder = match w.size {
            Some([x, y]) => builder.with_inner_size([x, y]),
            None => builder.with_inner_size([720.0, 560.0]),
        };
        if let Some([x, y]) = w.position {
            builder = builder.with_position([x, y]);
        }
        let tool = Arc::clone(&self.tool);
        let wid = w.id;
        let probe = self.selftest.as_ref().map(|s| Arc::clone(&s.probe));
        ctx.show_viewport_deferred(id, builder, move |ui, _class| {
            let mut tool = tool.lock();
            detached_window(ui, &mut tool, wid, id);
            if let (Some(probe), Some(ws)) = (&probe, &tool.ws) {
                probe
                    .painted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let titles = ws
                    .layout
                    .windows
                    .iter()
                    .filter(|w| w.id == wid)
                    .flat_map(Detached::tabs)
                    .filter_map(|t| ws.views.get(&t.id).map(|v| v.title(&ws.shared)))
                    .collect();
                *probe.titles.lock() = titles;
            }
        });
    }
}

/// The viewport of detached window `wid`.
pub(crate) fn viewport_id(wid: u64) -> egui::ViewportId {
    egui::ViewportId::from_hash_of(("bk-window", wid))
}

/// A number that changes whenever state shown in every window changes.
fn state_signature(ws: &super::Workspace) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ws.shared.nav.generation().hash(&mut h);
    ws.client.revision().hash(&mut h);
    ws.shared
        .highlight
        .as_ref()
        .map(|t| t.text.clone())
        .hash(&mut h);
    ws.shared.related.ranges.len().hash(&mut h);
    ws.shared
        .related
        .ranges
        .first()
        .map(|r| r.start)
        .hash(&mut h);
    ws.active.hash(&mut h);
    h.finish()
}

impl eframe::App for BasiliskApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let prefs = self.tool.lock().snapshot_prefs();
        eframe::set_value(storage, PREFS_KEY, &prefs);
    }

    fn auto_save_interval(&self) -> std::time::Duration {
        // Cmd+Q on macOS can skip the exit save (egui #7115): save often.
        std::time::Duration::from_secs(5)
    }
}

fn env<'a>(tool: &'a Tool, t: &'a Tokens, client: &'a crate::task::DataClient) -> Env<'a> {
    Env {
        tokens: t,
        keymap: &tool.prefs.keymap,
        actions: tool.action_context(),
        mac: tool.mac,
        client,
    }
}

/// Runs the overlay belonging to viewport `vp`, if any.
fn overlays(ctx: &egui::Context, tool: &mut Tool, vp: egui::ViewportId) {
    let t = tool.tokens();
    let Some(mut ws) = tool.ws.take() else { return };
    let outcome = match &mut ws.overlay {
        Some((at, o)) if *at == vp => {
            let e = env(tool, &t, &ws.client);
            Some(o.ui(ctx, &e))
        }
        _ => None,
    };
    tool.ws = Some(ws);
    if let Some(out) = outcome {
        tool.overlay_outcome(ctx, out, vp);
    }
}

fn process(
    ctx: &egui::Context,
    tool: &mut Tool,
    requests: Vec<Request>,
    run: Vec<ActionId>,
    vp: egui::ViewportId,
) {
    let mut actions = run;
    if let Some(ws) = &mut tool.ws {
        let now = ws.shared.now;
        actions.extend(ws.handle_requests(requests, now));
    }
    for a in actions {
        tool.run(ctx, a, vp);
    }
}

fn tab_commands(tool: &mut Tool, commands: Vec<dock::TabCommand>) {
    let Some(ws) = &mut tool.ws else { return };
    for c in commands {
        match c {
            dock::TabCommand::Detach(id) => {
                ws.layout.detach(id);
            }
            dock::TabCommand::Dock(id) => {
                if let Some(super::layout::Place::Window(w)) = ws.layout.window_of(id) {
                    ws.layout.dock(w);
                }
            }
        }
    }
}

/// One frame of the main window.
pub fn main_window(ui: &mut egui::Ui, tool: &mut Tool) {
    let ctx = ui.ctx().clone();
    tool.apply_style(&ctx);
    let t = tool.tokens();
    let now = ctx.input(|i| i.time);
    tool.tick(now);
    tool.shortcuts(&ctx, egui::ViewportId::ROOT);
    let mut run = Vec::new();
    let mut back_fwd = (None, None);
    let frame = egui::Frame::NONE.fill(t.palette.chrome);
    egui::Panel::top("bk-chrome")
        .frame(frame)
        .show_separator_line(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            run.extend(chrome::menu_bar(ui, tool, &t));
            let out = chrome::toolbar(ui, tool, &t);
            run.extend(out.run);
            back_fwd = (out.back_by, out.forward_by);
            let r = ui.max_rect();
            ui.painter().hline(
                r.x_range(),
                r.bottom(),
                egui::Stroke::new(1.0, t.palette.border),
            );
        });
    let mut cancel = Vec::new();
    egui::Panel::bottom("bk-status")
        .frame(frame)
        .show_separator_line(false)
        .show(ui, |ui| {
            let r = ui.max_rect();
            ui.painter().hline(
                r.x_range(),
                r.top(),
                egui::Stroke::new(1.0, t.palette.border),
            );
            cancel = chrome::status_bar(ui, tool, &t);
        });
    for j in cancel {
        j.progress.cancel();
    }
    let mut requests = Vec::new();
    let mut commands = Vec::new();
    egui::CentralPanel::default()
        .frame(egui::Frame::NONE.fill(t.palette.chrome))
        .show(ui, |ui| {
            let keymap = tool.prefs.keymap.clone();
            let mac = tool.mac;
            match &mut tool.ws {
                Some(ws) => commands = dock::show(ui, ws, None, &t, &keymap, mac, &mut requests),
                None => {
                    if let Some(a) = welcome::ui(ui, tool, &t) {
                        run.push(a);
                    }
                }
            }
        });
    if let Some(ws) = &mut tool.ws {
        if let Some(n) = back_fwd.0 {
            ws.shared.nav.back_by(n);
        }
        if let Some(n) = back_fwd.1 {
            ws.shared.nav.forward_by(n);
        }
    }
    tab_commands(tool, commands);
    overlays(&ctx, tool, egui::ViewportId::ROOT);
    if let Some(mut st) = tool.options.take() {
        let open = options::ui(&ctx, &mut st, &mut tool.prefs, &t, tool.mac);
        if open {
            tool.options = Some(st);
        }
    }
    if let Some(ws) = &tool.ws {
        ws.notices.ui(&ctx, &t, t.metrics.status_height);
    }
    process(&ctx, tool, requests, run, egui::ViewportId::ROOT);
}

/// One frame of detached window `wid`.
fn detached_window(ui: &mut egui::Ui, tool: &mut Tool, wid: u64, vp: egui::ViewportId) {
    let ctx = ui.ctx().clone();
    let before = tool.ws.as_ref().map(state_signature);
    let t = tool.tokens();
    if ctx.input(|i| i.viewport().close_requested()) {
        // Closing the window closes its panes (reopen them from Window).
        if let Some(ws) = &mut tool.ws {
            ws.layout.close_window(wid);
            ws.prune();
        }
        return;
    }
    let (pos, size) = ctx.input(|i| {
        let v = i.viewport();
        (v.outer_rect.map(|r| r.min), v.inner_rect.map(|r| r.size()))
    });
    if let Some(ws) = &mut tool.ws {
        ws.layout.set_window_rect(wid, pos, size);
    }
    tool.shortcuts(&ctx, vp);
    let mut requests = Vec::new();
    let mut commands = Vec::new();
    let mut run = Vec::new();
    let keymap = tool.prefs.keymap.clone();
    let mac = tool.mac;
    egui::Panel::top(egui::Id::new(("bk-detached-bar", wid)))
        .frame(
            egui::Frame::NONE
                .fill(t.palette.chrome)
                .inner_margin(egui::Margin::symmetric(8, 2)),
        )
        .show_separator_line(false)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Detached window")
                        .size(t.metrics.small_size)
                        .color(t.palette.text_muted),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::design::widgets::button(ui, &t, "Dock Window")
                        .on_hover_text("Put these panes back in the main window")
                        .clicked()
                        && let Some(ws) = &mut tool.ws
                    {
                        ws.layout.dock(wid);
                    }
                    if crate::design::widgets::icon_button(
                        ui,
                        &t,
                        crate::design::icons::PALETTE,
                        "Command Palette",
                        true,
                    )
                    .clicked()
                    {
                        run.push(ActionId::CommandPalette);
                    }
                });
            });
        });
    egui::CentralPanel::default()
        .frame(egui::Frame::NONE.fill(t.palette.chrome))
        .show(ui, |ui| {
            if let Some(ws) = &mut tool.ws {
                commands = dock::show(ui, ws, Some(wid), &t, &keymap, mac, &mut requests);
            }
        });
    tab_commands(tool, commands);
    overlays(&ctx, tool, vp);
    process(&ctx, tool, requests, run, vp);
    // Clicks in this window move the shared state: the main window (which
    // repaints the other detached ones) must redraw.
    if before != tool.ws.as_ref().map(state_signature)
        || ctx.input(|i| i.pointer.any_down() || !i.events.is_empty())
    {
        ctx.request_repaint_of(egui::ViewportId::ROOT);
    }
}
