//! The tool: preferences, the open program, and what every action does.

use std::sync::Arc;

use super::layout::{Layout, Tab};
use super::options::OptionsState;
use super::overlay::{Outcome, Overlay};
use super::palette::Mode;
use super::workspace::{EditKind, Workspace};
use crate::actions::{ActionContext, ActionId, Keymap, action};
use crate::design::{Density, ThemeKind, Tokens, theme};
use crate::model::{Address, CommentKind, Location, ProgramSource, Referent, SourceResult};
use crate::task::Pending;
use crate::views::{Level, ViewKind, search::SearchRequest};

/// Opens the program the tool shows (the demo, for now).
pub type Opener = Arc<dyn Fn() -> Result<Arc<dyn ProgramSource>, String> + Send + Sync>;

/// The comments at an address, loading.
type CommentsLoad = Pending<SourceResult<Vec<(CommentKind, String)>>>;

/// What is kept between runs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Theme.
    pub theme: ThemeKind,
    /// Row density.
    pub density: Density,
    /// Key bindings.
    pub keymap: Keymap,
    /// The window layout (main and detached windows).
    pub layout: Option<Layout>,
    /// Programs opened recently (names).
    pub recent: Vec<String>,
    /// Whether the last session ended with a program open.
    pub program_open: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: ThemeKind::Dark,
            density: Density::Comfortable,
            keymap: Keymap::default(),
            layout: None,
            recent: Vec::new(),
            program_open: true,
        }
    }
}

/// The whole tool, shared by every native window.
pub struct Tool {
    /// Preferences.
    pub prefs: Prefs,
    /// The open program.
    pub ws: Option<Workspace>,
    /// The Tool Options window, when open.
    pub options: Option<OptionsState>,
    /// Whether keys are shown with macOS names.
    pub mac: bool,
    opener: Opener,
    applied_style: Option<(ThemeKind, Density)>,
    pending_delete: Option<(Address, CommentsLoad)>,
    /// Set by File → Exit.
    pub quit: bool,
}

impl std::fmt::Debug for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tool")
            .field("prefs", &self.prefs)
            .field("ws", &self.ws)
            .finish_non_exhaustive()
    }
}

impl Tool {
    /// A tool with `prefs` that opens programs with `opener`.
    pub fn new(prefs: Prefs, opener: Opener, mac: bool) -> Self {
        let mut tool = Self {
            prefs,
            ws: None,
            options: None,
            mac,
            opener,
            applied_style: None,
            pending_delete: None,
            quit: false,
        };
        if tool.prefs.program_open {
            tool.open();
        }
        tool
    }

    /// The design tokens in force.
    pub fn tokens(&self) -> Tokens {
        Tokens::new(self.prefs.theme, self.prefs.density)
    }

    /// Forgets the applied theme, so the next frame applies it again.
    pub fn restyle(&mut self) {
        self.applied_style = None;
    }

    /// Applies the theme to `ctx` if it changed.
    pub fn apply_style(&mut self, ctx: &egui::Context) {
        let want = (self.prefs.theme, self.prefs.density);
        if self.applied_style != Some(want) {
            self.applied_style = Some(want);
            theme::apply(ctx, want.0, want.1);
        }
    }

    /// Opens the program.
    pub fn open(&mut self) {
        match (self.opener)() {
            Ok(source) => {
                let layout = self
                    .prefs
                    .layout
                    .clone()
                    .map_or_else(Layout::ghidra, Layout::repair);
                let ws = Workspace::new(source, layout);
                let name = ws.shared.program.name.clone();
                self.prefs.recent.retain(|r| *r != name);
                self.prefs.recent.insert(0, name);
                self.prefs.recent.truncate(8);
                self.prefs.program_open = true;
                self.ws = Some(ws);
            }
            Err(e) => {
                tracing::error!("cannot open program: {e}");
            }
        }
    }

    /// Closes the program, keeping its layout for next time.
    pub fn close(&mut self) {
        if let Some(ws) = self.ws.take() {
            self.prefs.layout = Some(ws.layout);
        }
        self.prefs.program_open = false;
    }

    /// Copies the live layout into the preferences (before saving).
    pub fn snapshot_prefs(&mut self) -> Prefs {
        if let Some(ws) = &self.ws {
            self.prefs.layout = Some(ws.layout.clone());
        }
        self.prefs.clone()
    }

    /// What is enabled now.
    pub fn action_context(&self) -> ActionContext {
        let Some(ws) = &self.ws else {
            return ActionContext::default();
        };
        let kind = ws.active_kind();
        ActionContext {
            program: true,
            code_view: kind.is_some_and(ViewKind::is_code),
            decompiler: kind == Some(ViewKind::Decompiler),
            detached: matches!(
                ws.active.and_then(|a| ws.layout.window_of(a)),
                Some(super::layout::Place::Window(_))
            ),
            can_back: ws.shared.nav.can_back(),
            can_forward: ws.shared.nav.can_forward(),
            can_undo: !ws.undo.is_empty(),
            can_redo: !ws.redo.is_empty(),
        }
    }

    /// Runs the key bindings pressed in viewport `vp` this frame.
    pub fn shortcuts(&mut self, ctx: &egui::Context, vp: egui::ViewportId) {
        if self.ws.as_ref().is_some_and(|w| w.overlay.is_some())
            || self.options.as_ref().is_some_and(OptionsState::capturing)
        {
            return;
        }
        let typing = ctx.egui_wants_keyboard_input();
        let cx = self.action_context();
        let mut fired = Vec::new();
        ctx.input_mut(|i| {
            let mut consumed = Vec::new();
            for e in &i.events {
                if let egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } = e
                    && let Some(id) = self.prefs.keymap.lookup(*key, *modifiers)
                {
                    let bare = !modifiers.command && !modifiers.alt;
                    let enabled = action(id).is_some_and(|a| a.enabled(cx));
                    if enabled && !(bare && typing) {
                        fired.push(id);
                        consumed.push((*modifiers, *key));
                    }
                }
            }
            for (m, k) in consumed {
                i.consume_key(m, k);
            }
        });
        for id in fired {
            self.run(ctx, id, vp);
        }
    }

    fn view_target(&self) -> Option<crate::views::Target> {
        let ws = self.ws.as_ref()?;
        ws.views.get(&ws.active?)?.target()
    }

    /// Sends an action to the active pane, or to the main Listing.
    fn send_to_view(&mut self, ctx: &egui::Context, id: ActionId) -> bool {
        let Some(ws) = &mut self.ws else { return false };
        let t = Tokens::new(self.prefs.theme, self.prefs.density);
        let mut requests = Vec::new();
        let mut targets: Vec<u64> = ws.active.into_iter().collect();
        if let Some(l) = ws.layout.find_kind(ViewKind::Listing) {
            targets.push(l);
        }
        let mut handled = false;
        for tab in targets {
            let focused = ws.active == Some(tab);
            if let Some(view) = ws.views.get_mut(&tab) {
                let mut cx = crate::views::ViewCx {
                    client: &ws.client,
                    tokens: &t,
                    shared: &mut ws.shared,
                    requests: &mut requests,
                    keymap: &self.prefs.keymap,
                    focused,
                    mac: self.mac,
                    ctx: ctx.clone(),
                };
                if view.handle(id, &mut cx) {
                    handled = true;
                    break;
                }
            }
        }
        let now = ws.shared.now;
        let more = ws.handle_requests(requests, now);
        for a in more {
            self.run(ctx, a, egui::ViewportId::ROOT);
        }
        handled
    }

    fn notify(&mut self, level: Level, text: impl Into<String>) {
        if let Some(ws) = &mut self.ws {
            let now = ws.shared.now;
            let text = text.into();
            ws.shared.log(level, text.clone());
            ws.notices.push(level, text, now);
        }
    }

    /// Runs an action from a menu, the toolbar, the palette or a key, for
    /// the window `vp` it came from.
    pub fn run(&mut self, ctx: &egui::Context, id: ActionId, vp: egui::ViewportId) {
        let cx = self.action_context();
        if let Some(a) = action(id)
            && !a.enabled(cx)
        {
            if let Some(r) = a.unavailable_reason() {
                self.notify(
                    Level::Info,
                    format!("{}: {r}", a.name.trim_end_matches("...")),
                );
            }
            return;
        }
        match id {
            ActionId::OpenProgram => {
                if self.ws.is_some() {
                    self.notify(
                        Level::Info,
                        "Opening other programs arrives with the loaders; the demo program is open",
                    );
                } else {
                    self.open();
                }
            }
            ActionId::CloseProgram => self.close(),
            ActionId::Exit => {
                self.quit = true;
                ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Close);
            }
            ActionId::SwitchTheme => {
                self.prefs.theme = match self.prefs.theme {
                    ThemeKind::Dark => ThemeKind::Light,
                    ThemeKind::Light => ThemeKind::Dark,
                };
            }
            ActionId::ToggleDensity => {
                self.prefs.density = match self.prefs.density {
                    Density::Comfortable => Density::Compact,
                    Density::Compact => Density::Comfortable,
                };
            }
            ActionId::ToolOptions => self.options = Some(OptionsState::default()),
            ActionId::ShowKeyBindings => self.options = Some(OptionsState::key_bindings()),
            ActionId::ResetLayout => {
                if let Some(ws) = &mut self.ws {
                    ws.layout = Layout::ghidra();
                    ws.prune();
                    ws.shared.log(Level::Info, "Window layout reset");
                } else {
                    self.prefs.layout = None;
                }
            }
            _ => self.run_program(ctx, id, vp),
        }
    }

    fn run_program(&mut self, ctx: &egui::Context, id: ActionId, vp: egui::ViewportId) {
        let target = self.view_target();
        let Some(ws) = &mut self.ws else { return };
        let overlay = |ws: &mut Workspace, o: Overlay| ws.overlay = Some((vp, o));
        match id {
            ActionId::CommandPalette => overlay(ws, Overlay::palette(Mode::All)),
            ActionId::GoTo => overlay(ws, Overlay::palette(Mode::GoTo)),
            ActionId::About => overlay(ws, Overlay::About),
            ActionId::SearchText => overlay(ws, Overlay::search(false)),
            ActionId::SearchMemory => overlay(ws, Overlay::search(true)),
            ActionId::SearchStrings | ActionId::ShowStrings => ws.show(ViewKind::Strings),
            ActionId::Back => {
                ws.shared.nav.back();
            }
            ActionId::Forward => {
                ws.shared.nav.forward();
            }
            ActionId::PreviousHistoryFunction => {
                ws.shared.nav.back_function();
            }
            ActionId::NextHistoryFunction => {
                ws.shared.nav.forward_function();
            }
            ActionId::ClearHistory => ws.shared.nav.clear(),
            ActionId::ClearHighlight => ws.shared.highlight = None,
            ActionId::Undo => {
                if let Some(e) = ws.undo.pop() {
                    let reverse = super::workspace::Edit {
                        command: e.undo.clone(),
                        undo: e.command.clone(),
                    };
                    let _ = reverse;
                    let pending = ws.client.apply(e.undo.clone());
                    ws.applying.push((pending, e, EditKind::Undo));
                }
            }
            ActionId::Redo => {
                if let Some(e) = ws.redo.pop() {
                    let pending = ws.client.apply(e.command.clone());
                    ws.applying.push((pending, e, EditKind::Redo));
                }
            }
            ActionId::Rename => {
                if let Some(t) = target {
                    overlay(ws, Overlay::rename(&t, None));
                }
            }
            ActionId::SetComment => {
                if let Some(t) = target {
                    let o = Overlay::comment(ws, t.address, None);
                    overlay(ws, o);
                }
            }
            ActionId::DeleteComment => {
                if let Some(t) = target {
                    let a = t.address;
                    self.pending_delete = Some((a, ws.client.request(move |s| s.comments(a))));
                }
            }
            ActionId::ShowReferences => {
                if let Some(t) = target {
                    let (a, name) = match t.token.as_ref().and_then(|k| {
                        k.referent
                            .as_ref()
                            .and_then(Referent::address)
                            .map(|a| (a, k.text.to_string()))
                    }) {
                        Some(x) => x,
                        None => (t.address, t.address.to_string()),
                    };
                    ws.shared.references_to = Some((a, name));
                    ws.show(ViewKind::References);
                }
            }
            ActionId::Snapshot => {
                if let Some(kind) = ws.active_kind().filter(|k| k.is_code()) {
                    let at = ws.shared.nav.current();
                    let id = ws.layout.new_id();
                    ws.layout.add(Tab {
                        id,
                        kind,
                        snapshot: Some(at),
                    });
                }
            }
            ActionId::DetachWindow => {
                if let Some(a) = ws.active {
                    ws.layout.detach(a);
                }
            }
            ActionId::DockWindow => {
                if let Some(super::layout::Place::Window(w)) =
                    ws.active.and_then(|a| ws.layout.window_of(a))
                {
                    ws.layout.dock(w);
                }
            }
            ActionId::ShowListing => ws.show(ViewKind::Listing),
            ActionId::ShowDecompiler => ws.show(ViewKind::Decompiler),
            ActionId::ShowSymbolTree => ws.show(ViewKind::SymbolTree),
            ActionId::ShowProgramTrees => ws.show(ViewKind::ProgramTrees),
            ActionId::ShowFunctions => ws.show(ViewKind::Functions),
            ActionId::ShowReferencesWindow => ws.show(ViewKind::References),
            ActionId::ShowConsole => ws.show(ViewKind::Console),
            ActionId::FollowReference
            | ActionId::Copy
            | ActionId::NextInstruction
            | ActionId::NextData
            | ActionId::NextLabel
            | ActionId::NextFunction
            | ActionId::PreviousFunction
            | ActionId::NextHighlight
            | ActionId::PreviousHighlight => {
                self.send_to_view(ctx, id);
            }
            _ => {}
        }
    }

    /// Per-frame work: finished edits, pending deletes.
    pub fn tick(&mut self, now: f64) {
        let Some(ws) = &mut self.ws else { return };
        ws.tick(now);
        if let Some((a, p)) = &mut self.pending_delete
            && let Some(r) = p.take()
        {
            let a = *a;
            self.pending_delete = None;
            let existing = r.unwrap_or_default();
            if existing.is_empty() {
                ws.notices
                    .push(Level::Info, format!("No comment at {a}"), now);
            }
            for (kind, old) in existing {
                ws.apply(
                    super::workspace::Edit {
                        command: crate::model::Command::SetComment {
                            address: a,
                            kind,
                            text: String::new(),
                        },
                        undo: crate::model::Command::SetComment {
                            address: a,
                            kind,
                            text: old,
                        },
                    },
                    EditKind::New,
                );
            }
        }
    }

    /// Acts on what an overlay decided.
    pub fn overlay_outcome(&mut self, ctx: &egui::Context, out: Outcome, vp: egui::ViewportId) {
        let Some(ws) = &mut self.ws else { return };
        match out {
            Outcome::Keep => {}
            Outcome::Close => ws.overlay = None,
            Outcome::Run(a) => {
                ws.overlay = None;
                self.run(ctx, a, vp);
            }
            Outcome::Go(a) => {
                ws.overlay = None;
                ws.shared.nav.go(Location::at(a));
                if ws.active_kind().is_none_or(|k| !k.is_code()) {
                    ws.active = ws.layout.find_kind(ViewKind::Listing);
                }
            }
            Outcome::Apply(edits) => {
                ws.overlay = None;
                for e in edits {
                    ws.apply(e, EditKind::New);
                }
            }
            Outcome::Search(query, text) => {
                ws.overlay = None;
                ws.search_serial += 1;
                ws.shared.search = Some(SearchRequest {
                    query,
                    text,
                    serial: ws.search_serial,
                });
                ws.show(ViewKind::SearchResults);
            }
        }
    }
}
