//! A program open in the tool: its data client, its views and their shared
//! state, the layout, and the edit history.
//!
//! One `Workspace` serves every window: the main window and each detached
//! one draw their panes from the same views and the same [`Shared`] state,
//! so navigation and highlights stay in step across windows by
//! construction.

use std::collections::HashMap;
use std::sync::Arc;

use super::layout::{Layout, Tab};
use super::notifications::Notices;
use super::overlay::Overlay;
use crate::model::{Command, FunctionInfo, Location, ProgramSource, SourceResult};
use crate::nav::Navigator;
use crate::task::{DataClient, Pending};
use crate::views::{self, Level, Related, Request, Shared, View, ViewKind};

/// An applied edit and how to reverse it.
#[derive(Debug, Clone, PartialEq)]
pub struct Edit {
    /// The edit as applied.
    pub command: Command,
    /// The edit that reverses it.
    pub undo: Command,
}

/// Which list an edit in flight goes to once it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditKind {
    New,
    Undo,
    Redo,
}

/// A program open in the tool.
pub struct Workspace {
    /// The data interface.
    pub client: DataClient,
    /// View state shared by every pane in every window.
    pub shared: Shared,
    /// Each pane's view, by tab id.
    pub views: HashMap<u64, Box<dyn View>>,
    /// Where the panes are.
    pub layout: Layout,
    /// The pane keyboard actions go to (the last one clicked).
    pub active: Option<u64>,
    /// The palette or dialog open, and the window it is open in.
    pub overlay: Option<(egui::ViewportId, Overlay)>,
    /// Edits that can be undone, newest last.
    pub undo: Vec<Edit>,
    /// Edits that can be redone.
    pub redo: Vec<Edit>,
    pub(crate) applying: Vec<(Pending<SourceResult<()>>, Edit, EditKind)>,
    function_req: Option<(u64, Pending<SourceResult<Option<FunctionInfo>>>)>,
    /// Transient messages.
    pub notices: Notices,
    pub(crate) search_serial: u64,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("program", &self.shared.program.name)
            .field("location", &self.shared.nav.current())
            .finish_non_exhaustive()
    }
}

impl Workspace {
    /// Opens `source` with `layout`.
    pub fn new(source: Arc<dyn ProgramSource>, layout: Layout) -> Self {
        let client = DataClient::new(source);
        let program = client.info();
        let shared = Shared {
            nav: Navigator::new(Location::at(program.entry)),
            highlight: None,
            related: Related::default(),
            function: None,
            references_to: None,
            search: None,
            log: Vec::new(),
            program,
            now: 0.0,
            revision: 0,
        };
        let mut ws = Self {
            client,
            shared,
            views: HashMap::new(),
            layout,
            active: None,
            overlay: None,
            undo: Vec::new(),
            redo: Vec::new(),
            applying: Vec::new(),
            function_req: None,
            notices: Notices::default(),
            search_serial: 0,
        };
        let p = &ws.shared.program;
        let msg = format!("Opened {} ({}, {})", p.name, p.format, p.language);
        ws.shared.log(Level::Info, msg);
        ws.active = ws.layout.find_kind(ViewKind::Listing);
        ws
    }

    /// The view of tab `tab`, created on first use.
    pub fn view(&mut self, tab: &Tab) -> &mut Box<dyn View> {
        self.views
            .entry(tab.id)
            .or_insert_with(|| views::new_view(tab.kind, tab.snapshot))
    }

    /// The kind of the active pane.
    pub fn active_kind(&self) -> Option<ViewKind> {
        let id = self.active?;
        self.layout.tabs().into_iter().find(|t| t.id == id).map(|t| t.kind)
    }

    /// Opens (or focuses) a pane of `kind` and makes it active.
    pub fn show(&mut self, kind: ViewKind) {
        let id = self.layout.show(kind);
        self.active = Some(id);
    }

    /// Drops views whose panes are gone.
    pub fn prune(&mut self) {
        let live: std::collections::HashSet<u64> =
            self.layout.tabs().iter().map(|t| t.id).collect();
        self.views.retain(|id, _| live.contains(id));
        if self.active.is_some_and(|a| !live.contains(&a)) {
            self.active = self.layout.find_kind(ViewKind::Listing);
        }
    }

    /// Starts an edit.
    pub(crate) fn apply(&mut self, edit: Edit, kind: EditKind) {
        let pending = self.client.apply(edit.command.clone());
        self.applying.push((pending, edit, kind));
    }

    /// Per-frame bookkeeping: finished edits, the current function.
    pub fn tick(&mut self, now: f64) {
        self.shared.now = now;
        let mut done = Vec::new();
        self.applying.retain_mut(|(p, edit, kind)| match p.take() {
            Some(r) => {
                done.push((r, edit.clone(), *kind));
                false
            }
            None => true,
        });
        for (r, edit, kind) in done {
            match r {
                Ok(()) => {
                    let what = edit.command.describe();
                    match kind {
                        EditKind::New => {
                            self.undo.push(edit);
                            self.redo.clear();
                        }
                        EditKind::Undo => self.redo.push(edit),
                        EditKind::Redo => self.undo.push(edit),
                    }
                    let verb = match kind {
                        EditKind::New => "",
                        EditKind::Undo => "Undo: ",
                        EditKind::Redo => "Redo: ",
                    };
                    self.shared.log(Level::Info, format!("{verb}{what}"));
                }
                Err(e) => {
                    let msg = format!("{}: {e}", edit.command.describe());
                    self.shared.log(Level::Error, msg.clone());
                    self.notices.push(Level::Error, msg, now);
                }
            }
        }
        // The function at the current location, for titles and the status bar.
        let generation = self.shared.nav.generation() ^ self.client.revision().rotate_left(32);
        let stale = self.function_req.as_ref().is_none_or(|(g, _)| *g != generation);
        if stale {
            let a = self.shared.nav.current().address;
            self.function_req = Some((generation, self.client.request(move |s| s.function_containing(a))));
        }
        if let Some((_, p)) = &mut self.function_req {
            if let Some(r) = p.poll() {
                let f = r.as_ref().ok().cloned().flatten();
                self.shared.nav.set_function(f.as_ref().map(|f| f.entry));
                self.shared.function = f;
            }
        }
        self.notices.expire(now);
    }

    /// Carries out what the views asked for this frame, except actions,
    /// which are returned for the shell to run.
    pub fn handle_requests(&mut self, requests: Vec<Request>, now: f64) -> Vec<crate::actions::ActionId> {
        let mut actions = Vec::new();
        for r in requests {
            match r {
                Request::Action(a) => actions.push(a),
                Request::Apply { command, undo } => self.apply(Edit { command, undo }, EditKind::New),
                Request::ShowReferences(a, name) => {
                    self.shared.references_to = Some((a, name));
                    self.show(ViewKind::References);
                }
                Request::EditComment(a, kind) => {
                    self.overlay = Some((egui::ViewportId::ROOT, Overlay::comment(self, a, Some(kind))));
                }
                Request::Snapshot(kind, at) => {
                    let id = self.layout.new_id();
                    self.layout.add(Tab {
                        id,
                        kind,
                        snapshot: Some(at),
                    });
                    self.active = Some(id);
                }
                Request::Notify(level, text) => self.notices.push(level, text, now),
            }
        }
        actions
    }
}
