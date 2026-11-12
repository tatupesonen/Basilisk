//! The views (Ghidra's component providers): each is a module behind the
//! [`View`] trait, so a new one plugs into docking, the Window menu,
//! navigation and the palette by adding a [`ViewKind`] variant and a
//! constructor in [`new_view`], without touching the shell.

pub mod console;
pub mod decompiler;
pub mod functions;
pub mod listing;
mod preview;
pub mod program_trees;
pub mod references;
pub mod scroller;
pub mod search;
pub mod strings;
pub mod symbol_tree;
pub mod table;

use crate::actions::{ActionId, Keymap};
use crate::design::{Tokens, icons};
use crate::model::{
    Address, AddressRange, Command, CommentKind, FunctionInfo, Location, ProgramInfo, Token,
};
use crate::nav::Navigator;
use crate::task::DataClient;

/// The kinds of view, with Ghidra's window names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ViewKind {
    /// The Listing (disassembly).
    Listing,
    /// The Decompiler ("Decompile" in Ghidra's Window menu).
    Decompiler,
    /// The Symbol Tree.
    SymbolTree,
    /// Program Trees (memory blocks).
    ProgramTrees,
    /// The Functions window.
    Functions,
    /// Defined Strings.
    Strings,
    /// Location References ("References to …").
    References,
    /// Search results.
    SearchResults,
    /// The Console.
    Console,
}

impl ViewKind {
    /// Every kind, in Window-menu order.
    pub const ALL: [Self; 9] = [
        Self::Listing,
        Self::Decompiler,
        Self::SymbolTree,
        Self::ProgramTrees,
        Self::Functions,
        Self::Strings,
        Self::References,
        Self::SearchResults,
        Self::Console,
    ];

    /// The window's name.
    pub fn title(self) -> &'static str {
        match self {
            Self::Listing => "Listing",
            Self::Decompiler => "Decompile",
            Self::SymbolTree => "Symbol Tree",
            Self::ProgramTrees => "Program Trees",
            Self::Functions => "Functions",
            Self::Strings => "Defined Strings",
            Self::References => "References",
            Self::SearchResults => "Search Results",
            Self::Console => "Console",
        }
    }

    /// The window's icon.
    pub fn icon(self) -> &'static str {
        match self {
            Self::Listing => icons::LISTING,
            Self::Decompiler => icons::DECOMPILER,
            Self::SymbolTree => icons::TREE,
            Self::ProgramTrees => icons::BLOCKS,
            Self::Functions => icons::FUNCTION,
            Self::Strings => icons::STRING,
            Self::References => icons::REFERENCES,
            Self::SearchResults => icons::SEARCH,
            Self::Console => icons::CONSOLE,
        }
    }

    /// The Window-menu action that shows it.
    pub fn show_action(self) -> Option<ActionId> {
        Some(match self {
            Self::Listing => ActionId::ShowListing,
            Self::Decompiler => ActionId::ShowDecompiler,
            Self::SymbolTree => ActionId::ShowSymbolTree,
            Self::ProgramTrees => ActionId::ShowProgramTrees,
            Self::Functions => ActionId::ShowFunctions,
            Self::Strings => ActionId::ShowStrings,
            Self::References => ActionId::ShowReferencesWindow,
            Self::Console => ActionId::ShowConsole,
            Self::SearchResults => return None,
        })
    }

    /// Whether it shows program code (and takes code-view actions).
    pub fn is_code(self) -> bool {
        matches!(self, Self::Listing | Self::Decompiler)
    }
}

/// A line in the Console.
#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    /// Seconds since the tool started.
    pub time: f64,
    /// Severity.
    pub level: Level,
    /// The message.
    pub text: String,
}

/// Severity of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Information.
    Info,
    /// Something to look at.
    Warning,
    /// Something failed.
    Error,
}

/// What is under a code view's cursor: the thing Rename, Set Comment and
/// Show References act on.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// The code unit at the cursor.
    pub address: Address,
    /// The token at the cursor, if the cursor is on one.
    pub token: Option<Token>,
    /// The function containing the cursor.
    pub function: Option<Address>,
}

/// The decompiler's cursor line, shown in the listing (cross-highlight).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Related {
    /// Instructions of the decompiler line under the cursor.
    pub ranges: Vec<AddressRange>,
}

impl Related {
    /// Whether `a` is one of the linked instructions.
    pub fn contains(&self, a: Address) -> bool {
        self.ranges.iter().any(|r| r.contains(a))
    }
}

/// View state shared by all views (no program data lives here).
#[derive(Debug)]
pub struct Shared {
    /// The current location and history.
    pub nav: Navigator,
    /// Ghidra's middle-click highlight: tokens matching this one are
    /// marked in every code view.
    pub highlight: Option<Token>,
    /// Listing rows linked to the decompiler's cursor line.
    pub related: Related,
    /// The function at the current location (for titles and the status bar).
    pub function: Option<FunctionInfo>,
    /// What the References window lists.
    pub references_to: Option<(Address, String)>,
    /// The latest search, for the Search Results window.
    pub search: Option<search::SearchRequest>,
    /// Console lines.
    pub log: Vec<LogLine>,
    /// The open program.
    pub program: ProgramInfo,
    /// Seconds since start (for log times).
    pub now: f64,
    /// Bumped when the user picks a function or location in a table, so
    /// tables can scroll to keep the current row in view.
    pub revision: u64,
}

impl Shared {
    /// Writes a line to the Console.
    pub fn log(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        match level {
            Level::Error => tracing::error!("{text}"),
            Level::Warning => tracing::warn!("{text}"),
            Level::Info => tracing::info!("{text}"),
        }
        self.log.push(LogLine {
            time: self.now,
            level,
            text,
        });
        if self.log.len() > 5000 {
            self.log.drain(..1000);
        }
    }
}

/// Something a view asks the shell to do.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Request {
    /// Run an action as if chosen from a menu.
    Action(ActionId),
    /// Apply an edit; `undo` reverses it.
    Apply {
        /// The edit.
        command: Command,
        /// The edit that undoes it.
        undo: Command,
    },
    /// Show the References window for an address.
    ShowReferences(Address, String),
    /// Open the comment editor at an address.
    EditComment(Address, CommentKind),
    /// Open a snapshot (unpinned copy) of a view at a location.
    Snapshot(ViewKind, Location),
    /// Show a transient message.
    Notify(Level, String),
}

/// What a view gets each frame.
pub struct ViewCx<'a> {
    /// The data interface.
    pub client: &'a DataClient,
    /// The design tokens.
    pub tokens: &'a Tokens,
    /// Shared view state.
    pub shared: &'a mut Shared,
    /// Requests to the shell.
    pub requests: &'a mut Vec<Request>,
    /// Key bindings (for menus inside views).
    pub keymap: &'a Keymap,
    /// Whether this view is the focused one.
    pub focused: bool,
    /// Whether the platform is macOS (shortcut labels).
    pub mac: bool,
    /// The egui context (clipboard, repaint).
    pub ctx: egui::Context,
}

impl std::fmt::Debug for ViewCx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewCx")
            .field("focused", &self.focused)
            .finish_non_exhaustive()
    }
}

/// A view: one dockable window.
pub trait View: std::fmt::Debug + Send {
    /// Its kind.
    fn kind(&self) -> ViewKind;

    /// The tab title (`Listing: licd`, `Decompile: main`).
    fn title(&self, shared: &Shared) -> String;

    /// Draws the view.
    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>);

    /// What is under the cursor, for code-view actions.
    fn target(&self) -> Option<Target> {
        None
    }

    /// Handles an action while focused; returns whether it did.
    fn handle(&mut self, _action: ActionId, _cx: &mut ViewCx<'_>) -> bool {
        false
    }

    /// Whether the view stays where it is instead of following the
    /// current location (a snapshot).
    fn is_snapshot(&self) -> bool {
        false
    }
}

/// Creates a view of `kind`; `snapshot` pins a code view at a location.
pub fn new_view(kind: ViewKind, snapshot: Option<Location>) -> Box<dyn View> {
    match kind {
        ViewKind::Listing => Box::new(listing::ListingView::new(snapshot)),
        ViewKind::Decompiler => Box::new(decompiler::DecompilerView::new(snapshot)),
        ViewKind::SymbolTree => Box::new(symbol_tree::SymbolTreeView::default()),
        ViewKind::ProgramTrees => Box::new(program_trees::ProgramTreesView::default()),
        ViewKind::Functions => Box::new(functions::FunctionsView::default()),
        ViewKind::Strings => Box::new(strings::StringsView::default()),
        ViewKind::References => Box::new(references::ReferencesView::default()),
        ViewKind::SearchResults => Box::new(search::SearchView::default()),
        ViewKind::Console => Box::new(console::ConsoleView::default()),
    }
}

/// Registers a token as an accessibility node (a link with its text), so
/// screen readers and UI tests can find code tokens by name.
pub(crate) fn token_node(ui: &egui::Ui, id: egui::Id, rect: egui::Rect, token: &Token) {
    let resp = ui.interact(rect, id, egui::Sense::hover());
    let text = token.text.to_string();
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Link, true, &text));
}

/// The name Ghidra gives the rename action for what is under the cursor.
pub fn rename_title(target: Option<&Target>) -> &'static str {
    let Some(t) = target else {
        return "Edit Label";
    };
    match t.token.as_ref().map(|t| (t.kind, &t.referent)) {
        Some((_, Some(crate::model::Referent::Variable { .. }))) => "Rename Variable",
        Some((crate::model::TokenKind::Function | crate::model::TokenKind::Import, _)) => {
            "Rename Function"
        }
        _ => "Edit Label",
    }
}

fn menu_item(ui: &mut egui::Ui, cx: &mut ViewCx<'_>, id: ActionId, text: &str) {
    let shortcut = cx
        .keymap
        .primary(id)
        .map(|k| k.label(cx.mac))
        .unwrap_or_default();
    if ui
        .add(egui::Button::new(text).shortcut_text(shortcut))
        .clicked()
    {
        cx.requests.push(Request::Action(id));
        ui.close();
    }
}

/// A submenu item with a Phosphor caret (egui's default arrow glyph is not
/// in the bundled fonts).
pub fn submenu(ui: &mut egui::Ui, text: &str, add: impl FnOnce(&mut egui::Ui)) {
    let button = egui::Button::new(text).right_text(icons::rich(icons::COLLAPSED));
    egui::containers::menu::SubMenuButton::from_button(button).ui(ui, add);
}

/// The right-click menu of the Listing and the Decompiler, laid out as
/// Ghidra's: clipboard, then label and comment edits, then references.
pub fn popup_menu(ui: &mut egui::Ui, cx: &mut ViewCx<'_>, target: Option<&Target>) {
    ui.set_min_width(240.0);
    menu_item(ui, cx, ActionId::Copy, "Copy");
    ui.separator();
    if target
        .and_then(|t| t.token.as_ref())
        .and_then(|t| t.referent.as_ref())
        .and_then(crate::model::Referent::address)
        .is_some()
    {
        menu_item(ui, cx, ActionId::FollowReference, "Follow Reference");
    }
    menu_item(ui, cx, ActionId::Rename, rename_title(target));
    submenu(ui, "Comments", |ui| {
        menu_item(ui, cx, ActionId::SetComment, "Set...");
        if let Some(t) = target {
            for kind in CommentKind::ALL {
                if ui.button(format!("Set {}...", kind.title())).clicked() {
                    cx.requests.push(Request::EditComment(t.address, kind));
                    ui.close();
                }
            }
        }
        menu_item(ui, cx, ActionId::DeleteComment, "Delete");
    });
    submenu(ui, "References", |ui| {
        let name = target
            .and_then(|t| t.token.as_ref())
            .map_or_else(String::new, |t| format!(" {}", t.text));
        menu_item(ui, cx, ActionId::ShowReferences, &format!("Show References to{name}"));
    });
    ui.separator();
    menu_item(ui, cx, ActionId::Snapshot, "Snapshot");
}
