//! Every action the interface offers, with Ghidra's names, menu places and
//! default key bindings. Menus, the toolbar, context menus, the palette and
//! the keyboard all read this one table.
//!
//! Key bindings are Ghidra's defaults, taken from its action definitions
//! (`KeyBindingData` in `Features/Base/.../plugin/core/*` and
//! `Features/Decompiler/.../decompile/actions/*`); see `ui-design.md` for
//! the list with sources and the few additions basilisk makes.

use super::keymap::KeyChord;

/// An action. The variant names are stable identifiers stored in the key
/// map file.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[non_exhaustive]
pub enum ActionId {
    // File
    /// File → Open...
    OpenProgram,
    /// File → Close
    CloseProgram,
    /// File → Save
    SaveProgram,
    /// File → Exit
    Exit,
    // Edit
    /// Edit → Undo
    Undo,
    /// Edit → Redo
    Redo,
    /// Copy the selection or the token under the cursor.
    Copy,
    /// Edit → Tool Options...
    ToolOptions,
    /// Edit → Theme → Switch Theme (dark/light).
    SwitchTheme,
    /// Edit → Theme → Compact Rows (basilisk).
    ToggleDensity,
    // Analysis
    /// Analysis → Auto Analyze...
    AutoAnalyze,
    // Navigation
    /// Navigation → Go To...
    GoTo,
    /// Previous Location in History (toolbar back).
    Back,
    /// Next Location in History (toolbar forward).
    Forward,
    /// Navigation → Previous History Function
    PreviousHistoryFunction,
    /// Navigation → Next History Function
    NextHistoryFunction,
    /// Navigation → Go To Next Function
    NextFunction,
    /// Navigation → Go To Previous Function
    PreviousFunction,
    /// Navigation → Clear History
    ClearHistory,
    /// Follow the reference under the cursor (double-click).
    FollowReference,
    /// Toolbar: next instruction.
    NextInstruction,
    /// Toolbar: next data.
    NextData,
    /// Toolbar: next label.
    NextLabel,
    // Search
    /// Search → Program Text...
    SearchText,
    /// Search → Memory...
    SearchMemory,
    /// Search → For Strings... (opens Defined Strings)
    SearchStrings,
    // Select
    /// Select → Program Highlight → Clear (clears the token highlight).
    ClearHighlight,
    /// Next highlighted token (decompiler).
    NextHighlight,
    /// Previous highlighted token (decompiler).
    PreviousHighlight,
    // Listing and Decompiler popups
    /// Edit Label / Rename Function / Rename Variable.
    Rename,
    /// Comments → Set...
    SetComment,
    /// Comments → Delete
    DeleteComment,
    /// References → Show References to
    ShowReferences,
    /// Snapshot: open a copy of the view that does not follow navigation.
    Snapshot,
    // Tools
    /// Tools → Command Palette (basilisk).
    CommandPalette,
    // Window
    /// Window → Listing
    ShowListing,
    /// Window → Decompile
    ShowDecompiler,
    /// Window → Symbol Tree
    ShowSymbolTree,
    /// Window → Program Trees
    ShowProgramTrees,
    /// Window → Functions
    ShowFunctions,
    /// Window → Defined Strings
    ShowStrings,
    /// Window → Location References
    ShowReferencesWindow,
    /// Window → Console
    ShowConsole,
    /// Window → Reset Window Layout (basilisk).
    ResetLayout,
    /// Window → Detach Window: move the active pane into its own native window.
    DetachWindow,
    /// Window → Dock Window: put a detached window's panes back in the main window.
    DockWindow,
    // Help
    /// Help → About basilisk
    About,
    /// Help → Key Bindings (opens the options at that page).
    ShowKeyBindings,
}

/// The top-level menus, in Ghidra's `CodeBrowser` order (File and Edit
/// first, the rest alphabetical, Window and Help last).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Menu {
    /// File
    File,
    /// Edit
    Edit,
    /// Analysis
    Analysis,
    /// Navigation
    Navigation,
    /// Search
    Search,
    /// Select
    Select,
    /// Tools
    Tools,
    /// Window
    Window,
    /// Help
    Help,
}

impl Menu {
    /// All menus, in menu-bar order.
    pub const ALL: [Self; 9] = [
        Self::File,
        Self::Edit,
        Self::Analysis,
        Self::Navigation,
        Self::Search,
        Self::Select,
        Self::Tools,
        Self::Window,
        Self::Help,
    ];

    /// The menu's title.
    pub fn title(self) -> &'static str {
        match self {
            Self::File => "File",
            Self::Edit => "Edit",
            Self::Analysis => "Analysis",
            Self::Navigation => "Navigation",
            Self::Search => "Search",
            Self::Select => "Select",
            Self::Tools => "Tools",
            Self::Window => "Window",
            Self::Help => "Help",
        }
    }
}

/// Where an action is offered, which decides when it is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Anywhere, even without a program.
    Global,
    /// Needs an open program.
    Program,
    /// Needs a code view (Listing or Decompiler) to have focus.
    CodeView,
    /// Needs the Decompiler to have focus.
    Decompiler,
    /// Not available yet in this version (shown disabled, with a reason).
    Unavailable(&'static str),
}

/// A description of one action.
#[derive(Debug, Clone, Copy)]
pub struct Action {
    /// Its id.
    pub id: ActionId,
    /// Ghidra's name for it, as shown in menus and the palette.
    pub name: &'static str,
    /// What it does, for the palette and tooltips.
    pub description: &'static str,
    /// The menu it sits in (None: toolbar, popup or palette only).
    pub menu: Option<Menu>,
    /// A group within the menu; a separator is drawn between groups.
    pub group: u8,
    /// Default key bindings.
    pub keys: &'static [KeyChord],
    /// When it can run.
    pub scope: Scope,
    /// Whether it appears in the Listing and Decompiler right-click menus.
    pub popup: bool,
}

use super::keymap::chord as k;
use egui::Key;

const NO_KEYS: &[KeyChord] = &[];

/// The table of actions.
#[rustfmt::skip]
pub const ACTIONS: &[Action] = &[
    // File
    a(ActionId::OpenProgram, "Open...", "Open a program", Some(Menu::File), 0, &[k(Key::O, true, false, false)], Scope::Global, false),
    a(ActionId::CloseProgram, "Close", "Close the program and return to the start screen", Some(Menu::File), 0, &[k(Key::W, true, false, false)], Scope::Program, false),
    a(ActionId::SaveProgram, "Save", "Save changes to the program", Some(Menu::File), 1, &[k(Key::S, true, false, false)], Scope::Unavailable("Saving arrives with the program database"), false),
    a(ActionId::Exit, "Exit", "Quit basilisk", Some(Menu::File), 2, &[k(Key::Q, true, false, false)], Scope::Global, false),
    // Edit
    a(ActionId::Undo, "Undo", "Undo the last change", Some(Menu::Edit), 0, &[k(Key::Z, true, false, false)], Scope::Program, false),
    a(ActionId::Redo, "Redo", "Redo the last undone change", Some(Menu::Edit), 0, &[k(Key::Z, true, true, false)], Scope::Program, false),
    a(ActionId::Copy, "Copy", "Copy the text under the cursor", None, 1, &[k(Key::C, true, false, false)], Scope::CodeView, true),
    a(ActionId::SwitchTheme, "Switch Theme", "Switch between the dark and light themes", Some(Menu::Edit), 2, NO_KEYS, Scope::Global, false),
    a(ActionId::ToggleDensity, "Compact Rows", "Switch between comfortable and compact row height", Some(Menu::Edit), 2, NO_KEYS, Scope::Global, false),
    a(ActionId::ToolOptions, "Tool Options...", "Appearance and key bindings", Some(Menu::Edit), 3, NO_KEYS, Scope::Global, false),
    // Analysis
    a(ActionId::AutoAnalyze, "Auto Analyze...", "Run the analyzers over the program", Some(Menu::Analysis), 0, &[k(Key::A, false, false, false)], Scope::Unavailable("Analysis arrives with the core (milestone M5)"), false),
    // Navigation
    a(ActionId::GoTo, "Go To...", "Go to an address, label or function by name", Some(Menu::Navigation), 0, &[k(Key::G, false, false, false)], Scope::Program, false),
    a(ActionId::Back, "Previous Location in History", "Go back to the previous location", None, 1, &[k(Key::ArrowLeft, false, false, true)], Scope::Program, false),
    a(ActionId::Forward, "Next Location in History", "Go forward again", None, 1, &[k(Key::ArrowRight, false, false, true)], Scope::Program, false),
    a(ActionId::PreviousHistoryFunction, "Previous History Function", "Go back to the previous function in the history", Some(Menu::Navigation), 1, &[k(Key::ArrowLeft, false, true, true)], Scope::Program, false),
    a(ActionId::NextHistoryFunction, "Next History Function", "Go forward to the next function in the history", Some(Menu::Navigation), 1, &[k(Key::ArrowRight, false, true, true)], Scope::Program, false),
    a(ActionId::ClearHistory, "Clear History", "Forget the navigation history", Some(Menu::Navigation), 1, NO_KEYS, Scope::Program, false),
    a(ActionId::NextFunction, "Go To Next Function", "Move to the next function", Some(Menu::Navigation), 2, &[k(Key::ArrowDown, true, false, false)], Scope::Program, false),
    a(ActionId::PreviousFunction, "Go To Previous Function", "Move to the previous function", Some(Menu::Navigation), 2, &[k(Key::ArrowUp, true, false, false)], Scope::Program, false),
    a(ActionId::FollowReference, "Follow Reference", "Go to what the token under the cursor refers to (double-click)", None, 3, &[k(Key::Enter, false, false, false)], Scope::CodeView, false),
    a(ActionId::NextInstruction, "Next Instruction", "Move to the next instruction", None, 4, &[k(Key::I, true, false, true)], Scope::Program, false),
    a(ActionId::NextData, "Next Data", "Move to the next defined data", None, 4, &[k(Key::D, true, false, true)], Scope::Program, false),
    a(ActionId::NextLabel, "Next Label", "Move to the next label", None, 4, &[k(Key::L, true, false, true)], Scope::Program, false),
    // Search
    a(ActionId::SearchText, "Program Text...", "Search the listing's text", Some(Menu::Search), 0, &[k(Key::F, true, false, false)], Scope::Program, false),
    a(ActionId::SearchMemory, "Memory...", "Search memory for bytes", Some(Menu::Search), 0, &[k(Key::S, false, false, false)], Scope::Program, false),
    a(ActionId::SearchStrings, "For Strings...", "List the program's defined strings", Some(Menu::Search), 1, NO_KEYS, Scope::Program, false),
    // Select
    a(ActionId::ClearHighlight, "Clear Highlight", "Remove the token highlight", Some(Menu::Select), 0, NO_KEYS, Scope::Program, false),
    a(ActionId::NextHighlight, "Next Highlight", "Move to the next highlighted token", None, 0, &[k(Key::Period, true, false, false)], Scope::Decompiler, false),
    a(ActionId::PreviousHighlight, "Previous Highlight", "Move to the previous highlighted token", None, 0, &[k(Key::Comma, true, false, false)], Scope::Decompiler, false),
    // Popups
    a(ActionId::Rename, "Rename", "Edit the label, or rename the function or variable, under the cursor", None, 0, &[k(Key::L, false, false, false)], Scope::CodeView, true),
    a(ActionId::SetComment, "Set Comment...", "Set a comment at the cursor", None, 0, &[k(Key::Semicolon, false, false, false)], Scope::CodeView, true),
    a(ActionId::DeleteComment, "Delete Comment", "Delete the comments at the cursor", None, 0, &[k(Key::Delete, false, false, false)], Scope::CodeView, true),
    a(ActionId::ShowReferences, "Show References to", "List the references to the item under the cursor", None, 1, &[k(Key::F, true, true, false)], Scope::CodeView, true),
    a(ActionId::Snapshot, "Snapshot", "Open a copy of this view that stays where it is", None, 2, NO_KEYS, Scope::CodeView, true),
    // Tools
    a(ActionId::CommandPalette, "Command Palette...", "Find any action, function, label or address by typing", Some(Menu::Tools), 0, &[k(Key::P, true, true, false)], Scope::Global, false),
    // Window
    a(ActionId::ShowListing, "Listing", "Show the Listing", Some(Menu::Window), 0, NO_KEYS, Scope::Program, false),
    a(ActionId::ShowDecompiler, "Decompile", "Show the Decompiler", Some(Menu::Window), 0, &[k(Key::E, true, false, false)], Scope::Program, false),
    a(ActionId::ShowSymbolTree, "Symbol Tree", "Show the Symbol Tree", Some(Menu::Window), 0, NO_KEYS, Scope::Program, false),
    a(ActionId::ShowProgramTrees, "Program Trees", "Show the Program Trees", Some(Menu::Window), 0, NO_KEYS, Scope::Program, false),
    a(ActionId::ShowFunctions, "Functions", "Show the Functions window", Some(Menu::Window), 1, NO_KEYS, Scope::Program, false),
    a(ActionId::ShowStrings, "Defined Strings", "Show the Defined Strings window", Some(Menu::Window), 1, NO_KEYS, Scope::Program, false),
    a(ActionId::ShowReferencesWindow, "Location References", "Show the references window", Some(Menu::Window), 1, NO_KEYS, Scope::Program, false),
    a(ActionId::ShowConsole, "Console", "Show the Console", Some(Menu::Window), 1, NO_KEYS, Scope::Global, false),
    a(ActionId::DetachWindow, "Detach Window", "Move the active pane into its own window", Some(Menu::Window), 2, NO_KEYS, Scope::Program, false),
    a(ActionId::DockWindow, "Dock Window", "Put the active detached window's panes back in the main window", Some(Menu::Window), 2, NO_KEYS, Scope::Program, false),
    a(ActionId::ResetLayout, "Reset Window Layout", "Put every window back where it starts (Ghidra's CodeBrowser layout)", Some(Menu::Window), 3, NO_KEYS, Scope::Global, false),
    // Help
    a(ActionId::ShowKeyBindings, "Key Bindings", "List and change key bindings", Some(Menu::Help), 0, NO_KEYS, Scope::Global, false),
    a(ActionId::About, "About basilisk", "Version and licences", Some(Menu::Help), 1, NO_KEYS, Scope::Global, false),
];

#[expect(
    clippy::too_many_arguments,
    reason = "a table row; named fields would triple the table"
)]
const fn a(
    id: ActionId,
    name: &'static str,
    description: &'static str,
    menu: Option<Menu>,
    group: u8,
    keys: &'static [KeyChord],
    scope: Scope,
    popup: bool,
) -> Action {
    Action {
        id,
        name,
        description,
        menu,
        group,
        keys,
        scope,
        popup,
    }
}

/// The description of `id`.
pub fn action(id: ActionId) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.id == id)
}

/// What the shell knows when deciding whether an action is enabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct ActionContext {
    /// A program is open.
    pub program: bool,
    /// A Listing or Decompiler has focus.
    pub code_view: bool,
    /// The Decompiler has focus.
    pub decompiler: bool,
    /// The active pane is in a detached window.
    pub detached: bool,
    /// History has somewhere to go back to.
    pub can_back: bool,
    /// History has somewhere to go forward to.
    pub can_forward: bool,
    /// There is something to undo.
    pub can_undo: bool,
    /// There is something to redo.
    pub can_redo: bool,
}

impl Action {
    /// Whether the action can run now.
    pub fn enabled(&self, cx: ActionContext) -> bool {
        let scoped = match self.scope {
            Scope::Global => true,
            Scope::Program => cx.program,
            Scope::CodeView => cx.program && cx.code_view,
            Scope::Decompiler => cx.program && cx.decompiler,
            Scope::Unavailable(_) => false,
        };
        scoped
            && match self.id {
                ActionId::Back | ActionId::PreviousHistoryFunction => cx.can_back,
                ActionId::Forward | ActionId::NextHistoryFunction => cx.can_forward,
                ActionId::Undo => cx.can_undo,
                ActionId::Redo => cx.can_redo,
                ActionId::DockWindow => cx.detached,
                _ => true,
            }
    }

    /// Why the action is unavailable, if it is unavailable for good.
    pub fn unavailable_reason(&self) -> Option<&'static str> {
        match self.scope {
            Scope::Unavailable(r) => Some(r),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_id_is_described_once() {
        let mut seen = HashSet::new();
        for a in ACTIONS {
            assert!(seen.insert(a.id), "{:?} twice", a.id);
            assert!(!a.name.is_empty() && !a.description.is_empty());
        }
        assert!(action(ActionId::GoTo).is_some());
    }

    #[test]
    fn ghidra_default_bindings() {
        let key = |id| {
            action(id)
                .unwrap()
                .keys
                .first()
                .copied()
                .unwrap()
                .to_string()
        };
        assert_eq!(key(ActionId::GoTo), "G");
        assert_eq!(key(ActionId::Rename), "L");
        assert_eq!(key(ActionId::SetComment), ";");
        assert_eq!(key(ActionId::SearchMemory), "S");
        assert_eq!(key(ActionId::Back), "Alt+Left");
        assert_eq!(key(ActionId::Forward), "Alt+Right");
        assert_eq!(key(ActionId::ShowReferences), "Ctrl+Shift+F");
        assert_eq!(key(ActionId::ShowDecompiler), "Ctrl+E");
        assert_eq!(key(ActionId::NextFunction), "Ctrl+Down");
    }

    #[test]
    fn no_two_actions_share_a_default_chord_in_one_scope() {
        let mut seen = HashSet::new();
        for a in ACTIONS {
            for c in a.keys {
                // Rename's L and Next Label's Ctrl+Alt+L differ by modifiers.
                assert!(seen.insert(*c), "{c} bound twice");
            }
        }
    }

    #[test]
    fn enabled_follows_context() {
        let back = action(ActionId::Back).unwrap();
        let mut cx = ActionContext {
            program: true,
            ..ActionContext::default()
        };
        assert!(!back.enabled(cx));
        cx.can_back = true;
        assert!(back.enabled(cx));
        assert!(!action(ActionId::Rename).unwrap().enabled(cx));
        cx.code_view = true;
        assert!(action(ActionId::Rename).unwrap().enabled(cx));
        assert!(!action(ActionId::AutoAnalyze).unwrap().enabled(cx));
    }
}
