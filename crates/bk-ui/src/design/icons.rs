//! The icon set: a few Phosphor glyphs (MIT), named for what they mean
//! here rather than what they depict, so a glyph can be swapped in one
//! place.

use egui_phosphor::regular as ph;

/// The font for an icon of `size` points.
pub fn font(size: f32) -> egui::FontId {
    egui::FontId::new(size, super::typography::icon_family())
}

/// An icon as text for a label.
pub fn rich(icon: &str) -> egui::RichText {
    egui::RichText::new(icon).family(super::typography::icon_family())
}

/// Navigate back (Ghidra's Previous Location).
pub const BACK: &str = ph::ARROW_LEFT;
/// Navigate forward.
pub const FORWARD: &str = ph::ARROW_RIGHT;
/// Save.
pub const SAVE: &str = ph::FLOPPY_DISK;
/// Search, filter.
pub const SEARCH: &str = ph::MAGNIFYING_GLASS;
/// Functions.
pub const FUNCTION: &str = ph::FUNCTION;
/// Symbol Tree.
pub const TREE: &str = ph::TREE_STRUCTURE;
/// Console.
pub const CONSOLE: &str = ph::TERMINAL_WINDOW;
/// Options.
pub const OPTIONS: &str = ph::GEAR;
/// Close.
pub const CLOSE: &str = ph::X;
/// Collapsed tree node.
pub const COLLAPSED: &str = ph::CARET_RIGHT;
/// Expanded tree node.
pub const EXPANDED: &str = ph::CARET_DOWN;
/// Pin a view to its location.
pub const PIN: &str = ph::PUSH_PIN;
/// A folder in a tree.
pub const FOLDER: &str = ph::FOLDER_SIMPLE;
/// Open folder.
pub const FOLDER_OPEN: &str = ph::FOLDER_OPEN;
/// Bookmarks.
pub const BOOKMARK: &str = ph::BOOKMARK_SIMPLE;
/// Labels.
pub const LABEL: &str = ph::TAG;
/// Defined strings.
pub const STRING: &str = ph::QUOTES;
/// Light theme.
pub const LIGHT: &str = ph::SUN;
/// Dark theme.
pub const DARK: &str = ph::MOON;
/// Warnings.
pub const WARNING: &str = ph::WARNING;
/// Information.
pub const INFO: &str = ph::INFO;
/// Done.
pub const CHECK: &str = ph::CHECK;
/// Undo.
pub const UNDO: &str = ph::ARROW_COUNTER_CLOCKWISE;
/// Redo.
pub const REDO: &str = ph::ARROW_CLOCKWISE;
/// The Listing.
pub const LISTING: &str = ph::TEXT_ALIGN_LEFT;
/// The Decompiler.
pub const DECOMPILER: &str = ph::BRACKETS_CURLY;
/// Imports.
pub const IMPORT: &str = ph::SIGN_IN;
/// Exports.
pub const EXPORT: &str = ph::SIGN_OUT;
/// A program file.
pub const PROGRAM: &str = ph::FILE_CODE;
/// Data, globals.
pub const DATA: &str = ph::DATABASE;
/// Program Trees, memory blocks.
pub const BLOCKS: &str = ph::STACK;
/// References.
pub const REFERENCES: &str = ph::ARROW_ELBOW_DOWN_RIGHT;
/// Copy.
pub const COPY: &str = ph::COPY;
/// Keyboard shortcuts.
pub const KEYBOARD: &str = ph::KEYBOARD;
/// The command palette.
pub const PALETTE: &str = ph::LIST_MAGNIFYING_GLASS;
/// Next-instruction navigation.
pub const NEXT_INSTRUCTION: &str = ph::CPU;
/// Next-data navigation.
pub const NEXT_DATA: &str = ph::BINARY;
/// Next-label navigation.
pub const NEXT_LABEL: &str = ph::TAG;
/// Next-function navigation.
pub const NEXT_FUNCTION: &str = ph::FUNCTION;
/// Go to.
pub const GOTO: &str = ph::CROSSHAIR;
/// Analysis.
pub const ANALYZE: &str = ph::PLAY;
/// Data Type Manager.
pub const DATATYPES: &str = ph::PUZZLE_PIECE;
/// Help.
pub const HELP: &str = ph::BOOK_OPEN;
/// Layout.
pub const LAYOUT: &str = ph::SQUARES_FOUR;
/// Graph.
pub const GRAPH: &str = ph::GRAPH;
