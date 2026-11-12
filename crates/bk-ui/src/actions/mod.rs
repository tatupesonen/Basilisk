//! Actions and key bindings: one registry that menus, toolbar, context
//! menus, the command palette and the keyboard all read.

pub mod keymap;
pub mod registry;

pub use keymap::{KeyChord, Keymap};
pub use registry::{ACTIONS, Action, ActionContext, ActionId, Menu, Scope, action};
