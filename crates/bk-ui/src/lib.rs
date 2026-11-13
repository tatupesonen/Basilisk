//! basilisk's desktop interface: the design system, the application shell
//! and the core views (listing, decompiler, symbol tree, functions, defined
//! strings, references, console), in egui.
//!
//! It corresponds to Ghidra's `CodeBrowser` tool and the plugins that make it
//! up (`Ghidra/Features/Base/.../app/plugin/core/codebrowser`,
//! `.../decompile`, `.../symboltree`, `.../functionwindow`,
//! `.../strings`, `.../navigation`, `.../console`), keeping Ghidra's
//! layout, names, menus and key bindings (`docs/features/ui-design.md`).
//!
//! The views know a program only through [`model::ProgramSource`], a
//! paged interface free of egui types, called off the UI thread through
//! [`task::DataClient`]. [`demo`] implements it for now.

pub mod actions;
pub mod demo;
pub mod design;
pub mod model;
pub mod nav;
pub mod shell;
pub mod task;
pub mod views;

pub use shell::{BasiliskApp, run_native};
