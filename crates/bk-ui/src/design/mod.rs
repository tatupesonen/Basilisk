//! The design system: tokens (colour, type, spacing), the egui theme built
//! from them, the syntax colours, icons and the shared components. The
//! reasoning is in `docs/features/ui-design.md`.

pub mod contrast;
pub mod icons;
pub mod syntax;
pub mod theme;
pub mod tokens;
pub mod typography;
pub mod widgets;

pub use tokens::{Density, ThemeKind, Tokens};
