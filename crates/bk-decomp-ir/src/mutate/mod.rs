//! The mutation interface (ADR-025 3a, spec 4.5): every structural change
//! of the IR goes through these methods of [`Ssa`](crate::Ssa), named after
//! `Funcdata`'s.

pub mod annotate;
pub mod env;
mod insert;
mod op;
pub mod varnode;
