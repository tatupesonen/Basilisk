//! Scope behaviour (Ghidra `Scope` and `ScopeInternal`), as methods of
//! [`Database`](crate::Database) taking the scope's id.

pub mod add;
mod build;
mod find;
mod mutate;
pub mod names;
pub mod query;
