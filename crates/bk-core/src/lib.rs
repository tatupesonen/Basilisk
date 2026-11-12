//! Address spaces, addresses, ranges, varnode data and bit helpers: the
//! address model everything else in basilisk speaks.
//!
//! This crate corresponds to Ghidra's `space.hh`/`space.cc`,
//! `address.hh`/`address.cc`, the `VarnodeData` part of `pcoderaw.hh` and the
//! `AddrSpaceManager` part of `translate.hh`/`translate.cc`. It depends on
//! `bk-marshal` and implements encoding and decoding for its types.
//!
//! **Work in progress (handover).** Only the modules declared below are part
//! of the build. `register.rs`, `varnode.rs` and `space/mod.rs` are written
//! but have never been compiled, because the modules they depend on
//! (`address`, `manager`, `space::codec`, `space::text`, `join`, `range`) do
//! not exist yet. See `docs/agents/core-marshal.md`.

pub mod bits;
pub mod error;
pub mod ids;

pub use bk_marshal::SpaceId;
pub use error::SpaceError;
