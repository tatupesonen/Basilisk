//! Address spaces, addresses, ranges, varnode data and bit helpers: the
//! address model everything else in basilisk speaks.
//!
//! This crate corresponds to Ghidra's `space.hh`/`space.cc`,
//! `address.hh`/`address.cc`, the `VarnodeData` part of `pcoderaw.hh` and the
//! `AddrSpaceManager` part of `translate.hh`/`translate.cc`. It depends on
//! `bk-marshal` and implements encoding and decoding for its types.
//!
//! - [`Space`] is one address space; [`SpaceManager`] owns the spaces of a
//!   processor, its join records and its registers ([`RegisterLookup`]).
//! - [`Address`] (space and offset, 16 bytes, ordered without the manager),
//!   [`SeqNum`], [`VarnodeData`] (space, offset and size).
//! - [`Range`] and [`RangeList`]; [`BitRange`].
//! - [`bits`]: the free bit-arithmetic helpers of `address.hh`.
//!
//! A [`SpaceId`] is the index of a space in its manager. Index 0 is always the
//! constant space, so an address knows it is a constant without the manager;
//! everything that depends on a space's properties takes the manager.

pub mod address;
pub mod bitrange;
pub mod bits;
pub mod error;
pub mod ids;
pub mod join;
pub mod manager;
pub mod provenance;
pub mod range;
pub mod rangelist;
pub mod register;
pub mod seqnum;
pub mod space;
pub mod varnode;

pub use address::{Address, RawAddress};
pub use bitrange::{BitOverlap, BitRange};
pub use bk_marshal::SpaceId;
pub use error::SpaceError;
pub use join::JoinRecord;
pub use manager::{AddressResolver, SpaceDirectory, SpaceManager, TruncationTag};
pub use provenance::Provenance;
pub use range::{Range, RangeBounds, RangeProperties};
pub use rangelist::{RangeList, RangeListBounds};
pub use register::{NoRegisters, RegisterLookup};
pub use seqnum::{RawSeqNum, SeqNum};
pub use space::{Space, SpaceFlags, SpaceKind, SpaceType};
pub use varnode::VarnodeData;
