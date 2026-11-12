//! Floating-point formats and their emulation.
//!
//! Two levels, as in Ghidra:
//!
//! - the *host* level ([`host`]): encodings of at most 8 bytes computed
//!   through the host's `f64`, matching the decompiler's C++ (`float.cc`);
//! - the *exact* level ([`BigFloat`], [`encode`], [`exact_ops`]):
//!   arbitrary-precision values with round-to-nearest-even for every format
//!   size, matching the Java emulator (`BigFloat.java`, `FloatFormat.java`).
//!
//! The two levels are separate implementations, as they are in Ghidra,
//! because they do not give identical results: the host level reproduces the
//! C++ including its treatment of NaN signs and its `round`, and can only
//! represent what a `u64` and an `f64` hold; the exact level reproduces the
//! Java, which canonicalises NaNs, rounds halfway cases differently and
//! supports the 10-, 16- and 32-byte formats. `docs/features/pcode.md`
//! lists where they differ.

mod arith;
pub mod bigfloat;
mod convert;
pub mod decimal;
pub mod display;
pub mod encode;
mod error;
pub mod exact_ops;
pub mod format;
pub mod host;

pub use bigfloat::{BigFloat, FloatKind};
pub use decimal::Decimal;
pub use error::FloatError;
pub use format::{FloatClass, FloatFormat, FloatFormats};
