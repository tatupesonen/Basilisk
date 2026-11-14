//! Circle ranges: sets of integers modulo 2ⁿ described as a half-open
//! interval `[left, right)` on the circle with a step, the values a
//! variable may take.
//!
//! Ghidra: class `CircleRange` in the decompiler's `rangeutil.hh` and
//! `rangeutil.cc` (lines 21–1,490). The decompiler pulls such ranges back
//! through operations (from a branch condition to the variable it
//! constrains) and pushes them forward (from inputs to an output);
//! jump-table recovery, value-set analysis and guard logic are built on
//! them. This crate ports the class and nothing above it: the wrapper
//! `pullBack(PcodeOp *, …)` arrives with the IR, and `ValueSet` and its
//! solver with the analyses that use them.
//!
//! Ghidra's approximations are the behaviour: a result that Ghidra
//! over-approximates is over-approximated here in the same way, and the
//! known gap in `contains` is kept. Where Ghidra's C++ is undefined (shift
//! counts of 64 or more, signed overflow), the result is the one both
//! reference builds compute; where it would divide by zero or loop forever
//! (only for steps no valid range has), the result is defined and
//! documented on the method (`docs/features/decomp-range.md`, section 8).
//! No method allocates or panics, whatever the field values.

mod arith;
mod compare;
mod overlap;
mod pull;
mod push;
mod range;
mod setops;

pub use compare::Translated;
pub use range::CircleRange;
pub use setops::Combined;
