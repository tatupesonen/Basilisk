//! P-code operation codes and the exact arithmetic of every p-code
//! operation.
//!
//! P-code is the intermediate language every processor is lifted to. This
//! crate defines its operation codes and what each operation computes —
//! integer, boolean and floating point, at every operand size — which the
//! decompiler uses to fold constants and the emulator to execute.
//!
//! | Module | Ghidra code it corresponds to |
//! |---|---|
//! | [`opcode`] | `opcodes.hh`/`.cc`, the opcode constants and mnemonics of `PcodeOp.java`, the boolean flips of `typeop.cc` |
//! | [`behavior`] | `opbehavior.hh`/`.cc` (operands of at most 8 bytes) and `ghidra/pcode/opbehavior/*.java` ([`behavior::wide`], operands of at most 64 bytes) |
//! | [`float`] | `float.hh`/`.cc` (the host level) and `ghidra/pcode/floatformat/` (`FloatFormat`, `BigFloat`: the exact level) |
//! | [`multiprecision`] | `multiprecision.hh`/`.cc` |
//! | [`mask`] | the size-mask and sign-extension helpers of `address.hh`/`.cc` and `ghidra/pcode/utils/Utils.java` |
//! | [`wide`] | the role `java.math.BigInteger` plays for operands wider than 8 bytes |
//!
//! Results equal Ghidra's bit for bit; the deliberate exceptions are listed
//! under "Differences from Ghidra" in `docs/features/pcode.md`.
//!
//! Evaluating an operation never panics, whatever the operand values and
//! sizes: failures are an [`EvalError`].
//!
//! ```
//! use bk_pcode::behavior::{evaluate_binary, evaluate_unary};
//! use bk_pcode::{EvalError, FloatFormats, OpCode};
//!
//! let formats = FloatFormats::DEFAULT;
//! // 0xff + 1 in one byte wraps to 0.
//! assert_eq!(evaluate_binary(OpCode::IntAdd, 1, 1, 0xff, 1, &formats), Ok(0));
//! // Sign-extend the byte 0x80 to four bytes.
//! assert_eq!(evaluate_unary(OpCode::IntSExt, 4, 1, 0x80, &formats), Ok(0xffff_ff80));
//! // 1.5f32 + 2.25f32
//! let sum = evaluate_binary(
//!     OpCode::FloatAdd,
//!     4,
//!     4,
//!     u64::from(1.5f32.to_bits()),
//!     u64::from(2.25f32.to_bits()),
//!     &formats,
//! );
//! assert_eq!(sum, Ok(u64::from(3.75f32.to_bits())));
//! assert_eq!(
//!     evaluate_binary(OpCode::IntDiv, 4, 4, 1, 0, &formats),
//!     Err(EvalError::DivideByZero)
//! );
//! ```

#![allow(
    clippy::float_cmp,
    reason = "this crate implements exact floating-point semantics; comparing floats exactly is the point"
)]

pub mod behavior;
pub mod error;
pub mod float;
pub mod mask;
pub mod multiprecision;
pub mod opcode;
pub mod wide;

pub use error::{Arity, EvalError, RecoverOp};
pub use float::{BigFloat, Decimal, FloatClass, FloatError, FloatFormat, FloatFormats, FloatKind};
pub use opcode::{BooleanFlip, OpCode, OpCodeError};
pub use wide::Wide;

/// The arbitrary-precision integer crate whose types appear in this crate's
/// exact-float API ([`BigFloat`], [`Decimal`]).
pub use num_bigint;
