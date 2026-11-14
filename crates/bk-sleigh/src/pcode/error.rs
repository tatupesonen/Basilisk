//! Why an instruction could not be lifted to p-code
//! (`features/sleigh-pcode.md` 4.4).

use bk_core::Address;

use crate::error::{DecodeError, ErrorClass, RawText};

/// A bound of p-code generation that Ghidra's C++ does not have (ADR-009).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LiftLimit {
    /// More ops in one instruction than the builder allows.
    Ops,
    /// More delay-slot and crossbuild levels nested than the builder allows.
    Nesting,
    /// `BUILD` directives nested more deeply than a parse can be.
    BuildDepth,
}

impl std::fmt::Display for LiftLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ops => "more than 65536 p-code ops in one instruction",
            Self::Nesting => "more than 64 nested delay-slot and crossbuild levels",
            Self::BuildDepth => "BUILD directives nested too deeply",
        })
    }
}

/// Why lifting failed. Nothing reaches the emitter when lifting fails.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LiftError {
    /// The instruction (or a delay-slot instruction) could not be decoded,
    /// or its handles not resolved.
    #[error(transparent)]
    Decode(DecodeError),
    /// A delay-slot instruction does not decode (Ghidra's `BadDataError`
    /// from the nested parse).
    #[error("{source}")]
    DelaySlot {
        /// The instruction being lifted.
        address: Address,
        /// The delay-slot instruction's error.
        source: DecodeError,
    },
    /// A constructor without a p-code template was reached (Ghidra
    /// `UnimplError`). `text` names the innermost instruction being built.
    #[error("Instruction not implemented in pcode:\n {text}")]
    Unimplemented {
        /// The instruction being lifted.
        address: Address,
        /// `<addr>: <mnemonic>  <body>` of the instruction without p-code.
        text: String,
        /// The flow length (the instruction and its delay slots).
        flow_length: u32,
    },
    /// The address is not a multiple of the language's alignment.
    #[error("Instruction address not aligned: {}", at.raw())]
    Unaligned {
        /// The instruction's address.
        address: Address,
        /// The address as text.
        at: RawText,
    },
    /// A relative branch names a label that was never placed.
    #[error("Reference to non-existant sleigh label")]
    MissingLabel {
        /// The instruction being lifted.
        address: Address,
    },
    /// `CROSSBUILD` inside a named section.
    #[error("CROSSBUILD directive within a named section")]
    CrossBuildInSection {
        /// The instruction being lifted.
        address: Address,
    },
    /// The crossbuild target does not decode.
    #[error("Could not obtain cached crossbuild instruction")]
    CrossBuildTarget {
        /// The instruction being lifted.
        address: Address,
        /// The target address.
        target: Address,
    },
    /// A delay slot's instructions were not decoded with the instruction
    /// (a delay slot of a delay-slot instruction reaching past the run
    /// [`Decoder::prepare`](crate::Decoder::prepare) decoded).
    #[error("Could not obtain cached delay slot instruction")]
    DelaySlotMissing {
        /// The instruction being lifted.
        address: Address,
    },
    /// `DELAY_SLOT` or `CROSSBUILD` in a free-standing template.
    #[error("{directive} directive in a free-standing template")]
    DirectiveInTemplate {
        /// The instruction address of the injection.
        address: Address,
        /// The directive.
        directive: &'static str,
    },
    /// One op with more than 4,096 varnodes.
    #[error("Maximum parameters exceeded for a single p-code op")]
    TooManyVarnodes {
        /// The instruction being lifted.
        address: Address,
    },
    /// A bound of the builder was exceeded.
    #[error("{limit}")]
    Limit {
        /// The instruction being lifted.
        address: Address,
        /// Which bound.
        limit: LiftLimit,
    },
}

impl From<DecodeError> for LiftError {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::Unaligned { address, at } => Self::Unaligned { address, at },
            other => Self::Decode(other),
        }
    }
}

impl LiftError {
    /// The address of the instruction being lifted.
    pub fn address(&self) -> Address {
        match self {
            Self::Decode(error) => error.address(),
            Self::DelaySlot { address, .. }
            | Self::Unimplemented { address, .. }
            | Self::Unaligned { address, .. }
            | Self::MissingLabel { address }
            | Self::CrossBuildInSection { address }
            | Self::CrossBuildTarget { address, .. }
            | Self::DelaySlotMissing { address }
            | Self::DirectiveInTemplate { address, .. }
            | Self::TooManyVarnodes { address }
            | Self::Limit { address, .. } => *address,
        }
    }

    /// The exception class Ghidra throws (`pcodedump`'s `U` record kind).
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::Decode(error) | Self::DelaySlot { source: error, .. } => error.class(),
            Self::Unimplemented { .. } | Self::Unaligned { .. } => ErrorClass::Unimplemented,
            _ => ErrorClass::Lowlevel,
        }
    }

    /// The length Ghidra reports with the error when it reports one (an
    /// unimplemented instruction: its flow length); `None` otherwise.
    pub fn flow_length(&self) -> Option<u32> {
        match self {
            Self::Unimplemented { flow_length, .. } if *flow_length > 0 => Some(*flow_length),
            _ => None,
        }
    }
}
