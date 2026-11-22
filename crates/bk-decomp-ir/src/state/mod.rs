//! Loading and writing the oracle's state dumps (`bkstate`,
//! `docs/features/decomp-oracle.md` 4.4, spec 4.8) for the parts of a
//! function this crate holds: the `K` counters, `@spaces` (read),
//! `@varnodes`, `@locorder`, `@deforder`, `@ops`, `@oplists`, `@blocks`.
//! Every other section passes through unchanged.
//!
//! Types are dump-local: `t<n>` loads as `TypeId::from_raw(n)` and writes
//! back as `t<n>`, until D07 attaches a type factory.

mod joins;
mod load;
mod names;
mod spaces;
mod write;

pub use joins::{JoinRecordDump, install_joins};
pub use load::load;
pub use names::DumpNames;
pub use spaces::spaces_from_dump;
pub use write::{CanonicalCalls, write};

/// Why a dump cannot be loaded or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// A name in the dump refers to nothing.
    #[error("{what} {name} does not exist")]
    Dangling {
        /// What kind of object.
        what: &'static str,
        /// The name.
        name: String,
    },
    /// A value is out of the range the IR accepts.
    #[error("{what} {value} is out of range")]
    Range {
        /// The field.
        what: &'static str,
        /// The value.
        value: String,
    },
    /// A value does not fit the integer type the IR stores it in.
    #[error("{what} {value} is out of range")]
    Convert {
        /// The field.
        what: &'static str,
        /// The value.
        value: String,
        /// The failed conversion.
        #[source]
        source: std::num::TryFromIntError,
    },
    /// The dump contradicts itself.
    #[error("inconsistent dump: {what} ({detail})")]
    Inconsistent {
        /// What is inconsistent.
        what: &'static str,
        /// The objects involved.
        detail: String,
    },
    /// An address space could not be built.
    #[error("space {name}: {source}")]
    Space {
        /// The space.
        name: String,
        /// Why.
        source: bk_core::SpaceError,
    },
    /// The block graph refused the dump's edges.
    #[error(transparent)]
    Cfg(#[from] bk_decomp_cfg::CfgError),
    /// The IR refused an operation.
    #[error(transparent)]
    Ir(#[from] crate::error::IrError),
}

pub(crate) fn inconsistent(what: &'static str, detail: impl std::fmt::Display) -> StateError {
    StateError::Inconsistent {
        what,
        detail: detail.to_string(),
    }
}

pub(crate) fn dangling(what: &'static str, name: impl std::fmt::Display) -> StateError {
    StateError::Dangling {
        what,
        name: name.to_string(),
    }
}
