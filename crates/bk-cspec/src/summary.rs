//! What decompiling a function tells about it, as plain data (ADR-025 3d):
//! [`FunctionSummary`] and [`CallSite`]. Nothing in this crate computes or
//! consumes a summary; the decompiler produces them (D17), the program
//! trait serves them (D06), and the program model stores them, which is
//! why the types live here and not in a decompiler crate.

use bk_core::{Address, Provenance, SpaceId, VarnodeData};
use serde::{Deserialize, Serialize};

use crate::proto::PrototypePieces;

/// An address in a serialisable form: space index and offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SummaryAddress {
    /// Index of the space in the program's space manager.
    pub space: u32,
    /// Byte offset.
    pub offset: u64,
}

impl SummaryAddress {
    /// The form of an address; `None` for the invalid address.
    pub fn from_address(addr: Address) -> Option<Self> {
        addr.space().map(|s| Self {
            space: s.index(),
            offset: addr.offset(),
        })
    }

    /// Back to an address.
    pub const fn to_address(self) -> Address {
        Address::new(SpaceId::new(self.space), self.offset)
    }
}

/// A storage location in a serialisable form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SummaryStorage {
    /// Start of the location.
    pub addr: SummaryAddress,
    /// Size in bytes.
    pub size: u32,
}

impl SummaryStorage {
    /// The form of a location; `None` without a space.
    pub fn from_varnode(v: VarnodeData) -> Option<Self> {
        Some(Self {
            addr: SummaryAddress::from_address(v.addr())?,
            size: v.size,
        })
    }
}

/// How sure the producer is of a part, in percent (0 to 100). An integer,
/// so summaries compare and serialise the same on every host.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Confidence(pub u8);

/// A part of a summary with where it came from and how sure it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sourced<T> {
    /// The value.
    pub value: T,
    /// Who supplied it.
    #[serde(with = "crate::provenance_serde")]
    pub provenance: Provenance,
    /// How sure.
    pub confidence: Confidence,
}

impl<T> Sourced<T> {
    /// A value from analysis with the given confidence.
    pub const fn analysis(value: T, confidence: u8) -> Self {
        Self {
            value,
            provenance: Provenance::Analysis,
            confidence: Confidence(confidence),
        }
    }
}

/// Whether a function returns to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Returns {
    /// Every path returns (or some do).
    Always,
    /// No path returns.
    Never,
    /// Not known.
    Unknown,
}

/// The function ends in a tail call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TailCall {
    /// The function jumped to, when known.
    pub target: Option<SummaryAddress>,
}

/// Whether an access reads or writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessKind {
    /// A load.
    Read,
    /// A store.
    Write,
}

/// One access through a pointer parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PointerAccess {
    /// Offset from the pointer.
    pub offset: i64,
    /// Bytes accessed.
    pub size: u32,
    /// Stride of an indexed access, 0 if none.
    pub stride: i64,
    /// Read or write.
    pub kind: AccessKind,
}

/// The accesses through one pointer parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamAccesses {
    /// Index of the parameter in the prototype.
    pub param: u32,
    /// The accesses, in the producer's order.
    pub accesses: Vec<PointerAccess>,
}

/// A function summary (ADR-025 3d).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// The function's entry.
    pub address: SummaryAddress,
    /// The prototype as pieces.
    pub prototype: Sourced<PrototypePieces>,
    /// Assigned storage: the return value first, then each parameter;
    /// `None` where there is none.
    pub storage: Sourced<Vec<Option<SummaryStorage>>>,
    /// Whether it returns.
    pub returns: Sourced<Returns>,
    /// Whether it ends in a tail call.
    pub tail_call: Sourced<Option<TailCall>>,
    /// The stack change across a call (`extrapop` as recovered), if known.
    pub stack_change: Sourced<Option<i32>>,
    /// Accesses through pointer parameters.
    pub pointer_accesses: Sourced<Vec<ParamAccesses>>,
    /// Functions called, in address order.
    pub callees: Sourced<Vec<SummaryAddress>>,
}

/// A call: the calling function and the address of the call instruction,
/// the key of D06's "does this call return" question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallSite {
    /// The calling function's entry.
    pub caller: SummaryAddress,
    /// The call instruction.
    pub address: SummaryAddress,
}
