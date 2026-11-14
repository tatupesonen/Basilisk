//! The decompiler's block graph, its analyses, the structured-block
//! hierarchy and the control-flow structurer.
//!
//! This crate corresponds to Ghidra's `block.hh`/`block.cc` (the graph-only
//! parts of `FlowBlock`, `BlockGraph` and every structured kind) and
//! `blockaction.hh`/`blockaction.cc` lines 20–1904 (`FloatingEdge`,
//! `LoopBody`, `TraceDAG`, `CollapseStructure`), under
//! `Ghidra/Features/Decompiler/src/decompile/cpp/`. Its specification is
//! `docs/features/decomp-cfg.md`.
//!
//! - [`Cfg`]: the control-flow graph as a value, with Ghidra's edge surgery
//!   and analyses (spanning tree, irreducible and loop edges, dominators).
//! - [`structure`]: ADR-025 item 3b — a pure function of a graph, per-block
//!   [`BlockFacts`] and [`StructureOptions`], returning a [`Structured`]
//!   (the [`Hierarchy`], the condition flips and goto marks to apply to the
//!   basic blocks, the data-flow change count and a [`Measure`]). Goto
//!   selection is the replaceable [`GotoSelector`] unit, whose Ghidra
//!   implementation is [`GhidraGotoSelector`].
//! - [`finish`]: what `ActionFinalStructure` does to the hierarchy.
//!
//! Behaviour is Ghidra's, including the order in which lists and edges are
//! walked and mutated, because the rules read edge positions. Nothing
//! recurses over input-sized structures, and every call is bounded by
//! [`Limits`].

mod analysis;
mod cfg;
pub mod codec;
mod error;
mod facts;
mod finish;
mod flags;
mod gotos;
mod graph;
mod hierarchy;
mod limits;
mod structure;

pub use cfg::Cfg;
pub use error::{CfgError, LimitKind};
pub use facts::{BlockFacts, Fact};
pub use finish::{CaseLabels, FinishMeasure, finish};
pub use flags::{CondOp, Kind, edge_labels, node_flags};
pub use gotos::selector::{CollapseView, GhidraGotoSelector, GotoSelector, LoopInfo, loop_bodies};
pub use graph::NodeId;
pub use hierarchy::{CaseOrder, EdgeView, Hierarchy};
pub use limits::Limits;
pub use structure::{
    Analyse, GotoCause, GotoCounts, GotoMark, Measure, RULE_BLOCKCAT, RULE_BLOCKDOWHILE,
    RULE_BLOCKGOTO, RULE_BLOCKIFELSE, RULE_BLOCKIFNOEXIT, RULE_BLOCKINFLOOP, RULE_BLOCKOR,
    RULE_BLOCKPROPERIF, RULE_BLOCKSWITCH, RULE_BLOCKWHILEDO, RULE_CASEFALLTHRU, Record,
    StructureOptions, Structured, TraceRecord, UNIT_SELECTGOTO, structure,
};
