//! A compiler specification as read from a `.cspec` (the state Ghidra's
//! `parseCompilerConfig` leaves in its `Architecture`).

mod apply;
mod elements;
mod reader;

use std::collections::BTreeMap;
use std::sync::Arc;

use bk_core::{Range, RangeProperties, SpaceId, VarnodeData};

pub use reader::{ReadOptions, find_cspec_path};

use crate::inject::{InjectLibrary, SegmentOpDecl};
use crate::model::{ModelId, ProtoModel};

/// The official stack (Ghidra's `<stackpointer>`, `decodeStackPointer`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackPointerDef {
    /// The space the stack lives in.
    pub base: SpaceId,
    /// The stack pointer register.
    pub register: VarnodeData,
    /// The register size as used, truncated to a truncated space.
    pub truncated_size: u32,
    /// Small values are justified opposite to the endianness.
    pub reverse_justify: bool,
    /// The stack grows towards smaller addresses.
    pub grows_negative: bool,
    /// The `stack` space created for it.
    pub space: SpaceId,
}

/// A further register-relative space (Ghidra's `<spacebase>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpacebaseDef {
    /// Name of the new space.
    pub name: String,
    /// The base register.
    pub register: VarnodeData,
    /// The space it points into.
    pub base: SpaceId,
    /// The space created.
    pub space: SpaceId,
}

/// A register the decompiler splits on sight (Ghidra
/// `PreferSplitRecord`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferSplit {
    /// The whole register.
    pub storage: VarnodeData,
    /// Bytes in the first (least significant) piece.
    pub split_offset: u32,
}

/// An element kept for another component to read (`<data_organization>`,
/// `<enum>`, `<context_data>`): its name and where it is in the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptElement {
    /// The element name.
    pub name: String,
    /// Index among the children of `<compiler_spec>`.
    pub position: usize,
    /// Byte offset of the element in [`CompilerSpec::source`].
    pub source_offset: usize,
}

/// A compiler specification: models, stack, memory properties, fix-up
/// declarations. Immutable after reading and `Send + Sync`.
#[derive(Clone, Debug)]
pub struct CompilerSpec {
    pub(crate) source: Arc<str>,
    pub(crate) models: Vec<ProtoModel>,
    pub(crate) names: BTreeMap<String, ModelId>,
    pub(crate) default_model: ModelId,
    pub(crate) eval_current: Option<ModelId>,
    pub(crate) eval_called: Option<ModelId>,
    pub(crate) stack_pointer: Option<StackPointerDef>,
    pub(crate) spacebases: Vec<SpacebaseDef>,
    pub(crate) default_return: Option<VarnodeData>,
    pub(crate) globals: Vec<RangeProperties>,
    pub(crate) readonly: Vec<Range>,
    pub(crate) no_high_ptr: Vec<Range>,
    pub(crate) prefer_split: Vec<PreferSplit>,
    pub(crate) aggressive_trim: bool,
    pub(crate) funcptr_align: u32,
    pub(crate) deadcode_delays: Vec<(SpaceId, i32)>,
    pub(crate) infer_ptr_bounds: Vec<Range>,
    pub(crate) injects: InjectLibrary,
    pub(crate) call_other_fixups: Vec<u32>,
    pub(crate) segment_ops: Vec<SegmentOpDecl>,
    pub(crate) kept: Vec<KeptElement>,
}

impl CompilerSpec {
    /// The text of the `.cspec` the spec was read from.
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Every model, aliases and merged models included, in reading order.
    pub fn models(&self) -> &[ProtoModel] {
        &self.models
    }
    /// The model with an id.
    pub fn model(&self, id: ModelId) -> Option<&ProtoModel> {
        self.models.get(id.0 as usize)
    }
    /// The id of a model by name (Ghidra `getModel`).
    pub fn model_id(&self, name: &str) -> Option<ModelId> {
        self.names.get(name).copied()
    }
    /// A model by name.
    pub fn model_by_name(&self, name: &str) -> Option<&ProtoModel> {
        self.model_id(name).and_then(|id| self.model(id))
    }
    /// Whether a model of that name exists (Ghidra `hasModel`); the
    /// callback D02's C parser takes.
    pub fn has_model(&self, name: &str) -> bool {
        self.names.contains_key(name)
    }
    /// Model names in Ghidra's map order (by name).
    pub fn model_names(&self) -> impl Iterator<Item = &str> {
        self.names.keys().map(String::as_str)
    }
    /// The default model (Ghidra `defaultfp`).
    pub const fn default_model(&self) -> ModelId {
        self.default_model
    }
    /// The default model's name, which D02's `TypeEnv::default_model`
    /// takes.
    pub fn default_model_name(&self) -> &str {
        self.model(self.default_model).map_or("", ProtoModel::name)
    }
    /// The model for evaluating the current function (Ghidra
    /// `evalfp_current`).
    pub const fn eval_current(&self) -> Option<ModelId> {
        self.eval_current
    }
    /// The model for evaluating called functions (Ghidra
    /// `evalfp_called`).
    pub const fn eval_called(&self) -> Option<ModelId> {
        self.eval_called
    }
    /// The official stack.
    pub const fn stack_pointer(&self) -> Option<&StackPointerDef> {
        self.stack_pointer.as_ref()
    }
    /// Further register-relative spaces.
    pub fn spacebases(&self) -> &[SpacebaseDef] {
        &self.spacebases
    }
    /// The default return address storage (Ghidra `defaultReturnAddr`).
    pub const fn default_return_address(&self) -> Option<VarnodeData> {
        self.default_return
    }
    /// Ranges holding global variables, as read (Ghidra's `<global>`).
    pub fn globals(&self) -> &[RangeProperties] {
        &self.globals
    }
    /// Read-only ranges.
    pub fn readonly(&self) -> &[Range] {
        &self.readonly
    }
    /// Ranges into which constants never point.
    pub fn no_high_ptr(&self) -> &[Range] {
        &self.no_high_ptr
    }
    /// Registers to split.
    pub fn prefer_split(&self) -> &[PreferSplit] {
        &self.prefer_split
    }
    /// Whether sign extensions are trimmed aggressively (Ghidra
    /// `aggressive_ext_trim`).
    pub const fn aggressive_trim(&self) -> bool {
        self.aggressive_trim
    }
    /// Low bits of function pointers that carry no address (Ghidra
    /// `funcptr_align`).
    pub const fn funcptr_align(&self) -> u32 {
        self.funcptr_align
    }
    /// Dead-code delays by space.
    pub fn deadcode_delays(&self) -> &[(SpaceId, i32)] {
        &self.deadcode_delays
    }
    /// Pointer-inference bounds.
    pub fn infer_ptr_bounds(&self) -> &[Range] {
        &self.infer_ptr_bounds
    }
    /// The payload declarations.
    pub const fn injects(&self) -> &InjectLibrary {
        &self.injects
    }
    /// Payload ids of the `<callotherfixup>`s, in order.
    pub fn call_other_fixups(&self) -> &[u32] {
        &self.call_other_fixups
    }
    /// The `<segmentop>` declarations.
    pub fn segment_ops(&self) -> &[SegmentOpDecl] {
        &self.segment_ops
    }
    /// Elements kept for other components (data organisation, enum,
    /// context data).
    pub fn kept_elements(&self) -> &[KeptElement] {
        &self.kept
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_spec_is_send_and_sync() {
        fn check<T: Send + Sync + 'static>() {}
        check::<super::CompilerSpec>();
        check::<crate::proto::FuncProto>();
    }
}
