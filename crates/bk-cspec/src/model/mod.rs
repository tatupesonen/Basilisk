//! Prototype models: calling conventions (Ghidra `ProtoModel`,
//! `ProtoModelMerged`, `ScoreProtoModel`, and the shared actions
//! `HiddenReturnAction`, `ShareStackAction` of `modelrules.cc`).

mod decode;
mod merged;
mod shared;

use bk_core::{Address, RangeList, SpaceId, SpaceManager, VarnodeData};

pub(crate) use decode::{DecodeContext, decode_model};
pub(crate) use merged::decode_merged;
pub use merged::{ScoreProtoModel, select_model};
pub use shared::SharedAction;

use crate::effect::{EffectKind, EffectRecord, lookup_effect};
use crate::entry::{Containment, Extension};
use crate::error::{CspecError, Result};
use crate::list::{Env, ParamList};
use crate::proto::{ParameterPieces, PrototypePieces};
use crate::status::Status;
use crate::trial::ParamActive;
use crate::types::ParamTypes;

/// Index of a model in its [`CompilerSpec`](crate::spec::CompilerSpec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelId(pub u32);

/// The reserved `extrapop` meaning "unknown" (Ghidra `extrapop_unknown`).
pub const EXTRAPOP_UNKNOWN: i32 = 0x8000;

/// A calling convention (Ghidra `ProtoModel`; a merged model has
/// [`ProtoModel::merged_models`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoModel {
    pub(crate) name: String,
    pub(crate) extrapop: i32,
    pub(crate) input: ParamList,
    pub(crate) output: ParamList,
    pub(crate) shared: Vec<SharedAction>,
    pub(crate) alias_of: Option<ModelId>,
    pub(crate) effects: Vec<EffectRecord>,
    pub(crate) likelytrash: Vec<VarnodeData>,
    pub(crate) internalstorage: Vec<VarnodeData>,
    pub(crate) inject_upon_entry: Option<u32>,
    pub(crate) inject_upon_return: Option<u32>,
    pub(crate) localrange: RangeList,
    pub(crate) paramrange: RangeList,
    pub(crate) stack_grows_negative: bool,
    pub(crate) has_this: bool,
    pub(crate) is_construct: bool,
    pub(crate) is_printed: bool,
    pub(crate) merged: Option<Vec<ModelId>>,
}

impl ProtoModel {
    /// The name (Ghidra `getName`).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Bytes popped beyond the return address, or [`EXTRAPOP_UNKNOWN`]
    /// (Ghidra `getExtraPop`).
    pub const fn extrapop(&self) -> i32 {
        self.extrapop
    }
    /// The input list (Ghidra `getInputResource`).
    pub const fn input(&self) -> &ParamList {
        &self.input
    }
    /// The output list (Ghidra `getOutputResource`).
    pub const fn output(&self) -> &ParamList {
        &self.output
    }
    /// The shared actions in order; the first is always the hidden return
    /// action.
    pub fn shared_actions(&self) -> &[SharedAction] {
        &self.shared
    }
    /// The model this is an alias of (Ghidra `getAliasParent`).
    pub const fn alias_of(&self) -> Option<ModelId> {
        self.alias_of
    }
    /// Side effects sorted by address (Ghidra `effectBegin`..`effectEnd`).
    pub fn effects(&self) -> &[EffectRecord] {
        &self.effects
    }
    /// Locations likely to hold trash, sorted (Ghidra `trashBegin`).
    pub fn likely_trash(&self) -> &[VarnodeData] {
        &self.likelytrash
    }
    /// Registers holding compiler constants, sorted (Ghidra
    /// `internalBegin`).
    pub fn internal_storage(&self) -> &[VarnodeData] {
        &self.internalstorage
    }
    /// Payload id injected at function entry (Ghidra
    /// `getInjectUponEntry`).
    pub const fn inject_upon_entry(&self) -> Option<u32> {
        self.inject_upon_entry
    }
    /// Payload id injected after a call (Ghidra `getInjectUponReturn`).
    pub const fn inject_upon_return(&self) -> Option<u32> {
        self.inject_upon_return
    }
    /// Possible local stack variables (Ghidra `getLocalRange`).
    pub const fn local_range(&self) -> &RangeList {
        &self.localrange
    }
    /// Possible stack parameters (Ghidra `getParamRange`).
    pub const fn param_range(&self) -> &RangeList {
        &self.paramrange
    }
    /// Ghidra `isStackGrowsNegative`.
    pub const fn is_stack_grows_negative(&self) -> bool {
        self.stack_grows_negative
    }
    /// Ghidra `hasThisPointer`.
    pub const fn has_this_pointer(&self) -> bool {
        self.has_this
    }
    /// Ghidra `isConstructor`.
    pub const fn is_constructor(&self) -> bool {
        self.is_construct
    }
    /// Whether the name is printed in declarations (Ghidra `printInDecl`).
    pub const fn print_in_decl(&self) -> bool {
        self.is_printed
    }
    /// For a merged model, the models it stands for (Ghidra `isMerged`,
    /// `getModel`).
    pub fn merged_models(&self) -> Option<&[ModelId]> {
        self.merged.as_deref()
    }
    /// Ghidra `isMerged`.
    pub const fn is_merged(&self) -> bool {
        self.merged.is_some()
    }

    /// Whether one model can stand for the other: the same, or one an
    /// alias of the other (Ghidra `isCompatible`).
    pub fn is_compatible(&self, me: ModelId, other: &Self, other_id: ModelId) -> bool {
        me == other_id || self.alias_of == Some(other_id) || other.alias_of == Some(me)
    }

    /// The effect of a call on a range (Ghidra `hasEffect`).
    pub fn has_effect(&self, manager: &SpaceManager, addr: Address, size: u32) -> EffectKind {
        lookup_effect(&self.effects, manager, addr, size)
    }

    /// Storage for every parameter of a prototype: the return value first,
    /// then the inputs, possibly with a hidden return pointer (Ghidra
    /// `assignParameterStorage`). With `ignore_output_error` a return value
    /// that cannot be assigned becomes `void`.
    pub fn assign_parameter_storage(
        &self,
        manager: &SpaceManager,
        types: &mut dyn ParamTypes,
        proto: &PrototypePieces,
        res: &mut Vec<ParameterPieces>,
        ignore_output_error: bool,
    ) -> Result<()> {
        let mut env = Env {
            manager,
            types,
            proto,
            depth: 0,
        };
        let mut input_status = Status::new(self.input.numgroup.max(0) as usize);
        let mut output_status = Status::new(self.output.numgroup.max(0) as usize);
        match self.output.assign_map(&mut env, &mut output_status, res) {
            Ok(()) => {}
            Err(CspecError::ParamUnassigned(_)) if ignore_output_error => {
                res.clear();
                let void = env.types.void();
                res.push(ParameterPieces::new(void));
            }
            Err(e) => return Err(e),
        }
        for a in &self.shared {
            a.apply_before(self, &mut env, res, &mut input_status, &output_status)?;
        }
        self.input.assign_map(&mut env, &mut input_status, res)?;
        for a in &self.shared {
            a.apply_after(self, &mut env, res, &input_status)?;
        }
        Ok(())
    }

    /// Marks input trials used or not (Ghidra `deriveInputMap`).
    pub fn derive_input_map(&self, manager: &SpaceManager, active: &mut ParamActive) -> Result<()> {
        self.input.fillin_map(manager, active)
    }
    /// Marks output trials used or not (Ghidra `deriveOutputMap`).
    pub fn derive_output_map(
        &self,
        manager: &SpaceManager,
        active: &mut ParamActive,
    ) -> Result<()> {
        self.output.fillin_map(manager, active)
    }
    /// Ghidra `checkInputJoin`.
    pub fn check_input_join(
        &self,
        m: &SpaceManager,
        hi: (Address, i32),
        lo: (Address, i32),
    ) -> bool {
        self.input.check_join(m, hi, lo)
    }
    /// Ghidra `checkOutputJoin`.
    pub fn check_output_join(
        &self,
        m: &SpaceManager,
        hi: (Address, i32),
        lo: (Address, i32),
    ) -> bool {
        self.output.check_join(m, hi, lo)
    }
    /// Ghidra `checkInputSplit`.
    pub fn check_input_split(&self, m: &SpaceManager, loc: Address, size: i32, split: i32) -> bool {
        self.input.check_split(m, loc, size, split)
    }
    /// Ghidra `characterizeAsInputParam`.
    pub fn characterize_as_input_param(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Containment {
        self.input.characterize(m, loc, size)
    }
    /// Ghidra `characterizeAsOutput`.
    pub fn characterize_as_output(&self, m: &SpaceManager, loc: Address, size: i32) -> Containment {
        self.output.characterize(m, loc, size)
    }
    /// Ghidra `possibleInputParam`.
    pub fn possible_input_param(&self, m: &SpaceManager, loc: Address, size: i32) -> bool {
        self.input.possible_param(m, loc, size)
    }
    /// Ghidra `possibleOutputParam`.
    pub fn possible_output_param(&self, m: &SpaceManager, loc: Address, size: i32) -> bool {
        self.output.possible_param(m, loc, size)
    }
    /// Ghidra `possibleInputParamWithSlot`.
    pub fn possible_input_param_with_slot(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<(i32, i32)> {
        self.input.possible_param_with_slot(m, loc, size)
    }
    /// Ghidra `possibleOutputParamWithSlot`.
    pub fn possible_output_param_with_slot(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<(i32, i32)> {
        self.output.possible_param_with_slot(m, loc, size)
    }
    /// Ghidra `unjustifiedInputParam`.
    pub fn unjustified_input_param(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        self.input.unjustified_container(m, loc, size)
    }
    /// Ghidra `assumedInputExtension`.
    pub fn assumed_input_extension(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> (Extension, Option<VarnodeData>) {
        self.input.assumed_extension(m, loc, size)
    }
    /// Ghidra `assumedOutputExtension`.
    pub fn assumed_output_extension(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> (Extension, Option<VarnodeData>) {
        self.output.assumed_extension(m, loc, size)
    }
    /// Ghidra `getBiggestContainedInputParam`.
    pub fn biggest_contained_input_param(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        self.input.biggest_contained_param(m, loc, size)
    }
    /// Ghidra `getBiggestContainedOutput`.
    pub fn biggest_contained_output(
        &self,
        m: &SpaceManager,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        self.output.biggest_contained_param(m, loc, size)
    }
    /// The stack space of the inputs (Ghidra `getSpacebase`).
    pub fn spacebase(&self) -> Option<SpaceId> {
        self.input.spacebase()
    }
    /// Ghidra `getMaxInputDelay`.
    pub const fn max_input_delay(&self) -> i32 {
        self.input.maxdelay
    }
    /// Ghidra `getMaxOutputDelay`.
    pub const fn max_output_delay(&self) -> i32 {
        self.output.maxdelay
    }
    /// Ghidra `isAutoKilledByCall`.
    pub const fn is_auto_killed_by_call(&self) -> bool {
        self.output.auto_killed_by_call
    }

    /// A copy under another name, as an alias of `parent` (Ghidra's copy
    /// constructor `ProtoModel(nm, op2)`).
    pub(crate) fn alias(&self, name: &str, parent: ModelId) -> Self {
        let mut m = self.clone();
        name.clone_into(&mut m.name);
        m.is_printed = true;
        if name == "__thiscall" {
            m.has_this = true;
        }
        m.alias_of = Some(parent);
        m
    }
}
