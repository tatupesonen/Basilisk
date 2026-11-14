//! A function's prototype with an internal store (Ghidra `FuncProto`, less
//! the four methods that touch a scope or varnodes, which are D07's).

use bitflags::bitflags;
use bk_core::{Provenance, SpaceManager, SpaceType, VarnodeData};

use super::pieces::{ParameterPieces, PieceFlags, PrototypePieces};
use super::store::{ParameterBasic, ProtoStoreInternal};
use crate::effect::EffectRecord;
use crate::error::{CspecError, Result};
use crate::model::{EXTRAPOP_UNKNOWN, ModelId, ProtoModel, select_model};
use crate::spec::CompilerSpec;
use crate::trial::ParamActive;
use crate::types::{Metatype, ParamTypes};

bitflags! {
    /// Properties of a prototype (Ghidra's `FuncProto` flag values).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct ProtoFlags: u32 {
        /// Takes variable arguments.
        const DOTDOTDOT = 1;
        /// Takes no inputs, locked.
        const VOIDINPUTLOCK = 2;
        /// The model is locked.
        const MODELLOCK = 4;
        /// Inlined by the decompiler.
        const IS_INLINE = 8;
        /// Does not return.
        const NO_RETURN = 16;
        /// Parameter shift applied.
        const PARAMSHIFT_APPLIED = 32;
        /// Inputs are not properly represented.
        const ERROR_INPUTPARAM = 64;
        /// The return value is not properly represented.
        const ERROR_OUTPUTPARAM = 128;
        /// Storage is custom.
        const CUSTOM_STORAGE = 256;
        /// A constructor.
        const IS_CONSTRUCTOR = 0x200;
        /// A destructor.
        const IS_DESTRUCTOR = 0x400;
        /// A method with a `this` pointer.
        const HAS_THISPTR = 0x800;
        /// Overrides one call site.
        const IS_OVERRIDE = 0x1000;
        /// Output storage is always killed by call.
        const AUTO_KILLEDBYCALL = 0x2000;
    }
}

/// A prototype's model: an id in the spec, and for a name the spec does
/// not know, that name with the default model's behaviour (Ghidra
/// `UnknownProtoModel`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModelRef {
    /// The model whose behaviour applies.
    pub id: ModelId,
    /// The unrecognised name, for an unknown model.
    pub unknown: Option<String>,
}

impl ModelRef {
    /// A known model.
    pub const fn known(id: ModelId) -> Self {
        Self { id, unknown: None }
    }
}

/// A function prototype (Ghidra `FuncProto` with a `ProtoStoreInternal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncProto {
    pub(crate) model: Option<ModelRef>,
    pub(crate) store: Option<ProtoStoreInternal>,
    pub(crate) extrapop: i32,
    pub(crate) flags: ProtoFlags,
    pub(crate) effects: Vec<EffectRecord>,
    pub(crate) likelytrash: Vec<VarnodeData>,
    pub(crate) injectid: Option<u32>,
    pub(crate) return_bytes_consumed: i32,
    /// Where the prototype came from (ADR-025 3f); no decision depends on
    /// it.
    pub provenance: Provenance,
}

impl Default for FuncProto {
    fn default() -> Self {
        Self::new()
    }
}

impl FuncProto {
    /// An empty prototype without model or store (Ghidra's constructor).
    pub const fn new() -> Self {
        Self {
            model: None,
            store: None,
            extrapop: 0,
            flags: ProtoFlags::empty(),
            effects: Vec::new(),
            likelytrash: Vec::new(),
            injectid: None,
            return_bytes_consumed: 0,
            provenance: Provenance::Default,
        }
    }

    /// The model reference.
    pub const fn model_ref(&self) -> Option<&ModelRef> {
        self.model.as_ref()
    }
    /// The model whose behaviour applies.
    pub fn model<'s>(&self, spec: &'s CompilerSpec) -> Option<&'s ProtoModel> {
        self.model.as_ref().and_then(|m| spec.model(m.id))
    }
    pub(crate) fn require_model<'s>(&self, spec: &'s CompilerSpec) -> Result<&'s ProtoModel> {
        self.model(spec)
            .ok_or_else(|| CspecError::new("Prototype has no model"))
    }
    /// The model's name, or the unknown name (Ghidra `getModelName`).
    pub fn model_name<'s>(&'s self, spec: &'s CompilerSpec) -> &'s str {
        match &self.model {
            Some(ModelRef {
                unknown: Some(n), ..
            }) => n,
            Some(m) => spec.model(m.id).map_or("", ProtoModel::name),
            None => "",
        }
    }
    /// Ghidra `isModelUnknown`.
    pub fn is_model_unknown(&self) -> bool {
        self.model.as_ref().is_some_and(|m| m.unknown.is_some())
    }
    /// Ghidra `printModelInDecl`: an unknown model prints unless it is
    /// named `unknown`.
    pub fn print_model_in_decl(&self, spec: &CompilerSpec) -> bool {
        match &self.model {
            Some(ModelRef {
                unknown: Some(n), ..
            }) => n != "unknown",
            Some(m) => spec.model(m.id).is_some_and(ProtoModel::print_in_decl),
            None => false,
        }
    }
    /// Ghidra `hasModel`.
    pub const fn has_model(&self) -> bool {
        self.model.is_some()
    }
    /// The store.
    pub const fn store(&self) -> Option<&ProtoStoreInternal> {
        self.store.as_ref()
    }
    /// The flags.
    pub const fn flags(&self) -> ProtoFlags {
        self.flags
    }
    /// Sets or clears flags (the individual `set*` methods of Ghidra).
    pub fn set_flag(&mut self, flag: ProtoFlags, val: bool) {
        self.flags.set(flag, val);
    }
    /// Ghidra `getExtraPop`.
    pub const fn extrapop(&self) -> i32 {
        self.extrapop
    }
    /// Ghidra `setExtraPop`.
    pub fn set_extrapop(&mut self, val: i32) {
        self.extrapop = val;
    }
    /// The call fix-up id, if inlined by one (Ghidra `getInjectId`).
    pub const fn inject_id(&self) -> Option<u32> {
        self.injectid
    }
    /// Ghidra `getReturnBytesConsumed`.
    pub const fn return_bytes_consumed(&self) -> i32 {
        self.return_bytes_consumed
    }
    /// Ghidra `isDotdotdot`.
    pub const fn is_dotdotdot(&self) -> bool {
        self.flags.contains(ProtoFlags::DOTDOTDOT)
    }
    /// Ghidra `isModelLocked`.
    pub const fn is_model_locked(&self) -> bool {
        self.flags.contains(ProtoFlags::MODELLOCK)
    }
    /// Ghidra `getComparableFlags`.
    pub const fn comparable_flags(&self) -> u32 {
        self.flags.bits()
            & (ProtoFlags::DOTDOTDOT.bits()
                | ProtoFlags::IS_CONSTRUCTOR.bits()
                | ProtoFlags::IS_DESTRUCTOR.bits()
                | ProtoFlags::HAS_THISPTR.bits())
    }
    /// The parameters (Ghidra `numParams`, `getParam`).
    pub fn params(&self) -> impl Iterator<Item = Option<&ParameterBasic>> {
        self.store
            .iter()
            .flat_map(|s| s.inputs.iter().map(Option::as_ref))
    }
    /// Ghidra `numParams`.
    pub fn num_params(&self) -> usize {
        self.store
            .as_ref()
            .map_or(0, ProtoStoreInternal::num_inputs)
    }
    /// Ghidra `getParam`.
    pub fn param(&self, i: usize) -> Option<&ParameterBasic> {
        self.store.as_ref().and_then(|s| s.input(i))
    }
    /// Ghidra `getOutput`.
    pub fn output(&self) -> Option<&ParameterBasic> {
        self.store.as_ref().map(ProtoStoreInternal::output)
    }

    /// Establishes a model; the `extrapop` and method flags follow it
    /// (Ghidra `setModel`).
    pub fn set_model(&mut self, spec: &CompilerSpec, model: Option<ModelRef>) {
        let Some(m) = model.as_ref().and_then(|r| spec.model(r.id)) else {
            self.model = model;
            self.extrapop = EXTRAPOP_UNKNOWN;
            return;
        };
        if self.model.is_none() || m.extrapop() != EXTRAPOP_UNKNOWN {
            self.extrapop = m.extrapop();
        }
        if m.has_this_pointer() {
            self.flags |= ProtoFlags::HAS_THISPTR;
        }
        if m.is_constructor() {
            self.flags |= ProtoFlags::IS_CONSTRUCTOR;
        }
        if m.is_auto_killed_by_call() {
            self.flags |= ProtoFlags::AUTO_KILLEDBYCALL;
        }
        self.model = model;
    }

    /// Gives the prototype an internal store and, if it has none, a model
    /// (Ghidra `setInternal`).
    pub fn set_internal(
        &mut self,
        spec: &CompilerSpec,
        model: ModelRef,
        void_ty: crate::types::TypeHandle,
    ) {
        self.store = Some(ProtoStoreInternal::new(void_ty));
        if self.model.is_none() {
            self.set_model(spec, Some(model));
        }
    }

    /// Copies another prototype (Ghidra `copy`).
    pub fn copy_from(&mut self, other: &Self) {
        self.model.clone_from(&other.model);
        self.extrapop = other.extrapop;
        self.flags = other.flags;
        self.store.clone_from(&other.store);
        self.effects.clone_from(&other.effects);
        self.likelytrash.clone_from(&other.likelytrash);
        self.injectid = other.injectid;
    }

    /// Copies the properties that affect data-flow (Ghidra
    /// `copyFlowEffects`).
    pub fn copy_flow_effects(&mut self, other: &Self) {
        let mask = ProtoFlags::IS_INLINE | ProtoFlags::NO_RETURN;
        self.flags.remove(mask);
        self.flags |= other.flags & mask;
        self.injectid = other.injectid;
    }

    /// Ghidra `isInputLocked`.
    pub fn is_input_locked(&self) -> bool {
        if self.flags.contains(ProtoFlags::VOIDINPUTLOCK) {
            return true;
        }
        self.param(0).is_some_and(ParameterBasic::is_type_locked)
    }
    /// Ghidra `isOutputLocked`.
    pub fn is_output_locked(&self) -> bool {
        self.output().is_some_and(ParameterBasic::is_type_locked)
    }

    /// Locks or unlocks the input types (Ghidra `setInputLock`).
    pub fn set_input_lock(&mut self, types: &dyn ParamTypes, val: bool) {
        if val {
            self.flags |= ProtoFlags::MODELLOCK;
        }
        if self.num_params() == 0 {
            self.flags.set(ProtoFlags::VOIDINPUTLOCK, val);
            return;
        }
        if let Some(s) = &mut self.store {
            for p in s.inputs.iter_mut().flatten() {
                p.set_type_lock(types, val);
            }
        }
    }

    /// Locks or unlocks the return type (Ghidra `setOutputLock`).
    pub fn set_output_lock(&mut self, types: &dyn ParamTypes, val: bool) {
        if val {
            self.flags |= ProtoFlags::MODELLOCK;
        }
        if let Some(s) = &mut self.store {
            s.output.set_type_lock(types, val);
        }
    }

    /// Ghidra `setModelLock`.
    pub fn set_model_lock(&mut self, val: bool) {
        self.flags.set(ProtoFlags::MODELLOCK, val);
    }

    /// Records the smallest hint of return bytes used (Ghidra
    /// `setReturnBytesConsumed`).
    pub fn set_return_bytes_consumed(&mut self, val: i32) -> bool {
        if val == 0 {
            return false;
        }
        if self.return_bytes_consumed == 0 || val < self.return_bytes_consumed {
            self.return_bytes_consumed = val;
            return true;
        }
        false
    }

    /// For a locked prototype with unknown `extrapop`, computes it as
    /// 32-bit x86 would (Ghidra `resolveExtraPop`).
    pub fn resolve_extra_pop(&mut self, manager: &SpaceManager) {
        if !self.is_input_locked() {
            return;
        }
        if self.is_dotdotdot() {
            if self.num_params() != 0 {
                self.extrapop = 4;
            }
            return;
        }
        let mut expop = 4;
        for p in self.params().flatten() {
            if !p.has_storage() {
                continue;
            }
            let on_stack = manager
                .space_of(p.addr)
                .is_some_and(|s| s.space_type() == SpaceType::Spacebase);
            if !on_stack {
                continue;
            }
            let cur = (p.addr.offset() as i32)
                .wrapping_add(p.size)
                .wrapping_add(3)
                & 0xfff_fffc;
            expop = expop.max(cur);
        }
        self.extrapop = expop;
    }

    /// Ghidra `clearUnlockedInput`.
    pub fn clear_unlocked_input(&mut self) {
        if self.is_input_locked() {
            return;
        }
        if let Some(s) = &mut self.store {
            s.clear_all_inputs();
        }
    }

    /// Ghidra `clearUnlockedOutput`.
    pub fn clear_unlocked_output(&mut self, types: &mut dyn ParamTypes) {
        let has_model = self.model.is_some();
        if let Some(s) = &mut self.store {
            if s.output.is_type_locked() {
                if s.output.is_size_type_locked() && has_model {
                    s.output.reset_size_lock_type(types);
                }
            } else {
                s.clear_output();
            }
        }
        self.return_bytes_consumed = 0;
    }

    /// Ghidra `clearInput`.
    pub fn clear_input(&mut self) {
        if let Some(s) = &mut self.store {
            s.clear_all_inputs();
        }
        self.flags.remove(ProtoFlags::VOIDINPUTLOCK);
    }

    /// Ghidra `setInjectId`; `None` cancels (Ghidra `cancelInjectId`).
    pub fn set_inject_id(&mut self, id: Option<u32>) {
        self.injectid = id;
        self.flags.set(ProtoFlags::IS_INLINE, id.is_some());
    }

    /// Specialises a merged model to the one that best fits the trials
    /// (Ghidra `resolveModel`).
    pub fn resolve_model(
        &mut self,
        spec: &CompilerSpec,
        manager: &SpaceManager,
        active: &ParamActive,
    ) -> Result<()> {
        let Some(merged) = self.model(spec).and_then(ProtoModel::merged_models) else {
            return Ok(());
        };
        let id = select_model(merged, &|i| spec.model(i), manager, active)?;
        self.set_model(spec, Some(ModelRef::known(id)));
        Ok(())
    }

    /// The raw pieces of the prototype (Ghidra `getPieces`).
    pub fn pieces(&self, spec: &CompilerSpec) -> Option<PrototypePieces> {
        let store = self.store.as_ref()?;
        let mut p = PrototypePieces::new(store.output.ty);
        p.model = self
            .model
            .as_ref()
            .map(|_| self.model_name(spec).to_owned());
        for param in store.inputs.iter().flatten() {
            p.intypes.push(param.ty);
            p.innames.push(param.name.clone());
        }
        p.first_vararg = if self.is_dotdotdot() {
            store.num_inputs() as i32
        } else {
            -1
        };
        p.provenance = self.provenance;
        Some(p)
    }

    /// Sets the whole prototype from pieces, locked (Ghidra `setPieces`).
    pub fn set_pieces(
        &mut self,
        ctx: (&CompilerSpec, &SpaceManager),
        types: &mut dyn ParamTypes,
        pieces: &PrototypePieces,
    ) -> Result<()> {
        let (spec, _) = ctx;
        if let Some(name) = &pieces.model {
            let r = match spec.model_id(name) {
                Some(id) => ModelRef::known(id),
                None => ModelRef {
                    id: spec.default_model(),
                    unknown: Some(name.clone()),
                },
            };
            self.set_model(spec, Some(r));
        }
        self.provenance = pieces.provenance;
        self.update_all_types(ctx, types, pieces)?;
        self.set_input_lock(&*types, true);
        self.set_output_lock(&*types, true);
        self.set_model_lock(true);
        Ok(())
    }

    /// Assigns storage through the model and refills the store; a failed
    /// assignment marks the inputs in error (Ghidra `updateAllTypes`).
    pub fn update_all_types(
        &mut self,
        ctx: (&CompilerSpec, &SpaceManager),
        types: &mut dyn ParamTypes,
        proto: &PrototypePieces,
    ) -> Result<()> {
        let (spec, manager) = ctx;
        self.set_model(spec, self.model.clone());
        let model = self.require_model(spec)?;
        let store = self
            .store
            .as_mut()
            .ok_or_else(|| CspecError::new("Prototype storage must be set"))?;
        store.clear_all_inputs();
        store.clear_output();
        self.flags.remove(ProtoFlags::VOIDINPUTLOCK);
        self.flags
            .set(ProtoFlags::DOTDOTDOT, proto.first_vararg >= 0);
        let mut pieces = Vec::with_capacity(proto.intypes.len() + 2);
        match model.assign_parameter_storage(manager, types, proto, &mut pieces, false) {
            Ok(()) => {
                fill_store(store, &*types, &pieces, &proto.innames);
            }
            Err(CspecError::ParamUnassigned(_)) => self.flags |= ProtoFlags::ERROR_INPUTPARAM,
            Err(e) => return Err(e),
        }
        self.update_this_pointer(spec);
        Ok(())
    }

    /// Prepends `shift` unknown 4-byte parameters (Ghidra `paramShift`).
    pub fn param_shift(
        &mut self,
        ctx: (&CompilerSpec, &SpaceManager),
        types: &mut dyn ParamTypes,
        shift: usize,
    ) -> Result<()> {
        let (spec, manager) = ctx;
        let model = self
            .model(spec)
            .filter(|_| self.store.is_some())
            .ok_or_else(|| CspecError::new("Cannot parameter shift without a model"))?;
        let void = types.void();
        let out = if self.is_output_locked() {
            self.output().map_or(void, |o| o.ty)
        } else {
            void
        };
        let mut proto = PrototypePieces::new(out);
        let extra = types.unknown(4);
        proto.intypes = vec![extra; shift];
        proto.innames = vec![String::new(); shift];
        if self.is_input_locked() {
            for p in self.params().flatten() {
                proto.innames.push(p.name.clone());
                proto.intypes.push(p.ty);
            }
        } else {
            proto.first_vararg = shift as i32;
        }
        let mut pieces = Vec::new();
        model.assign_parameter_storage(manager, types, &proto, &mut pieces, false)?;
        let mut store = ProtoStoreInternal::new(void);
        if let Some(first) = pieces.first() {
            store.set_output(first, types.size(first.ty));
        }
        let mut j = 0usize;
        for (i, piece) in pieces.iter().enumerate().skip(1) {
            let size = types.size(piece.ty);
            if piece.flags.contains(PieceFlags::HIDDENRETPARM) {
                store.set_input(i - 1, "rethidden", piece, size);
                continue;
            }
            let name = proto.innames.get(j).map_or("", String::as_str);
            store.set_input(j, name, piece, size);
            j += 1;
        }
        self.store = Some(store);
        self.set_input_lock(&*types, true);
        self.flags
            .set(ProtoFlags::DOTDOTDOT, proto.first_vararg >= 0);
        Ok(())
    }

    /// Marks the `this` parameter when the model has one (Ghidra
    /// `updateThisPointer`).
    pub(crate) fn update_this_pointer(&mut self, spec: &CompilerSpec) {
        if !self.model(spec).is_some_and(ProtoModel::has_this_pointer) {
            return;
        }
        let Some(s) = &mut self.store else { return };
        let n = s.num_inputs();
        if n == 0 {
            return;
        }
        let mut idx = 0;
        if s.input(0).is_some_and(ParameterBasic::is_hidden_return) {
            if n < 2 {
                return;
            }
            idx = 1;
        }
        if let Some(p) = s.input_mut(idx) {
            p.set_this_pointer(true);
        }
    }
}

/// Fills a store from assigned pieces: the return value, then the inputs,
/// a hidden return parameter named `rethidden` (Ghidra's loop in
/// `updateAllTypes`).
pub(crate) fn fill_store(
    store: &mut ProtoStoreInternal,
    types: &dyn ParamTypes,
    pieces: &[ParameterPieces],
    names: &[String],
) {
    if let Some(first) = pieces.first() {
        let size = if types.metatype(first.ty) == Metatype::Void {
            0
        } else {
            types.size(first.ty)
        };
        store.set_output(first, size);
    }
    let mut j = 0usize;
    for (i, piece) in pieces.iter().enumerate().skip(1) {
        let size = types.size(piece.ty);
        if piece.flags.contains(PieceFlags::HIDDENRETPARM) {
            store.set_input(i - 1, "rethidden", piece, size);
            continue;
        }
        let name = names.get(j).map_or("", String::as_str);
        store.set_input(i - 1, name, piece, size);
        j += 1;
    }
}
