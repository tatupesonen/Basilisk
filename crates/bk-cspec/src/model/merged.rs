//! Merged models and scoring (Ghidra `ProtoModelMerged`, `ScoreProtoModel`).

use bk_core::{Address, SpaceManager, VarnodeData};
use bk_marshal::Decoder;
use bk_marshal::ids::ATTRIB_NAME;

use super::decode::{DecodeContext, default_local_range, default_param_range};
use super::{EXTRAPOP_UNKNOWN, ModelId, ProtoModel};
use crate::effect::EffectRecord;
use crate::error::{CspecError, Result};
use crate::ids::{ELEM_MODEL, ELEM_RESOLVEPROTOTYPE};
use crate::list::{ListKind, ParamList};
use crate::trial::ParamActive;

/// How well trials fit a model's inputs; lower is better (Ghidra
/// `ScoreProtoModel`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoreProtoModel {
    input: bool,
    /// (original index, slot, slot count) per fitting trial.
    entries: Vec<(usize, i32, i32)>,
    score: i32,
    mismatch: i32,
}

impl ScoreProtoModel {
    /// A scorer against the inputs (`input`) or outputs of a model.
    pub fn new(input: bool, num_params: usize) -> Self {
        Self {
            input,
            entries: Vec::with_capacity(num_params),
            score: -1,
            mismatch: 0,
        }
    }

    /// Registers a trial (Ghidra `addParameter`).
    pub fn add_parameter(
        &mut self,
        model: &ProtoModel,
        manager: &SpaceManager,
        addr: Address,
        size: i32,
    ) {
        let orig = self.entries.len();
        let found = if self.input {
            model.possible_input_param_with_slot(manager, addr, size)
        } else {
            model.possible_output_param_with_slot(manager, addr, size)
        };
        match found {
            Some((slot, slots)) => self.entries.push((orig, slot, slots)),
            None => self.mismatch += 1,
        }
    }

    /// Computes the score (Ghidra `doScore`).
    #[expect(clippy::comparison_chain, reason = "follows Ghidra's three-way test")]
    pub fn do_score(&mut self) {
        // std::sort by slot is not stable; equal slots score the same in
        // either order.
        self.entries.sort_by_key(|e| e.1);
        let penalty = [16, 10, 7, 5];
        let (final_penalty, mismatch_penalty) = (3, 20);
        let mut nextfree = 0i32;
        let mut base = 0i32;
        for &(_, slot, size) in &self.entries {
            if slot > nextfree {
                // (an `if` chain: Ghidra's order of tests, kept)
                while nextfree < slot {
                    base += usize::try_from(nextfree)
                        .ok()
                        .and_then(|i| penalty.get(i))
                        .copied()
                        .unwrap_or(final_penalty);
                    nextfree += 1;
                }
                nextfree += size;
            } else if nextfree > slot {
                base += mismatch_penalty;
                if slot + size > nextfree {
                    nextfree = slot + size;
                }
            } else {
                nextfree = slot + size;
            }
        }
        self.score = base + mismatch_penalty * self.mismatch;
    }

    /// The score (Ghidra `getScore`).
    pub const fn score(&self) -> i32 {
        self.score
    }
    /// Trials that fit no entry (Ghidra `getNumMismatch`).
    pub const fn mismatches(&self) -> i32 {
        self.mismatch
    }
}

/// Keeps the records of `list` that also appear in `other`, both sorted by
/// address (Ghidra `intersectEffects`).
fn intersect_effects(list: &mut Vec<EffectRecord>, other: &[EffectRecord]) {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while let (Some(a), Some(b)) = (list.get(i), other.get(j)) {
        match a.cmp_by_address(b) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                if a == b {
                    out.push(*a);
                }
                i += 1;
                j += 1;
            }
        }
    }
    *list = out;
}

/// Ghidra `intersectRegisters`.
fn intersect_registers(list: &mut Vec<VarnodeData>, other: &[VarnodeData]) {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while let (Some(a), Some(b)) = (list.get(i), other.get(j)) {
        match a.cmp(b) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(*a);
                i += 1;
                j += 1;
            }
        }
    }
    *list = out;
}

/// Reads a `<resolveprototype>` over the models read so far (Ghidra
/// `ProtoModelMerged::decode` and `foldIn`).
pub(crate) fn decode_merged(
    dec: &mut dyn Decoder<'_>,
    ctx: &DecodeContext<'_>,
    lookup: &dyn Fn(&str) -> Option<(ModelId, ProtoModel)>,
) -> Result<ProtoModel> {
    let elem = dec.open_element_expecting(ELEM_RESOLVEPROTOTYPE)?;
    let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
    let mut m = ProtoModel {
        name,
        extrapop: 0,
        input: ParamList::merged(),
        output: ParamList::empty(ListKind::StandardOut),
        shared: Vec::new(),
        alias_of: None,
        effects: Vec::new(),
        likelytrash: Vec::new(),
        internalstorage: Vec::new(),
        inject_upon_entry: None,
        inject_upon_return: None,
        localrange: bk_core::RangeList::new(),
        paramrange: bk_core::RangeList::new(),
        stack_grows_negative: true,
        has_this: false,
        is_construct: false,
        is_printed: true,
        merged: Some(Vec::new()),
    };
    if let Some(stack) = ctx.stack {
        default_local_range(ctx.manager, stack, true, &mut m.localrange);
        default_param_range(ctx.manager, stack, true, &mut m.paramrange);
    }
    let mut first = true;
    let mut maxdelay = 0;
    while let Some(sub) = dec.open_element()? {
        if sub != ELEM_MODEL {
            // Ghidra ends the list at the first other element, leaving it
            // open, so closing `<resolveprototype>` then fails.
            return Err(CspecError::new("Unexpected element in <resolveprototype>"));
        }
        let model_name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
        let Some((id, other)) = lookup(&model_name) else {
            return Err(CspecError::new(format!(
                "Missing prototype model: {model_name}"
            )));
        };
        dec.close_element(sub)?;
        fold_in(&mut m, &other, first)?;
        maxdelay = maxdelay.max(other.input.maxdelay);
        first = false;
        if let Some(list) = &mut m.merged {
            list.push(id);
        }
    }
    dec.close_element(elem)?;
    m.input.finalize_merged(maxdelay);
    Ok(m)
}

/// Ghidra `ProtoModelMerged::foldIn`.
fn fold_in(m: &mut ProtoModel, other: &ProtoModel, first: bool) -> Result<()> {
    if !matches!(other.input.kind, ListKind::Standard | ListKind::Register) {
        return Err(CspecError::new(
            "Can only resolve between standard prototype models",
        ));
    }
    if first {
        // Ghidra copies the output list as a ParamListStandardOut whatever
        // its class.
        m.output = other.output.clone();
        m.output.kind = ListKind::StandardOut;
        m.input.fold_in(&other.input);
        m.extrapop = other.extrapop;
        m.effects.clone_from(&other.effects);
        m.inject_upon_entry = other.inject_upon_entry;
        m.inject_upon_return = other.inject_upon_return;
        m.likelytrash.clone_from(&other.likelytrash);
        m.localrange = other.localrange.clone();
        m.paramrange = other.paramrange.clone();
        return Ok(());
    }
    m.input.fold_in(&other.input);
    if m.extrapop != other.extrapop {
        m.extrapop = EXTRAPOP_UNKNOWN;
    }
    if m.inject_upon_entry != other.inject_upon_entry
        || m.inject_upon_return != other.inject_upon_return
    {
        return Err(CspecError::new(
            "Cannot merge prototype models with different inject ids",
        ));
    }
    intersect_effects(&mut m.effects, &other.effects);
    intersect_registers(&mut m.likelytrash, &other.likelytrash);
    intersect_registers(&mut m.internalstorage, &other.internalstorage);
    m.localrange.merge(&other.localrange);
    m.paramrange.merge(&other.paramrange);
    Ok(())
}

/// The model that best fits the active input trials (Ghidra
/// `ProtoModelMerged::selectModel`). `models` resolves the merged ids.
pub fn select_model<'m>(
    merged: &[ModelId],
    models: &dyn Fn(ModelId) -> Option<&'m ProtoModel>,
    manager: &SpaceManager,
    active: &ParamActive,
) -> Result<ModelId> {
    let mut best_score = 500;
    let mut best = None;
    for &id in merged {
        let Some(model) = models(id) else { continue };
        let mut s = ScoreProtoModel::new(true, active.num_trials());
        for t in active.trials().iter().filter(|t| t.is_active()) {
            s.add_parameter(model, manager, t.addr, t.size);
        }
        s.do_score();
        if s.score() < best_score {
            best_score = s.score();
            best = Some(id);
            if best_score == 0 {
                break;
            }
        }
    }
    best.ok_or_else(|| CspecError::new("No model matches : missing default"))
}
