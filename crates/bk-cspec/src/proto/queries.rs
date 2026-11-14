//! Questions about a prototype that go to the locked parameters when there
//! are some and to the model otherwise (Ghidra `FuncProto::
//! characterizeAsInputParam`, `possibleInputParam`, … , `hasEffect`,
//! `isCompatible`, `getThisPointerStorage`, `printRaw`).

use bk_core::{Address, SpaceManager, VarnodeData};

use super::funcproto::{FuncProto, ModelRef, ProtoFlags};
use super::pieces::{PieceFlags, PrototypePieces};
use super::store::ParameterBasic;
use crate::effect::{EffectKind, EffectRecord, lookup_effect};
use crate::entry::{Containment, Extension};
use crate::error::Result;
use crate::model::ProtoModel;
use crate::spec::CompilerSpec;
use crate::trial::ParamActive;
use crate::types::{ParamTypes, TypeHandle};

/// The spec and manager every query needs.
pub type Ctx<'a> = (&'a CompilerSpec, &'a SpaceManager);

impl FuncProto {
    /// The locked parameters with storage, unless the prototype is
    /// variadic; `Err(())` stands for Ghidra's void-input-lock answer.
    fn locked_inputs(&self) -> Result<Vec<&ParameterBasic>, ()> {
        if self.is_dotdotdot() {
            return Ok(Vec::new());
        }
        if self.flags.contains(ProtoFlags::VOIDINPUTLOCK) {
            return Err(());
        }
        Ok(self
            .params()
            .flatten()
            .filter(|p| p.is_type_locked() && p.has_storage())
            .collect())
    }

    /// Ghidra `characterizeAsInputParam`.
    pub fn characterize_as_input_param(
        &self,
        (spec, m): Ctx<'_>,
        addr: Address,
        size: i32,
    ) -> Containment {
        let Ok(locked) = self.locked_inputs() else {
            return Containment::None;
        };
        if !locked.is_empty() {
            let mut contains = false;
            let mut contained_by = false;
            for p in locked {
                match p
                    .addr
                    .justified_contain(m, p.size as u32, addr, size as u32, false)
                {
                    Some(0) => return Containment::ContainsJustified,
                    Some(_) => contains = true,
                    None => {}
                }
                if p.addr.contained_by(p.size as u32, addr, size as u32) {
                    contained_by = true;
                }
            }
            if contains {
                return Containment::ContainsUnjustified;
            }
            if contained_by {
                return Containment::ContainedBy;
            }
            return Containment::None;
        }
        self.model(spec).map_or(Containment::None, |md| {
            md.characterize_as_input_param(m, addr, size)
        })
    }

    fn locked_output(&self) -> Option<&ParameterBasic> {
        self.output().filter(|o| o.is_type_locked())
    }

    /// Ghidra `characterizeAsOutput`.
    pub fn characterize_as_output(
        &self,
        (spec, m): Ctx<'_>,
        addr: Address,
        size: i32,
    ) -> Containment {
        if let Some(o) = self.locked_output() {
            if !o.has_storage() {
                return Containment::None;
            }
            return match o
                .addr
                .justified_contain(m, o.size as u32, addr, size as u32, false)
            {
                Some(0) => Containment::ContainsJustified,
                Some(_) => Containment::ContainsUnjustified,
                None if o.addr.contained_by(o.size as u32, addr, size as u32) => {
                    Containment::ContainedBy
                }
                None => Containment::None,
            };
        }
        self.model(spec).map_or(Containment::None, |md| {
            md.characterize_as_output(m, addr, size)
        })
    }

    /// Ghidra `possibleInputParam`.
    pub fn possible_input_param(&self, (spec, m): Ctx<'_>, addr: Address, size: i32) -> bool {
        let Ok(locked) = self.locked_inputs() else {
            return false;
        };
        if !locked.is_empty() {
            return locked.iter().any(|p| {
                p.addr
                    .justified_contain(m, p.size as u32, addr, size as u32, false)
                    == Some(0)
            });
        }
        self.model(spec)
            .is_some_and(|md| md.possible_input_param(m, addr, size))
    }

    /// Ghidra `possibleOutputParam`.
    pub fn possible_output_param(&self, (spec, m): Ctx<'_>, addr: Address, size: i32) -> bool {
        if let Some(o) = self.locked_output() {
            return o.has_storage()
                && o.addr
                    .justified_contain(m, o.size as u32, addr, size as u32, false)
                    == Some(0);
        }
        self.model(spec)
            .is_some_and(|md| md.possible_output_param(m, addr, size))
    }

    /// Ghidra `unjustifiedInputParam`.
    pub fn unjustified_input_param(
        &self,
        (spec, m): Ctx<'_>,
        addr: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        let locked = self.locked_inputs().ok()?;
        if !locked.is_empty() {
            for p in locked {
                match p
                    .addr
                    .justified_contain(m, p.size as u32, addr, size as u32, false)
                {
                    Some(0) => return None,
                    Some(_) => return Some(VarnodeData::from_address(p.addr, p.size as u32)),
                    None => {}
                }
            }
            return None;
        }
        self.model(spec)?.unjustified_input_param(m, addr, size)
    }

    /// Ghidra `assumedInputExtension`.
    pub fn assumed_input_extension(
        &self,
        (spec, m): Ctx<'_>,
        addr: Address,
        size: i32,
    ) -> (Extension, Option<VarnodeData>) {
        self.model(spec).map_or((Extension::Copy, None), |md| {
            md.assumed_input_extension(m, addr, size)
        })
    }

    /// Ghidra `assumedOutputExtension`.
    pub fn assumed_output_extension(
        &self,
        (spec, m): Ctx<'_>,
        addr: Address,
        size: i32,
    ) -> (Extension, Option<VarnodeData>) {
        self.model(spec).map_or((Extension::Copy, None), |md| {
            md.assumed_output_extension(m, addr, size)
        })
    }

    /// Ghidra `getBiggestContainedInputParam`. With locked parameters
    /// Ghidra answers `true` exactly when *no* locked parameter is inside
    /// the range, passing back an empty location; reproduced: `Some` of a
    /// zero-size location then.
    pub fn biggest_contained_input_param(
        &self,
        (spec, m): Ctx<'_>,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        let locked = self.locked_inputs().ok()?;
        if !locked.is_empty() {
            let mut best = VarnodeData::NONE;
            for p in locked {
                if p.addr.contained_by(p.size as u32, loc, size as u32) && p.size as u32 > best.size
                {
                    best = VarnodeData::from_address(p.addr, p.size as u32);
                }
            }
            return (best.size == 0).then_some(best);
        }
        self.model(spec)?
            .biggest_contained_input_param(m, loc, size)
    }

    /// Ghidra `getBiggestContainedOutput`.
    pub fn biggest_contained_output(
        &self,
        (spec, m): Ctx<'_>,
        loc: Address,
        size: i32,
    ) -> Option<VarnodeData> {
        if let Some(o) = self.locked_output() {
            return (o.has_storage() && o.addr.contained_by(o.size as u32, loc, size as u32))
                .then(|| VarnodeData::from_address(o.addr, o.size as u32));
        }
        self.model(spec)?.biggest_contained_output(m, loc, size)
    }

    /// The effect list in force: the prototype's own, else the model's
    /// (Ghidra `effectBegin`).
    pub fn effects<'s>(&'s self, spec: &'s CompilerSpec) -> &'s [EffectRecord] {
        if self.effects.is_empty() {
            return self.model(spec).map_or(&[], ProtoModel::effects);
        }
        &self.effects
    }

    /// The likely-trash list in force (Ghidra `trashBegin`).
    pub fn likely_trash<'s>(&'s self, spec: &'s CompilerSpec) -> &'s [VarnodeData] {
        if self.likelytrash.is_empty() {
            return self.model(spec).map_or(&[], ProtoModel::likely_trash);
        }
        &self.likelytrash
    }

    /// Ghidra `hasEffect`.
    pub fn has_effect(&self, (spec, m): Ctx<'_>, addr: Address, size: u32) -> EffectKind {
        lookup_effect(self.effects(spec), m, addr, size)
    }

    /// Ghidra `isAutoKilledByCall`.
    pub fn is_auto_killed_by_call(&self) -> bool {
        self.flags.contains(ProtoFlags::AUTO_KILLEDBYCALL) || self.is_output_locked()
    }

    /// Ghidra `deriveInputMap`.
    pub fn derive_input_map(&self, (spec, m): Ctx<'_>, active: &mut ParamActive) -> Result<()> {
        self.require_model(spec)?.derive_input_map(m, active)
    }

    /// Ghidra `deriveOutputMap`.
    pub fn derive_output_map(&self, (spec, m): Ctx<'_>, active: &mut ParamActive) -> Result<()> {
        self.require_model(spec)?.derive_output_map(m, active)
    }

    /// Where the `this` pointer of type `ty` would be stored (Ghidra
    /// `getThisPointerStorage`).
    pub fn this_pointer_storage(
        &self,
        (spec, m): Ctx<'_>,
        types: &mut dyn ParamTypes,
        ty: TypeHandle,
    ) -> Result<Address> {
        let Some(model) = self.model(spec).filter(|md| md.has_this_pointer()) else {
            return Ok(Address::INVALID);
        };
        let out = self.output().map_or_else(|| types.void(), |o| o.ty);
        let proto = PrototypePieces::new(out).with_inputs(vec![ty]);
        let mut res = Vec::new();
        model.assign_parameter_storage(m, types, &proto, &mut res, true)?;
        Ok(res
            .iter()
            .skip(1)
            .find(|p| !p.flags.contains(PieceFlags::HIDDENRETPARM))
            .map_or(Address::INVALID, |p| p.addr))
    }

    /// Whether this prototype can be restricted to `other` without missing
    /// data-flow (Ghidra `isCompatible`).
    pub fn is_compatible(&self, spec: &CompilerSpec, other: &Self) -> bool {
        if !models_compatible(spec, self.model.as_ref(), other.model.as_ref()) {
            return false;
        }
        if other.is_output_locked() && self.is_output_locked() {
            let (a, b) = (self.output(), other.output());
            if a.map(|o| (o.addr, o.ty)) != b.map(|o| (o.addr, o.ty)) {
                return false;
            }
        }
        if self.extrapop != crate::model::EXTRAPOP_UNKNOWN && self.extrapop != other.extrapop {
            return false;
        }
        if self.is_dotdotdot() != other.is_dotdotdot()
            && (!other.is_dotdotdot() || self.is_input_locked())
        {
            return false;
        }
        let mask = ProtoFlags::IS_INLINE | ProtoFlags::NO_RETURN;
        self.injectid == other.injectid
            && (self.flags & mask) == (other.flags & mask)
            && self.effects == other.effects
            && self.likelytrash == other.likelytrash
    }

    /// One line of text: model, return type, name, parameter types,
    /// `extrapop` (Ghidra `printRaw`, with types named by the type model).
    pub fn print_raw(&self, spec: &CompilerSpec, types: &dyn ParamTypes, funcname: &str) -> String {
        let mut s = String::new();
        if self.model.is_some() {
            s.push_str(self.model_name(spec));
            s.push(' ');
        } else {
            s.push_str("(no model) ");
        }
        if let Some(o) = self.output() {
            s.push_str(&types.name(o.ty));
        }
        s.push(' ');
        s.push_str(funcname);
        s.push('(');
        let names: Vec<String> = self.params().flatten().map(|p| types.name(p.ty)).collect();
        s.push_str(&names.join(","));
        if self.is_dotdotdot() {
            if !names.is_empty() {
                s.push(',');
            }
            s.push_str("...");
        }
        s.push_str(") extrapop=");
        s.push_str(&self.extrapop.to_string());
        s
    }
}

/// Ghidra `ProtoModel::isCompatible` through model references: the same
/// model, or one is a copy (alias or unknown placeholder) of the other.
fn models_compatible(spec: &CompilerSpec, a: Option<&ModelRef>, b: Option<&ModelRef>) -> bool {
    let (Some(a), Some(b)) = (a, b) else {
        return a.is_none() && b.is_none();
    };
    if a == b {
        return true;
    }
    let parent = |r: &ModelRef| {
        if r.unknown.is_some() {
            Some(ModelRef::known(r.id))
        } else {
            spec.model(r.id)
                .and_then(ProtoModel::alias_of)
                .map(ModelRef::known)
        }
    };
    parent(a).as_ref() == Some(b) || parent(b).as_ref() == Some(a)
}
