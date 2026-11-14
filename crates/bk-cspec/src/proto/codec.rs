//! The `<prototype>` XML of a function prototype (Ghidra `FuncProto::
//! encode`, `decode`, `encodeEffect`, `encodeLikelyTrash`, `decodeEffect`,
//! `decodeLikelyTrash`, `ProtoStoreInternal::encode`, `decode`).

use bk_core::{Address, SpaceManager, VarnodeData};
use bk_marshal::ids::{
    ATTRIB_CONSTRUCTOR, ATTRIB_CONTENT, ATTRIB_DESTRUCTOR, ATTRIB_EXTRAPOP, ATTRIB_HIDDENRETPARM,
    ATTRIB_INDIRECTSTORAGE, ATTRIB_MODEL, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_THISPTR,
    ATTRIB_TYPELOCK, ELEM_RETURNADDRESS,
};
use bk_marshal::{Decoder, Encoder};

use super::funcproto::{FuncProto, ModelRef, ProtoFlags};
use super::pieces::{ParameterPieces, PieceFlags, PrototypePieces};
use super::store::ProtoStoreInternal;
use crate::effect::{EffectKind, EffectRecord, lookup_record, sort_effects};
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_CUSTOM, ATTRIB_DOTDOTDOT, ATTRIB_FIRST, ATTRIB_INLINE, ATTRIB_MODELLOCK,
    ATTRIB_NORETURN, ATTRIB_PROVENANCE, ATTRIB_VOIDLOCK, ELEM_INJECT, ELEM_INTERNALLIST,
    ELEM_KILLEDBYCALL, ELEM_LIKELYTRASH, ELEM_PARAM, ELEM_PROTOTYPE, ELEM_RETPARAM, ELEM_RETURNSYM,
    ELEM_UNAFFECTED,
};
use crate::inject::InjectKind;
use crate::model::EXTRAPOP_UNKNOWN;
use crate::spec::CompilerSpec;
use crate::types::{Metatype, ParamTypes};

/// Which form [`FuncProto::encode`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EncodeMode {
    /// Exactly Ghidra's elements and attributes.
    #[default]
    Ghidra,
    /// Ghidra's form plus basilisk's provenance attributes (ADR-025 3f).
    Basilisk,
}

type Ctx<'a> = (&'a CompilerSpec, &'a SpaceManager);

fn write_provenance(enc: &mut dyn Encoder, mode: EncodeMode, p: bk_core::Provenance) -> Result<()> {
    if mode == EncodeMode::Basilisk
        && let Some(name) = crate::provenance_serde::name(p)
    {
        enc.write_string(ATTRIB_PROVENANCE, name)?;
    }
    Ok(())
}

impl FuncProto {
    /// Writes the prototype as a `<prototype>` element (Ghidra `encode`).
    pub fn encode(
        &self,
        (spec, m): Ctx<'_>,
        types: &dyn ParamTypes,
        enc: &mut dyn Encoder,
        mode: EncodeMode,
    ) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| CspecError::new("Prototype storage must be set"))?;
        let model = self.require_model(spec)?;
        enc.open_element(ELEM_PROTOTYPE);
        enc.write_string(ATTRIB_MODEL, self.model_name(spec))?;
        if self.extrapop == EXTRAPOP_UNKNOWN {
            enc.write_string(ATTRIB_EXTRAPOP, "unknown")?;
        } else {
            enc.write_signed(ATTRIB_EXTRAPOP, i64::from(self.extrapop));
        }
        let bools = [
            (ProtoFlags::DOTDOTDOT, ATTRIB_DOTDOTDOT),
            (ProtoFlags::MODELLOCK, ATTRIB_MODELLOCK),
            (ProtoFlags::VOIDINPUTLOCK, ATTRIB_VOIDLOCK),
            (ProtoFlags::IS_INLINE, ATTRIB_INLINE),
            (ProtoFlags::NO_RETURN, ATTRIB_NORETURN),
            (ProtoFlags::CUSTOM_STORAGE, ATTRIB_CUSTOM),
            (ProtoFlags::IS_CONSTRUCTOR, ATTRIB_CONSTRUCTOR),
            (ProtoFlags::IS_DESTRUCTOR, ATTRIB_DESTRUCTOR),
        ];
        for (flag, attr) in bools {
            if self.flags.contains(flag) {
                enc.write_bool(attr, true);
            }
        }
        write_provenance(enc, mode, self.provenance)?;
        let out = &store.output;
        enc.open_element(ELEM_RETURNSYM);
        if out.is_type_locked() {
            enc.write_bool(ATTRIB_TYPELOCK, true);
        }
        out.addr.encode_sized(enc, m, out.size as u32)?;
        types.encode_ref(enc, out.ty)?;
        enc.close_element(ELEM_RETURNSYM);
        self.encode_effects(m, model, enc)?;
        self.encode_likely_trash(m, model, enc)?;
        if let Some(id) = self.injectid {
            enc.open_element(ELEM_INJECT);
            enc.write_string(ATTRIB_CONTENT, spec.injects().call_fixup_name(id))?;
            enc.close_element(ELEM_INJECT);
        }
        encode_store(store, m, types, enc, mode)?;
        enc.close_element(ELEM_PROTOTYPE);
        Ok(())
    }

    /// Writes the effects that differ from the model's (Ghidra
    /// `encodeEffect`).
    fn encode_effects(
        &self,
        m: &SpaceManager,
        model: &crate::model::ProtoModel,
        enc: &mut dyn Encoder,
    ) -> Result<()> {
        let mut unaffected = Vec::new();
        let mut killed = Vec::new();
        let mut retaddr = None;
        for r in &self.effects {
            if model.has_effect(m, r.address(), r.size()) == r.kind {
                continue;
            }
            match r.kind {
                EffectKind::Unaffected => unaffected.push(r),
                EffectKind::KilledByCall => killed.push(r),
                EffectKind::ReturnAddress => retaddr = Some(r),
                EffectKind::Unknown => {}
            }
        }
        for (list, elem) in [(&unaffected, ELEM_UNAFFECTED), (&killed, ELEM_KILLEDBYCALL)] {
            if list.is_empty() {
                continue;
            }
            enc.open_element(elem);
            for r in list {
                r.range.encode(enc, m)?;
            }
            enc.close_element(elem);
        }
        if let Some(r) = retaddr {
            enc.open_element(ELEM_RETURNADDRESS);
            r.range.encode(enc, m)?;
            enc.close_element(ELEM_RETURNADDRESS);
        }
        Ok(())
    }

    /// Writes likely-trash locations the model lacks (Ghidra
    /// `encodeLikelyTrash`).
    fn encode_likely_trash(
        &self,
        m: &SpaceManager,
        model: &crate::model::ProtoModel,
        enc: &mut dyn Encoder,
    ) -> Result<()> {
        if self.likelytrash.is_empty() {
            return Ok(());
        }
        enc.open_element(ELEM_LIKELYTRASH);
        for v in &self.likelytrash {
            if model.likely_trash().binary_search(v).is_ok() {
                continue;
            }
            v.encode(enc, m)?;
        }
        enc.close_element(ELEM_LIKELYTRASH);
        Ok(())
    }

    /// Reads a `<prototype>`; the prototype must have a store (Ghidra
    /// `decode`).
    pub fn decode(
        &mut self,
        (spec, m): Ctx<'_>,
        types: &mut dyn ParamTypes,
        dec: &mut dyn Decoder<'_>,
    ) -> Result<()> {
        if self.store.is_none() {
            return Err(CspecError::new(
                "Prototype storage must be set before restoring FuncProto",
            ));
        }
        let mut model: Option<ModelRef> = None;
        let mut read_extrapop = None;
        self.flags = ProtoFlags::empty();
        self.injectid = None;
        let elem = dec.open_element_expecting(ELEM_PROTOTYPE)?;
        let bools = [
            (ATTRIB_MODELLOCK, ProtoFlags::MODELLOCK),
            (ATTRIB_DOTDOTDOT, ProtoFlags::DOTDOTDOT),
            (ATTRIB_VOIDLOCK, ProtoFlags::VOIDINPUTLOCK),
            (ATTRIB_INLINE, ProtoFlags::IS_INLINE),
            (ATTRIB_NORETURN, ProtoFlags::NO_RETURN),
            (ATTRIB_CUSTOM, ProtoFlags::CUSTOM_STORAGE),
            (ATTRIB_CONSTRUCTOR, ProtoFlags::IS_CONSTRUCTOR),
            (ATTRIB_DESTRUCTOR, ProtoFlags::IS_DESTRUCTOR),
        ];
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_MODEL {
                let name = dec.read_string()?;
                model = Some(if name.is_empty() || name == "default" {
                    ModelRef::known(spec.default_model())
                } else {
                    match spec.model_id(name) {
                        Some(id) => ModelRef::known(id),
                        None => ModelRef {
                            id: spec.default_model(),
                            unknown: Some(name.to_owned()),
                        },
                    }
                });
            } else if attr == ATTRIB_EXTRAPOP {
                read_extrapop =
                    Some(dec.read_signed_or_string("unknown", i64::from(EXTRAPOP_UNKNOWN))? as i32);
            } else if attr == ATTRIB_PROVENANCE {
                if let Some(p) = crate::provenance_serde::from_name(dec.read_string()?) {
                    self.provenance = p;
                }
            } else if let Some((_, flag)) = bools.iter().find(|(a, _)| attr == *a)
                && dec.read_bool()?
            {
                self.flags |= *flag;
            }
        }
        if model.is_some() {
            self.set_model(spec, model);
        }
        if let Some(e) = read_extrapop {
            self.extrapop = e;
        }
        self.decode_output(m, types, dec)?;
        if self.flags.contains(ProtoFlags::VOIDINPUTLOCK) || self.is_output_locked() {
            self.flags |= ProtoFlags::MODELLOCK;
        }
        while let Some(sub) = dec.peek_element() {
            if sub == ELEM_UNAFFECTED || sub == ELEM_KILLEDBYCALL || sub == ELEM_RETURNADDRESS {
                let kind = if sub == ELEM_UNAFFECTED {
                    EffectKind::Unaffected
                } else if sub == ELEM_KILLEDBYCALL {
                    EffectKind::KilledByCall
                } else {
                    EffectKind::ReturnAddress
                };
                let e = dec
                    .open_element()?
                    .ok_or_else(|| CspecError::new("Missing element"))?;
                while dec.peek_element().is_some() {
                    self.effects
                        .push(EffectRecord::new(VarnodeData::decode(dec, m)?, kind));
                }
                dec.close_element(e)?;
            } else if sub == ELEM_LIKELYTRASH {
                let e = dec
                    .open_element()?
                    .ok_or_else(|| CspecError::new("Missing element"))?;
                while dec.peek_element().is_some() {
                    self.likelytrash.push(VarnodeData::decode(dec, m)?);
                }
                dec.close_element(e)?;
            } else if sub == ELEM_INJECT {
                let e = dec
                    .open_element()?
                    .ok_or_else(|| CspecError::new("Missing element"))?;
                let name = dec.read_string_attr(ATTRIB_CONTENT)?;
                // Ghidra keeps -1 for an unknown name and still inlines.
                self.injectid = spec.injects().payload_id(InjectKind::CallFixup, name);
                self.flags |= ProtoFlags::IS_INLINE;
                dec.close_element(e)?;
            } else if sub == ELEM_INTERNALLIST {
                self.decode_store((spec, m), types, dec)?;
            } else {
                // Ghidra's loop does not end on another element.
                return Err(CspecError::new("Unknown element in <prototype>"));
            }
        }
        dec.close_element(elem)?;
        self.merge_overrides(spec, m)?;
        if !self.is_model_locked() && self.is_input_locked() {
            self.flags |= ProtoFlags::MODELLOCK;
        }
        if self.extrapop == EXTRAPOP_UNKNOWN {
            self.resolve_extra_pop(m);
        }
        if let Some(out) = self.output()
            && types.metatype(out.ty) != Metatype::Void
            && out.addr.is_invalid()
        {
            return Err(CspecError::new(
                "<returnsym> tag must include a valid storage address",
            ));
        }
        self.update_this_pointer(spec);
        Ok(())
    }

    fn decode_output(
        &mut self,
        m: &SpaceManager,
        types: &mut dyn ParamTypes,
        dec: &mut dyn Decoder<'_>,
    ) -> Result<()> {
        let Some(sub) = dec.peek_element() else {
            return Err(CspecError::new("Missing <returnsym> tag"));
        };
        let mut lock = false;
        let mut prov = None;
        let (addr, ty) = if sub == ELEM_RETURNSYM {
            let e = dec
                .open_element()?
                .ok_or_else(|| CspecError::new("Missing <returnsym> tag"))?;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_TYPELOCK {
                    lock = dec.read_bool()?;
                } else if attr == ATTRIB_PROVENANCE {
                    prov = crate::provenance_serde::from_name(dec.read_string()?);
                }
            }
            let (addr, _) = Address::decode_sized(dec, m)?;
            let ty = types.decode_type(dec)?;
            dec.close_element(e)?;
            (addr, ty)
        } else if sub == bk_core::ids::ELEM_ADDR {
            let (addr, _) = Address::decode_sized(dec, m)?;
            (addr, types.decode_type(dec)?)
        } else {
            return Err(CspecError::new("Missing <returnsym> tag"));
        };
        let piece = ParameterPieces {
            addr,
            ty,
            flags: PieceFlags::empty(),
        };
        let size = types.size(ty);
        if let Some(store) = &mut self.store {
            let out = store.set_output(&piece, size);
            out.set_type_lock(&*types, lock);
            if let Some(p) = prov {
                out.provenance = p;
            }
        }
        Ok(())
    }

    /// Merges the read effect and likely-trash overrides into complete
    /// lists (Ghidra `decodeEffect`, `decodeLikelyTrash`).
    fn merge_overrides(&mut self, spec: &CompilerSpec, m: &SpaceManager) -> Result<()> {
        let Some(model) = self.model(spec) else {
            return Ok(());
        };
        if !self.effects.is_empty() {
            let read = std::mem::take(&mut self.effects);
            self.effects = model.effects().to_vec();
            let size = self.effects.len();
            let mut new = false;
            for r in read {
                match lookup_record(&self.effects, size, m, r.address(), r.size()) {
                    Err(true) => {
                        return Err(CspecError::new(
                            "Partial overlap of prototype override with existing effects",
                        ));
                    }
                    Ok(i) => {
                        if let Some(slot) = self.effects.get_mut(i) {
                            *slot = r;
                        }
                    }
                    Err(false) => {
                        self.effects.push(r);
                        new = true;
                    }
                }
            }
            if new {
                sort_effects(&mut self.effects);
            }
        }
        if !self.likelytrash.is_empty() {
            let read = std::mem::take(&mut self.likelytrash);
            let base = model.likely_trash();
            self.likelytrash = base.to_vec();
            for v in read {
                if base.binary_search(&v).is_err() {
                    self.likelytrash.push(v);
                }
            }
            self.likelytrash.sort();
        }
        Ok(())
    }

    /// Ghidra `ProtoStoreInternal::decode`: reads `<internallist>`, and
    /// when any storage is missing assigns it through the model.
    fn decode_store(
        &mut self,
        (spec, m): Ctx<'_>,
        types: &mut dyn ParamTypes,
        dec: &mut dyn Decoder<'_>,
    ) -> Result<()> {
        let model = self.require_model(spec)?;
        let Some(store) = &mut self.store else {
            return Ok(());
        };
        let mut pieces = Vec::new();
        let out = &store.output;
        let mut out_flags = PieceFlags::empty();
        if out.is_type_locked() {
            out_flags |= PieceFlags::TYPELOCK;
        }
        if out.is_indirect_storage() {
            out_flags |= PieceFlags::INDIRECTSTORAGE;
        }
        pieces.push(ParameterPieces {
            addr: out.addr,
            ty: out.ty,
            flags: out_flags,
        });
        let mut determined = !out.addr.is_invalid();
        let mut proto = PrototypePieces::new(out.ty);
        proto.model = Some(model.name().to_owned());
        let mut provs = Vec::new();
        let elem = dec.open_element_expecting(ELEM_INTERNALLIST)?;
        if let Some(attr) = dec.next_attribute()?
            && attr == ATTRIB_FIRST
        {
            proto.first_vararg = dec.read_signed()? as i32;
        }
        while let Some(sub) = dec.open_element()? {
            if sub == ELEM_RETPARAM {
                // Ghidra's decoder reads <retparam>, which its own encoder
                // writes first, as one more input parameter, so its round
                // trip of an internal store does not hold; basilisk skips
                // it (the return value comes from <returnsym>).
                dec.close_element_skipping(sub)?;
                continue;
            }
            let mut name = String::new();
            let mut flags = PieceFlags::empty();
            let mut prov = bk_core::Provenance::Default;
            let names = [
                (ATTRIB_TYPELOCK, PieceFlags::TYPELOCK),
                (ATTRIB_NAMELOCK, PieceFlags::NAMELOCK),
                (ATTRIB_THISPTR, PieceFlags::ISTHIS),
                (ATTRIB_INDIRECTSTORAGE, PieceFlags::INDIRECTSTORAGE),
                (ATTRIB_HIDDENRETPARM, PieceFlags::HIDDENRETPARM),
            ];
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_NAME {
                    dec.read_string()?.clone_into(&mut name);
                } else if attr == ATTRIB_PROVENANCE {
                    prov = crate::provenance_serde::from_name(dec.read_string()?).unwrap_or(prov);
                } else if let Some((_, f)) = names.iter().find(|(a, _)| attr == *a)
                    && dec.read_bool()?
                {
                    flags |= *f;
                }
            }
            if !flags.contains(PieceFlags::HIDDENRETPARM) {
                proto.innames.push(name);
            }
            let addr = Address::decode(dec, m)?;
            let ty = types.decode_type(dec)?;
            if addr.is_invalid() {
                determined = false;
            }
            pieces.push(ParameterPieces { addr, ty, flags });
            provs.push(prov);
            dec.close_element(sub)?;
        }
        dec.close_element(elem)?;
        if !determined {
            proto.outtype = pieces.first().map_or(proto.outtype, |p| p.ty);
            proto.intypes = pieces.iter().skip(1).map(|p| p.ty).collect();
            let mut assigned = Vec::new();
            model.assign_parameter_storage(m, types, &proto, &mut assigned, true)?;
            // Ghidra's swap leaves the read flags with the *assigned*
            // list's non-hidden pieces, in order.
            let read_flags: Vec<PieceFlags> = pieces.iter().map(|p| p.flags).collect();
            let mut k = 0;
            for p in &mut assigned {
                if p.flags.contains(PieceFlags::HIDDENRETPARM) {
                    continue;
                }
                p.flags = read_flags.get(k).copied().unwrap_or_default();
                k += 1;
            }
            pieces = assigned;
            if let Some(first) = pieces.first_mut()
                && first.addr.is_invalid()
            {
                first.flags.remove(PieceFlags::TYPELOCK);
            }
            if let Some(first) = pieces.first() {
                let size = types.size(first.ty);
                let lock = first.flags.contains(PieceFlags::TYPELOCK);
                store.set_output(first, size).set_type_lock(&*types, lock);
            }
        }
        let out_lock = pieces
            .first()
            .is_some_and(|p| p.flags.contains(PieceFlags::TYPELOCK));
        let mut j = 0usize;
        for (i, piece) in pieces.iter().enumerate().skip(1) {
            let size = types.size(piece.ty);
            if piece.flags.contains(PieceFlags::HIDDENRETPARM) {
                store
                    .set_input(i - 1, "rethidden", piece, size)
                    .set_type_lock(&*types, out_lock);
                continue;
            }
            let name = proto.innames.get(j).map_or("", String::as_str);
            let p = store.set_input(i - 1, name, piece, size);
            p.set_type_lock(&*types, piece.flags.contains(PieceFlags::TYPELOCK));
            p.set_name_lock(piece.flags.contains(PieceFlags::NAMELOCK));
            if let Some(&pv) = provs.get(i - 1) {
                p.provenance = pv;
            }
            j += 1;
        }
        Ok(())
    }
}

/// Ghidra `ProtoStoreInternal::encode`.
fn encode_store(
    store: &ProtoStoreInternal,
    m: &SpaceManager,
    types: &dyn ParamTypes,
    enc: &mut dyn Encoder,
    mode: EncodeMode,
) -> Result<()> {
    enc.open_element(ELEM_INTERNALLIST);
    enc.open_element(ELEM_RETPARAM);
    if store.output.is_type_locked() {
        enc.write_bool(ATTRIB_TYPELOCK, true);
    }
    store.output.addr.encode(enc, m)?;
    types.encode_ref(enc, store.output.ty)?;
    enc.close_element(ELEM_RETPARAM);
    for p in store.inputs.iter().flatten() {
        enc.open_element(ELEM_PARAM);
        if !p.name.is_empty() {
            enc.write_string(ATTRIB_NAME, &p.name)?;
        }
        let bools = [
            (p.is_type_locked(), ATTRIB_TYPELOCK),
            (p.is_name_locked(), ATTRIB_NAMELOCK),
            (p.is_this_pointer(), ATTRIB_THISPTR),
            (p.is_indirect_storage(), ATTRIB_INDIRECTSTORAGE),
            (p.is_hidden_return(), ATTRIB_HIDDENRETPARM),
        ];
        for (set, attr) in bools {
            if set {
                enc.write_bool(attr, true);
            }
        }
        write_provenance(enc, mode, p.provenance)?;
        p.addr.encode(enc, m)?;
        types.encode_ref(enc, p.ty)?;
        enc.close_element(ELEM_PARAM);
    }
    enc.close_element(ELEM_INTERNALLIST);
    Ok(())
}
