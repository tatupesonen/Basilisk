//! Storage assignment within one list (Ghidra
//! `ParamListStandard::assignAddressFallback`, `assignAddress`,
//! `assignMap`, and the `assignMap` of `ParamListStandardOut`,
//! `ParamListRegisterOut` and `ParamListMerged`).

use bk_core::{Address, SpaceManager};

use super::{ListKind, ParamList};
use crate::error::{CspecError, Result};
use crate::proto::{ParameterPieces, PieceFlags, PrototypePieces};
use crate::status::Status;
use crate::types::{Metatype, ParamTypes, TypeClass, TypeHandle};

/// Deepest recursion through rules that assign a pointer or each primitive
/// again; Ghidra has no limit, so a `pointermax` below the pointer size
/// recurses until the stack overflows (ADR-009).
const MAX_DEPTH: u32 = 32;

/// The answer of an assignment step (Ghidra's `AssignAction` response
/// codes, with their numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AssignResult {
    /// Storage was assigned.
    Success = 0,
    /// This step could not assign; try the next.
    Fail = 1,
    /// Assign no storage to this parameter.
    NoAssignment = 2,
    /// Return through a hidden pointer passed as the first parameter.
    HiddenretPtrparam = 3,
    /// Return through a hidden pointer in a dedicated register.
    HiddenretSpecialreg = 4,
    /// As [`AssignResult::HiddenretSpecialreg`], with no normal return.
    HiddenretSpecialregVoid = 5,
}

impl AssignResult {
    /// Ghidra's name for the code.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Fail => "fail",
            Self::NoAssignment => "no_assignment",
            Self::HiddenretPtrparam => "hiddenret_ptrparam",
            Self::HiddenretSpecialreg => "hiddenret_specialreg",
            Self::HiddenretSpecialregVoid => "hiddenret_specialreg_void",
        }
    }

    const fn is_hidden_return(self) -> bool {
        matches!(
            self,
            Self::HiddenretPtrparam | Self::HiddenretSpecialreg | Self::HiddenretSpecialregVoid
        )
    }
}

/// What an assignment needs besides the list: the space manager (join
/// addresses), the type model (pointers it creates) and the prototype the
/// parameter belongs to.
pub(crate) struct Env<'a> {
    pub(crate) manager: &'a SpaceManager,
    pub(crate) types: &'a mut dyn ParamTypes,
    pub(crate) proto: &'a PrototypePieces,
    pub(crate) depth: u32,
}

impl ParamList {
    /// Assigns the first entry of class `resource` (or a general entry
    /// unless `exact`) with a free group that fits (Ghidra
    /// `assignAddressFallback`).
    pub(crate) fn assign_fallback(
        &self,
        env: &mut Env<'_>,
        resource: TypeClass,
        (tp, exact): (TypeHandle, bool),
        status: &mut Status,
        param: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        let size = env.types.align_size(tp);
        let align = env.types.alignment(tp);
        for entry in &self.entries {
            let grp = entry.group();
            if status.get(grp) < 0 {
                continue;
            }
            if resource != entry.class && (exact || entry.class != TypeClass::General) {
                continue;
            }
            let mut slot = status.get(grp);
            let addr = entry.addr_by_slot(env.manager, &mut slot, size, align)?;
            status.set(grp, slot);
            param.addr = addr;
            if addr.is_invalid() {
                continue;
            }
            if entry.is_exclusion() {
                for &g in &entry.groups {
                    status.set(g, -1);
                }
            }
            param.ty = tp;
            param.flags = PieceFlags::empty();
            return Ok(AssignResult::Success);
        }
        Ok(AssignResult::Fail)
    }

    /// Assigns one parameter (`pos` ≥ 0) or the return value (`pos` -1):
    /// the first rule that does not fail, else the fall-back (Ghidra
    /// `assignAddress`).
    pub(crate) fn assign_address(
        &self,
        env: &mut Env<'_>,
        dt: TypeHandle,
        pos: i32,
        status: &mut Status,
        res: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        if env.depth > MAX_DEPTH {
            return Ok(AssignResult::Fail);
        }
        for rule in &self.rules {
            let code = rule.assign_address(self, env, dt, pos, status, res)?;
            if code != AssignResult::Fail {
                return Ok(code);
            }
        }
        let class = env.types.metatype(dt).type_class();
        self.assign_fallback(env, class, (dt, false), status, res)
    }

    /// Appends the storage of the return value (output lists) or of every
    /// parameter (input lists) to `res` (Ghidra `assignMap`).
    pub(crate) fn assign_map(
        &self,
        env: &mut Env<'_>,
        status: &mut Status,
        res: &mut Vec<ParameterPieces>,
    ) -> Result<()> {
        match self.kind {
            ListKind::Standard | ListKind::Register => {
                for (i, &dt) in env.proto.intypes.iter().enumerate() {
                    let mut piece = ParameterPieces::new(dt);
                    let code = self.assign_address(env, dt, i as i32, status, &mut piece)?;
                    res.push(piece);
                    if matches!(code, AssignResult::Fail | AssignResult::NoAssignment) {
                        return Err(CspecError::ParamUnassigned(format!(
                            "Cannot assign parameter address for {}",
                            env.types.name(dt)
                        )));
                    }
                }
                Ok(())
            }
            ListKind::StandardOut => self.assign_output(env, status, res),
            ListKind::RegisterOut => {
                let out = env.proto.outtype;
                let mut piece = ParameterPieces::new(out);
                if env.types.metatype(out) != Metatype::Void {
                    self.assign_address(env, out, -1, status, &mut piece)?;
                    if piece.addr.is_invalid() {
                        res.push(piece);
                        return Err(CspecError::ParamUnassigned(format!(
                            "Cannot assign parameter address for {}",
                            env.types.name(out)
                        )));
                    }
                }
                res.push(piece);
                Ok(())
            }
            ListKind::Merged => Err(CspecError::new(
                "Cannot assign prototype before model has been resolved",
            )),
        }
    }

    /// `ParamListStandardOut::assignMap`: a return value that fits nowhere
    /// becomes a hidden pointer parameter.
    fn assign_output(
        &self,
        env: &mut Env<'_>,
        status: &mut Status,
        res: &mut Vec<ParameterPieces>,
    ) -> Result<()> {
        let out = env.proto.outtype;
        let mut piece = ParameterPieces::new(out);
        if env.types.metatype(out) == Metatype::Void {
            res.push(piece);
            return Ok(());
        }
        let mut code = self.assign_address(env, out, -1, status, &mut piece)?;
        if code == AssignResult::Fail {
            code = AssignResult::HiddenretPtrparam;
        }
        if !code.is_hidden_return() {
            res.push(piece);
            return Ok(());
        }
        let (ptr_size, word_size) = pointer_shape(self, env.manager);
        let pointer = env.types.pointer_to(out, ptr_size, word_size);
        if code == AssignResult::HiddenretSpecialregVoid {
            piece.ty = env.types.void();
        } else {
            piece.ty = pointer;
            if self.assign_address(env, pointer, -1, status, &mut piece)? == AssignResult::Fail {
                return Err(CspecError::ParamUnassigned(
                    "Cannot assign return value as a pointer".into(),
                ));
            }
        }
        piece.flags = PieceFlags::INDIRECTSTORAGE;
        res.push(piece);
        let special = matches!(
            code,
            AssignResult::HiddenretSpecialreg | AssignResult::HiddenretSpecialregVoid
        );
        res.push(ParameterPieces {
            addr: Address::INVALID,
            ty: pointer,
            flags: if special {
                PieceFlags::HIDDENRETPARM
            } else {
                PieceFlags::empty()
            },
        });
        Ok(())
    }
}

/// Size and word size of a pointer created for this list: the stack
/// space's if the list has a stack entry, else the default data space's
/// (Ghidra's `getSpacebase()` / `getDefaultDataSpace()` choice).
pub(crate) fn pointer_shape(list: &ParamList, manager: &SpaceManager) -> (i32, u32) {
    pointer_shape_for(list.spacebase(), manager)
}

/// [`pointer_shape`] for an explicit space (or the default data space).
pub(crate) fn pointer_shape_for(
    space: Option<bk_core::SpaceId>,
    manager: &SpaceManager,
) -> (i32, u32) {
    let spc = space
        .and_then(|s| manager.space(s))
        .or_else(|| manager.default_data_space());
    spc.map_or((4, 1), |s| (s.addr_size() as i32, s.word_size()))
}
