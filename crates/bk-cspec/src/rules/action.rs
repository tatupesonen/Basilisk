//! Assign actions, preconditions and side effects of a `<rule>` (Ghidra's
//! `AssignAction` hierarchy: `GotoStack`, `ConvertToPointer`, `ConsumeAs`,
//! `HiddenReturnAssign`, `ConsumeExtra`, `ExtraStack`, `ConsumeRemaining`;
//! the multi-register actions are in `multislot` and `dualclass`).

use bk_core::SpaceId;
use bk_marshal::Decoder;
use bk_marshal::ids::ATTRIB_STORAGE;

use super::dualclass::DualClassAssign;
use super::multislot::{MultiMemberAssign, MultiSlotAssign};
use crate::entry::type_class;
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_AFTER_BYTES, ATTRIB_AFTER_STORAGE, ATTRIB_MATCHSIZE, ATTRIB_STRATEGY, ATTRIB_VOIDLOCK,
    ELEM_CONSUME, ELEM_CONSUME_EXTRA, ELEM_CONSUME_REMAINING, ELEM_CONVERT_TO_PTR,
    ELEM_EXTRA_STACK, ELEM_GOTO_STACK, ELEM_HIDDEN_RETURN, ELEM_JOIN, ELEM_JOIN_DUAL_CLASS,
    ELEM_JOIN_PER_PRIMITIVE,
};
use crate::list::{AssignResult, Env, ParamList};
use crate::proto::{ParameterPieces, PieceFlags};
use crate::status::Status;
use crate::trial::ParamActive;
use crate::types::{TypeClass, TypeHandle};

/// One way of assigning storage (Ghidra's `AssignAction` subclasses).
/// Entries are named by their index in the owning list.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssignAction {
    /// The next stack slot (`<goto_stack>`, Ghidra `GotoStack`).
    GotoStack {
        /// The stack entry.
        stack: usize,
    },
    /// Pass a pointer instead (`<convert_to_ptr>`, Ghidra
    /// `ConvertToPointer`).
    ConvertToPointer {
        /// The space whose pointer size is used; the default data space
        /// when `None`.
        space: Option<SpaceId>,
    },
    /// Join several registers (`<join>`, Ghidra `MultiSlotAssign`).
    MultiSlot(MultiSlotAssign),
    /// A register per primitive (`<join_per_primitive>`, Ghidra
    /// `MultiMemberAssign`).
    MultiMember(MultiMemberAssign),
    /// Registers of two classes by eightbyte (`<join_dual_class>`, Ghidra
    /// `MultiSlotDualAssign`).
    DualClass(DualClassAssign),
    /// A register of one class only (`<consume>`, Ghidra `ConsumeAs`).
    ConsumeAs {
        /// The class consumed from.
        class: TypeClass,
    },
    /// Return through a hidden pointer (`<hidden_return>`, Ghidra
    /// `HiddenReturnAssign`).
    HiddenReturn {
        /// The code passed back.
        code: AssignResult,
    },
    /// Consume registers of another class too (`<consume_extra>`, Ghidra
    /// `ConsumeExtra`).
    ConsumeExtra {
        /// The class consumed from.
        class: TypeClass,
        /// Consume up to the type's size, not one register.
        match_size: bool,
        /// The registers that can be consumed.
        tiles: Vec<usize>,
    },
    /// Consume stack as well (`<extra_stack>`, Ghidra `ExtraStack`).
    ExtraStack {
        /// Only after this many bytes of `after_storage` are consumed.
        after_bytes: i32,
        /// The class counted.
        after_storage: TypeClass,
        /// The stack entry.
        stack: usize,
    },
    /// Consume every remaining register of a class
    /// (`<consume_remaining>`, Ghidra `ConsumeRemaining`).
    ConsumeRemaining {
        /// The class consumed from.
        class: TypeClass,
        /// The registers that can be consumed.
        tiles: Vec<usize>,
    },
}

fn stack_entry_for(list: &ParamList, action: &str) -> Result<usize> {
    list.stack_entry().ok_or_else(|| {
        CspecError::new(format!(
            "Cannot find matching <pentry> for action: {action}"
        ))
    })
}

fn tiles_for(list: &ParamList, class: TypeClass, action: &str) -> Result<Vec<usize>> {
    let tiles = list.extract_tiles(class);
    if tiles.is_empty() {
        return Err(CspecError::new(format!(
            "Could not find matching resources for action: {action}"
        )));
    }
    Ok(tiles)
}

impl AssignAction {
    /// Reads the action of a rule (Ghidra `AssignAction::decodeAction`).
    pub(crate) fn decode_action(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let Some(peek) = dec.peek_element() else {
            return Err(CspecError::new("Expecting model rule action"));
        };
        if peek == ELEM_GOTO_STACK {
            let elem = dec.open_element_expecting(ELEM_GOTO_STACK)?;
            dec.close_element(elem)?;
            Ok(Self::GotoStack {
                stack: stack_entry_for(list, "goto_stack")?,
            })
        } else if peek == ELEM_JOIN {
            Ok(Self::MultiSlot(MultiSlotAssign::decode(dec, list)?))
        } else if peek == ELEM_CONSUME {
            let elem = dec.open_element_expecting(ELEM_CONSUME)?;
            let class = type_class(dec.read_string_attr(ATTRIB_STORAGE)?)?;
            dec.close_element(elem)?;
            Ok(Self::ConsumeAs { class })
        } else if peek == ELEM_CONVERT_TO_PTR {
            let elem = dec.open_element_expecting(ELEM_CONVERT_TO_PTR)?;
            dec.close_element(elem)?;
            Ok(Self::ConvertToPointer {
                space: list.spacebase(),
            })
        } else if peek == ELEM_HIDDEN_RETURN {
            let elem = dec.open_element_expecting(ELEM_HIDDEN_RETURN)?;
            let mut code = AssignResult::HiddenretSpecialreg;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_VOIDLOCK {
                    code = AssignResult::HiddenretSpecialregVoid;
                } else if attr == ATTRIB_STRATEGY {
                    code = match dec.read_string()? {
                        "normalparam" => AssignResult::HiddenretPtrparam,
                        "special" => AssignResult::HiddenretSpecialreg,
                        s => {
                            return Err(CspecError::new(format!(
                                "Bad <hidden_return> strategy: {s}"
                            )));
                        }
                    };
                } else {
                    break;
                }
            }
            dec.close_element(elem)?;
            Ok(Self::HiddenReturn { code })
        } else if peek == ELEM_JOIN_PER_PRIMITIVE {
            Ok(Self::MultiMember(MultiMemberAssign::decode(dec, list)?))
        } else if peek == ELEM_JOIN_DUAL_CLASS {
            Ok(Self::DualClass(DualClassAssign::decode(dec, list)?))
        } else {
            Err(CspecError::new("Expecting model rule action"))
        }
    }

    /// Reads a precondition if one is next (Ghidra `decodePrecondition`).
    pub(crate) fn decode_precondition(
        dec: &mut dyn Decoder<'_>,
        list: &ParamList,
    ) -> Result<Option<Self>> {
        if dec.peek_element().is_some_and(|p| p == ELEM_CONSUME_EXTRA) {
            return Self::decode_consume_extra(dec, list).map(Some);
        }
        Ok(None)
    }

    /// Reads a side effect (Ghidra `decodeSideeffect`).
    pub(crate) fn decode_side_effect(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let Some(peek) = dec.peek_element() else {
            return Err(CspecError::new("Expecting model rule sideeffect"));
        };
        if peek == ELEM_CONSUME_EXTRA {
            Self::decode_consume_extra(dec, list)
        } else if peek == ELEM_EXTRA_STACK {
            let elem = dec.open_element_expecting(ELEM_EXTRA_STACK)?;
            let mut after_bytes = -1;
            let mut after_storage = TypeClass::General;
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_AFTER_BYTES {
                    after_bytes = dec.read_unsigned()? as i32;
                } else if attr == ATTRIB_AFTER_STORAGE {
                    after_storage = type_class(dec.read_string()?)?;
                }
            }
            dec.close_element(elem)?;
            Ok(Self::ExtraStack {
                after_bytes,
                after_storage,
                stack: stack_entry_for(list, "extra_stack")?,
            })
        } else if peek == ELEM_CONSUME_REMAINING {
            let elem = dec.open_element_expecting(ELEM_CONSUME_REMAINING)?;
            let class = type_class(dec.read_string_attr(ATTRIB_STORAGE)?)?;
            dec.close_element(elem)?;
            Ok(Self::ConsumeRemaining {
                class,
                tiles: tiles_for(list, class, "consume_remaining")?,
            })
        } else {
            Err(CspecError::new("Expecting model rule sideeffect"))
        }
    }

    fn decode_consume_extra(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let elem = dec.open_element_expecting(ELEM_CONSUME_EXTRA)?;
        let mut class = TypeClass::General;
        let mut match_size = true;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_STORAGE {
                class = type_class(dec.read_string()?)?;
            } else if attr == ATTRIB_MATCHSIZE {
                match_size = dec.read_bool()?;
            }
        }
        dec.close_element(elem)?;
        Ok(Self::ConsumeExtra {
            class,
            match_size,
            tiles: tiles_for(list, class, "consume_extra")?,
        })
    }

    /// Ghidra's element name for the action.
    pub const fn element_name(&self) -> &'static str {
        match self {
            Self::GotoStack { .. } => "goto_stack",
            Self::ConvertToPointer { .. } => "convert_to_ptr",
            Self::MultiSlot(_) => "join",
            Self::MultiMember(_) => "join_per_primitive",
            Self::DualClass(_) => "join_dual_class",
            Self::ConsumeAs { .. } => "consume",
            Self::HiddenReturn { .. } => "hidden_return",
            Self::ConsumeExtra { .. } => "consume_extra",
            Self::ExtraStack { .. } => "extra_stack",
            Self::ConsumeRemaining { .. } => "consume_remaining",
        }
    }

    /// Whether the action takes part in return value recovery (Ghidra
    /// `canAffectFillinOutput`).
    pub const fn can_affect_fillin_output(&self) -> bool {
        matches!(
            self,
            Self::GotoStack { .. }
                | Self::MultiSlot(_)
                | Self::MultiMember(_)
                | Self::DualClass(_)
                | Self::ConsumeAs { .. }
        )
    }

    /// Assigns storage, or acts as a precondition or side effect (Ghidra
    /// `assignAddress`).
    pub(crate) fn assign_address(
        &self,
        list: &ParamList,
        env: &mut Env<'_>,
        dt: TypeHandle,
        pos: i32,
        status: &mut Status,
        res: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        match self {
            Self::GotoStack { stack } => {
                let Some(entry) = list.entry(*stack) else {
                    return Ok(AssignResult::Fail);
                };
                let grp = entry.group();
                let mut slot = status.get(grp);
                let (size, align) = (env.types.size(dt), env.types.alignment(dt));
                res.ty = dt;
                res.addr = entry.addr_by_slot(env.manager, &mut slot, size, align)?;
                status.set(grp, slot);
                res.flags = PieceFlags::empty();
                Ok(AssignResult::Success)
            }
            Self::ConvertToPointer { space } => {
                let (size, ws) = crate::list::pointer_shape_for(*space, env.manager);
                let pointer = env.types.pointer_to(dt, size, ws);
                env.depth += 1;
                let code = list.assign_address(env, pointer, pos, status, res);
                env.depth -= 1;
                res.flags = PieceFlags::INDIRECTSTORAGE;
                code
            }
            Self::MultiSlot(a) => a.assign(list, env, dt, status, res),
            Self::MultiMember(a) => a.assign(list, env, (dt, pos), status, res),
            Self::DualClass(a) => a.assign(list, env, dt, status, res),
            Self::ConsumeAs { class } => list.assign_fallback(env, *class, (dt, true), status, res),
            Self::HiddenReturn { code } => Ok(*code),
            Self::ConsumeExtra {
                match_size, tiles, ..
            } => {
                let mut left = env.types.size(dt);
                for &t in tiles {
                    if left <= 0 {
                        break;
                    }
                    let Some(entry) = list.entry(t) else { continue };
                    if status.get(entry.group()) != 0 {
                        continue;
                    }
                    status.set(entry.group(), -1);
                    left = left.wrapping_sub(entry.size());
                    if !match_size {
                        break;
                    }
                }
                Ok(AssignResult::Success)
            }
            Self::ExtraStack {
                after_bytes,
                after_storage,
                stack,
            } => extra_stack(
                list,
                env,
                dt,
                status,
                res,
                (*after_bytes, *after_storage, *stack),
            ),
            Self::ConsumeRemaining { tiles, .. } => {
                for &t in tiles {
                    if let Some(entry) = list.entry(t)
                        && status.get(entry.group()) == 0
                    {
                        status.set(entry.group(), -1);
                    }
                }
                Ok(AssignResult::Success)
            }
        }
    }

    /// Whether the trials, matched and sorted, can be return storage made
    /// by this action (Ghidra `fillinOutputMap`).
    pub(crate) fn fillin_output_map(&self, list: &ParamList, active: &mut ParamActive) -> bool {
        match self {
            Self::GotoStack { stack } => {
                let mut count = 0;
                for t in active.trials() {
                    let Some(e) = t.entry else { break };
                    if e != *stack {
                        return false;
                    }
                    count += 1;
                    if count > 1 {
                        return false;
                    }
                }
                count == 1
            }
            Self::MultiSlot(a) => a.fillin_output_map(list, active),
            Self::MultiMember(a) => a.fillin_output_map(list, active),
            Self::DualClass(a) => a.fillin_output_map(list, active),
            Self::ConsumeAs { class } => {
                let mut count = 0;
                for t in active.trials() {
                    let Some(e) = t.entry.and_then(|e| list.entry(e)) else {
                        break;
                    };
                    if e.type_class() != *class || !e.is_first_in_class() {
                        return false;
                    }
                    count += 1;
                    if count > 1 || t.offset != 0 {
                        return false;
                    }
                }
                count > 0
            }
            _ => false,
        }
    }
}

/// `ExtraStack::assignAddress`: consume the stack as if the parameter were
/// there, unless it already is or not enough of a class is consumed yet.
fn extra_stack(
    list: &ParamList,
    env: &mut Env<'_>,
    dt: TypeHandle,
    status: &mut Status,
    res: &ParameterPieces,
    (after_bytes, after_storage, stack): (i32, TypeClass, usize),
) -> Result<AssignResult> {
    let Some(entry) = list.entry(stack) else {
        return Ok(AssignResult::Success);
    };
    if res.addr.space() == Some(entry.space()) {
        return Ok(AssignResult::Success);
    }
    let grp = entry.group();
    if after_bytes > 0 {
        let consumed: i32 = list
            .entries()
            .iter()
            .filter(|e| e.group() != grp && e.type_class() == after_storage)
            .filter(|e| status.get(e.group()) != 0)
            .map(crate::entry::ParamEntry::size)
            .fold(0, i32::wrapping_add);
        if consumed < after_bytes {
            return Ok(AssignResult::Success);
        }
    }
    let mut slot = status.get(grp);
    let (size, align) = (env.types.size(dt), env.types.alignment(dt));
    let _consumed = entry.addr_by_slot(env.manager, &mut slot, size, align)?;
    status.set(grp, slot);
    Ok(AssignResult::Success)
}
