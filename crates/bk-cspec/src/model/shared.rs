//! Actions that see both input and output assignment (Ghidra
//! `SharedAction`, `HiddenReturnAction`, `ShareStackAction`).

use bk_marshal::Decoder;
use bk_marshal::ids::ATTRIB_ALIGN;

use super::ProtoModel;
use crate::error::Result;
use crate::ids::{ATTRIB_FIRST, ELEM_SHARESTACK};
use crate::list::{Env, ParamList};
use crate::proto::{ParameterPieces, PieceFlags};
use crate::status::Status;
use crate::types::TypeClass;

/// An action run around input assignment (Ghidra's `SharedAction`
/// subclasses).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAction {
    /// Assigns the hidden return pointer from the inputs and marks `this`
    /// (Ghidra `HiddenReturnAction`).
    HiddenReturn,
    /// Lets inputs and outputs share the stack (Ghidra
    /// `ShareStackAction`).
    ShareStack {
        /// Inputs take the stack first.
        input_first: bool,
        /// Extra alignment between the first and second allocations.
        extra_align: i32,
        /// The input stack entry when the element was read.
        input_stack: Option<usize>,
        /// The output stack entry when the element was read.
        output_stack: Option<usize>,
    },
}

impl SharedAction {
    /// Reads a `<sharestack>`; the stack entries are those of the lists as
    /// read so far, as in Ghidra's constructor.
    pub(crate) fn decode_share_stack(
        dec: &mut dyn Decoder<'_>,
        input: &ParamList,
        output: &ParamList,
    ) -> Result<Self> {
        let elem = dec.open_element_expecting(ELEM_SHARESTACK)?;
        let mut input_first = false;
        let mut extra_align = 0;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_FIRST {
                input_first = dec.read_string()? == "input";
            } else if attr == ATTRIB_ALIGN {
                extra_align = dec.read_unsigned()? as i32;
            }
        }
        dec.close_element(elem)?;
        Ok(Self::ShareStack {
            input_first,
            extra_align,
            input_stack: input.stack_entry(),
            output_stack: output.stack_entry(),
        })
    }

    /// Ghidra `applyBefore`.
    pub(crate) fn apply_before(
        &self,
        model: &ProtoModel,
        env: &mut Env<'_>,
        params: &mut [ParameterPieces],
        input_status: &mut Status,
        output_status: &Status,
    ) -> Result<()> {
        match self {
            Self::HiddenReturn => {
                if let [_, last] = params {
                    let input = &model.input;
                    if last.flags.contains(PieceFlags::HIDDENRETPARM) {
                        let ty = last.ty;
                        input.assign_fallback(
                            env,
                            TypeClass::HiddenRet,
                            (ty, false),
                            input_status,
                            last,
                        )?;
                    } else {
                        let ty = last.ty;
                        input.assign_address(env, ty, 0, input_status, last)?;
                    }
                    last.flags |= PieceFlags::HIDDENRETPARM;
                }
                Ok(())
            }
            Self::ShareStack {
                input_first,
                extra_align,
                input_stack,
                output_stack,
            } => {
                if *input_first {
                    return Ok(());
                }
                let (Some(ins), Some(outs)) = (
                    input_stack.and_then(|i| model.input.entry(i)),
                    output_stack.and_then(|i| model.output.entry(i)),
                ) else {
                    return Ok(());
                };
                let slot = align_slot(output_status.get(outs.group()), ins.align(), *extra_align);
                input_status.set(ins.group(), slot);
                Ok(())
            }
        }
    }

    /// Ghidra `applyAfter`.
    pub(crate) fn apply_after(
        &self,
        model: &ProtoModel,
        env: &mut Env<'_>,
        params: &mut [ParameterPieces],
        input_status: &Status,
    ) -> Result<()> {
        match self {
            Self::HiddenReturn => {
                if !model.has_this || params.len() <= 1 {
                    return Ok(());
                }
                let mut this_index = 1;
                let hidden = params
                    .get(1)
                    .is_some_and(|p| p.flags.contains(PieceFlags::HIDDENRETPARM));
                if hidden && params.len() > 2 {
                    if model.input.thisbeforeret {
                        if let [_, a, b, ..] = params {
                            a.swap_markup(b);
                        }
                    } else {
                        this_index = 2;
                    }
                }
                if let Some(p) = params.get_mut(this_index) {
                    p.flags |= PieceFlags::ISTHIS;
                }
                Ok(())
            }
            Self::ShareStack {
                input_first,
                extra_align,
                input_stack,
                output_stack,
            } => {
                if !*input_first {
                    return Ok(());
                }
                let (Some(ins), Some(outs)) = (
                    input_stack.and_then(|i| model.input.entry(i)),
                    output_stack.and_then(|i| model.output.entry(i)),
                ) else {
                    return Ok(());
                };
                let Some(out) = params.first_mut() else {
                    return Ok(());
                };
                if out.addr.is_invalid() || out.addr.space() != Some(outs.space()) {
                    return Ok(());
                }
                let mut slot = align_slot(input_status.get(ins.group()), ins.align(), *extra_align);
                let (size, align) = (env.types.size(out.ty), env.types.alignment(out.ty));
                out.addr = ins.addr_by_slot(env.manager, &mut slot, size, align)?;
                Ok(())
            }
        }
    }
}

/// Rounds a slot count up to an extra alignment (shared by both halves of
/// `ShareStackAction`).
fn align_slot(mut slot: i32, align: i32, extra: i32) -> i32 {
    if align > 0 && extra > align {
        let tmp = slot.wrapping_mul(align).wrapping_rem(extra);
        if tmp != 0 {
            slot = slot.wrapping_add((extra - tmp) / align);
        }
    }
    slot
}
