//! Writing p-code templates (Ghidra `ConstructTpl::encode` and the template
//! classes' `encode`).

use bk_marshal::{EncodeError, Encoder};

use super::{SpaceNames, space_ref};
use crate::ids::*;
use crate::model::template::{ConstTpl, HandleSelect, TemplateRef, VarnodeTpl};

fn encode_const<E: Encoder, N: SpaceNames + ?Sized>(enc: &mut E, names: &N, value: &ConstTpl) {
    let simple = |enc: &mut E, element| {
        enc.open_element(element);
        enc.close_element(element);
    };
    match *value {
        ConstTpl::Real(value) => {
            enc.open_element(ELEM_CONST_REAL);
            enc.write_unsigned(ATTRIB_VAL, value);
            enc.close_element(ELEM_CONST_REAL);
        }
        ConstTpl::Handle {
            index,
            select,
            plus,
        } => {
            enc.open_element(ELEM_CONST_HANDLE);
            enc.write_signed(ATTRIB_VAL, i64::from(index));
            enc.write_signed(ATTRIB_S, select.number());
            if select == HandleSelect::OffsetPlus {
                enc.write_unsigned(ATTRIB_PLUS, plus);
            }
            enc.close_element(ELEM_CONST_HANDLE);
        }
        ConstTpl::Start => simple(enc, ELEM_CONST_START),
        ConstTpl::Next => simple(enc, ELEM_CONST_NEXT),
        ConstTpl::Next2 => simple(enc, ELEM_CONST_NEXT2),
        ConstTpl::CurSpace => simple(enc, ELEM_CONST_CURSPACE),
        ConstTpl::CurSpaceSize => simple(enc, ELEM_CONST_CURSPACE_SIZE),
        ConstTpl::Space(index) => {
            enc.open_element(ELEM_CONST_SPACEID);
            enc.write_space(ATTRIB_SPACE, &space_ref(names, index));
            enc.close_element(ELEM_CONST_SPACEID);
        }
        ConstTpl::Relative(value) => {
            enc.open_element(ELEM_CONST_RELATIVE);
            enc.write_unsigned(ATTRIB_VAL, value);
            enc.close_element(ELEM_CONST_RELATIVE);
        }
        ConstTpl::FlowRef => simple(enc, ELEM_CONST_FLOWREF),
        ConstTpl::FlowRefSize => simple(enc, ELEM_CONST_FLOWREF_SIZE),
        ConstTpl::FlowDest => simple(enc, ELEM_CONST_FLOWDEST),
        ConstTpl::FlowDestSize => simple(enc, ELEM_CONST_FLOWDEST_SIZE),
    }
}

fn encode_varnode<E: Encoder, N: SpaceNames + ?Sized>(
    enc: &mut E,
    names: &N,
    varnode: &VarnodeTpl,
) {
    enc.open_element(ELEM_VARNODE_TPL);
    encode_const(enc, names, &varnode.space);
    encode_const(enc, names, &varnode.offset);
    encode_const(enc, names, &varnode.size);
    enc.close_element(ELEM_VARNODE_TPL);
}

/// Writes one `construct_tpl`.
pub(crate) fn encode_template<E: Encoder, N: SpaceNames + ?Sized>(
    enc: &mut E,
    names: &N,
    template: &TemplateRef<'_>,
) -> Result<(), EncodeError> {
    let header = template.header();
    enc.open_element(ELEM_CONSTRUCT_TPL);
    if let Some(section) = header.section {
        enc.write_signed(ATTRIB_SECTION, i64::from(section));
    }
    if header.delay != 0 {
        enc.write_signed(ATTRIB_DELAY, i64::from(header.delay));
    }
    if header.labels != 0 {
        enc.write_signed(ATTRIB_LABELS, i64::from(header.labels));
    }
    if let Some(handle) = template.result() {
        enc.open_element(ELEM_HANDLE_TPL);
        for part in &handle.parts() {
            encode_const(enc, names, part);
        }
        enc.close_element(ELEM_HANDLE_TPL);
    } else {
        enc.open_element(ELEM_NULL);
        enc.close_element(ELEM_NULL);
    }
    for op in template.ops() {
        enc.open_element(ELEM_OP_TPL);
        enc.write_enum(ATTRIB_CODE, u64::from(op.opcode.value()), op.opcode.name());
        if let Some(output) = template.output(op) {
            encode_varnode(enc, names, output);
        } else {
            enc.open_element(ELEM_NULL);
            enc.close_element(ELEM_NULL);
        }
        for input in template.inputs(op) {
            encode_varnode(enc, names, input);
        }
        enc.close_element(ELEM_OP_TPL);
    }
    enc.close_element(ELEM_CONSTRUCT_TPL);
    Ok(())
}
