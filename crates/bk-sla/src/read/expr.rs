//! Decoding pattern expressions and p-code templates.

use super::decode::{Reader, need, to_i32, to_index, to_u32};
use super::source::Source;
use crate::error::Fail;
use crate::ids::{self, a, e};
use crate::model::constructor::ContextChange;
use crate::model::expr::{BinaryOp, Expr, Field, UnaryOp};
use crate::model::handles::{ExprId, FieldId, HandleId, Span, SymbolId};
use crate::model::template::{ConstTpl, ConstructTpl, HandleSelect, HandleTpl, OpTpl, VarnodeTpl};

fn binary(id: u32) -> Option<BinaryOp> {
    Some(match id {
        e::PLUS_EXP => BinaryOp::Plus,
        e::SUB_EXP => BinaryOp::Sub,
        e::MULT_EXP => BinaryOp::Mult,
        e::LSHIFT_EXP => BinaryOp::LeftShift,
        e::RSHIFT_EXP => BinaryOp::RightShift,
        e::AND_EXP => BinaryOp::And,
        e::OR_EXP => BinaryOp::Or,
        e::XOR_EXP => BinaryOp::Xor,
        e::DIV_EXP => BinaryOp::Div,
        _ => return None,
    })
}

pub(crate) fn read_expr<'a, S: Source<'a>>(
    r: &mut Reader<'a, '_, S>,
    depth: u32,
) -> Result<ExprId, Fail> {
    if depth >= r.limits.expr_depth {
        return Err(Fail::limit(
            "expression nesting",
            u64::from(r.limits.expr_depth),
            u64::from(depth) + 1,
        ));
    }
    let Some(id) = r.src.peek()? else {
        return Err(Fail::invalid("Invalid pattern expression element: none present"));
    };
    let expr = match id {
        e::TOKENFIELD | e::CONTEXTFIELD => {
            r.src.open()?;
            let field = read_field(r, id == e::TOKENFIELD)?;
            let field_id = FieldId::new(r.a.fields.len() as u32);
            r.a.fields.push(field);
            if id == e::TOKENFIELD {
                Expr::TokenField(field_id)
            } else {
                Expr::ContextField(field_id)
            }
        }
        e::INTB => {
            r.src.open()?;
            let mut value = None;
            while let Some(attr) = r.src.next_attr()? {
                if attr == a::VAL {
                    value = Some(r.src.signed()?);
                }
            }
            Expr::Constant(need(value, "val")?)
        }
        e::OPERAND_EXP => {
            r.src.open()?;
            let (mut index, mut table, mut ct) = (None, None, None);
            while let Some(attr) = r.src.next_attr()? {
                match attr {
                    a::INDEX => index = Some(to_i32(r.src.signed()?, "index")?),
                    a::TABLE => table = Some(to_u32(r.src.unsigned()?, "table")?),
                    a::CT => ct = Some(to_u32(r.src.unsigned()?, "ct")?),
                    _ => {}
                }
            }
            Expr::Operand {
                index: need(index, "index")?,
                table: SymbolId::new(need(table, "table")?),
                ct: need(ct, "ct")?,
            }
        }
        e::START_EXP => {
            r.src.open()?;
            Expr::Start
        }
        e::END_EXP => {
            r.src.open()?;
            Expr::End
        }
        e::NEXT2_EXP => {
            r.src.open()?;
            Expr::Next2
        }
        e::MINUS_EXP | e::NOT_EXP => {
            r.src.open()?;
            let operand = read_expr(r, depth + 1)?;
            let op = if id == e::MINUS_EXP { UnaryOp::Minus } else { UnaryOp::Not };
            Expr::Unary { op, operand }
        }
        _ => {
            let Some(op) = binary(id) else {
                return Err(Fail::invalid(format!(
                    "Invalid pattern expression element: {}",
                    super::source::element_text(id)
                )));
            };
            r.src.open()?;
            let left = read_expr(r, depth + 1)?;
            let right = read_expr(r, depth + 1)?;
            Expr::Binary { op, left, right }
        }
    };
    r.src.close()?;
    let expr_id = ExprId::new(r.a.exprs.len() as u32);
    r.a.exprs.push(expr);
    Ok(expr_id)
}

fn read_field<'a, S: Source<'a>>(r: &mut Reader<'a, '_, S>, token: bool) -> Result<Field, Fail> {
    let mut big_endian = None;
    let mut sign_bit = None;
    let mut values: [Option<i32>; 5] = [None; 5];
    while let Some(attr) = r.src.next_attr()? {
        let slot = match attr {
            a::BIGENDIAN if token => {
                big_endian = Some(r.src.bool()?);
                continue;
            }
            a::SIGNBIT => {
                sign_bit = Some(r.src.bool()?);
                continue;
            }
            a::STARTBIT => 0,
            a::ENDBIT => 1,
            a::STARTBYTE => 2,
            a::ENDBYTE => 3,
            a::SHIFT => 4,
            _ => continue,
        };
        let name = ids::attribute_name(attr).unwrap_or("?");
        if let Some(value) = values.get_mut(slot) {
            *value = Some(to_i32(r.src.signed()?, name)?);
        }
    }
    let [start_bit, end_bit, start_byte, end_byte, shift] = values;
    Ok(Field {
        big_endian: if token { need(big_endian, "bigendian")? } else { false },
        sign_bit: need(sign_bit, "signbit")?,
        start_bit: need(start_bit, "startbit")?,
        end_bit: need(end_bit, "endbit")?,
        start_byte: need(start_byte, "startbyte")?,
        end_byte: need(end_byte, "endbyte")?,
        shift: need(shift, "shift")?,
    })
}

/// Reads a `context_op` or `commit` (already peeked as `id`).
pub(crate) fn read_context_change<'a, S: Source<'a>>(
    r: &mut Reader<'a, '_, S>,
    id: u32,
) -> Result<ContextChange, Fail> {
    r.src.open()?;
    let (mut word, mut shift, mut mask, mut symbol, mut flow) = (None, None, None, None, None);
    while let Some(attr) = r.src.next_attr()? {
        match attr {
            a::I if id == e::CONTEXT_OP => word = Some(to_i32(r.src.signed()?, "i")?),
            a::NUMBER if id == e::COMMIT => word = Some(to_i32(r.src.signed()?, "number")?),
            a::SHIFT if id == e::CONTEXT_OP => shift = Some(to_i32(r.src.signed()?, "shift")?),
            a::MASK => mask = Some(to_u32(r.src.unsigned()?, "mask")?),
            a::ID if id == e::COMMIT => symbol = Some(to_u32(r.src.unsigned()?, "id")?),
            a::FLOW if id == e::COMMIT => flow = Some(r.src.bool()?),
            _ => {}
        }
    }
    let change = if id == e::CONTEXT_OP {
        ContextChange::Op {
            word: need(word, "i")?,
            shift: need(shift, "shift")?,
            mask: need(mask, "mask")?,
            expr: read_expr(r, 0)?,
        }
    } else {
        ContextChange::Commit {
            symbol: SymbolId::new(need(symbol, "id")?),
            word: need(word, "number")?,
            mask: need(mask, "mask")?,
            flow: need(flow, "flow")?,
        }
    };
    r.src.close()?;
    Ok(change)
}

fn read_const<'a, S: Source<'a>>(r: &mut Reader<'a, '_, S>) -> Result<ConstTpl, Fail> {
    let id = r.src.open()?;
    let value = match id {
        e::CONST_REAL | e::CONST_RELATIVE => {
            let mut value = None;
            while let Some(attr) = r.src.next_attr()? {
                if attr == a::VAL {
                    value = Some(r.src.unsigned()?);
                }
            }
            let value = need(value, "val")?;
            if id == e::CONST_REAL {
                ConstTpl::Real(value)
            } else {
                ConstTpl::Relative(value)
            }
        }
        e::CONST_HANDLE => {
            let (mut index, mut select, mut plus) = (None, None, None);
            while let Some(attr) = r.src.next_attr()? {
                match attr {
                    a::VAL => index = Some(to_index(r.src.signed()?, "val")?),
                    a::S => select = Some(r.src.signed()?),
                    a::PLUS => plus = Some(r.src.unsigned()?),
                    _ => {}
                }
            }
            let select = HandleSelect::from_number(need(select, "s")?)
                .ok_or_else(|| Fail::invalid("Bad handle selector encoding"))?;
            let plus = if select == HandleSelect::OffsetPlus {
                need(plus, "plus")?
            } else {
                0
            };
            ConstTpl::Handle {
                index: need(index, "val")?,
                select,
                plus,
            }
        }
        e::CONST_SPACEID => {
            let mut space = None;
            while let Some(attr) = r.src.next_attr()? {
                if attr == a::SPACE {
                    let attr = r.src.space()?;
                    space = Some(r.space_ref(attr)?);
                }
            }
            ConstTpl::Space(need(space, "space")?)
        }
        e::CONST_START => ConstTpl::Start,
        e::CONST_NEXT => ConstTpl::Next,
        e::CONST_NEXT2 => ConstTpl::Next2,
        e::CONST_CURSPACE => ConstTpl::CurSpace,
        e::CONST_CURSPACE_SIZE => ConstTpl::CurSpaceSize,
        e::CONST_FLOWREF => ConstTpl::FlowRef,
        e::CONST_FLOWREF_SIZE => ConstTpl::FlowRefSize,
        e::CONST_FLOWDEST => ConstTpl::FlowDest,
        e::CONST_FLOWDEST_SIZE => ConstTpl::FlowDestSize,
        _ => return Err(Fail::invalid(format!(
            "Bad constant type: {}",
            super::source::element_text(id)
        ))),
    };
    r.src.close()?;
    Ok(value)
}

fn read_varnode<'a, S: Source<'a>>(r: &mut Reader<'a, '_, S>) -> Result<VarnodeTpl, Fail> {
    r.open_expect(ids::ELEM_VARNODE_TPL)?;
    let space = read_const(r)?;
    let offset = read_const(r)?;
    let size = read_const(r)?;
    r.src.close()?;
    Ok(VarnodeTpl { space, offset, size })
}

/// Reads one `construct_tpl` (already peeked) into the template arenas and
/// returns its header.
pub(crate) fn read_template<'a, S: Source<'a>>(
    r: &mut Reader<'a, '_, S>,
) -> Result<ConstructTpl, Fail> {
    r.open_expect(ids::ELEM_CONSTRUCT_TPL)?;
    let (mut section, mut delay, mut labels) = (None, 0, 0);
    while let Some(attr) = r.src.next_attr()? {
        match attr {
            a::DELAY => delay = to_i32(r.src.signed()?, "delay")?,
            a::LABELS => labels = to_i32(r.src.signed()?, "labels")?,
            a::SECTION => {
                let value = to_i32(r.src.signed()?, "section")?;
                section = u32::try_from(value).ok();
            }
            _ => {}
        }
    }
    let result = if r.src.peek()? == Some(e::NULL) {
        r.src.open()?;
        r.src.close()?;
        None
    } else {
        r.open_expect(ids::ELEM_HANDLE_TPL)?;
        let mut parts = [ConstTpl::Start; 7];
        for part in &mut parts {
            *part = read_const(r)?;
        }
        r.src.close()?;
        let handle = HandleId::new(r.a.handles.len() as u32);
        r.a.handles.push(HandleTpl::from_parts(parts));
        Some(handle)
    };
    let ops_start = r.a.ops.len();
    while r.src.peek()?.is_some() {
        r.open_expect(ids::ELEM_OP_TPL)?;
        let mut opcode = None;
        while let Some(attr) = r.src.next_attr()? {
            if attr == a::CODE {
                opcode = Some(r.opcode()?);
            }
        }
        let opcode = need(opcode, "code")?;
        let start = r.a.varnodes.len();
        let has_output = if r.src.peek()? == Some(e::NULL) {
            r.src.open()?;
            r.src.close()?;
            false
        } else {
            let output = read_varnode(r)?;
            r.a.varnodes.push(output);
            true
        };
        while r.src.peek()?.is_some() {
            let input = read_varnode(r)?;
            r.a.varnodes.push(input);
        }
        r.src.close()?;
        r.a.ops.push(OpTpl {
            opcode,
            has_output,
            varnodes: Span::since(start, &r.a.varnodes),
        });
    }
    r.src.close()?;
    Ok(ConstructTpl {
        section,
        delay,
        labels,
        result,
        ops: Span::since(ops_start, &r.a.ops),
    })
}
