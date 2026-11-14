//! Macros (inventory 9.7; `SleighCompile::createMacro`, `buildMacro`,
//! `expandMacros`; `MacroBuilder`; `VarnodeTpl::transfer`,
//! `ConstTpl::transfer`).

use bk_pcode::OpCode;
use bk_sla::{ConstTpl, HandleSelect, HandleTpl};
use bk_sleigh_syntax::ast::MacroDef;

use super::resolver::CtorResolver;
use super::{Compiler, Fatal, MacroData};
use crate::ids::{MacroId, ScopeId};
use crate::pcode::{Builder, Stop, propagate_size};
use crate::symbols::SymbolKind;
use crate::template::{LABEL, MACROBUILD, Op, Tpl, UNIQUE_SPACE, Vn, export_handle, is_zero, real};

/// The largest number of ops one section may grow to by macro expansion
/// (spec 4.5).
pub(crate) const MAX_EXPANDED_OPS: usize = 1_000_000;

/// `ConstTpl::transfer`: a handle part of a macro parameter becomes the
/// matching part of the argument.
fn transfer_const(c: &mut ConstTpl, params: &[HandleTpl]) -> Result<(), String> {
    let ConstTpl::Handle { index, select, plus } = *c else {
        return Ok(());
    };
    let Some(hand) = params.get(index as usize) else {
        return Err("Macro parameter out of range".to_owned());
    };
    match select {
        HandleSelect::Space => *c = hand.space,
        HandleSelect::Offset => *c = hand.ptr_offset,
        HandleSelect::Size => *c = hand.size,
        HandleSelect::OffsetPlus => {
            *c = match hand.ptr_offset {
                ConstTpl::Real(v) => ConstTpl::Real(v.wrapping_add(plus & 0xffff)),
                ConstTpl::Handle {
                    index,
                    select: HandleSelect::Offset,
                    ..
                } => ConstTpl::Handle {
                    index,
                    select: HandleSelect::OffsetPlus,
                    plus,
                },
                _ => return Err("Cannot truncate macro input in this way".to_owned()),
            };
        }
    }
    Ok(())
}

/// `VarnodeTpl::transfer`: returns the truncation still to apply (the
/// `plus` of an offset-plus reference to a temporary or a zero-size
/// argument), or `None`.
fn transfer_vn(vn: &mut Vn, params: &[HandleTpl]) -> Result<Option<i32>, String> {
    let offset_plus = match vn.offset {
        ConstTpl::Handle {
            index,
            select: HandleSelect::OffsetPlus,
            plus,
        } => Some((index, plus as i32)),
        _ => None,
    };
    transfer_const(&mut vn.space, params)?;
    transfer_const(&mut vn.offset, params)?;
    transfer_const(&mut vn.size, params)?;
    if let Some((index, plus)) = offset_plus {
        if vn.is_local_temp() {
            return Ok(Some(plus));
        }
        if params.get(index as usize).is_some_and(|h| is_zero(&h.size)) {
            return Ok(Some(plus));
        }
    }
    Ok(None)
}

impl<'a> Compiler<'a> {
    /// `createMacro` + the body + `buildMacro`.
    pub(crate) fn macro_def(&mut self, m: &'a MacroDef) -> Result<(), Fatal> {
        self.cur_ctor = None;
        let id = MacroId::next(self.macros.len());
        let index = self.macro_templates.len() as u32;
        let symbol = self.add_symbol(m.name.name, SymbolKind::Macro(id), m.name.span);
        self.macros.push(MacroData {
            symbol,
            index,
            params: Vec::new(),
        });
        self.cur_macro = Some(id);
        if self.symbols.add_scope().is_err() {
            self.diags.error(Some(m.span), "Too many scopes");
            return Err(Fatal);
        }
        for (i, param) in m.params.iter().enumerate() {
            let op = self.new_operand(param.name, i as u32, None, param.span);
            if let Some(data) = self.macros.get_mut(id.slot()) {
                data.params.push(op);
            }
        }
        let env = self.build_env();
        let parsed = self.parsed;
        let mut resolver = CtorResolver { compiler: self };
        let mut builder = Builder::new(&env, &mut resolver, &parsed.names, &parsed.spec.nodes);
        let result = builder.section(&m.body.statements, true);
        let labels = builder.label_problems();
        let diagnostics = builder.take_diagnostics();
        for d in diagnostics {
            self.diags.push(d);
        }
        let mut tpl = match result {
            Ok(tpl) => tpl,
            Err(Stop::Abort) => {
                self.symbols.set_current(ScopeId::GLOBAL);
                self.cur_macro = None;
                return Ok(());
            }
            Err(Stop::Fatal(message)) => {
                self.diags.error(Some(m.span), message);
                return Err(Fatal);
            }
        };
        let name = self.text(m.name.name).to_owned();
        if tpl.ops.is_empty() && tpl.result.is_none() {
            self.nops.push(bk_sleigh_syntax::Span::at(m.body.span.end.saturating_sub(1)));
        }
        if !labels.is_empty() {
            self.diags.error_at(m.span, format!("In definition of macro '{name}': {labels}"));
            return Ok(());
        }
        if !self.expand_macros(&mut tpl) {
            self.diags.error_at(m.span, format!("Could not expand submacro in definition of macro '{name}'"));
            return Ok(());
        }
        if let Err(e) = propagate_size(&mut tpl.ops) {
            self.diags.error(Some(m.span), e.to_string());
            return Err(Fatal);
        }
        if self.fatal {
            return Err(Fatal);
        }
        self.symbols.pop_scope();
        self.macro_templates.push(tpl);
        self.cur_macro = None;
        Ok(())
    }

    /// `expandMacros`: replaces each macro placeholder of `tpl` by the
    /// macro's ops. False if a macro could not be expanded.
    pub(crate) fn expand_macros(&mut self, tpl: &mut Tpl) -> bool {
        if !tpl.ops.iter().any(|op| op.opcode == MACROBUILD) {
            return true;
        }
        let ops = std::mem::take(&mut tpl.ops);
        let mut out = Vec::with_capacity(ops.len());
        let mut ok = true;
        for op in ops {
            if op.opcode != MACROBUILD {
                out.push(op);
                continue;
            }
            let index = op.inputs.first().map_or(u64::MAX, |v| real(&v.offset)) as usize;
            let Some(body) = self.macro_templates.get(index).cloned() else {
                tpl.ops = out;
                return false;
            };
            let params: Vec<HandleTpl> = op.inputs.iter().skip(1).map(export_handle).collect();
            let label_base = u64::from(tpl.labels);
            if !self.expand_one(&body, &params, label_base, &mut out) {
                ok = false;
            }
            tpl.labels = tpl.labels.wrapping_add(body.labels);
            if out.len() > MAX_EXPANDED_OPS {
                self.diags.error(None, "Macro expansion exceeds 1000000 ops");
                self.fatal = true;
                tpl.ops = out;
                return false;
            }
            if !ok {
                tpl.ops = out;
                return false;
            }
        }
        tpl.ops = out;
        ok
    }

    /// `MacroBuilder::build` for one invocation.
    fn expand_one(&mut self, body: &Tpl, params: &[HandleTpl], label_base: u64, out: &mut Vec<Op>) -> bool {
        let mut ok = true;
        for op in &body.ops {
            let mut clone = op.clone();
            if op.opcode == LABEL {
                if let Some(input) = clone.inputs.first_mut() {
                    input.offset = ConstTpl::Real(real(&input.offset).wrapping_add(label_base));
                }
                out.push(clone);
                continue;
            }
            for input in &mut clone.inputs {
                if let ConstTpl::Relative(v) = input.offset {
                    input.offset = ConstTpl::Relative(v.wrapping_add(label_base));
                }
            }
            match self.transfer_op(clone, params, out) {
                Ok(true) => {}
                Ok(false) => ok = false,
                Err(message) => {
                    self.diags.error(None, message);
                    self.fatal = true;
                    return false;
                }
            }
        }
        ok
    }

    /// `MacroBuilder::transferOp`.
    fn transfer_op(&mut self, mut op: Op, params: &[HandleTpl], out: &mut Vec<Op>) -> Result<bool, String> {
        if let Some(output) = op.output.as_mut()
            && let Some(plus) = transfer_vn(output, params)?
            && plus >= 0
        {
            self.diags.error(None, "Cannot currently assign to bitrange of macro parameter that is a temporary");
            return Ok(false);
        }
        let mut handle_index = 0_u32;
        let mut has_real_size = false;
        let mut real_size = 0_u64;
        for i in 0..op.inputs.len() {
            let Some(vn) = op.inputs.get_mut(i) else { break };
            if let ConstTpl::Handle { index, .. } = vn.offset {
                handle_index = index;
                has_real_size = matches!(vn.size, ConstTpl::Real(_));
                real_size = real(&vn.size);
            }
            let Some(plus) = transfer_vn(vn, params)? else { continue };
            if plus < 0 {
                continue;
            }
            if !has_real_size {
                self.diags.error(None, "Problem with bit range operator in macro");
                return Ok(false);
            }
            let temp = self.unique_addr();
            let new_vn = Vn::new(ConstTpl::Space(UNIQUE_SPACE), ConstTpl::Real(temp), ConstTpl::Real(real_size));
            let hand = params.get(handle_index as usize).copied().unwrap_or_else(|| export_handle(&Vn::constant(0, 0)));
            out.push(Op {
                opcode: OpCode::SubPiece,
                output: Some(new_vn),
                inputs: vec![
                    Vn::new(hand.space, hand.ptr_offset, hand.size),
                    Vn::constant(plus as u64, 4),
                ],
            });
            if let Some(slot) = op.inputs.get_mut(i) {
                *slot = new_vn;
            }
        }
        out.push(op);
        Ok(true)
    }
}
