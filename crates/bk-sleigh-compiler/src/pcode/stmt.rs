//! Statements (`statement`, `jumpdest`, `exportvarnode` of `slghparse.y`;
//! `PcodeCompile::newOutput`, `createStore`, `placeLabel`,
//! `SleighCompile::createMacroUse`, `setResultVarnode`).

use bk_pcode::OpCode;
use bk_sla::{ConstTpl, HandleTpl};
use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{ExportValue, ExprList, Ident, IntLit, JumpDest, LValue, Statement};

use super::expr::{ExprTree, is_keyword};
use super::{Builder, LabelId, LabelState, NameRef, Stop, SymbolResolver};
use crate::template::{
    BUILD, CONST_SPACE, CROSSBUILD, DELAY_SLOT, LABEL, MACROBUILD, Op, UNIQUE_SPACE, Vn,
    export_handle,
};

impl<R: SymbolResolver> Builder<'_, R> {
    /// Compiles one statement into ops.
    pub(crate) fn statement(&mut self, statement: &Statement) -> Result<Vec<Op>, Stop> {
        match statement {
            Statement::Assign {
                local,
                target,
                value,
                span,
                ..
            } => self.assign(*local, target, *value, *span),
            Statement::Declare { name, size, span } => {
                if self.lookup(*name) != NameRef::Unknown || is_keyword(self.name(*name)) {
                    self.syntax_error(name.span);
                    return Err(Stop::Abort);
                }
                let size = match size {
                    Some(lit) => self.int_or_abort(lit)? as u32,
                    None => 0,
                };
                let offset = self.resolver.allocate_temp();
                let vn = Vn::new(
                    ConstTpl::Space(UNIQUE_SPACE),
                    ConstTpl::Real(offset),
                    ConstTpl::Real(u64::from(size)),
                );
                self.define_local(*name, vn, *span);
                Ok(Vec::new())
            }
            Statement::Apply { name, args, span } => self.apply_statement(*name, *args, *span),
            Statement::Build { operand, .. } => {
                if let NameRef::Operand { index, .. } = self.lookup(*operand) {
                    Ok(vec![Op::new(
                        BUILD,
                        vec![Vn::constant(u64::from(index), 4)],
                    )])
                } else {
                    self.syntax_error(operand.span);
                    Err(Stop::Abort)
                }
            }
            Statement::CrossBuild {
                address, section, ..
            } => {
                let address = self.varnode(*address)?;
                let id = match self.lookup(*section) {
                    NameRef::Section(id) => id,
                    NameRef::Unknown => {
                        let name = self.name(*section);
                        match self.resolver.new_section(name, section.span) {
                            Ok(id) => id,
                            Err(e) => {
                                self.error(Some(section.span), e.0);
                                0
                            }
                        }
                    }
                    _ => {
                        self.syntax_error(section.span);
                        return Err(Stop::Abort);
                    }
                };
                Ok(vec![Op::new(
                    CROSSBUILD,
                    vec![address, Vn::constant(u64::from(id), 4)],
                )])
            }
            Statement::Goto { dest, .. } => self.branch(OpCode::Branch, OpCode::BranchInd, dest),
            Statement::Call { dest, .. } => self.branch(OpCode::Call, OpCode::CallInd, dest),
            Statement::If {
                condition, dest, ..
            } => {
                let cond = self.expr(*condition)?;
                if let JumpDest::Dynamic(e) = dest {
                    let span = self.nodes[*e].span();
                    self.syntax_error(span);
                    return Err(Stop::Abort);
                }
                let dest = self.jump_dest(dest)?;
                let mut ops = cond.ops;
                let c = cond.out.unwrap_or_else(|| Vn::constant(0, 0));
                ops.push(Op::new(OpCode::CBranch, vec![dest, c]));
                Ok(ops)
            }
            Statement::Return { target, .. } => {
                let tree = self.expr(*target)?;
                Ok(no_out(OpCode::Return, tree))
            }
            Statement::Label { name, span } => {
                let id = self.label(*name, *span)?;
                Ok(vec![self.place_label(id)])
            }
            Statement::Export { span, .. } | Statement::Section { span, .. } => {
                self.syntax_error(*span);
                Err(Stop::Abort)
            }
            Statement::Error(_) => Err(Stop::Abort),
        }
    }

    fn define_local(&mut self, name: Ident, vn: Vn, at: Span) {
        let text = self.name(name);
        if let Err(e) = self.resolver.define_local(text, vn, at) {
            self.error(Some(name.span), e.0);
        }
    }

    fn assign(
        &mut self,
        local: bool,
        target: &LValue,
        value: bk_sleigh_syntax::ast::ExprId,
        span: Span,
    ) -> Result<Vec<Op>, Stop> {
        match target {
            LValue::Ident(name) => match self.lookup(*name) {
                NameRef::Unknown if !is_keyword(self.name(*name)) => {
                    let rhs = self.expr(value)?;
                    self.new_output(local, rhs, *name, 0, span)
                }
                NameRef::Varnode(vn)
                | NameRef::Special(vn)
                | NameRef::Jump(vn)
                | NameRef::Operand { varnode: vn, .. } => {
                    if local {
                        let message = format!("Redefinition of symbol: {}", self.name(*name));
                        self.error(Some(name.span), message);
                        return Err(Stop::Abort);
                    }
                    let mut rhs = self.expr(value)?;
                    Self::set_output(&mut rhs, vn)?;
                    Ok(rhs.ops)
                }
                NameRef::Bitrange {
                    varnode,
                    offset,
                    bits,
                } if !local => {
                    let rhs = self.expr(value)?;
                    self.assign_bit_range(varnode, offset, bits, rhs, span)
                }
                NameRef::Subtable if !local => {
                    let message = format!("Subtable not attached to operand: {}", self.name(*name));
                    self.error(Some(name.span), message);
                    Err(Stop::Abort)
                }
                _ => {
                    self.syntax_error(name.span);
                    Err(Stop::Abort)
                }
            },
            LValue::Sized { name, size } => {
                let known = self.lookup(*name);
                match known {
                    NameRef::Unknown if !is_keyword(self.name(*name)) => {
                        let size = self.int_or_abort(size)? as u32;
                        let rhs = self.expr(value)?;
                        // Ghidra passes "uses local" for `name:size = ...`
                        // with or without the keyword.
                        self.new_output(true, rhs, *name, size, span)
                    }
                    NameRef::Varnode(_)
                    | NameRef::Special(_)
                    | NameRef::Jump(_)
                    | NameRef::Operand { .. }
                        if !local =>
                    {
                        self.error(
                            Some(span),
                            "Illegal truncation on left-hand side of assignment",
                        );
                        Err(Stop::Abort)
                    }
                    _ => {
                        self.syntax_error(name.span);
                        Err(Stop::Abort)
                    }
                }
            }
            LValue::BitRange { name, low, width } => {
                if local {
                    self.syntax_error(name.span);
                    return Err(Stop::Abort);
                }
                let vn = match self.lookup(*name) {
                    NameRef::Varnode(vn)
                    | NameRef::Special(vn)
                    | NameRef::Jump(vn)
                    | NameRef::Operand { varnode: vn, .. } => vn,
                    NameRef::Unknown => {
                        let message = format!("Unknown assignment varnode: {}", self.name(*name));
                        self.error(Some(name.span), message);
                        return Err(Stop::Abort);
                    }
                    NameRef::Subtable => {
                        let message =
                            format!("Subtable not attached to operand: {}", self.name(*name));
                        self.error(Some(name.span), message);
                        return Err(Stop::Abort);
                    }
                    _ => {
                        self.syntax_error(name.span);
                        return Err(Stop::Abort);
                    }
                };
                let low = self.int_or_abort(low)? as u32;
                let width = self.int_or_abort(width)? as u32;
                let rhs = self.expr(value)?;
                self.assign_bit_range(vn, low, width, rhs, span)
            }
            LValue::Deref { star, address } => {
                if local {
                    self.syntax_error(star.span);
                    return Err(Stop::Abort);
                }
                let (space, size) = self.star(star)?;
                let ptr = self.expr(*address)?;
                let val = self.expr(value)?;
                Self::store(space, size, ptr, val)
            }
        }
    }

    /// `ExprTree::setOutput`: the expression's value goes to `out`.
    pub(crate) fn set_output(tree: &mut ExprTree, out: Vn) -> Result<(), Stop> {
        let Some(current) = tree.out else {
            return Err(Stop::Fatal("Expression has no output".to_owned()));
        };
        if current.unnamed {
            if let Some(last) = tree.ops.last_mut() {
                last.output = Some(out);
            }
        } else {
            tree.ops.push(Op {
                opcode: OpCode::Copy,
                output: Some(out),
                inputs: vec![current],
            });
        }
        tree.out = Some(out);
        Ok(())
    }

    /// `newOutput`: a new named temporary receives the value of `rhs`.
    fn new_output(
        &mut self,
        uses_local: bool,
        mut rhs: ExprTree,
        name: Ident,
        size: u32,
        span: Span,
    ) -> Result<Vec<Op>, Stop> {
        let mut tmp = self.temp();
        if size != 0 {
            tmp.size = ConstTpl::Real(u64::from(size));
        } else if let Some(ConstTpl::Real(s)) = rhs.out.map(|o| o.size)
            && s != 0
        {
            tmp.size = ConstTpl::Real(s);
        }
        Self::set_output(&mut rhs, tmp)?;
        let size = match tmp.size {
            ConstTpl::Real(s) => s as i32,
            _ => 0,
        };
        let symbol = Vn::new(
            tmp.space,
            tmp.offset,
            ConstTpl::Real(u64::from(size as u32)),
        );
        self.define_local(name, symbol, span);
        if !uses_local && self.env.enforce_local_key {
            let message = format!(
                "Must use 'local' keyword to define symbol '{}'",
                self.name(name)
            );
            self.error_at(Some(span), message);
        }
        Ok(rhs.ops)
    }

    /// `createStore`.
    fn store(space: ConstTpl, size: u64, ptr: ExprTree, val: ExprTree) -> Result<Vec<Op>, Stop> {
        let mut ops = ptr.ops;
        ops.extend(val.ops);
        let p = ptr.out.unwrap_or_else(|| Vn::constant(0, 0));
        let v = val.out.unwrap_or_else(|| Vn::constant(0, 0));
        ops.push(Op::new(
            OpCode::Store,
            vec![
                Vn::new(ConstTpl::Space(CONST_SPACE), space, ConstTpl::Real(8)),
                p,
                v,
            ],
        ));
        let last = ops.len().saturating_sub(1);
        super::sizes::force_size_at(&mut ops, last, 2, ConstTpl::Real(size))
            .map_err(|e| Stop::Fatal(e.to_string()))?;
        Ok(ops)
    }

    fn apply_statement(
        &mut self,
        name: Ident,
        args: ExprList,
        span: Span,
    ) -> Result<Vec<Op>, Stop> {
        let text = self.name(name);
        if text == "delayslot" {
            let nodes = self.nodes;
            if let [arg] = nodes.exprs(args)
                && let bk_sleigh_syntax::ast::Expr::Int(lit) = &nodes[*arg]
            {
                let n = self.int_or_abort(lit)?;
                return Ok(vec![Op::new(DELAY_SLOT, vec![Vn::constant(n, 4)])]);
            }
            self.syntax_error(span);
            return Err(Stop::Abort);
        }
        match self.lookup(name) {
            NameRef::UserOp(index) => {
                let (mut ops, mut values) = self.args(args)?;
                values.insert(0, Vn::constant(u64::from(index), 4));
                ops.push(Op::new(OpCode::CallOther, values));
                Ok(ops)
            }
            NameRef::Macro { index, params } => self.macro_use(name, index, params, args, span),
            NameRef::Varnode(_)
            | NameRef::Special(_)
            | NameRef::Jump(_)
            | NameRef::Operand { .. } => {
                let nodes = self.nodes;
                if let [arg] = nodes.exprs(args)
                    && matches!(nodes[*arg], bk_sleigh_syntax::ast::Expr::Int(_))
                {
                    self.error(
                        Some(span),
                        "Illegal subpiece on left-hand side of assignment",
                    );
                } else {
                    self.syntax_error(span);
                }
                Err(Stop::Abort)
            }
            NameRef::Unknown if !is_keyword(text) => {
                let message = format!("Unknown varnode parameter: {text}");
                self.error(Some(name.span), message);
                Err(Stop::Abort)
            }
            NameRef::Subtable => {
                let message = format!("Subtable not attached to operand: {text}");
                self.error(Some(name.span), message);
                Err(Stop::Abort)
            }
            _ => {
                self.syntax_error(name.span);
                Err(Stop::Abort)
            }
        }
    }

    /// `createMacroUse`: a placeholder op the elaborator expands later.
    fn macro_use(
        &mut self,
        name: Ident,
        index: u32,
        params: u32,
        args: ExprList,
        span: Span,
    ) -> Result<Vec<Op>, Stop> {
        let (ops, values) = self.args(args)?;
        if values.len() != params as usize {
            let which = if values.len() > params as usize {
                "many"
            } else {
                "few"
            };
            let message = format!(
                "Invocation of macro '{}' passes too {which} parameters",
                self.name(name)
            );
            self.error_at(Some(span), message);
            return Ok(Vec::new());
        }
        for (i, value) in values.iter().enumerate() {
            if let ConstTpl::Handle { index: hand, .. } = value.offset
                && self.resolver.macro_param_is_code(index, i as u32)
            {
                self.resolver.mark_code_address(hand);
            }
        }
        let mut ops = ops;
        let mut inputs = Vec::with_capacity(values.len() + 1);
        inputs.push(Vn::constant(u64::from(index), 4));
        inputs.extend(values);
        ops.push(Op::new(MACROBUILD, inputs));
        Ok(ops)
    }

    fn branch(
        &mut self,
        direct: OpCode,
        indirect: OpCode,
        dest: &JumpDest,
    ) -> Result<Vec<Op>, Stop> {
        if let JumpDest::Dynamic(e) = dest {
            let tree = self.expr(*e)?;
            return Ok(no_out(indirect, tree));
        }
        let vn = self.jump_dest(dest)?;
        Ok(vec![Op::new(direct, vec![vn])])
    }

    /// The grammar's `jumpdest`.
    fn jump_dest(&mut self, dest: &JumpDest) -> Result<Vn, Stop> {
        match dest {
            JumpDest::Symbol(ident) => match self.lookup(*ident) {
                NameRef::Jump(vn) => Ok(Vn::new(
                    ConstTpl::CurSpace,
                    vn.offset,
                    ConstTpl::CurSpaceSize,
                )),
                NameRef::Operand { index, varnode } => {
                    self.resolver.mark_code_address(index);
                    Ok(varnode)
                }
                NameRef::Unknown if !is_keyword(self.name(*ident)) => {
                    let message = format!("Unknown jump destination: {}", self.name(*ident));
                    self.error(Some(ident.span), message);
                    Err(Stop::Abort)
                }
                _ => {
                    self.syntax_error(ident.span);
                    Err(Stop::Abort)
                }
            },
            JumpDest::Absolute(lit) => {
                let value = self.int_or_report(lit);
                Ok(Vn::new(
                    ConstTpl::CurSpace,
                    ConstTpl::Real(value),
                    ConstTpl::CurSpaceSize,
                ))
            }
            JumpDest::Relative { offset, space } => self.relative_dest(offset, *space),
            JumpDest::Label(ident) => {
                let id = self.label(*ident, ident.span)?;
                let index = self.labels.get(id.0 as usize).map_or(0, |l| l.index);
                if let Some(label) = self.labels.get_mut(id.0 as usize) {
                    label.refs = label.refs.saturating_add(1);
                }
                Ok(Vn::new(
                    ConstTpl::Space(CONST_SPACE),
                    ConstTpl::Relative(u64::from(index)),
                    ConstTpl::Real(4),
                ))
            }
            JumpDest::Dynamic(e) => {
                let span = self.nodes[*e].span();
                self.syntax_error(span);
                Err(Stop::Abort)
            }
        }
    }

    fn relative_dest(&mut self, offset: &IntLit, space: Ident) -> Result<Vn, Stop> {
        if offset.to_u64().is_none() {
            self.int_or_report(offset);
            self.syntax_error(space.span);
            return Err(Stop::Abort);
        }
        let value = self.int_or_abort(offset)?;
        let NameRef::Space(index) = self.lookup(space) else {
            self.syntax_error(space.span);
            return Err(Stop::Abort);
        };
        let size = self.env.space(index).map_or(0, |s| s.addr_size);
        Ok(Vn::new(
            ConstTpl::Space(index),
            ConstTpl::Real(value),
            ConstTpl::Real(u64::from(size)),
        ))
    }

    /// The label `name`: an existing one, or a new one (`defineLabel`).
    fn label(&mut self, name: Ident, at: Span) -> Result<LabelId, Stop> {
        match self.lookup(name) {
            NameRef::Label(id) => Ok(id),
            NameRef::Unknown if !is_keyword(self.name(name)) => {
                let id = LabelId(self.labels.len() as u32);
                let text = self.name(name);
                self.labels.push(LabelState {
                    name: text.to_owned(),
                    section: self.section,
                    index: self.next_label,
                    placed: false,
                    refs: 0,
                    at,
                });
                self.next_label = self.next_label.wrapping_add(1);
                if let Err(e) = self.resolver.define_label(text, id, at) {
                    self.error(Some(name.span), e.0);
                }
                Ok(id)
            }
            _ => {
                self.syntax_error(name.span);
                Err(Stop::Abort)
            }
        }
    }

    /// `placeLabel`.
    fn place_label(&mut self, id: LabelId) -> Op {
        let (index, placed, name, at) = match self.labels.get(id.0 as usize) {
            Some(l) => (l.index, l.placed, l.name.clone(), l.at),
            None => (0, false, String::new(), Span::default()),
        };
        if placed {
            self.error_at(Some(at), format!("Label '{name}' is placed more than once"));
        }
        if let Some(label) = self.labels.get_mut(id.0 as usize) {
            label.placed = true;
        }
        Op::new(LABEL, vec![Vn::constant(u64::from(index), 4)])
    }

    /// The export of a section (`setResultVarnode`, `setResultStarVarnode`).
    pub(crate) fn export(&mut self, value: &ExportValue) -> Result<HandleTpl, Stop> {
        match value {
            ExportValue::Varnode(e) => {
                let nodes = self.nodes;
                let vn = match &nodes[*e] {
                    bk_sleigh_syntax::ast::Expr::Ident(ident) => {
                        self.export_name(*ident, "Unknown export varnode: ")?
                    }
                    bk_sleigh_syntax::ast::Expr::AddressOf { .. }
                    | bk_sleigh_syntax::ast::Expr::SizedInt { .. } => self.integer_varnode(*e)?,
                    other => {
                        self.syntax_error(other.span());
                        return Err(Stop::Abort);
                    }
                };
                Ok(export_handle(&vn))
            }
            ExportValue::Deref { star, name } => {
                let (space, size) = self.star(star)?;
                // Ghidra's parser reduces the name to `lhsvarnode` first, so the
                // message is that of an assignment.
                let vn = self.export_name(*name, "Unknown assignment varnode: ")?;
                let temp = self.resolver.allocate_temp();
                Ok(HandleTpl {
                    space,
                    size: ConstTpl::Real(size),
                    ptr_space: vn.space,
                    ptr_offset: vn.offset,
                    ptr_size: vn.size,
                    temp_space: ConstTpl::Space(UNIQUE_SPACE),
                    temp_offset: ConstTpl::Real(temp),
                })
            }
        }
    }

    fn export_name(&mut self, ident: Ident, unknown: &str) -> Result<Vn, Stop> {
        match self.lookup(ident) {
            NameRef::Varnode(vn)
            | NameRef::Special(vn)
            | NameRef::Jump(vn)
            | NameRef::Operand { varnode: vn, .. } => Ok(vn),
            NameRef::Unknown if !is_keyword(self.name(ident)) => {
                let message = format!("{unknown}{}", self.name(ident));
                self.error(Some(ident.span), message);
                Err(Stop::Abort)
            }
            NameRef::Subtable => {
                let message = format!("Subtable not attached to operand: {}", self.name(ident));
                self.error(Some(ident.span), message);
                Err(Stop::Abort)
            }
            _ => {
                self.syntax_error(ident.span);
                Err(Stop::Abort)
            }
        }
    }
}

/// `createOpNoOut` with one input.
fn no_out(opcode: OpCode, tree: ExprTree) -> Vec<Op> {
    let mut ops = tree.ops;
    ops.push(Op::new(
        opcode,
        vec![tree.out.unwrap_or_else(|| Vn::constant(0, 0))],
    ));
    ops
}
