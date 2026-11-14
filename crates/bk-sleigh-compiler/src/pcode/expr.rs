//! Expressions (`expr`, `varnode`, `integervarnode` of `slghparse.y`;
//! `PcodeCompile::createOp`, `createLoad`, `createUserOp`, `addressOf`).

use bk_pcode::OpCode;
use bk_sla::ConstTpl;
use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{BinaryOp, Expr, ExprId, ExprList, Ident, IntLit, SizedStar, UnaryOp};

use super::{Builder, NameRef, Stop, SymbolResolver};
use crate::template::{CONST_SPACE, Op, UNIQUE_SPACE, Vn};

/// An expression being compiled (`ExprTree`): its ops and the varnode
/// holding its value.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExprTree {
    pub(crate) ops: Vec<Op>,
    pub(crate) out: Option<Vn>,
}

impl ExprTree {
    pub(crate) fn leaf(vn: Vn) -> Self {
        Self {
            ops: Vec::new(),
            out: Some(vn),
        }
    }
}

/// A built-in operator called like a function, by its keyword.
fn builtin(name: &str) -> Option<(OpCode, &'static [usize])> {
    Some(match name {
        "zext" => (OpCode::IntZExt, &[1]),
        "sext" => (OpCode::IntSExt, &[1]),
        "carry" => (OpCode::IntCarry, &[2]),
        "scarry" => (OpCode::IntSCarry, &[2]),
        "sborrow" => (OpCode::IntSBorrow, &[2]),
        "nan" => (OpCode::FloatNan, &[1]),
        "abs" => (OpCode::FloatAbs, &[1]),
        "sqrt" => (OpCode::FloatSqrt, &[1]),
        "ceil" => (OpCode::FloatCeil, &[1]),
        "floor" => (OpCode::FloatFloor, &[1]),
        "round" => (OpCode::FloatRound, &[1]),
        "int2float" => (OpCode::FloatInt2Float, &[1]),
        "float2float" => (OpCode::FloatFloat2Float, &[1]),
        "trunc" => (OpCode::FloatTrunc, &[1]),
        "newobject" => (OpCode::New, &[1, 2]),
        "popcount" => (OpCode::PopCount, &[1]),
        "lzcount" => (OpCode::LzCount, &[1]),
        // `cpool` takes any number; `borrow` is a keyword without a rule.
        "cpool" => (OpCode::CPoolRef, &[]),
        "borrow" => (OpCode::IntSBorrow, &[usize::MAX]),
        _ => return None,
    })
}

/// Words of the semantic lexer that are never identifiers.
pub(crate) fn is_keyword(name: &str) -> bool {
    builtin(name).is_some()
        || matches!(
            name,
            "if" | "goto"
                | "call"
                | "return"
                | "delayslot"
                | "crossbuild"
                | "export"
                | "build"
                | "local"
        )
}

impl<R: SymbolResolver> Builder<'_, R> {
    /// The name `ident` means here; keywords mean nothing.
    pub(crate) fn lookup(&self, ident: Ident) -> NameRef {
        let name = self.name(ident);
        if is_keyword(name) {
            NameRef::Other
        } else {
            self.resolver.lookup(name)
        }
    }

    /// A new unnamed temporary of unknown size (`buildTemporary`).
    pub(crate) fn temp(&mut self) -> Vn {
        let offset = self.resolver.allocate_temp();
        Vn {
            space: ConstTpl::Space(UNIQUE_SPACE),
            offset: ConstTpl::Real(offset),
            size: ConstTpl::Real(0),
            unnamed: true,
        }
    }

    /// An integer literal of a `varnode` position: an overflow is reported
    /// and reads as 0 (`BADINTEGER`).
    pub(crate) fn int_or_report(&mut self, lit: &IntLit) -> u64 {
        lit.to_u64().unwrap_or_else(|| {
            self.error(Some(lit.span), "Parsed integer is too big (overflow)");
            0
        })
    }

    /// An integer where Ghidra's grammar has no overflow alternative: an
    /// overflow is a syntax error.
    pub(crate) fn int_or_abort(&mut self, lit: &IntLit) -> Result<u64, Stop> {
        lit.to_u64().ok_or_else(|| {
            self.syntax_error(lit.span);
            Stop::Abort
        })
    }

    /// The space and size of a `*[space]:size` (`sizedstar`).
    pub(crate) fn star(&mut self, star: &SizedStar) -> Result<(ConstTpl, u64), Stop> {
        let space = match star.space {
            Some(ident) => {
                let NameRef::Space(index) = self.lookup(ident) else {
                    self.syntax_error(ident.span);
                    return Err(Stop::Abort);
                };
                index
            }
            // With no default space Ghidra uses a null space here; the
            // missing default is reported at the end of the compile.
            None => self.env.default_space.unwrap_or(u32::MAX),
        };
        let size = match &star.size {
            Some(lit) => u64::from(self.int_or_abort(lit)? as u32),
            None => 0,
        };
        Ok((ConstTpl::Space(space), size))
    }

    /// The grammar's `specificsymbol` for a name used as a varnode.
    fn specific_varnode(&mut self, ident: Ident) -> Result<Vn, Stop> {
        match self.lookup(ident) {
            NameRef::Varnode(vn) | NameRef::Special(vn) | NameRef::Jump(vn) => Ok(vn),
            NameRef::Operand { varnode, .. } => Ok(varnode),
            NameRef::Unknown => {
                let message = format!("Unknown varnode parameter: {}", self.name(ident));
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

    /// The grammar's `varnode`: a specific symbol or an `integervarnode`.
    pub(crate) fn varnode(&mut self, id: ExprId) -> Result<Vn, Stop> {
        let nodes = self.nodes;
        match &nodes[id] {
            Expr::Ident(ident) => self.specific_varnode(*ident),
            Expr::Int(_) | Expr::SizedInt { .. } | Expr::AddressOf { .. } => {
                self.integer_varnode(id)
            }
            other => {
                self.syntax_error(other.span());
                Err(Stop::Abort)
            }
        }
    }

    /// The grammar's `integervarnode`: `k`, `k:n`, `&v`, `&:n v`.
    pub(crate) fn integer_varnode(&mut self, id: ExprId) -> Result<Vn, Stop> {
        let nodes = self.nodes;
        match &nodes[id] {
            Expr::Int(lit) => {
                let value = self.int_or_report(lit);
                Ok(Vn::constant(value, 0))
            }
            Expr::SizedInt { value, size } => {
                if value.to_u64().is_none() {
                    self.int_or_report(value);
                    self.syntax_error(size.span);
                    return Err(Stop::Abort);
                }
                let v = self.int_or_abort(value)?;
                let s = self.int_or_abort(size)?;
                Ok(Vn::constant(v, s))
            }
            Expr::AddressOf { size, operand, .. } => {
                let size = match size {
                    Some(lit) => self.int_or_abort(lit)? as u32,
                    None => 0,
                };
                let var = self.varnode(*operand)?;
                Ok(self.address_of(&var, size))
            }
            other => {
                self.syntax_error(other.span());
                Err(Stop::Abort)
            }
        }
    }

    /// `PcodeCompile::addressOf`: a constant holding a varnode's offset.
    pub(crate) fn address_of(&self, var: &Vn, size: u32) -> Vn {
        let space = match var.space {
            ConstTpl::Space(index) => self.env.space(index),
            _ => None,
        };
        let size = if size == 0 {
            space.map_or(0, |s| s.addr_size)
        } else {
            size
        };
        let offset = match (var.offset, space) {
            (ConstTpl::Real(off), Some(space)) => ConstTpl::Real(space.byte_to_address(off)),
            (ConstTpl::Real(off), None) if matches!(var.space, ConstTpl::Space(_)) => {
                ConstTpl::Real(off)
            }
            (offset, _) => offset,
        };
        Vn::new(
            ConstTpl::Space(CONST_SPACE),
            offset,
            ConstTpl::Real(u64::from(size)),
        )
    }

    /// `createOp` with one input: the op's output is a new temporary.
    pub(crate) fn create_op1(&mut self, opcode: OpCode, mut tree: ExprTree) -> ExprTree {
        let out = self.temp();
        let input = tree.out.take().unwrap_or_else(|| Vn::constant(0, 0));
        tree.ops.push(Op {
            opcode,
            output: Some(out),
            inputs: vec![input],
        });
        tree.out = Some(out);
        tree
    }

    /// `createOp` with two inputs.
    pub(crate) fn create_op2(
        &mut self,
        opcode: OpCode,
        mut a: ExprTree,
        mut b: ExprTree,
    ) -> ExprTree {
        let out = self.temp();
        a.ops.append(&mut b.ops);
        let x = a.out.take().unwrap_or_else(|| Vn::constant(0, 0));
        let y = b.out.take().unwrap_or_else(|| Vn::constant(0, 0));
        a.ops.push(Op {
            opcode,
            output: Some(out),
            inputs: vec![x, y],
        });
        a.out = Some(out);
        a
    }

    /// `appendOp`: `tree.out op constant` into a new temporary.
    pub(crate) fn append_op(&mut self, opcode: OpCode, tree: &mut ExprTree, value: u64, size: u64) {
        let out = self.temp();
        let input = tree.out.take().unwrap_or_else(|| Vn::constant(0, 0));
        tree.ops.push(Op {
            opcode,
            output: Some(out),
            inputs: vec![input, Vn::constant(value, size)],
        });
        tree.out = Some(out);
    }

    /// Compiles the arguments of a call, left to right; returns their ops
    /// and values (`paramlist`, `ExprTree::appendParams`).
    pub(crate) fn args(&mut self, list: ExprList) -> Result<(Vec<Op>, Vec<Vn>), Stop> {
        let nodes = self.nodes;
        let mut ops = Vec::new();
        let mut values = Vec::new();
        let mut trees = Vec::new();
        for &arg in nodes.exprs(list) {
            trees.push(self.expr(arg)?);
        }
        for mut tree in trees {
            ops.append(&mut tree.ops);
            values.push(tree.out.unwrap_or_else(|| Vn::constant(0, 0)));
        }
        Ok((ops, values))
    }

    /// Compiles an expression.
    pub(crate) fn expr(&mut self, id: ExprId) -> Result<ExprTree, Stop> {
        let nodes = self.nodes;
        match &nodes[id] {
            Expr::Int(_) | Expr::SizedInt { .. } | Expr::AddressOf { .. } => {
                Ok(ExprTree::leaf(self.integer_varnode(id)?))
            }
            Expr::Ident(ident) => match self.lookup(*ident) {
                NameRef::Bitrange {
                    varnode,
                    offset,
                    bits,
                } => self.create_bit_range(*ident, varnode, offset, bits),
                _ => Ok(ExprTree::leaf(self.specific_varnode(*ident)?)),
            },
            Expr::Truncate { name, size } => {
                let size = self.int_or_abort(size)?;
                let vn = self.truncation_base(*name)?;
                self.create_bit_range(*name, vn, 0, size.wrapping_mul(8) as u32)
            }
            Expr::BitRange {
                name, low, width, ..
            } => {
                let low = self.int_or_abort(low)? as u32;
                let width = self.int_or_abort(width)? as u32;
                let vn = self.truncation_base(*name)?;
                self.create_bit_range(*name, vn, low, width)
            }
            Expr::Paren { inner, .. } => self.expr(*inner),
            Expr::Apply { name, args, span } => self.apply(*name, *args, *span),
            Expr::Unary { op, operand, .. } => {
                let tree = self.expr(*operand)?;
                let opcode = match op {
                    UnaryOp::Not => OpCode::BoolNegate,
                    UnaryOp::Invert => OpCode::IntNegate,
                    UnaryOp::Negate => OpCode::Int2Comp,
                    UnaryOp::FNegate => OpCode::FloatNeg,
                };
                Ok(self.create_op1(opcode, tree))
            }
            Expr::Deref { star, operand, .. } => {
                let (space, size) = self.star(star)?;
                let ptr = self.expr(*operand)?;
                self.load(space, size, ptr)
            }
            Expr::Binary { op, lhs, rhs, .. } => {
                let a = self.expr(*lhs)?;
                let b = self.expr(*rhs)?;
                let (opcode, swap) = binary(*op);
                Ok(if swap {
                    self.create_op2(opcode, b, a)
                } else {
                    self.create_op2(opcode, a, b)
                })
            }
            Expr::Error(_) => Err(Stop::Abort),
        }
    }

    /// The varnode of `name` in `name:n` and `name[lo,len]`: a specific
    /// symbol.
    fn truncation_base(&mut self, name: Ident) -> Result<Vn, Stop> {
        self.specific_varnode(name)
    }

    /// `createLoad`.
    fn load(&mut self, space: ConstTpl, size: u64, mut ptr: ExprTree) -> Result<ExprTree, Stop> {
        let out = self.temp();
        let address = ptr.out.take().unwrap_or_else(|| Vn::constant(0, 0));
        ptr.ops.push(Op {
            opcode: OpCode::Load,
            output: Some(out),
            inputs: vec![
                Vn::new(ConstTpl::Space(CONST_SPACE), space, ConstTpl::Real(8)),
                address,
            ],
        });
        if size > 0 {
            let last = ptr.ops.len().saturating_sub(1);
            super::sizes::force_size_at(&mut ptr.ops, last, -1, ConstTpl::Real(size))
                .map_err(|e| Stop::Fatal(e.to_string()))?;
        }
        ptr.out = ptr.ops.last().and_then(|op| op.output);
        Ok(ptr)
    }

    /// A call in an expression: a built-in, a user op, or `sym(k)`.
    fn apply(&mut self, name: Ident, args: ExprList, span: Span) -> Result<ExprTree, Stop> {
        let text = self.name(name);
        if let Some((opcode, arities)) = builtin(text) {
            let count = args.len();
            if opcode == OpCode::CPoolRef && arities.is_empty() {
                let (ops, values) = self.args(args)?;
                if values.len() < 2 {
                    self.error(Some(span), "Must be at least two inputs to cpool");
                    return Err(Stop::Abort);
                }
                let out = self.temp();
                let mut tree = ExprTree { ops, out: None };
                tree.ops.push(Op {
                    opcode,
                    output: Some(out),
                    inputs: values,
                });
                tree.out = Some(out);
                return Ok(tree);
            }
            if !arities.contains(&count) {
                self.syntax_error(span);
                return Err(Stop::Abort);
            }
            let nodes = self.nodes;
            let list = nodes.exprs(args);
            return match list {
                [a] => {
                    let a = self.expr(*a)?;
                    Ok(self.create_op1(opcode, a))
                }
                [a, b] => {
                    let a = self.expr(*a)?;
                    let b = self.expr(*b)?;
                    Ok(self.create_op2(opcode, a, b))
                }
                _ => {
                    self.syntax_error(span);
                    Err(Stop::Abort)
                }
            };
        }
        match self.lookup(name) {
            NameRef::UserOp(index) => {
                let (ops, mut values) = self.args(args)?;
                let out = self.temp();
                values.insert(0, Vn::constant(u64::from(index), 4));
                let mut tree = ExprTree {
                    ops,
                    out: Some(out),
                };
                tree.ops.push(Op {
                    opcode: OpCode::CallOther,
                    output: Some(out),
                    inputs: values,
                });
                Ok(tree)
            }
            NameRef::Varnode(_)
            | NameRef::Special(_)
            | NameRef::Jump(_)
            | NameRef::Operand { .. } => {
                let nodes = self.nodes;
                let [arg] = nodes.exprs(args) else {
                    self.syntax_error(span);
                    return Err(Stop::Abort);
                };
                let base = self.specific_varnode(name)?;
                let k = self.integer_varnode(*arg)?;
                Ok(self.create_op2(OpCode::SubPiece, ExprTree::leaf(base), ExprTree::leaf(k)))
            }
            NameRef::Unknown | NameRef::Subtable => self.specific_varnode(name).map(ExprTree::leaf),
            _ => {
                self.syntax_error(name.span);
                Err(Stop::Abort)
            }
        }
    }
}

/// The opcode of a binary operator, and whether the operands are swapped
/// (`>` is `<` with the operands exchanged, and so on).
fn binary(op: BinaryOp) -> (OpCode, bool) {
    match op {
        BinaryOp::BoolOr => (OpCode::BoolOr, false),
        BinaryOp::BoolAnd => (OpCode::BoolAnd, false),
        BinaryOp::BoolXor => (OpCode::BoolXor, false),
        BinaryOp::Or => (OpCode::IntOr, false),
        BinaryOp::Xor => (OpCode::IntXor, false),
        BinaryOp::And => (OpCode::IntAnd, false),
        BinaryOp::Equal => (OpCode::IntEqual, false),
        BinaryOp::NotEqual => (OpCode::IntNotEqual, false),
        BinaryOp::FEqual => (OpCode::FloatEqual, false),
        BinaryOp::FNotEqual => (OpCode::FloatNotEqual, false),
        BinaryOp::Less => (OpCode::IntLess, false),
        BinaryOp::GreatEqual => (OpCode::IntLessEqual, true),
        BinaryOp::LessEqual => (OpCode::IntLessEqual, false),
        BinaryOp::Great => (OpCode::IntLess, true),
        BinaryOp::SLess => (OpCode::IntSLess, false),
        BinaryOp::SGreatEqual => (OpCode::IntSLessEqual, true),
        BinaryOp::SLessEqual => (OpCode::IntSLessEqual, false),
        BinaryOp::SGreat => (OpCode::IntSLess, true),
        BinaryOp::FLess => (OpCode::FloatLess, false),
        BinaryOp::FGreatEqual => (OpCode::FloatLessEqual, true),
        BinaryOp::FLessEqual => (OpCode::FloatLessEqual, false),
        BinaryOp::FGreat => (OpCode::FloatLess, true),
        BinaryOp::Left => (OpCode::IntLeft, false),
        BinaryOp::Right => (OpCode::IntRight, false),
        BinaryOp::SRight => (OpCode::IntSRight, false),
        BinaryOp::Add => (OpCode::IntAdd, false),
        BinaryOp::Sub => (OpCode::IntSub, false),
        BinaryOp::FAdd => (OpCode::FloatAdd, false),
        BinaryOp::FSub => (OpCode::FloatSub, false),
        BinaryOp::Mult => (OpCode::IntMult, false),
        BinaryOp::Div => (OpCode::IntDiv, false),
        BinaryOp::Rem => (OpCode::IntRem, false),
        BinaryOp::SDiv => (OpCode::IntSDiv, false),
        BinaryOp::SRem => (OpCode::IntSRem, false),
        BinaryOp::FMult => (OpCode::FloatMult, false),
        BinaryOp::FDiv => (OpCode::FloatDiv, false),
    }
}
