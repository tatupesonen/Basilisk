//! Size restrictions (`ConsistencyChecker::sizeRestriction`, `recoverSize`,
//! `checkSubtable`, `setPostOrder`, `printOpError`, `printOpName`,
//! `slgh_compile.cc` 320-1003, 1115-1235).

use bk_pcode::OpCode;
use bk_sla::ConstTpl;
use rustc_hash::FxHashMap;

use super::CheckFatal;
use crate::compiler::Compiler;
use crate::ids::{CtorId, TableId};
use crate::symbols::SymbolKind;
use crate::template::{Op, Tpl, is_const_space, real};

/// The checker's state (`ConsistencyChecker`).
#[derive(Debug, Default)]
pub(crate) struct Checker {
    pub(crate) postorder: Vec<TableId>,
    pub(crate) sizemap: FxHashMap<TableId, i32>,
    pub(crate) unnecessary: u32,
    pub(crate) read_no_write: u32,
    pub(crate) write_no_read: u32,
}

/// The template of section `k` of a constructor (−1 = main).
pub(crate) fn section_mut(ctor: &mut crate::compiler::CtorData, k: i32) -> Option<&mut Tpl> {
    if k < 0 {
        ctor.main.as_mut()
    } else {
        ctor.named.get_mut(k as usize).and_then(Option::as_mut)
    }
}

/// `printOpName`.
pub(crate) fn op_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::Copy => "Copy(=)",
        OpCode::Load => "Load(*)",
        OpCode::Store => "Store(*)",
        OpCode::Branch => "Branch(goto)",
        OpCode::CBranch => "Conditional branch(if)",
        OpCode::BranchInd => "Indirect branch(goto[])",
        OpCode::Call => "Call",
        OpCode::CallInd => "Indirect Call",
        OpCode::CallOther => "User defined",
        OpCode::Return => "Return",
        OpCode::IntEqual => "Equality(==)",
        OpCode::IntNotEqual => "Notequal(!=)",
        OpCode::IntSLess => "Signed less than(s<)",
        OpCode::IntSLessEqual => "Signed less than or equal(s<=)",
        OpCode::IntLess => "Less than(<)",
        OpCode::IntLessEqual => "Less than or equal(<=)",
        OpCode::IntZExt => "Zero extension(zext)",
        OpCode::IntSExt => "Signed extension(sext)",
        OpCode::IntAdd => "Addition(+)",
        OpCode::IntSub => "Subtraction(-)",
        OpCode::IntCarry => "Carry",
        OpCode::IntSCarry => "Signed carry",
        OpCode::IntSBorrow => "Signed borrow",
        OpCode::Int2Comp => "Twos complement(-)",
        OpCode::IntNegate => "Negate(~)",
        OpCode::IntXor => "Exclusive or(^)",
        OpCode::IntAnd => "And(&)",
        OpCode::IntOr => "Or(|)",
        OpCode::IntLeft => "Left shift(<<)",
        OpCode::IntRight => "Right shift(>>)",
        OpCode::IntSRight => "Signed right shift(s>>)",
        OpCode::IntMult => "Multiplication(*)",
        OpCode::IntDiv => "Division(/)",
        OpCode::IntSDiv => "Signed division(s/)",
        OpCode::IntRem => "Remainder(%)",
        OpCode::IntSRem => "Signed remainder(s%)",
        OpCode::BoolNegate => "Boolean negate(!)",
        OpCode::BoolXor => "Boolean xor(^^)",
        OpCode::BoolAnd => "Boolean and(&&)",
        OpCode::BoolOr => "Boolean or(||)",
        OpCode::FloatEqual => "Float equal(f==)",
        OpCode::FloatNotEqual => "Float notequal(f!=)",
        OpCode::FloatLess => "Float less than(f<)",
        OpCode::FloatLessEqual => "Float less than or equal(f<=)",
        OpCode::FloatNan => "Not a number(nan)",
        OpCode::FloatAdd => "Float addition(f+)",
        OpCode::FloatDiv => "Float division(f/)",
        OpCode::FloatMult => "Float multiplication(f*)",
        OpCode::FloatSub => "Float subtractions(f-)",
        OpCode::FloatNeg => "Float minus(f-)",
        OpCode::FloatAbs => "Absolute value(abs)",
        OpCode::FloatSqrt => "Square root",
        OpCode::FloatInt2Float => "Integer to float conversion(int2float)",
        OpCode::FloatFloat2Float => "Float to float conversion(float2float)",
        OpCode::FloatTrunc => "Float truncation(trunc)",
        OpCode::FloatCeil => "Ceiling(ceil)",
        OpCode::FloatFloor => "Floor",
        OpCode::FloatRound => "Round",
        OpCode::MultiEqual => "Build",
        OpCode::Indirect => "Delay",
        OpCode::SubPiece => "Truncation(:)",
        OpCode::SegmentOp => "Segment table(segment)",
        OpCode::CPoolRef => "Constant Pool(cpool)",
        OpCode::New => "New object(newobject)",
        OpCode::PopCount => "Count bits(popcount)",
        OpCode::LzCount => "Count leading zero bits(lzcount)",
        _ => "",
    }
}

/// What `sizeRestriction` found wrong with an op.
enum Violation {
    /// An error about two slots (−1 = output), with its text.
    Error(i32, i32, &'static str),
    /// An extension to the same size.
    UnnecessaryExt,
    /// A truncation to the same size.
    UnnecessaryTrunc,
}

impl Compiler<'_> {
    /// `setPostOrder`: tables reachable from the root, dependencies first.
    pub(crate) fn post_order(&self, checker: &mut Checker) {
        checker.postorder.clear();
        checker.sizemap.clear();
        let root = TableId(0);
        checker.sizemap.insert(root, -1);
        // (table, constructor index, operand index)
        let mut path: Vec<(TableId, usize, usize)> = vec![(root, 0, 0)];
        while let Some(&(table, ct, oper)) = path.last() {
            let ctors = self
                .tables
                .get(table.slot())
                .map_or(&[][..], |t| &t.ctors[..]);
            let Some(&ctor) = ctors.get(ct) else {
                path.pop();
                checker.postorder.push(table);
                continue;
            };
            let operands = self
                .ctors
                .get(ctor.slot())
                .map_or(&[][..], |c| &c.operands[..]);
            let Some(&op) = operands.get(oper) else {
                if let Some(top) = path.last_mut() {
                    *top = (table, ct + 1, 0);
                }
                continue;
            };
            if let Some(top) = path.last_mut() {
                *top = (table, ct, oper + 1);
            }
            let sub = self
                .operands
                .get(op.slot())
                .and_then(|o| o.def_symbol)
                .and_then(|s| match self.kind(s) {
                    Some(SymbolKind::Subtable(t)) => Some(*t),
                    _ => None,
                });
            if let Some(sub) = sub
                && !checker.sizemap.contains_key(&sub)
            {
                checker.sizemap.insert(sub, -1);
                path.push((sub, 0, 0));
            }
        }
    }

    /// `TripleSymbol::getSize` of an operand's defining symbol.
    fn operand_size(&self, ctor: CtorId, index: u32) -> Result<(i32, Option<TableId>), CheckFatal> {
        let op = self
            .ctors
            .get(ctor.slot())
            .and_then(|c| c.operands.get(index as usize))
            .ok_or_else(|| CheckFatal("Could not recover varnode template size".to_owned()))?;
        let Some(sym) = self.operands.get(op.slot()).and_then(|o| o.def_symbol) else {
            return Ok((0, None));
        };
        match self.kind(sym) {
            Some(SymbolKind::Subtable(t)) => Ok((-1, Some(*t))),
            Some(SymbolKind::Varnode(vn)) => Ok((vn.size, None)),
            Some(SymbolKind::VarnodeList(_, list)) => {
                for entry in list.iter().flatten() {
                    if let Some(SymbolKind::Varnode(vn)) = self.kind(*entry) {
                        return Ok((vn.size, None));
                    }
                }
                let name = self
                    .symbols
                    .get(sym)
                    .map_or("", |s| self.names.resolve(s.name));
                Err(CheckFatal(format!("No register attached to: {name}")))
            }
            _ => Ok((0, None)),
        }
    }

    /// `recoverSize`.
    pub(crate) fn recover_size(
        &self,
        checker: &Checker,
        size: &ConstTpl,
        ctor: CtorId,
    ) -> Result<i32, CheckFatal> {
        match *size {
            ConstTpl::Real(v) => Ok(v as i32),
            ConstTpl::Handle { index, .. } => {
                let (size, table) = self.operand_size(ctor, index)?;
                if size != -1 {
                    return Ok(size);
                }
                let table = table.ok_or_else(|| {
                    CheckFatal("Could not recover varnode template size".to_owned())
                })?;
                checker
                    .sizemap
                    .get(&table)
                    .copied()
                    .ok_or_else(|| CheckFatal("Subtable out of order".to_owned()))
            }
            _ => Err(CheckFatal(
                "Bad constant type as varnode template size".to_owned(),
            )),
        }
    }

    fn size_of(
        &self,
        checker: &Checker,
        op: &Op,
        slot: i32,
        ctor: CtorId,
    ) -> Result<i32, CheckFatal> {
        let size = op.slot(slot).map_or(ConstTpl::Real(0), |v| v.size);
        self.recover_size(checker, &size, ctor)
    }

    /// `printOpError`.
    pub(crate) fn op_error(
        &mut self,
        op: &Op,
        ctor: CtorId,
        slot1: i32,
        slot2: i32,
        message: &str,
    ) {
        let operand_name = |c: &Self, slot: i32| -> Option<String> {
            let ConstTpl::Handle { index, .. } = op.slot(slot)?.size else {
                return None;
            };
            let id = *c.ctors.get(ctor.slot())?.operands.get(index as usize)?;
            let symbol = c.operands.get(id.slot())?.symbol;
            Some(
                c.symbols
                    .get(symbol)
                    .map_or("", |s| c.names.resolve(s.name))
                    .to_owned(),
            )
        };
        let a = operand_name(self, slot1);
        let b = if slot2 == slot1 {
            None
        } else {
            operand_name(self, slot2)
        };
        let table = self
            .ctors
            .get(ctor.slot())
            .and_then(|c| self.tables.get(c.table.slot()))
            .and_then(|t| self.symbols.get(t.symbol))
            .map_or("", |s| self.names.resolve(s.name))
            .to_owned();
        let lead = match (a, b) {
            (Some(a), Some(b)) => format!("  Problem with operands '{a}' and '{b}'"),
            (Some(a), None) => format!("  Problem with operand 1 '{a}'"),
            (None, Some(b)) => format!("  Problem with operand 2 '{b}'"),
            (None, None) => "  Problem".to_owned(),
        };
        let text = format!(
            "Size restriction error in table '{table}'\n{lead} in {} operator\n  {message}",
            op_name(op.opcode)
        );
        let at = self.ctor_at(ctor);
        self.diags.error_at(at, text);
    }

    /// `sizeRestriction`: checks one op, rewriting an unnecessary extension
    /// or truncation into a `COPY`. Returns whether it passed.
    pub(crate) fn size_restriction(
        &mut self,
        checker: &mut Checker,
        op: &mut Op,
        ctor: CtorId,
    ) -> Result<bool, CheckFatal> {
        let violation = self.restriction(checker, op, ctor)?;
        let Some(v) = violation else { return Ok(true) };
        match v {
            Violation::UnnecessaryExt | Violation::UnnecessaryTrunc => {
                if self.options.warn_unnecessary_pcode {
                    let at = self.ctor_at(ctor);
                    self.diags
                        .warning_at(at, format!("Unnecessary {}", op_name(op.opcode)));
                }
                if matches!(v, Violation::UnnecessaryTrunc) && op.inputs.len() > 1 {
                    op.inputs.remove(1);
                }
                op.opcode = OpCode::Copy;
                checker.unnecessary = checker.unnecessary.saturating_add(1);
                Ok(true)
            }
            Violation::Error(a, b, message) => {
                self.op_error(op, ctor, a, b, message);
                Ok(false)
            }
        }
    }

    fn restriction(
        &self,
        checker: &Checker,
        op: &Op,
        ctor: CtorId,
    ) -> Result<Option<Violation>, CheckFatal> {
        const SUBTABLE: &str = "Using subtable with exports in expression";
        const BOOL_OUT: &str = "Output must be a boolean (size 1)";
        const BOOL_IN: &str = "Input must be a boolean (size 1)";
        let size = |slot: i32| self.size_of(checker, op, slot, ctor);
        macro_rules! sized {
            ($slot:expr) => {{
                let s = size($slot)?;
                if s == -1 {
                    return Ok(Some(Violation::Error($slot, $slot, SUBTABLE)));
                }
                s
            }};
        }
        let result = match op.opcode {
            OpCode::Copy
            | OpCode::Int2Comp
            | OpCode::IntNegate
            | OpCode::FloatNeg
            | OpCode::FloatAbs
            | OpCode::FloatSqrt
            | OpCode::FloatCeil
            | OpCode::FloatFloor
            | OpCode::FloatRound => {
                let out = sized!(-1);
                let in0 = sized!(0);
                (out != in0 && out != 0 && in0 != 0).then_some(Violation::Error(
                    -1,
                    0,
                    "Input and output sizes must match",
                ))
            }
            OpCode::IntAdd
            | OpCode::IntSub
            | OpCode::IntXor
            | OpCode::IntAnd
            | OpCode::IntOr
            | OpCode::IntMult
            | OpCode::IntDiv
            | OpCode::IntSDiv
            | OpCode::IntRem
            | OpCode::IntSRem
            | OpCode::FloatAdd
            | OpCode::FloatDiv
            | OpCode::FloatMult
            | OpCode::FloatSub => {
                const ALL: &str = "The output and all input sizes must match";
                let out = sized!(-1);
                let in0 = sized!(0);
                let in1 = sized!(1);
                if out != 0 && in0 != 0 && out != in0 {
                    Some(Violation::Error(-1, 0, ALL))
                } else if out != 0 && in1 != 0 && out != in1 {
                    Some(Violation::Error(-1, 1, ALL))
                } else if in0 != 0 && in1 != 0 && in0 != in1 {
                    Some(Violation::Error(0, 1, ALL))
                } else {
                    None
                }
            }
            OpCode::FloatNan => {
                let out = sized!(-1);
                (out != 1).then_some(Violation::Error(-1, -1, BOOL_OUT))
            }
            OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntSLess
            | OpCode::IntSLessEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntCarry
            | OpCode::IntSCarry
            | OpCode::IntSBorrow
            | OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual => {
                let out = sized!(-1);
                if out != 1 {
                    return Ok(Some(Violation::Error(-1, -1, BOOL_OUT)));
                }
                let in0 = sized!(0);
                let in1 = sized!(1);
                (in0 != 0 && in1 != 0 && in0 != in1).then_some(Violation::Error(
                    0,
                    1,
                    "Inputs must be the same size",
                ))
            }
            OpCode::BoolXor | OpCode::BoolAnd | OpCode::BoolOr | OpCode::BoolNegate => {
                let out = sized!(-1);
                if out != 1 {
                    return Ok(Some(Violation::Error(-1, -1, BOOL_OUT)));
                }
                let in0 = sized!(0);
                (in0 != 1).then_some(Violation::Error(0, 0, BOOL_IN))
            }
            OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight => {
                let out = sized!(-1);
                let in0 = sized!(0);
                (out != 0 && in0 != 0 && out != in0).then_some(Violation::Error(
                    -1,
                    0,
                    "Output and first input must be the same size",
                ))
            }
            OpCode::IntZExt | OpCode::IntSExt => {
                let out = sized!(-1);
                let in0 = sized!(0);
                if out == 0 || in0 == 0 {
                    None
                } else if out == in0 {
                    Some(Violation::UnnecessaryExt)
                } else if out < in0 {
                    Some(Violation::Error(
                        -1,
                        0,
                        "Output size must be strictly bigger than input size",
                    ))
                } else {
                    None
                }
            }
            OpCode::CBranch => {
                let in1 = sized!(1);
                (in1 != 1).then_some(Violation::Error(1, 1, BOOL_IN))
            }
            OpCode::Load | OpCode::Store => {
                let space = op.inputs.first().map(|v| v.offset);
                let Some(ConstTpl::Space(space)) = space else {
                    return Ok(None);
                };
                let in1 = sized!(1);
                let addr = self
                    .spaces
                    .get(space as usize)
                    .map_or(0, |s| s.addr_size as i32);
                (in1 != 0 && in1 != addr).then_some(Violation::Error(
                    1,
                    1,
                    "Pointer size must match size of space",
                ))
            }
            OpCode::SubPiece => {
                let out = sized!(-1);
                let in0 = sized!(0);
                let in1 = op.inputs.get(1).map_or(0, |v| real(&v.offset)) as i32;
                if out == 0 || in0 == 0 {
                    None
                } else if out == in0 && in1 == 0 {
                    Some(Violation::UnnecessaryTrunc)
                } else if out >= in0 {
                    Some(Violation::Error(
                        -1,
                        0,
                        "Output must be strictly smaller than input",
                    ))
                } else if out > in0.wrapping_sub(in1) {
                    Some(Violation::Error(-1, 0, "Too much truncation"))
                } else {
                    None
                }
            }
            _ => None,
        };
        Ok(result)
    }

    /// `checkOpMisuse`.
    fn check_op_misuse(&mut self, op: &Op, ctor: CtorId) {
        if op.opcode == OpCode::IntLess
            && let Some(vn) = op.inputs.get(1)
            && is_const_space(&vn.space)
            && matches!(vn.offset, ConstTpl::Real(0))
        {
            let at = self.ctor_at(ctor);
            self.diags
                .warning_at(at, "Unsigned comparison with zero is always false");
        }
    }

    /// `checkConstructorSection`.
    fn check_section(
        &mut self,
        checker: &mut Checker,
        tpl: &mut Tpl,
        ctor: CtorId,
    ) -> Result<bool, CheckFatal> {
        let mut ok = true;
        for op in &mut tpl.ops {
            if !self.size_restriction(checker, op, ctor)? {
                ok = false;
            }
            self.check_op_misuse(op, ctor);
        }
        Ok(ok)
    }

    /// `checkSubtable`.
    pub(crate) fn check_subtable(
        &mut self,
        checker: &mut Checker,
        table: TableId,
    ) -> Result<bool, CheckFatal> {
        let ctors = self
            .tables
            .get(table.slot())
            .map(|t| t.ctors.clone())
            .unwrap_or_default();
        let name = self
            .tables
            .get(table.slot())
            .and_then(|t| self.symbols.get(t.symbol))
            .map_or("", |s| self.names.resolve(s.name))
            .to_owned();
        let mut ok = true;
        let mut table_size = -1;
        let (mut seen_empty, mut seen_export) = (false, false);
        for ctor in ctors {
            let (mut main, mut named) = match self.ctors.get_mut(ctor.slot()) {
                Some(c) => (c.main.take(), std::mem::take(&mut c.named)),
                None => continue,
            };
            let mut result = Ok(());
            if let Some(tpl) = main.as_mut() {
                match self.check_section(checker, tpl, ctor) {
                    Ok(passed) => ok &= passed,
                    Err(e) => result = Err(e),
                }
            }
            for tpl in named.iter_mut().flatten() {
                if result.is_err() {
                    break;
                }
                match self.check_section(checker, tpl, ctor) {
                    Ok(passed) => ok &= passed,
                    Err(e) => result = Err(e),
                }
            }
            let export = main.as_ref().map(|t| t.result.map(|h| h.size));
            if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                c.main = main;
                c.named = named;
            }
            result?;
            let Some(export) = export else { continue };
            let line = self.ctors.get(ctor.slot()).map_or(0, |c| c.line);
            let at = self.ctor_at(ctor);
            if let Some(size) = export {
                if seen_empty && !seen_export {
                    self.diags.error_at(at, format!("Table '{name}' exports inconsistently; Constructor starting at line {line} is first inconsistency"));
                    ok = false;
                }
                seen_export = true;
                let size = self.recover_size(checker, &size, ctor)?;
                if table_size == -1 {
                    table_size = size;
                }
                if size != table_size {
                    self.diags.error_at(at, format!("Table '{name}' has inconsistent export size; Constructor starting at line {line} is first conflict"));
                    ok = false;
                }
            } else {
                if seen_export && !seen_empty {
                    self.diags.error_at(at, format!("Table '{name}' exports inconsistently; Constructor starting at line {line} is first inconsistency"));
                    ok = false;
                }
                seen_empty = true;
            }
        }
        if seen_export {
            if table_size == 0 {
                let at = self.tables.get(table.slot()).and_then(|t| t.at);
                let message = format!("Table '{name}' exports size 0");
                match at {
                    Some(at) => self.diags.warning_at(at, message),
                    None => self.diags.warning(None, message),
                }
            }
            checker.sizemap.insert(table, table_size);
        } else {
            checker.sizemap.insert(table, -1);
        }
        Ok(ok)
    }

    /// `testSizeRestrictions`.
    pub(crate) fn test_size_restrictions(
        &mut self,
        checker: &mut Checker,
    ) -> Result<bool, CheckFatal> {
        self.post_order(checker);
        let mut ok = true;
        for table in checker.postorder.clone() {
            if !self.check_subtable(checker, table)? {
                ok = false;
            }
        }
        Ok(ok)
    }
}
