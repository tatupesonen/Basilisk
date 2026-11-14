//! The compiler's working form of p-code templates (Ghidra's `ConstructTpl`,
//! `OpTpl`, `VarnodeTpl`, `HandleTpl`, `semantics.hh`): owned and mutable,
//! with the values of [`bk_sla`] inside.

use bk_pcode::OpCode;
use bk_sla::{ConstTpl, HandleSelect, HandleTpl, Template, VarnodeTpl};

/// The index of the constant space.
pub const CONST_SPACE: u32 = 0;
/// The index of the `OTHER` space.
pub const OTHER_SPACE: u32 = 1;
/// The index of the unique (temporary) space.
pub const UNIQUE_SPACE: u32 = 2;

/// The `BUILD` directive's opcode slot.
pub const BUILD: OpCode = OpCode::MultiEqual;
/// The `DELAY_SLOT` directive's opcode slot.
pub const DELAY_SLOT: OpCode = OpCode::Indirect;
/// The label directive's opcode slot.
pub const LABEL: OpCode = OpCode::PtrAdd;
/// The `CROSSBUILD` directive's opcode slot.
pub const CROSSBUILD: OpCode = OpCode::PtrSub;
/// The macro-call placeholder's opcode slot (only inside the compiler).
pub const MACROBUILD: OpCode = OpCode::Cast;

/// Ghidra's `ConstTpl::operator==`: the types must agree; real constants
/// compare by value, handles by index and selector (not by `plus`), spaces
/// by space; every other type compares equal to itself regardless of value
/// (including two relative label constants).
pub fn const_eq(a: &ConstTpl, b: &ConstTpl) -> bool {
    match (a, b) {
        (ConstTpl::Real(x), ConstTpl::Real(y)) => x == y,
        (
            ConstTpl::Handle {
                index: i, select: s, ..
            },
            ConstTpl::Handle {
                index: j, select: t, ..
            },
        ) => i == j && s == t,
        (ConstTpl::Space(x), ConstTpl::Space(y)) => x == y,
        _ => std::mem::discriminant(a) == std::mem::discriminant(b),
    }
}

/// `ConstTpl::isZero`: a real zero.
pub fn is_zero(c: &ConstTpl) -> bool {
    matches!(c, ConstTpl::Real(0))
}

/// `ConstTpl::isUniqueSpace`.
pub fn is_unique_space(c: &ConstTpl) -> bool {
    matches!(c, ConstTpl::Space(UNIQUE_SPACE))
}

/// `ConstTpl::isConstSpace`.
pub fn is_const_space(c: &ConstTpl) -> bool {
    matches!(c, ConstTpl::Space(CONST_SPACE))
}

/// `ConstTpl::getReal`: the value of a real constant, the `plus` of a
/// handle, the label of a relative constant, and 0 otherwise.
pub fn real(c: &ConstTpl) -> u64 {
    match *c {
        ConstTpl::Real(v) | ConstTpl::Relative(v) | ConstTpl::Handle { plus: v, .. } => v,
        _ => 0,
    }
}

/// A handle constant of operand `index`.
pub const fn handle(index: u32, select: HandleSelect) -> ConstTpl {
    ConstTpl::Handle {
        index,
        select,
        plus: 0,
    }
}

/// A varnode template while it is being compiled (`VarnodeTpl`), with the
/// "unnamed temporary" flag `ExprTree::setOutput` looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vn {
    /// The space.
    pub space: ConstTpl,
    /// The offset.
    pub offset: ConstTpl,
    /// The size.
    pub size: ConstTpl,
    /// An unnamed temporary: the value of an operator, not a symbol.
    pub unnamed: bool,
}

impl Vn {
    /// A named varnode.
    pub const fn new(space: ConstTpl, offset: ConstTpl, size: ConstTpl) -> Self {
        Self {
            space,
            offset,
            size,
            unnamed: false,
        }
    }

    /// A constant of the given value and size.
    pub const fn constant(value: u64, size: u64) -> Self {
        Self::new(
            ConstTpl::Space(CONST_SPACE),
            ConstTpl::Real(value),
            ConstTpl::Real(size),
        )
    }

    /// The handle of operand `index` (`VarnodeTpl(hand, zerosize)`).
    pub const fn operand(index: u32, zero_size: bool) -> Self {
        Self::new(
            handle(index, HandleSelect::Space),
            handle(index, HandleSelect::Offset),
            if zero_size {
                ConstTpl::Real(0)
            } else {
                handle(index, HandleSelect::Size)
            },
        )
    }

    /// `VarnodeTpl::isZeroSize`.
    pub fn is_zero_size(&self) -> bool {
        is_zero(&self.size)
    }

    /// `VarnodeTpl::isLocalTemp`: in the unique space.
    pub fn is_local_temp(&self) -> bool {
        is_unique_space(&self.space)
    }

    /// `VarnodeTpl::isRelative`.
    pub fn is_relative(&self) -> bool {
        matches!(self.offset, ConstTpl::Relative(_))
    }

    /// `VarnodeTpl::operator==` (Ghidra's constant equality on each part).
    pub fn same(&self, other: &Self) -> bool {
        const_eq(&self.space, &other.space)
            && const_eq(&self.offset, &other.offset)
            && const_eq(&self.size, &other.size)
    }

    /// The value as the file writes it.
    pub const fn to_sla(&self) -> VarnodeTpl {
        VarnodeTpl {
            space: self.space,
            offset: self.offset,
            size: self.size,
        }
    }
}

/// An op template (`OpTpl`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    /// The opcode or directive.
    pub opcode: OpCode,
    /// The output, if any.
    pub output: Option<Vn>,
    /// The inputs.
    pub inputs: Vec<Vn>,
}

impl Op {
    /// An op without output.
    pub const fn new(opcode: OpCode, inputs: Vec<Vn>) -> Self {
        Self {
            opcode,
            output: None,
            inputs,
        }
    }

    /// `OpTpl::isZeroSize`: the output or an input has size zero.
    pub fn is_zero_size(&self) -> bool {
        self.output.as_ref().is_some_and(Vn::is_zero_size) || self.inputs.iter().any(Vn::is_zero_size)
    }

    /// The varnode in `slot` (−1 = output).
    pub fn slot(&self, slot: i32) -> Option<&Vn> {
        if slot < 0 {
            self.output.as_ref()
        } else {
            self.inputs.get(slot as usize)
        }
    }

    /// The varnode in `slot` (−1 = output), mutably.
    pub fn slot_mut(&mut self, slot: i32) -> Option<&mut Vn> {
        if slot < 0 {
            self.output.as_mut()
        } else {
            self.inputs.get_mut(slot as usize)
        }
    }
}

/// The handle of an exported varnode (`HandleTpl(const VarnodeTpl *)`).
pub const fn export_handle(vn: &Vn) -> HandleTpl {
    HandleTpl {
        space: vn.space,
        size: vn.size,
        ptr_space: ConstTpl::Real(0),
        ptr_offset: vn.offset,
        ptr_size: ConstTpl::Real(0),
        temp_space: ConstTpl::Real(0),
        temp_offset: ConstTpl::Real(0),
    }
}

/// A section of p-code templates (`ConstructTpl`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tpl {
    /// Delay-slot byte count (0 if none).
    pub delay: u32,
    /// Number of labels.
    pub labels: u32,
    /// The export, if any.
    pub result: Option<HandleTpl>,
    /// The ops.
    pub ops: Vec<Op>,
}

impl Tpl {
    /// `ConstructTpl::buildOnly`: every op is a `BUILD`.
    pub fn build_only(&self) -> bool {
        self.ops.iter().all(|op| op.opcode == BUILD)
    }

    /// Lowers to a standalone [`bk_sla::Template`] for section `section`.
    pub fn to_template(&self, section: Option<u32>) -> Template {
        let mut template = Template::new();
        template.set_header(section, self.delay as i32, self.labels as i32);
        template.set_result(self.result);
        let mut inputs = Vec::new();
        for op in &self.ops {
            inputs.clear();
            inputs.extend(op.inputs.iter().map(Vn::to_sla));
            template.push_op(op.opcode, op.output.as_ref().map(Vn::to_sla), &inputs);
        }
        template
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_constant_equality() {
        let h1 = ConstTpl::Handle {
            index: 1,
            select: HandleSelect::OffsetPlus,
            plus: 5,
        };
        let h2 = ConstTpl::Handle {
            index: 1,
            select: HandleSelect::OffsetPlus,
            plus: 9,
        };
        assert!(const_eq(&h1, &h2));
        assert!(const_eq(&ConstTpl::Relative(1), &ConstTpl::Relative(2)));
        assert!(!const_eq(&ConstTpl::Real(1), &ConstTpl::Real(2)));
        assert!(!const_eq(&ConstTpl::Space(1), &ConstTpl::Space(2)));
        assert!(!const_eq(&ConstTpl::Start, &ConstTpl::Next));
    }

    #[test]
    fn lowering_keeps_ops_in_order() {
        let mut tpl = Tpl::default();
        tpl.ops.push(Op::new(BUILD, vec![Vn::constant(0, 4)]));
        tpl.ops.push(Op {
            opcode: OpCode::Copy,
            output: Some(Vn::new(
                ConstTpl::Space(UNIQUE_SPACE),
                ConstTpl::Real(0x100),
                ConstTpl::Real(4),
            )),
            inputs: vec![Vn::constant(7, 4)],
        });
        let template = tpl.to_template(None);
        assert_eq!(template.as_ref().ops().len(), 2);
    }
}
