//! Template-building helpers of the `bkpc` fixture (`pcode.rs`).

use bk_pcode::OpCode;
use bk_sla::{
    BlockDef, ConstTpl, ConstructorDef, HandleSelect, HandleTpl, PatternDef, Template, VarnodeTpl,
};

pub(super) const UNIQUE: u32 = 2;
pub(super) const RAM: u32 = 3;
pub(super) const REG: u32 = 4;

pub(super) fn h(index: u32, select: HandleSelect) -> ConstTpl {
    ConstTpl::Handle {
        index,
        select,
        plus: 0,
    }
}

/// Operand `index` as a varnode.
pub(super) fn opnd(index: u32) -> VarnodeTpl {
    VarnodeTpl {
        space: h(index, HandleSelect::Space),
        offset: h(index, HandleSelect::Offset),
        size: h(index, HandleSelect::Size),
    }
}

/// `size` bytes of operand `index` starting `plus` bytes in (a truncation).
pub(super) fn part(index: u32, plus: u64, size: u64) -> VarnodeTpl {
    VarnodeTpl {
        space: h(index, HandleSelect::Space),
        offset: ConstTpl::Handle {
            index,
            select: HandleSelect::OffsetPlus,
            plus,
        },
        size: ConstTpl::Real(size),
    }
}

pub(super) fn vn(space: u32, offset: ConstTpl, size: u64) -> VarnodeTpl {
    VarnodeTpl {
        space: ConstTpl::Space(space),
        offset,
        size: ConstTpl::Real(size),
    }
}

pub(super) fn cst(value: u64, size: u64) -> VarnodeTpl {
    vn(0, ConstTpl::Real(value), size)
}

pub(super) fn uniq(offset: u64, size: u64) -> VarnodeTpl {
    vn(UNIQUE, ConstTpl::Real(offset), size)
}

pub(super) fn rel(label: u64, size: u64) -> VarnodeTpl {
    vn(0, ConstTpl::Relative(label), size)
}

pub(super) type Op = (OpCode, Option<VarnodeTpl>, Vec<VarnodeTpl>);

pub(super) fn tpl(section: Option<u32>, delay: i32, labels: i32, ops: Vec<Op>) -> Template {
    let mut t = Template::new();
    t.set_header(section, delay, labels);
    for (opcode, output, inputs) in ops {
        t.push_op(opcode, output, &inputs);
    }
    t
}

pub(super) fn build(index: u64) -> Op {
    (OpCode::MultiEqual, None, vec![cst(index, 4)])
}

pub(super) fn label(n: u64) -> Op {
    (OpCode::PtrAdd, None, vec![cst(n, 4)])
}

pub(super) fn crossbuild(target: VarnodeTpl, section: u64) -> Op {
    (OpCode::PtrSub, None, vec![target, cst(section, 4)])
}

/// A dynamic export: `*[ram]:4 <operand 0>`, its value in a unique temp.
pub(super) fn deref_export(ptr_space: ConstTpl, ptr_size: ConstTpl, temp: u64) -> HandleTpl {
    HandleTpl {
        space: ConstTpl::Space(RAM),
        size: ConstTpl::Real(4),
        ptr_space,
        ptr_offset: h(0, HandleSelect::Offset),
        ptr_size,
        temp_space: ConstTpl::Space(UNIQUE),
        temp_offset: ConstTpl::Real(temp),
    }
}

pub(super) fn always() -> PatternDef {
    PatternDef::Instruction(BlockDef {
        offset: 0,
        nonzero: 0,
        words: Vec::new(),
    })
}

pub(super) fn with_templates(mut c: ConstructorDef, templates: Vec<Template>) -> ConstructorDef {
    c.templates = templates;
    c
}
