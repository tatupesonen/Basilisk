//! `bkpc`: a language built in Rust with `SlaBuilder` whose templates
//! exercise p-code generation, so that the differential check of p-code
//! against `pcodedump` runs everywhere (its output is recorded in
//! `tests/data/pcode-fixture-oracle.txt`).
//!
//! Instructions are two bytes (four for `cst`), big endian; byte 0 is the
//! opcode, byte 1 holds `ra` (bits 4–5), `rb` (bits 0–1) or a signed
//! 8-bit value.
//!
//! | byte 0 | what it exercises |
//! |---|---|
//! | 01 | `add`: plain op; a section-0 template (crossbuild target) |
//! | 02 | `ld`: dynamic input (`LOAD`); implied build of a section in `mem` |
//! | 03 | `st`: dynamic output (`STORE`) |
//! | 04 | `ldb`: truncated dynamic input (`INT_ADD` + `LOAD`) |
//! | 05 | `stb`: truncated dynamic output (`INT_ADD` + `STORE`) |
//! | 06 | `lbl`: labels, a forward and a backward relative branch |
//! | 07 | `call`: a user op |
//! | 08 | `bd`: delay slot of one instruction |
//! | 09 | `bd2`: delay slot of two instructions |
//! | 0a | `xb`: crossbuild of the previous instruction's section 0 |
//! | 0b | `xs`: crossbuild of its own section 0 |
//! | 0c | `ops`: one op of every opcode |
//! | 0d | `cst`: constants (start, next, space size, masking, offset-plus) |
//! | 0e | `halt`: `unimpl` |
//! | 0f | `nest`: nested `BUILD`s with labels in each level |
//! | 10 | `dyn2`: dynamic input and output in one op |
//! | 11 | `cptr`: a pointer with a constant offset (static after all) |
//! | 12 | `badl`: a relative branch to a label never placed |
//! | 13 | `xin`: `CROSSBUILD` inside a named section |
//! | 14 | `uq`: unique temporaries with the `uniqmask` bits |

use bk_pcode::OpCode;
use bk_sla::{
    BlockDef, ConstTpl, ConstructorDef, Expr, Field, HandleSelect, HandleTpl, Header, PatternDef,
    PrintDef, ScopeId, Sla, SlaBuilder, SpaceKind, SymbolDef, SymbolId, TableDef, Template,
    VarnodeTpl,
};

use super::{Def, Fx, ctor, leaf, pattern, space, text, token};

/// The language id.
pub(crate) const ID: &str = "BkPcode:BE:32:default";

/// The `.ldefs`.
pub(crate) const LDEFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="BkPcode" endian="big" size="32" variant="default" version="1.0"
            slafile="bkpc.sla" processorspec="bkpc.pspec" id="BkPcode:BE:32:default">
    <description>basilisk p-code test fixture</description>
    <compiler name="default" spec="bkpc.cspec" id="default"/>
  </language>
</language_definitions>
"#;

/// The processor specification (nothing to set).
pub(crate) const PSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
</processor_spec>
"#;

const UNIQUE: u32 = 2;
const RAM: u32 = 3;
const REG: u32 = 4;

fn h(index: u32, select: HandleSelect) -> ConstTpl {
    ConstTpl::Handle {
        index,
        select,
        plus: 0,
    }
}

/// Operand `index` as a varnode.
fn opnd(index: u32) -> VarnodeTpl {
    VarnodeTpl {
        space: h(index, HandleSelect::Space),
        offset: h(index, HandleSelect::Offset),
        size: h(index, HandleSelect::Size),
    }
}

/// `size` bytes of operand `index` starting `plus` bytes in (a truncation).
fn part(index: u32, plus: u64, size: u64) -> VarnodeTpl {
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

fn vn(space: u32, offset: ConstTpl, size: u64) -> VarnodeTpl {
    VarnodeTpl {
        space: ConstTpl::Space(space),
        offset,
        size: ConstTpl::Real(size),
    }
}

fn cst(value: u64, size: u64) -> VarnodeTpl {
    vn(0, ConstTpl::Real(value), size)
}

fn uniq(offset: u64, size: u64) -> VarnodeTpl {
    vn(UNIQUE, ConstTpl::Real(offset), size)
}

fn rel(label: u64, size: u64) -> VarnodeTpl {
    vn(0, ConstTpl::Relative(label), size)
}

type Op = (OpCode, Option<VarnodeTpl>, Vec<VarnodeTpl>);

fn tpl(section: Option<u32>, delay: i32, labels: i32, ops: Vec<Op>) -> Template {
    let mut t = Template::new();
    t.set_header(section, delay, labels);
    for (opcode, output, inputs) in ops {
        t.push_op(opcode, output, &inputs);
    }
    t
}

fn build(index: u64) -> Op {
    (OpCode::MultiEqual, None, vec![cst(index, 4)])
}

fn label(n: u64) -> Op {
    (OpCode::PtrAdd, None, vec![cst(n, 4)])
}

fn crossbuild(target: VarnodeTpl, section: u64) -> Op {
    (OpCode::PtrSub, None, vec![target, cst(section, 4)])
}

/// A dynamic export: `*[ram]:4 <operand 0>`, its value in a unique temp.
fn deref_export(ptr_space: ConstTpl, ptr_size: ConstTpl, temp: u64) -> HandleTpl {
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

fn always() -> PatternDef {
    PatternDef::Instruction(BlockDef {
        offset: 0,
        nonzero: 0,
        words: Vec::new(),
    })
}

fn with_templates(mut c: ConstructorDef, templates: Vec<Template>) -> ConstructorDef {
    c.templates = templates;
    c
}

/// Builds the fixture language.
#[expect(clippy::too_many_lines, reason = "one table of constructors")]
pub(crate) fn build_sla() -> Sla {
    let mut fx = Fx {
        b: SlaBuilder::new(Header {
            big_endian: true,
            align: 2,
            unique_base: 0x1000,
            max_delay: 4,
            unique_mask: 0x6,
            num_sections: 1,
        }),
        global: ScopeId::new(0),
    };
    fx.b.source_file("bkpc.slaspec");
    fx.b.space(space(SpaceKind::Other, "OTHER", 1, 0, 8));
    fx.b.space(space(SpaceKind::Unique, "unique", UNIQUE, 0, 4));
    fx.b.space(space(SpaceKind::Processor, "ram", RAM, 1, 4));
    fx.b.space(space(SpaceKind::Processor, "register", REG, 0, 4));
    fx.b.default_space("ram");
    fx.global = fx.b.scope(None);

    let instruction = fx.global("instruction", SymbolDef::Start);
    let mem = fx.global("mem", SymbolDef::Start);
    let cmem = fx.global("cmem", SymbolDef::Start);
    let inner = fx.global("inner", SymbolDef::Start);
    let leafsub = fx.global("leafsub", SymbolDef::Start);
    let regs: Vec<SymbolId> = (0..4)
        .map(|i| {
            fx.global(
                &format!("r{i}"),
                SymbolDef::Varnode {
                    space: REG,
                    offset: 4 * i,
                    size: 4,
                },
            )
        })
        .collect();
    fx.global("syscall", SymbolDef::UserOp { index: 0 });
    fx.global("inst_start", SymbolDef::Start);
    fx.global("inst_next", SymbolDef::End);
    let e = fx.field_expr(token(4, 5, false));
    let ra = fx.global(
        "ra",
        SymbolDef::VarnodeList {
            expr: e,
            entries: regs.iter().map(|r| Some(*r)).collect(),
        },
    );
    let e = fx.field_expr(token(0, 1, false));
    let rb = fx.global(
        "rb",
        SymbolDef::VarnodeList {
            expr: e,
            entries: regs.iter().map(|r| Some(*r)).collect(),
        },
    );
    let e = fx.field_expr(token(0, 7, true));
    let simm8 = fx.global("simm8", SymbolDef::Value { expr: e });
    let imm16_field = fx.b.field(Field {
        big_endian: true,
        sign_bit: false,
        start_bit: 0,
        end_bit: 15,
        start_byte: 2,
        end_byte: 3,
        shift: 0,
    });
    let e = fx.expr(Expr::TokenField(imm16_field));
    let imm16 = fx.global("imm16", SymbolDef::Value { expr: e });

    // Branch targets: inst_start + simm8 * 2; crossbuild target inst_start - 2.
    let start = fx.expr(Expr::Start);
    let imm = fx.field_expr(token(0, 7, true));
    let two = fx.expr(Expr::Constant(2));
    let scaled = fx.expr(Expr::Binary {
        op: bk_sla::BinaryOp::Mult,
        left: imm,
        right: two,
    });
    let target = fx.expr(Expr::Binary {
        op: bk_sla::BinaryOp::Plus,
        left: start,
        right: scaled,
    });
    let prev = fx.expr(Expr::Binary {
        op: bk_sla::BinaryOp::Sub,
        left: start,
        right: two,
    });

    let mut root: Vec<ConstructorDef> = Vec::new();
    let mut pairs: Vec<(u32, PatternDef)> = Vec::new();
    let mut add = |root: &mut Vec<ConstructorDef>, code: u8, c: ConstructorDef| {
        pairs.push((
            root.len() as u32,
            PatternDef::Instruction(pattern(&[(0xff, code)])),
        ));
        root.push(c);
    };
    let two_regs = |fx: &mut Fx, n: u32| {
        fx.operands(
            instruction,
            n,
            vec![
                ("ra", Def::Sym(ra), 0, -1, 0),
                ("rb", Def::Sym(rb), 0, -1, 0),
            ],
        )
    };
    let print2 = |m: &str| {
        vec![
            text(m),
            text(" "),
            PrintDef::Operand(0),
            text(","),
            PrintDef::Operand(1),
        ]
    };

    // 01 add ra, rb
    let n = root.len() as u32;
    let ops = two_regs(&mut fx, n);
    let c = ctor(2, 1, ops, print2("add"));
    let main = tpl(
        None,
        0,
        0,
        vec![(OpCode::IntAdd, Some(opnd(0)), vec![opnd(0), opnd(1)])],
    );
    let sect = tpl(
        Some(0),
        0,
        0,
        vec![(OpCode::Copy, Some(uniq(0x10, 4)), vec![opnd(0)])],
    );
    add(&mut root, 0x01, with_templates(c, vec![main, sect]));

    // 02 ld ra, [mem]  03 st [mem], ra  04 ldb  05 stb  10 dyn2
    let mem_ops = |fx: &mut Fx, n: u32| {
        fx.operands(
            instruction,
            n,
            vec![
                ("ra", Def::Sym(ra), 0, -1, 0),
                ("m", Def::Sym(mem), 0, -1, 0),
            ],
        )
    };
    let mem_cases: [(u8, &str, Op); 5] = [
        (0x02, "ld", (OpCode::Copy, Some(opnd(0)), vec![opnd(1)])),
        (0x03, "st", (OpCode::Copy, Some(opnd(1)), vec![opnd(0)])),
        (
            0x04,
            "ldb",
            (OpCode::IntZExt, Some(opnd(0)), vec![part(1, 3, 1)]),
        ),
        (
            0x05,
            "stb",
            (OpCode::Copy, Some(part(1, 1, 1)), vec![part(0, 0, 1)]),
        ),
        (
            0x10,
            "dyn2",
            (OpCode::IntAdd, Some(opnd(1)), vec![opnd(1), opnd(0)]),
        ),
    ];
    for (code, name, op) in mem_cases {
        let n = root.len() as u32;
        let ops = mem_ops(&mut fx, n);
        let c = ctor(2, 2 + u32::from(code) as i32, ops, print2(name));
        add(
            &mut root,
            code,
            with_templates(c, vec![tpl(None, 0, 0, vec![op])]),
        );
    }

    // 06 lbl ra, rb: labels 0 and 1, a backward and a forward branch.
    let n = root.len() as u32;
    let ops = two_regs(&mut fx, n);
    let c = ctor(2, 6, ops, print2("lbl"));
    let main = tpl(
        None,
        0,
        2,
        vec![
            label(1),
            (OpCode::CBranch, None, vec![rel(0, 4), opnd(0)]),
            (OpCode::Copy, Some(opnd(0)), vec![opnd(1)]),
            label(0),
            (OpCode::CBranch, None, vec![rel(1, 2), opnd(1)]),
            (OpCode::Branch, None, vec![rel(0, 8)]),
        ],
    );
    add(&mut root, 0x06, with_templates(c, vec![main]));

    // 07 call ra: CALLOTHER syscall
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("ra", Def::Sym(ra), 0, -1, 0)]);
    let c = ctor(
        2,
        7,
        ops,
        vec![text("call"), text(" "), PrintDef::Operand(0)],
    );
    let main = tpl(
        None,
        0,
        0,
        vec![(
            OpCode::CallOther,
            Some(uniq(0x14, 4)),
            vec![cst(0, 4), opnd(0)],
        )],
    );
    add(&mut root, 0x07, with_templates(c, vec![main]));

    // 08 bd target, 09 bd2 target
    for (code, name, bytes) in [(0x08u8, "bd", 2u64), (0x09, "bd2", 4)] {
        let n = root.len() as u32;
        let ops = fx.operands(
            instruction,
            n,
            vec![("target", Def::Expr(target), 0, -1, 0)],
        );
        let c = ctor(2, 8, ops, vec![text(name), text(" "), PrintDef::Operand(0)]);
        let main = tpl(
            None,
            bytes as i32,
            0,
            vec![
                (OpCode::Indirect, None, vec![cst(bytes, 4)]),
                (
                    OpCode::Branch,
                    None,
                    vec![vn(RAM, h(0, HandleSelect::Offset), 4)],
                ),
            ],
        );
        add(&mut root, code, with_templates(c, vec![main]));
    }

    // 0a xb: crossbuild section 0 of the instruction at inst_start - 2
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("p", Def::Expr(prev), 0, -1, 0)]);
    let c = ctor(
        2,
        10,
        ops,
        vec![text("xb"), text(" "), PrintDef::Operand(0)],
    );
    let main = tpl(
        None,
        0,
        0,
        vec![
            crossbuild(vn(RAM, h(0, HandleSelect::Offset), 4), 0),
            (
                OpCode::Copy,
                Some(uniq(0x30, 4)),
                vec![vn(0, ConstTpl::Start, 4)],
            ),
        ],
    );
    add(&mut root, 0x0a, with_templates(c, vec![main]));

    // 0b xs: crossbuild its own section 0
    let c = ctor(2, 11, Vec::new(), vec![text("xs")]);
    let main = tpl(None, 0, 0, vec![crossbuild(vn(RAM, ConstTpl::Start, 4), 0)]);
    let sect = tpl(
        Some(0),
        0,
        0,
        vec![(
            OpCode::Copy,
            Some(uniq(0x40, 4)),
            vec![vn(0, ConstTpl::Next, 4)],
        )],
    );
    add(&mut root, 0x0b, with_templates(c, vec![main, sect]));

    // 0c ops ra, rb: one op of every opcode
    let n = root.len() as u32;
    let ops = two_regs(&mut fx, n);
    let c = ctor(2, 12, ops, print2("ops"));
    let space_id = vn(0, ConstTpl::Space(RAM), 8);
    let every: Vec<Op> = OpCode::ALL
        .iter()
        .filter(|op| {
            !matches!(
                op,
                OpCode::MultiEqual | OpCode::Indirect | OpCode::PtrAdd | OpCode::PtrSub
            )
        })
        .map(|&op| match op {
            OpCode::Load => (op, Some(uniq(0x18, 4)), vec![space_id, opnd(1)]),
            OpCode::Store => (op, None, vec![space_id, opnd(1), opnd(0)]),
            OpCode::CallOther => (op, None, vec![cst(0, 4), opnd(0)]),
            _ => (op, Some(uniq(0x1c, 4)), vec![opnd(0), opnd(1)]),
        })
        .collect();
    add(
        &mut root,
        0x0c,
        with_templates(c, vec![tpl(None, 0, 0, every)]),
    );

    // 0d cst ra, imm16 (four bytes)
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![
            ("ra", Def::Sym(ra), 0, -1, 0),
            ("i", Def::Sym(imm16), 0, -1, 0),
        ],
    );
    let c = ctor(4, 13, ops, print2("cst"));
    let shifted = ConstTpl::Handle {
        index: 1,
        select: HandleSelect::OffsetPlus,
        plus: 1 << 16,
    };
    let main = tpl(
        None,
        0,
        0,
        vec![
            (
                OpCode::Copy,
                Some(uniq(0x20, 4)),
                vec![vn(0, ConstTpl::Start, 4)],
            ),
            (
                OpCode::Copy,
                Some(uniq(0x20, 4)),
                vec![vn(0, ConstTpl::Next, 4)],
            ),
            (
                OpCode::Copy,
                Some(uniq(0x20, 4)),
                vec![vn(0, ConstTpl::CurSpaceSize, 4)],
            ),
            (OpCode::Copy, Some(uniq(0x24, 1)), vec![cst(0x1234, 1)]),
            (OpCode::Copy, Some(uniq(0x24, 1)), vec![vn(0, shifted, 1)]),
            (
                OpCode::Copy,
                Some(uniq(0x24, 4)),
                vec![vn(0, h(1, HandleSelect::Size), 4)],
            ),
            (OpCode::Copy, Some(uniq(0x24, 2)), vec![part(0, 2, 2)]),
            (OpCode::Copy, Some(uniq(0x28, 8)), vec![cst(u64::MAX, 8)]),
        ],
    );
    add(&mut root, 0x0d, with_templates(c, vec![main]));

    // 0e halt: unimpl
    let mut c = ctor(2, 14, Vec::new(), vec![text("halt")]);
    c.templates = Vec::new();
    add(&mut root, 0x0e, c);

    // 0f nest ra: BUILD inner (labels in each level), no section 0 of its own
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("in", Def::Sym(inner), 0, -1, 0)]);
    let c = ctor(
        2,
        15,
        ops,
        vec![text("nest"), text(" "), PrintDef::Operand(0)],
    );
    let main = tpl(
        None,
        0,
        1,
        vec![label(0), build(0), (OpCode::Branch, None, vec![rel(0, 1)])],
    );
    add(&mut root, 0x0f, with_templates(c, vec![main]));

    // 11 cptr ra, cmem: pointer with a constant offset
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![
            ("ra", Def::Sym(ra), 0, -1, 0),
            ("c", Def::Sym(cmem), 0, -1, 0),
        ],
    );
    let c = ctor(2, 17, ops, print2("cptr"));
    let main = tpl(
        None,
        0,
        0,
        vec![(OpCode::Copy, Some(opnd(0)), vec![opnd(1)])],
    );
    add(&mut root, 0x11, with_templates(c, vec![main]));

    // 12 badl: a branch to a label never placed
    let c = ctor(2, 18, Vec::new(), vec![text("badl")]);
    let main = tpl(None, 0, 1, vec![(OpCode::Branch, None, vec![rel(0, 4)])]);
    add(&mut root, 0x12, with_templates(c, vec![main]));

    // 13 xin: its section 0 has a CROSSBUILD
    let c = ctor(2, 19, Vec::new(), vec![text("xin")]);
    let main = tpl(None, 0, 0, vec![crossbuild(vn(RAM, ConstTpl::Start, 4), 0)]);
    let sect = tpl(
        Some(0),
        0,
        0,
        vec![crossbuild(vn(RAM, ConstTpl::Start, 4), 0)],
    );
    add(&mut root, 0x13, with_templates(c, vec![main, sect]));

    // 14 uq ra: unique temporaries
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("ra", Def::Sym(ra), 0, -1, 0)]);
    let c = ctor(
        2,
        20,
        ops,
        vec![text("uq"), text(" "), PrintDef::Operand(0)],
    );
    let main = tpl(
        None,
        0,
        0,
        vec![
            (OpCode::Copy, Some(uniq(0x60, 4)), vec![opnd(0)]),
            (
                OpCode::IntAdd,
                Some(opnd(0)),
                vec![uniq(0x60, 4), uniq(0x60, 4)],
            ),
        ],
    );
    add(&mut root, 0x14, with_templates(c, vec![main]));

    // mem: *[ram]:4 rb, with a section-0 template (implied build target)
    let ops = fx.operands(mem, 0, vec![("rb", Def::Sym(rb), 0, -1, 0)]);
    let mut c = ctor(2, 30, ops, vec![text("["), PrintDef::Operand(0), text("]")]);
    let mut main = Template::new();
    main.set_result(Some(deref_export(
        h(0, HandleSelect::Space),
        h(0, HandleSelect::Size),
        0x80,
    )));
    let sect = tpl(
        Some(0),
        0,
        0,
        vec![(OpCode::Copy, Some(uniq(0x50, 4)), vec![cst(0x55, 4)])],
    );
    c.templates = vec![main, sect];
    let mem_table = TableDef {
        constructors: vec![c],
        decision: leaf(vec![(0, always())]),
    };

    // cmem: *[ram]:4 simm8 (a constant pointer)
    let ops = fx.operands(cmem, 0, vec![("v", Def::Sym(simm8), 0, -1, 0)]);
    let mut c = ctor(2, 31, ops, vec![text("@"), PrintDef::Operand(0)]);
    let mut main = Template::new();
    main.set_result(Some(deref_export(
        ConstTpl::Space(0),
        ConstTpl::Real(4),
        0x90,
    )));
    c.templates = vec![main];
    let cmem_table = TableDef {
        constructors: vec![c],
        decision: leaf(vec![(0, always())]),
    };

    // inner: a label of its own, a forward branch, BUILD leafsub; section 0
    let ops = fx.operands(inner, 0, vec![("l", Def::Sym(leafsub), 0, -1, 0)]);
    let mut c = ctor(2, 32, ops, vec![text("<"), PrintDef::Operand(0), text(">")]);
    c.templates = vec![
        tpl(
            None,
            0,
            1,
            vec![
                (OpCode::CBranch, None, vec![rel(0, 1), opnd(0)]),
                build(0),
                label(0),
            ],
        ),
        tpl(
            Some(0),
            0,
            0,
            vec![(OpCode::Copy, Some(uniq(0x70, 4)), vec![cst(7, 4)])],
        ),
    ];
    let inner_table = TableDef {
        constructors: vec![c],
        decision: leaf(vec![(0, always())]),
    };
    let ops = fx.operands(leafsub, 0, vec![("ra", Def::Sym(ra), 0, -1, 0)]);
    let mut c = ctor(2, 33, ops, vec![PrintDef::Operand(0)]);
    let mut main = tpl(
        None,
        0,
        1,
        vec![
            label(0),
            (OpCode::IntNegate, Some(opnd(0)), vec![opnd(0)]),
            (OpCode::CBranch, None, vec![rel(0, 2), opnd(0)]),
        ],
    );
    main.set_result(Some(HandleTpl {
        space: h(0, HandleSelect::Space),
        size: h(0, HandleSelect::Size),
        ptr_space: ConstTpl::Real(0),
        ptr_offset: h(0, HandleSelect::Offset),
        ptr_size: ConstTpl::Real(0),
        temp_space: ConstTpl::Real(0),
        temp_offset: ConstTpl::Real(0),
    }));
    c.templates = vec![main];
    let leaf_table = TableDef {
        constructors: vec![c],
        decision: leaf(vec![(0, always())]),
    };

    fx.b.set_symbol(
        instruction,
        SymbolDef::Subtable(TableDef {
            constructors: root,
            decision: leaf(pairs),
        }),
    );
    fx.b.set_symbol(mem, SymbolDef::Subtable(mem_table));
    fx.b.set_symbol(cmem, SymbolDef::Subtable(cmem_table));
    fx.b.set_symbol(inner, SymbolDef::Subtable(inner_table));
    fx.b.set_symbol(leafsub, SymbolDef::Subtable(leaf_table));
    fx.b.finish().expect("the bkpc fixture is valid")
}

/// Writes the fixture as a language directory `pcodedump` can load.
pub(crate) fn write_language_dir(dir: &std::path::Path) {
    build_sla()
        .write_file(&dir.join("bkpc.sla"))
        .expect("write bkpc.sla");
    std::fs::write(dir.join("bkpc.ldefs"), LDEFS).unwrap();
    std::fs::write(dir.join("bkpc.pspec"), PSPEC).unwrap();
}
