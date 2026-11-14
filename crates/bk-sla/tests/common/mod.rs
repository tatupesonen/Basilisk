//! A hand-built model holding every element kind and every optional
//! attribute of the format, including those no shipped file contains
//! (`epsilon_sym`, `next2_exp`, `const_flowref` and friends).
#![allow(dead_code, reason = "each test file uses part of this module")]

use bk_pcode::OpCode;
use bk_sla::{
    BinaryOp, BlockDef, ConstTpl, ConstructorDef, ContextChange, DecisionDef, Expr, ExprId, Field,
    HandleSelect, HandleTpl, Header, MaskWord, Operand, PairDef, PatternDef, PrintDef, ScopeId,
    Sla, SlaBuilder, SpaceDef, SpaceKind, SymbolDef, SymbolId, TableDef, Template, UnaryOp,
    VarnodeTpl,
};

fn space(
    kind: SpaceKind,
    name: &str,
    index: u32,
    delay: i32,
    size: i32,
    word: i32,
    phys: bool,
) -> SpaceDef {
    SpaceDef {
        kind,
        name: name.to_owned(),
        index,
        big_endian: true,
        delay,
        size,
        word_size: word,
        physical: phys,
    }
}

pub(crate) fn real(value: u64) -> ConstTpl {
    ConstTpl::Real(value)
}

pub(crate) fn vn(space: ConstTpl, offset: ConstTpl, size: ConstTpl) -> VarnodeTpl {
    VarnodeTpl {
        space,
        offset,
        size,
    }
}

pub(crate) fn constant(value: u64) -> VarnodeTpl {
    vn(ConstTpl::Space(0), real(value), real(4))
}

/// The main template of `instruction` constructor 0: every constant kind,
/// every directive, an export.
pub(crate) fn main_template() -> Template {
    let mut t = Template::new();
    t.set_header(None, 1, 1);
    let handle = |s| ConstTpl::Handle {
        index: 0,
        select: s,
        plus: 0,
    };
    t.set_result(Some(HandleTpl {
        space: handle(HandleSelect::Space),
        size: handle(HandleSelect::Size),
        ptr_space: ConstTpl::Space(3),
        ptr_offset: handle(HandleSelect::Offset),
        ptr_size: real(4),
        temp_space: ConstTpl::Space(2),
        temp_offset: real(0x80),
    }));
    t.push_op(
        OpCode::Copy,
        Some(vn(ConstTpl::Space(3), real(0x10), real(4))),
        &[vn(
            handle(HandleSelect::Space),
            ConstTpl::Handle {
                index: 1,
                select: HandleSelect::OffsetPlus,
                plus: 0x0001_0002,
            },
            handle(HandleSelect::Size),
        )],
    );
    t.push_op(OpCode::MultiEqual, None, &[constant(0)]);
    t.push_op(OpCode::Indirect, None, &[constant(1)]);
    t.push_op(OpCode::PtrAdd, None, &[constant(0)]);
    t.push_op(
        OpCode::Branch,
        None,
        &[vn(ConstTpl::Space(0), ConstTpl::Relative(0), real(4))],
    );
    t.push_op(
        OpCode::PtrSub,
        None,
        &[
            vn(ConstTpl::CurSpace, ConstTpl::Next2, ConstTpl::CurSpaceSize),
            constant(1),
        ],
    );
    t.push_op(
        OpCode::IntAdd,
        Some(vn(ConstTpl::Space(2), ConstTpl::Start, real(4))),
        &[
            vn(ConstTpl::FlowRef, ConstTpl::FlowRefSize, ConstTpl::FlowDest),
            vn(ConstTpl::FlowDestSize, ConstTpl::Next, real(4)),
        ],
    );
    t
}

pub(crate) struct Ids {
    pub(crate) instruction: SymbolId,
    pub(crate) dst: SymbolId,
    pub(crate) calc: SymbolId,
}

/// Builds the full model.
pub(crate) fn full_model() -> Sla {
    full_builder()
        .0
        .finish()
        .expect("the full fixture is valid")
}

pub(crate) fn full_builder() -> (SlaBuilder, Ids) {
    let mut b = SlaBuilder::new(Header {
        big_endian: true,
        align: 2,
        unique_base: 0x100,
        max_delay: 1,
        unique_mask: 0xf0,
        num_sections: 2,
    });
    b.source_file("a.sinc");
    b.source_file("b.sinc");
    b.space(space(SpaceKind::Other, "OTHER", 1, 0, 8, 1, false));
    b.space(space(SpaceKind::Unique, "unique", 2, 0, 4, 1, true));
    b.space(space(SpaceKind::Processor, "ram", 3, 1, 4, 1, true));
    b.space(space(SpaceKind::Processor, "register", 4, 0, 4, 1, true));
    b.space(space(SpaceKind::Processor, "code", 5, 1, 4, 2, true));
    b.default_space("ram");
    let global = b.scope(None);
    let scope1 = b.scope(Some(global));
    let scope2 = b.scope(Some(global));

    let token = b.field(Field {
        big_endian: true,
        sign_bit: false,
        start_bit: 0,
        end_bit: 7,
        start_byte: 0,
        end_byte: 0,
        shift: 0,
    });
    let ctx = b.field(Field {
        big_endian: false,
        sign_bit: true,
        start_bit: 0,
        end_bit: 3,
        start_byte: 0,
        end_byte: 0,
        shift: 4,
    });
    let tf = |b: &mut SlaBuilder| b.expr(Expr::TokenField(token));

    let instruction = SymbolId::new(0);
    let sub = SymbolId::new(14);
    // Symbol 0 is filled in at the end.
    b.symbol("instruction", global, SymbolDef::Start);
    b.symbol(
        "r0",
        global,
        SymbolDef::Varnode {
            space: 4,
            offset: 0,
            size: 4,
        },
    );
    b.symbol(
        "r1",
        global,
        SymbolDef::Varnode {
            space: 4,
            offset: 4,
            size: 4,
        },
    );
    b.symbol(
        "contextreg",
        global,
        SymbolDef::Varnode {
            space: 4,
            offset: 0x100,
            size: 4,
        },
    );
    b.symbol("segment", global, SymbolDef::UserOp { index: 0 });
    let e = tf(&mut b);
    b.symbol("fval", global, SymbolDef::Value { expr: e });
    let e = tf(&mut b);
    b.symbol(
        "fmap",
        global,
        SymbolDef::ValueMap {
            expr: e,
            values: vec![-1, 0xBAD_BEEF],
        },
    );
    let e = tf(&mut b);
    b.symbol(
        "fname",
        global,
        SymbolDef::Name {
            expr: e,
            names: vec![Some("a<&>".to_owned()), None],
        },
    );
    let e = tf(&mut b);
    b.symbol(
        "flist",
        global,
        SymbolDef::VarnodeList {
            expr: e,
            entries: vec![Some(SymbolId::new(1)), None],
        },
    );
    let e = b.expr(Expr::ContextField(ctx));
    b.symbol(
        "mode",
        global,
        SymbolDef::Context {
            varnode: SymbolId::new(3),
            low: 0,
            high: 3,
            flow: true,
            expr: e,
        },
    );
    b.symbol("inst_start", global, SymbolDef::Start);
    b.symbol("inst_next", global, SymbolDef::End);
    b.symbol("inst_next2", global, SymbolDef::Next2);
    b.symbol("epsilon", global, SymbolDef::Epsilon);
    b.symbol("sub", global, SymbolDef::Start);

    let local = b.expr(Expr::Operand {
        index: 0,
        table: instruction,
        ct: 0,
    });
    let dst = b.symbol(
        "dst",
        scope1,
        SymbolDef::Operand(Operand {
            index: 0,
            offset: 0,
            base: -1,
            min_length: 1,
            code: true,
            defining_symbol: Some(sub),
            local_expr: local,
            defining_expr: None,
        }),
    );
    let calc_expr = calc_expr(&mut b, instruction);
    let local = b.expr(Expr::Operand {
        index: 1,
        table: instruction,
        ct: 0,
    });
    let calc = b.symbol(
        "calc",
        scope1,
        SymbolDef::Operand(Operand {
            index: 1,
            offset: 0,
            base: 0,
            min_length: 0,
            code: false,
            defining_symbol: None,
            local_expr: local,
            defining_expr: Some(calc_expr),
        }),
    );
    let local = b.expr(Expr::Operand {
        index: 0,
        table: sub,
        ct: 0,
    });
    let reg = b.symbol(
        "reg",
        scope2,
        SymbolDef::Operand(Operand {
            index: 0,
            offset: 1,
            base: -1,
            min_length: 1,
            code: false,
            defining_symbol: Some(SymbolId::new(8)),
            local_expr: local,
            defining_expr: None,
        }),
    );

    let three = b.expr(Expr::Constant(3));
    let mut section0 = Template::new();
    section0.set_header(Some(0), 0, 0);
    section0.push_op(
        OpCode::Copy,
        Some(vn(ConstTpl::Space(4), real(0), real(4))),
        &[constant(7)],
    );
    let mut section1 = Template::new();
    section1.set_header(Some(1), 0, 0);
    let ct0 = ConstructorDef {
        first: 1,
        length: 2,
        source: 0,
        line: 10,
        operands: vec![dst, calc],
        print: vec![
            PrintDef::Text("op".to_owned()),
            PrintDef::Text(" ".to_owned()),
            PrintDef::Operand(0),
            PrintDef::Text(",".to_owned()),
            PrintDef::Operand(1),
        ],
        context: vec![
            ContextChange::Op {
                word: 0,
                shift: 28,
                mask: 0xf000_0000,
                expr: three,
            },
            ContextChange::Commit {
                symbol: SymbolId::new(9),
                word: 0,
                mask: 0xf000_0000,
                flow: true,
            },
        ],
        templates: vec![section1, main_template(), section0],
    };
    let ct1 = ConstructorDef {
        first: 1,
        length: 1,
        source: 1,
        line: 20,
        print: vec![PrintDef::Text("nop".to_owned())],
        ..ConstructorDef::default()
    };
    let block = |offset, nonzero, words: &[(u32, u32)]| BlockDef {
        offset,
        nonzero,
        words: words
            .iter()
            .map(|&(mask, value)| MaskWord { mask, value })
            .collect(),
    };
    let leaf = |pairs| DecisionDef {
        number: 1,
        pairs,
        ..DecisionDef::default()
    };
    let tree = DecisionDef {
        number: 3,
        context: false,
        start_bit: 0,
        size: 1,
        pairs: vec![],
        children: vec![
            leaf(vec![PairDef {
                constructor: 0,
                pattern: PatternDef::Combine(
                    block(0, 4, &[(0xf000_0000, 0x3000_0000)]),
                    block(0, 8, &[(0, 0), (0x00ff_0000, 0x0012_0000)]),
                ),
            }]),
            leaf(vec![
                PairDef {
                    constructor: 1,
                    pattern: PatternDef::Instruction(block(0, 4, &[(0x8000_0000, 0x8000_0000)])),
                },
                PairDef {
                    constructor: 0,
                    pattern: PatternDef::Context(block(0, 4, &[(0x0f00_0000, 0x0100_0000)])),
                },
            ]),
        ],
    };
    b.set_symbol(
        instruction,
        SymbolDef::Subtable(TableDef {
            constructors: vec![ct0, ct1],
            decision: tree,
        }),
    );

    let mut sub_main = Template::new();
    sub_main.set_result(Some(HandleTpl::from_parts([
        ConstTpl::Handle {
            index: 0,
            select: HandleSelect::Space,
            plus: 0,
        },
        ConstTpl::Handle {
            index: 0,
            select: HandleSelect::Size,
            plus: 0,
        },
        real(0),
        real(0),
        real(0),
        real(0),
        real(0),
    ])));
    let sub_ct = ConstructorDef {
        first: -1,
        length: 1,
        source: 1,
        line: 30,
        operands: vec![reg],
        print: vec![PrintDef::Operand(0)],
        templates: vec![sub_main],
        ..ConstructorDef::default()
    };
    b.set_symbol(
        sub,
        SymbolDef::Subtable(TableDef {
            constructors: vec![sub_ct],
            decision: leaf(vec![PairDef {
                constructor: 0,
                pattern: PatternDef::Instruction(block(0, 0, &[])),
            }]),
        }),
    );
    let _ = ScopeId::new(0);
    (
        b,
        Ids {
            instruction,
            dst,
            calc,
        },
    )
}

/// An expression with every operator and value kind.
fn calc_expr(b: &mut SlaBuilder, instruction: SymbolId) -> ExprId {
    let c = |b: &mut SlaBuilder, v| b.expr(Expr::Constant(v));
    let bin = |b: &mut SlaBuilder, op, left, right| b.expr(Expr::Binary { op, left, right });
    let (c100, c2) = (c(b, 100), c(b, 2));
    let mut e = bin(b, BinaryOp::Div, c100, c2);
    let c1 = c(b, 1);
    e = bin(b, BinaryOp::Xor, e, c1);
    let start = b.expr(Expr::Start);
    e = bin(b, BinaryOp::Or, e, start);
    let end = b.expr(Expr::End);
    e = bin(b, BinaryOp::And, e, end);
    let c1 = c(b, 1);
    e = bin(b, BinaryOp::RightShift, e, c1);
    let c2 = c(b, 2);
    e = bin(b, BinaryOp::LeftShift, e, c2);
    let next2 = b.expr(Expr::Next2);
    e = bin(b, BinaryOp::Mult, e, next2);
    let c1 = c(b, -1);
    let minus = b.expr(Expr::Unary {
        op: UnaryOp::Minus,
        operand: c1,
    });
    e = bin(b, BinaryOp::Sub, e, minus);
    let operand = b.expr(Expr::Operand {
        index: 0,
        table: instruction,
        ct: 0,
    });
    let not = b.expr(Expr::Unary {
        op: UnaryOp::Not,
        operand,
    });
    bin(b, BinaryOp::Plus, e, not)
}
