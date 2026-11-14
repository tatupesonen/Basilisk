//! `bkfix`: a small language built in Rust with `SlaBuilder`, so that a
//! differential check against `pcodedump` runs everywhere without Ghidra's
//! files (ADR-002): the oracle's output for it is recorded once and checked
//! in (`tests/data/fixture-oracle.txt`).
//!
//! Instructions are two bytes, big endian, `op` in the top nibble of byte 0
//! (except where noted):
//!
//! | op | what it exercises |
//! |---|---|
//! | 0 | `nop` (only with byte 0 = 0x00) |
//! | 1 | varnode lists with an unusable entry |
//! | 2 | signed value operand |
//! | 3 | value map with negative and unusable (`0xBADBEEF`) entries |
//! | 4 | name table with `_` and missing entries |
//! | 5 | operand defined by an expression of `inst_start` (code address) |
//! | 6 | context op + flowing commit to `inst_next` (sets `mode`) |
//! | 7 | `mode` = 1: combined pattern; `mode` = 0: clears `mode` |
//! | 8 | 3+ bytes: sub-table operand and an operand placed after it |
//! | 9 | flow-through printing of a sub-table |
//! | 10 | delay slot of 2 bytes |
//! | 11 | 21 operands (Ghidra's C++ cannot decode it) |
//! | 12 | 4 bytes: little-endian field over bytes 2..3 |
//! | 13 | noflow commit of `nf` to `inst_next` |
//! | 14 | prints the context variable `nf` and `inst_next` |
//! | 15 | `unimpl` body |
#![allow(dead_code, reason = "each test file uses part of this module")]

pub(crate) mod pcode;

use bk_sla::{
    BlockDef, ConstructorDef, ContextChange, DecisionDef, Expr, ExprId, Field, Header, MaskWord,
    Operand, PairDef, PatternDef, PrintDef, ScopeId, Sla, SlaBuilder, SpaceDef, SpaceKind,
    SymbolDef, SymbolId, TableDef, Template,
};

/// The `.ldefs` and `.pspec` that go with the fixture's `.sla`.
pub(crate) const LDEFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="BkFix" endian="big" size="32" variant="default" version="1.0"
            slafile="bkfix.sla" processorspec="bkfix.pspec" id="BkFix:BE:32:default">
    <description>basilisk test fixture</description>
    <compiler name="default" spec="bkfix.cspec" id="default"/>
  </language>
</language_definitions>
"#;

/// The processor specification: `nf` = 2 over the whole of `ram`.
pub(crate) const PSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
  <context_data>
    <context_set space="ram">
      <set name="nf" val="2"/>
    </context_set>
  </context_data>
</processor_spec>
"#;

/// The language id.
pub(crate) const ID: &str = "BkFix:BE:32:default";

pub(super) struct Fx {
    pub(super) b: SlaBuilder,
    pub(super) global: ScopeId,
}

/// A big-endian field of the two-byte token at the constructor's offset
/// (`lo..=hi`, bit 0 least significant), or of a later byte with `byte`.
pub(super) fn token(lo: i32, hi: i32, signed: bool) -> Field {
    Field {
        big_endian: true,
        sign_bit: signed,
        start_bit: lo,
        end_bit: hi,
        start_byte: (16 - hi - 1) / 8,
        end_byte: (16 - lo - 1) / 8,
        shift: lo % 8,
    }
}

pub(super) fn context(lo: i32, hi: i32) -> Field {
    Field {
        big_endian: false,
        sign_bit: false,
        start_bit: lo,
        end_bit: hi,
        start_byte: lo / 8,
        end_byte: hi / 8,
        shift: 7 - hi % 8,
    }
}

pub(super) fn pattern(bytes: &[(u8, u8)]) -> BlockDef {
    let mut words = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut mask = 0u32;
        let mut value = 0u32;
        for (i, &(m, v)) in chunk.iter().enumerate() {
            mask |= u32::from(m) << (24 - 8 * i);
            value |= u32::from(v & m) << (24 - 8 * i);
        }
        words.push(MaskWord { mask, value });
    }
    BlockDef {
        offset: 0,
        nonzero: 4 * words.len() as i32,
        words,
    }
}

pub(super) fn text(s: &str) -> PrintDef {
    PrintDef::Text(s.to_owned())
}

/// What defines an operand.
pub(super) enum Def {
    Sym(SymbolId),
    Expr(ExprId),
}

impl Fx {
    pub(super) fn expr(&mut self, e: Expr) -> ExprId {
        self.b.expr(e)
    }

    pub(super) fn field_expr(&mut self, f: Field) -> ExprId {
        let id = self.b.field(f);
        self.b.expr(Expr::TokenField(id))
    }

    pub(super) fn global(&mut self, name: &str, def: SymbolDef) -> SymbolId {
        self.b.symbol(name, self.global, def)
    }

    /// Operand symbols of constructor `ct` of `table`: (name, def, offset,
    /// base, minlen).
    pub(super) fn operands(
        &mut self,
        table: SymbolId,
        ct: u32,
        ops: Vec<(&str, Def, i32, i32, i32)>,
    ) -> Vec<SymbolId> {
        let scope = self.b.scope(Some(self.global));
        let mut out = Vec::new();
        for (index, (name, def, offset, base, min_length)) in ops.into_iter().enumerate() {
            let local = self.expr(Expr::Operand {
                index: index as i32,
                table,
                ct,
            });
            let (defining_symbol, defining_expr) = match def {
                Def::Sym(s) => (Some(s), None),
                Def::Expr(e) => (None, Some(e)),
            };
            out.push(self.b.symbol(
                name,
                scope,
                SymbolDef::Operand(Operand {
                    index: index as i32,
                    offset,
                    base,
                    min_length,
                    code: false,
                    defining_symbol,
                    local_expr: local,
                    defining_expr,
                }),
            ));
        }
        out
    }
}

pub(super) fn ctor(
    length: i32,
    line: i32,
    operands: Vec<SymbolId>,
    print: Vec<PrintDef>,
) -> ConstructorDef {
    let first = print
        .iter()
        .position(|p| *p == PrintDef::Text(" ".to_owned()))
        .map_or(-1, |p| p as i32);
    ConstructorDef {
        first,
        length,
        source: 0,
        line,
        operands,
        print,
        context: Vec::new(),
        templates: vec![Template::new()],
    }
}

pub(super) fn leaf(pairs: Vec<(u32, PatternDef)>) -> DecisionDef {
    DecisionDef {
        number: pairs.len() as i32,
        context: false,
        start_bit: 0,
        size: 0,
        pairs: pairs
            .into_iter()
            .map(|(constructor, pattern)| PairDef {
                constructor,
                pattern,
            })
            .collect(),
        children: Vec::new(),
    }
}

pub(super) fn space(kind: SpaceKind, name: &str, index: u32, delay: i32, size: i32) -> SpaceDef {
    SpaceDef {
        kind,
        name: name.to_owned(),
        index,
        big_endian: true,
        delay,
        size,
        word_size: 1,
        physical: true,
    }
}

/// Builds the fixture language.
pub(crate) fn build() -> Sla {
    let mut fx = Fx {
        b: SlaBuilder::new(Header {
            big_endian: true,
            align: 2,
            unique_base: 0x1000,
            max_delay: 2,
            unique_mask: 0,
            num_sections: 0,
        }),
        global: ScopeId::new(0),
    };
    fx.b.source_file("bkfix.slaspec");
    fx.b.space(space(SpaceKind::Other, "OTHER", 1, 0, 8));
    fx.b.space(space(SpaceKind::Unique, "unique", 2, 0, 4));
    fx.b.space(space(SpaceKind::Processor, "ram", 3, 1, 4));
    fx.b.space(space(SpaceKind::Processor, "register", 4, 0, 4));
    fx.b.default_space("ram");
    fx.global = fx.b.scope(None);

    // Placeholders filled in at the end.
    let instruction = fx.global("instruction", SymbolDef::Start);
    let sub = fx.global("sub", SymbolDef::Start);
    let sub2 = fx.global("sub2", SymbolDef::Start);

    let regs: Vec<SymbolId> = (0..4)
        .map(|i| {
            fx.global(
                &format!("r{i}"),
                SymbolDef::Varnode {
                    space: 4,
                    offset: 4 * i,
                    size: 4,
                },
            )
        })
        .collect();
    let contextreg = fx.global(
        "contextreg",
        SymbolDef::Varnode {
            space: 4,
            offset: 0x100,
            size: 4,
        },
    );
    let ctx_mode = fx.b.field(context(0, 0));
    let e = fx.expr(Expr::ContextField(ctx_mode));
    let mode = fx.global(
        "mode",
        SymbolDef::Context {
            varnode: contextreg,
            low: 31,
            high: 31,
            flow: true,
            expr: e,
        },
    );
    let ctx_nf = fx.b.field(context(1, 3));
    let e = fx.expr(Expr::ContextField(ctx_nf));
    let nf = fx.global(
        "nf",
        SymbolDef::Context {
            varnode: contextreg,
            low: 28,
            high: 30,
            flow: false,
            expr: e,
        },
    );
    let inst_start = fx.global("inst_start", SymbolDef::Start);
    let inst_next = fx.global("inst_next", SymbolDef::End);
    fx.global("inst_next2", SymbolDef::Next2);

    let e = fx.field_expr(token(8, 9, false));
    let ra_list = fx.global(
        "ra_list",
        SymbolDef::VarnodeList {
            expr: e,
            entries: vec![Some(regs[0]), Some(regs[1]), None, Some(regs[3])],
        },
    );
    let e = fx.field_expr(token(4, 5, false));
    let rb_list = fx.global(
        "rb_list",
        SymbolDef::VarnodeList {
            expr: e,
            entries: regs.iter().map(|r| Some(*r)).collect(),
        },
    );
    let e = fx.field_expr(token(0, 7, true));
    let simm8 = fx.global("simm8", SymbolDef::Value { expr: e });
    let e = fx.field_expr(token(4, 7, false));
    let map = fx.global(
        "map",
        SymbolDef::ValueMap {
            expr: e,
            values: vec![
                0, 1, -1, 0x7fff, -0x8000, 0xBAD_BEEF, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ],
        },
    );
    let e = fx.field_expr(token(8, 11, false));
    let mut names: Vec<Option<String>> = (0..16).map(|i| Some(format!("c{i}"))).collect();
    names[3] = Some("_".to_owned());
    names[7] = None;
    let cond = fx.global("cond", SymbolDef::Name { expr: e, names });
    let e = fx.field_expr(token(0, 3, false));
    let low4 = fx.global("low4", SymbolDef::Value { expr: e });
    let e = fx.field_expr(token(8, 15, false));
    let byte0 = fx.global("byte0", SymbolDef::Value { expr: e });
    let le = fx.b.field(Field {
        big_endian: false,
        sign_bit: false,
        start_bit: 0,
        end_bit: 15,
        start_byte: 2,
        end_byte: 3,
        shift: 0,
    });
    let e = fx.expr(Expr::TokenField(le));
    let le16 = fx.global("le16", SymbolDef::Value { expr: e });

    let mut root: Vec<ConstructorDef> = Vec::new();
    let mut pairs: Vec<(u32, PatternDef)> = Vec::new();
    let mut add = |root: &mut Vec<ConstructorDef>, c: ConstructorDef, p: PatternDef| {
        pairs.push((root.len() as u32, p));
        root.push(c);
    };

    // 0 nop
    add(
        &mut root,
        ctor(2, 1, vec![], vec![text("nop")]),
        PatternDef::Instruction(pattern(&[(0xff, 0x00)])),
    );
    // 1 mov ra, rb
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![
            ("ra", Def::Sym(ra_list), 0, -1, 0),
            ("rb", Def::Sym(rb_list), 0, -1, 0),
        ],
    );
    add(
        &mut root,
        ctor(
            2,
            2,
            ops,
            vec![
                text("mov"),
                text(" "),
                PrintDef::Operand(0),
                text(","),
                PrintDef::Operand(1),
            ],
        ),
        PatternDef::Instruction(pattern(&[(0xf0, 0x10)])),
    );
    // 2 li ra, simm8
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![
            ("ra", Def::Sym(rb_list), 0, -1, 0),
            ("imm", Def::Sym(simm8), 0, -1, 0),
        ],
    );
    add(
        &mut root,
        ctor(
            2,
            3,
            ops,
            vec![
                text("li"),
                text(" "),
                PrintDef::Operand(0),
                text(", #"),
                PrintDef::Operand(1),
            ],
        ),
        PatternDef::Instruction(pattern(&[(0xf0, 0x20)])),
    );
    // 3 ldm map
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("m", Def::Sym(map), 0, -1, 0)]);
    add(
        &mut root,
        ctor(
            2,
            4,
            ops,
            vec![text("ldm"), text(" "), PrintDef::Operand(0)],
        ),
        PatternDef::Instruction(pattern(&[(0xf0, 0x30)])),
    );
    // 4 cc cond
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("c", Def::Sym(cond), 0, -1, 0)]);
    add(
        &mut root,
        ctor(2, 5, ops, vec![text("b."), PrintDef::Operand(0)]),
        PatternDef::Instruction(pattern(&[(0xf0, 0x40)])),
    );
    // 5 br target = inst_start + simm8*2
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
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![("target", Def::Expr(target), 0, -1, 0)],
    );
    add(
        &mut root,
        ctor(2, 6, ops, vec![text("br"), text(" "), PrintDef::Operand(0)]),
        PatternDef::Instruction(pattern(&[(0xf0, 0x50)])),
    );
    // 6 setmode: mode = 1; globalset(inst_next, mode)
    let one = fx.expr(Expr::Constant(1));
    let mut c = ctor(2, 7, vec![], vec![text("setmode")]);
    c.context = vec![
        ContextChange::Op {
            word: 0,
            shift: 31,
            mask: 0x8000_0000,
            expr: one,
        },
        ContextChange::Commit {
            symbol: inst_next,
            word: 0,
            mask: 0x8000_0000,
            flow: true,
        },
    ];
    add(
        &mut root,
        c,
        PatternDef::Instruction(pattern(&[(0xf0, 0x60)])),
    );
    // 7 with mode = 1: m1op low4
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("x", Def::Sym(low4), 0, -1, 0)]);
    let ctx_one = BlockDef {
        offset: 0,
        nonzero: 4,
        words: vec![MaskWord {
            mask: 0x8000_0000,
            value: 0x8000_0000,
        }],
    };
    add(
        &mut root,
        ctor(
            2,
            8,
            ops,
            vec![text("m1op"), text(" "), PrintDef::Operand(0)],
        ),
        PatternDef::Combine(ctx_one, pattern(&[(0xf0, 0x70)])),
    );
    // 7 with mode = 0: clrmode (mode = 0, flowing commit)
    let zero = fx.expr(Expr::Constant(0));
    let mut c = ctor(2, 9, vec![], vec![text("clrmode")]);
    c.context = vec![
        ContextChange::Op {
            word: 0,
            shift: 31,
            mask: 0x8000_0000,
            expr: zero,
        },
        ContextChange::Commit {
            symbol: inst_next,
            word: 0,
            mask: 0x8000_0000,
            flow: true,
        },
    ];
    add(
        &mut root,
        c,
        PatternDef::Instruction(pattern(&[(0xf0, 0x70)])),
    );
    // 8 ext sub, byte after it
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![
            ("s", Def::Sym(sub), 1, -1, 1),
            ("after", Def::Sym(byte0), 0, 0, 1),
        ],
    );
    add(
        &mut root,
        ctor(
            1,
            10,
            ops,
            vec![
                text("ext"),
                text(" "),
                PrintDef::Operand(0),
                text(" ; "),
                PrintDef::Operand(1),
            ],
        ),
        PatternDef::Instruction(pattern(&[(0xf0, 0x80)])),
    );
    // 9 flow-through into sub2
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("f", Def::Sym(sub2), 0, -1, 2)]);
    add(
        &mut root,
        ctor(0, 11, ops, vec![PrintDef::Operand(0)]),
        PatternDef::Instruction(pattern(&[(0xf0, 0x90)])),
    );
    // 10 bd target with a 2-byte delay slot
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![("target", Def::Expr(target), 0, -1, 0)],
    );
    let mut c = ctor(
        2,
        12,
        ops,
        vec![text("bd"), text(" "), PrintDef::Operand(0)],
    );
    let mut delayed = Template::new();
    delayed.set_header(None, 2, 0);
    // DELAY_SLOT 2 (the directive in INDIRECT's slot), as the compiler
    // writes it whenever a template has a delay.
    let two_bytes = bk_sla::VarnodeTpl {
        space: bk_sla::ConstTpl::Space(0),
        offset: bk_sla::ConstTpl::Real(2),
        size: bk_sla::ConstTpl::Real(4),
    };
    delayed.push_op(bk_pcode::OpCode::Indirect, None, &[two_bytes]);
    c.templates = vec![delayed];
    add(
        &mut root,
        c,
        PatternDef::Instruction(pattern(&[(0xf0, 0xa0)])),
    );
    // 11 twenty-one operands
    let n = root.len() as u32;
    let many: Vec<(&str, Def, i32, i32, i32)> =
        (0..21).map(|_| ("v", Def::Sym(low4), 0, -1, 0)).collect();
    let ops = fx.operands(instruction, n, many);
    let mut print = vec![text("many"), text(" ")];
    for i in 0..21 {
        if i > 0 {
            print.push(text(","));
        }
        print.push(PrintDef::Operand(i));
    }
    add(
        &mut root,
        ctor(2, 13, ops, print),
        PatternDef::Instruction(pattern(&[(0xf0, 0xb0)])),
    );
    // 12 le16 over bytes 2..3
    let n = root.len() as u32;
    let ops = fx.operands(instruction, n, vec![("v", Def::Sym(le16), 0, -1, 0)]);
    add(
        &mut root,
        ctor(
            4,
            14,
            ops,
            vec![text("le16"), text(" "), PrintDef::Operand(0)],
        ),
        PatternDef::Instruction(pattern(&[(0xf0, 0xc0)])),
    );
    // 13 setnf: nf = low4 (noflow commit)
    let low = fx.field_expr(token(0, 3, false));
    let mut c = ctor(2, 15, vec![], vec![text("setnf")]);
    c.context = vec![
        ContextChange::Op {
            word: 0,
            shift: 28,
            mask: 0x7000_0000,
            expr: low,
        },
        ContextChange::Commit {
            symbol: inst_next,
            word: 0,
            mask: 0x7000_0000,
            flow: false,
        },
    ];
    add(
        &mut root,
        c,
        PatternDef::Instruction(pattern(&[(0xf0, 0xd0)])),
    );
    // 14 shownf nf, inst_next
    let n = root.len() as u32;
    let ops = fx.operands(
        instruction,
        n,
        vec![
            ("n", Def::Sym(nf), 0, -1, 0),
            ("nx", Def::Sym(inst_next), 0, -1, 0),
            ("st", Def::Sym(inst_start), 0, -1, 0),
        ],
    );
    add(
        &mut root,
        ctor(
            2,
            16,
            ops,
            vec![
                text("shownf"),
                text(" "),
                PrintDef::Operand(0),
                text(","),
                PrintDef::Operand(1),
                text(","),
                PrintDef::Operand(2),
            ],
        ),
        PatternDef::Instruction(pattern(&[(0xf0, 0xe0)])),
    );
    // 15 unimpl
    let mut c = ctor(2, 17, vec![], vec![text("halt")]);
    c.templates = Vec::new();
    add(
        &mut root,
        c,
        PatternDef::Instruction(pattern(&[(0xf0, 0xf0)])),
    );

    // sub: at byte 1; "a" (high nibble 0), "b rb" (high nibble 1), "c" with its
    // own sub-table... kept small.
    let mut sub_ctors = Vec::new();
    sub_ctors.push(ctor(1, 20, vec![], vec![text("a")]));
    let ops = fx.operands(sub, 1, vec![("r", Def::Sym(rb_list), 0, -1, 0)]);
    sub_ctors.push(ctor(1, 21, ops, vec![text("b:"), PrintDef::Operand(0)]));
    let sub_pairs = vec![
        (0, PatternDef::Instruction(pattern(&[(0xf0, 0x00)]))),
        (1, PatternDef::Instruction(pattern(&[(0xf0, 0x10)]))),
    ];
    // sub2: flow-through targets
    let mut sub2_ctors = Vec::new();
    sub2_ctors.push(ctor(2, 30, vec![], vec![text("fa")]));
    let ops = fx.operands(sub2, 1, vec![("r", Def::Sym(rb_list), 0, -1, 0)]);
    sub2_ctors.push(ctor(
        2,
        31,
        ops,
        vec![text("fb"), text(" "), PrintDef::Operand(0)],
    ));
    let sub2_pairs = vec![
        (0, PatternDef::Instruction(pattern(&[(0xff, 0x90)]))),
        (1, PatternDef::Instruction(pattern(&[(0xf0, 0x90)]))),
    ];

    fx.b.set_symbol(
        instruction,
        SymbolDef::Subtable(TableDef {
            constructors: root,
            decision: leaf(pairs),
        }),
    );
    fx.b.set_symbol(
        sub,
        SymbolDef::Subtable(TableDef {
            constructors: sub_ctors,
            decision: leaf(sub_pairs),
        }),
    );
    fx.b.set_symbol(
        sub2,
        SymbolDef::Subtable(TableDef {
            constructors: sub2_ctors,
            decision: leaf(sub2_pairs),
        }),
    );
    let _ = mode;
    fx.b.finish().expect("the bkfix fixture is valid")
}

/// Writes the fixture as a language directory `pcodedump` can load.
pub(crate) fn write_language_dir(dir: &std::path::Path) {
    let sla = build();
    sla.write_file(&dir.join("bkfix.sla"))
        .expect("write bkfix.sla");
    std::fs::write(dir.join("bkfix.ldefs"), LDEFS).unwrap();
    std::fs::write(dir.join("bkfix.pspec"), PSPEC).unwrap();
}
