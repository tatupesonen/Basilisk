//! Behaviour derived from the source (`features/sleigh-decode.md` 6.3) on
//! small languages built with `SlaBuilder`: the 16-byte window, division by
//! zero, the depth limit, context fields across words, operand expressions
//! evaluated before their operand is parsed, and commits to computed
//! addresses in a word-addressed space and at the top of a space.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

use std::sync::Arc;

use bk_core::{Address, SpaceId};
use bk_sla::{
    BinaryOp, BlockDef, ConstructorDef, ContextChange, DecisionDef, Expr, ExprId, Field, Header, MaskWord,
    Operand, PairDef, PatternDef, PrintDef, ScopeId, SlaBuilder, SpaceDef, SpaceKind, SymbolDef, SymbolId,
    TableDef, Template,
};
use bk_sleigh::{ContextDb, DecodeError, Decoder, Language, Limit, SliceBytes};

struct Mini {
    b: SlaBuilder,
    global: ScopeId,
    instruction: SymbolId,
    contextreg: SymbolId,
    inst_next: SymbolId,
}

fn byte_field(byte: i32, signed: bool) -> Field {
    Field {
        big_endian: true,
        sign_bit: signed,
        start_bit: 0,
        end_bit: 7,
        start_byte: byte,
        end_byte: byte,
        shift: 0,
    }
}

fn first_byte(value: u8) -> PatternDef {
    PatternDef::Instruction(BlockDef {
        offset: 0,
        nonzero: 1,
        words: vec![MaskWord {
            mask: 0xff00_0000,
            value: u32::from(value) << 24,
        }],
    })
}

impl Mini {
    fn new(word_size: i32) -> Self {
        let mut b = SlaBuilder::new(Header {
            big_endian: true,
            align: 1,
            unique_base: 0x100,
            max_delay: 0,
            unique_mask: 0,
            num_sections: 0,
        });
        b.source_file("mini.slaspec");
        let space = |kind, name: &str, index, word_size| SpaceDef {
            kind,
            name: name.to_owned(),
            index,
            big_endian: true,
            delay: 0,
            size: 4,
            word_size,
            physical: true,
        };
        b.space(space(SpaceKind::Other, "OTHER", 1, 1));
        b.space(space(SpaceKind::Unique, "unique", 2, 1));
        b.space(space(SpaceKind::Processor, "ram", 3, word_size));
        b.space(space(SpaceKind::Processor, "register", 4, 1));
        b.default_space("ram");
        let global = b.scope(None);
        let instruction = b.symbol("instruction", global, SymbolDef::Start);
        let contextreg = b.symbol(
            "contextreg",
            global,
            SymbolDef::Varnode {
                space: 4,
                offset: 0x100,
                size: 8,
            },
        );
        b.symbol("inst_start", global, SymbolDef::Start);
        let inst_next = b.symbol("inst_next", global, SymbolDef::End);
        b.symbol("inst_next2", global, SymbolDef::Next2);
        Self {
            b,
            global,
            instruction,
            contextreg,
            inst_next,
        }
    }

    fn expr(&mut self, e: Expr) -> ExprId {
        self.b.expr(e)
    }

    fn field(&mut self, f: Field) -> ExprId {
        let id = self.b.field(f);
        self.b.expr(Expr::TokenField(id))
    }

    /// An operand of constructor `ct` of `table` defined by a symbol or an
    /// expression.
    fn operand(&mut self, table: SymbolId, ct: u32, index: i32, offset: i32, base: i32, def: (Option<SymbolId>, Option<ExprId>)) -> SymbolId {
        let scope = self.b.scope(Some(self.global));
        let local = self.expr(Expr::Operand { index, table, ct });
        self.b.symbol(
            "op",
            scope,
            SymbolDef::Operand(Operand {
                index,
                offset,
                base,
                min_length: 0,
                code: false,
                defining_symbol: def.0,
                local_expr: local,
                defining_expr: def.1,
            }),
        )
    }

    fn value(&mut self, name: &str, e: ExprId) -> SymbolId {
        self.b.symbol(name, self.global, SymbolDef::Value { expr: e })
    }

    fn table(&mut self, id: SymbolId, constructors: Vec<ConstructorDef>, pairs: Vec<(u32, PatternDef)>) {
        let decision = DecisionDef {
            number: pairs.len() as i32,
            context: false,
            start_bit: 0,
            size: 0,
            pairs: pairs.into_iter().map(|(constructor, pattern)| PairDef { constructor, pattern }).collect(),
            children: Vec::new(),
        };
        self.b.set_symbol(id, SymbolDef::Subtable(TableDef { constructors, decision }));
    }

    fn finish(self) -> Arc<Language> {
        Arc::new(Language::from_sla(Arc::new(self.b.finish().unwrap())).unwrap())
    }
}

fn ctor(length: i32, operands: Vec<SymbolId>, print: Vec<PrintDef>) -> ConstructorDef {
    ConstructorDef {
        first: print.iter().position(|p| *p == PrintDef::Text(" ".into())).map_or(-1, |p| p as i32),
        length,
        source: 0,
        line: 1,
        operands,
        print,
        context: Vec::new(),
        templates: vec![Template::new()],
    }
}

fn text(s: &str) -> PrintDef {
    PrintDef::Text(s.to_owned())
}

fn ram(lang: &Language, offset: u64) -> Address {
    Address::new(lang.default_space(), offset)
}

fn disassemble(lang: &Arc<Language>, bytes: &[u8], db: &ContextDb) -> Result<String, DecodeError> {
    let mut decoder = Decoder::new(Arc::clone(lang));
    let d = decoder.disassemble(ram(lang, 0), &SliceBytes::new(0, bytes), db)?;
    Ok(format!("{} {}", d.mnemonic, d.body))
}

/// An operand at offset `offset` reading a 16-bit field.
#[test]
fn the_window_is_sixteen_bytes_and_reads_zero_past_it() {
    let mut m = Mini::new(1);
    let root = m.instruction;
    let wide = Field {
        big_endian: true,
        sign_bit: false,
        start_bit: 0,
        end_bit: 15,
        start_byte: 0,
        end_byte: 1,
        shift: 0,
    };
    let e = m.field(wide);
    let word = m.value("word", e);
    let mut ctors = Vec::new();
    let mut pairs = Vec::new();
    for (i, offset) in [14, 15, 16].into_iter().enumerate() {
        let op = m.operand(root, i as u32, 0, offset, -1, (Some(word), None));
        ctors.push(ctor(1, vec![op], vec![text("w"), text(" "), PrintDef::Operand(0)]));
        pairs.push((i as u32, first_byte(i as u8 + 1)));
    }
    m.table(root, ctors, pairs);
    let lang = m.finish();
    let db = lang.initial_context();
    let mut bytes = [0u8; 16];
    bytes[14] = 0x12;
    bytes[15] = 0x34;
    bytes[0] = 1;
    assert_eq!(disassemble(&lang, &bytes, &db).unwrap(), "w 0x1234");
    bytes[0] = 2;
    assert_eq!(disassemble(&lang, &bytes, &db).unwrap(), "w 0x3400");
    let mut decoder = Decoder::new(Arc::clone(&lang));
    decoder.decode(ram(&lang, 0), &SliceBytes::new(0, &bytes), &db).unwrap();
    let mut s = String::new();
    decoder.body(&mut s).unwrap();
    assert!(decoder.parse().reads_past_window());
    bytes[0] = 3;
    let err = disassemble(&lang, &bytes, &db).unwrap_err();
    assert!(matches!(err, DecodeError::TooLong { .. }), "{err:?}");
    assert_eq!(err.to_string(), "Instruction is using more than 16 bytes");
}

#[test]
fn division_by_zero_is_a_decode_error() {
    let mut m = Mini::new(1);
    let root = m.instruction;
    let hundred = m.expr(Expr::Constant(100));
    let divisor = m.field(byte_field(1, false));
    let quotient = m.expr(Expr::Binary {
        op: BinaryOp::Div,
        left: hundred,
        right: divisor,
    });
    let op = m.operand(root, 0, 0, 0, -1, (None, Some(quotient)));
    m.table(root, vec![ctor(2, vec![op], vec![text("div"), text(" "), PrintDef::Operand(0)])], vec![(0, first_byte(7))]);
    let lang = m.finish();
    let db = lang.initial_context();
    assert_eq!(disassemble(&lang, &[7, 3], &db).unwrap(), "div 0x21");
    let err = disassemble(&lang, &[7, 0], &db).unwrap_err();
    assert!(matches!(err, DecodeError::DivisionByZero { .. }), "{err:?}");
}

#[test]
fn nesting_deeper_than_ghidras_limit_is_an_error() {
    let mut m = Mini::new(1);
    let root = m.instruction;
    let sub = m.b.symbol("sub", m.global, SymbolDef::Start);
    let op = m.operand(root, 0, 0, 0, -1, (Some(sub), None));
    m.table(root, vec![ctor(1, vec![op], vec![PrintDef::Operand(0)])], vec![(0, first_byte(1))]);
    // `sub` contains itself at offset 0: the walk only stops at the limit.
    let inner = m.operand(sub, 0, 0, 0, -1, (Some(sub), None));
    m.table(sub, vec![ctor(1, vec![inner], vec![PrintDef::Operand(0)])], vec![(0, first_byte(1))]);
    let lang = m.finish();
    let err = disassemble(&lang, &[1], &lang.initial_context()).unwrap_err();
    assert_eq!(
        err,
        DecodeError::Limit {
            address: ram(&lang, 0),
            limit: Limit::Depth
        }
    );
    assert_eq!(err.to_string(), "SLEIGH exceeded maximum parse depth");
}

#[test]
fn context_fields_read_across_a_word_boundary() {
    let mut m = Mini::new(1);
    let root = m.instruction;
    let field = m.b.field(Field {
        big_endian: false,
        sign_bit: false,
        start_bit: 28,
        end_bit: 35,
        start_byte: 3,
        end_byte: 4,
        shift: 7 - 35 % 8,
    });
    let e = m.expr(Expr::ContextField(field));
    let reg = m.contextreg;
    let ctx = m.b.symbol(
        "straddle",
        m.global,
        SymbolDef::Value { expr: e },
    );
    let _ = reg;
    let op = m.operand(root, 0, 0, 0, -1, (Some(ctx), None));
    m.table(root, vec![ctor(1, vec![op], vec![text("c"), text(" "), PrintDef::Operand(0)])], vec![(0, first_byte(1))]);
    let lang = m.finish();
    assert_eq!(lang.context_words(), 2);
    let mut db = lang.empty_context();
    db.region(ram(&lang, 0), None, 0, 0xf, 0xa);
    db.region(ram(&lang, 0), None, 1, 0xf000_0000, 0x5000_0000);
    assert_eq!(disassemble(&lang, &[1], &db).unwrap(), "c 0xa5");
}

/// A context operation reads an operand placed relative to the constructor
/// before that operand's node exists, and a sub-table then tests the result.
#[test]
fn operand_values_are_available_to_context_operations() {
    let mut m = Mini::new(1);
    let root = m.instruction;
    let sub = m.b.symbol("sub", m.global, SymbolDef::Start);
    let byte1 = m.field(byte_field(0, false));
    let b1 = m.value("b1", byte1);
    let op0 = m.operand(root, 0, 0, 1, -1, (Some(b1), None));
    let op1 = m.operand(root, 0, 1, 0, 0, (Some(sub), None));
    let read = m.expr(Expr::Operand {
        index: 0,
        table: root,
        ct: 0,
    });
    let mut c = ctor(1, vec![op0, op1], vec![text("x"), text(" "), PrintDef::Operand(1)]);
    c.context = vec![ContextChange::Op {
        word: 0,
        shift: 24,
        mask: 0xff00_0000,
        expr: read,
    }];
    m.table(root, vec![c], vec![(0, first_byte(5))]);
    let ctx_pattern = PatternDef::Context(BlockDef {
        offset: 0,
        nonzero: 1,
        words: vec![MaskWord {
            mask: 0xff00_0000,
            value: 0x4200_0000,
        }],
    });
    let always = PatternDef::Instruction(BlockDef::default());
    m.table(
        sub,
        vec![ctor(0, vec![], vec![text("yes")]), ctor(0, vec![], vec![text("no")])],
        vec![(0, ctx_pattern), (1, always)],
    );
    // The context field must exist for the context to have a word.
    let field = m.b.field(Field {
        big_endian: false,
        sign_bit: false,
        start_bit: 0,
        end_bit: 7,
        start_byte: 0,
        end_byte: 0,
        shift: 0,
    });
    let e = m.expr(Expr::ContextField(field));
    let reg = m.contextreg;
    m.b.symbol(
        "cbyte",
        m.global,
        SymbolDef::Context {
            varnode: reg,
            low: 56,
            high: 63,
            flow: true,
            expr: e,
        },
    );
    let lang = m.finish();
    let db = lang.initial_context();
    assert_eq!(disassemble(&lang, &[5, 0x42], &db).unwrap(), "x yes");
    assert_eq!(disassemble(&lang, &[5, 0x41], &db).unwrap(), "x no");
}

/// Commits to a computed address (scaled by the word size) and, without
/// flow, at the top of the space (where Ghidra uses the flowing form because
/// the next address wraps).
#[test]
fn commits_to_computed_addresses() {
    for word_size in [1, 2] {
        let mut m = Mini::new(word_size);
        let root = m.instruction;
        let field = m.b.field(Field {
            big_endian: false,
            sign_bit: false,
            start_bit: 0,
            end_bit: 7,
            start_byte: 0,
            end_byte: 0,
            shift: 0,
        });
        let e = m.expr(Expr::ContextField(field));
        let reg = m.contextreg;
        m.b.symbol(
            "cbyte",
            m.global,
            SymbolDef::Context {
                varnode: reg,
                low: 56,
                high: 63,
                flow: false,
                expr: e,
            },
        );
        let ten = m.expr(Expr::Constant(0x10));
        let top = m.expr(Expr::Constant(0xffff_ffff));
        let seven = m.expr(Expr::Constant(7));
        let at10 = m.operand(root, 0, 0, 0, -1, (None, Some(ten)));
        let attop = m.operand(root, 1, 0, 0, -1, (None, Some(top)));
        let mut flowing = ctor(1, vec![at10], vec![text("f")]);
        flowing.context = vec![
            ContextChange::Op { word: 0, shift: 24, mask: 0xff00_0000, expr: seven },
            ContextChange::Commit { symbol: at10, word: 0, mask: 0xff00_0000, flow: true },
        ];
        let mut at_top = ctor(1, vec![attop], vec![text("t")]);
        at_top.context = vec![
            ContextChange::Op { word: 0, shift: 24, mask: 0xff00_0000, expr: seven },
            ContextChange::Commit { symbol: attop, word: 0, mask: 0xff00_0000, flow: false },
        ];
        let next = m.inst_next;
        let mut to_next = ctor(1, vec![], vec![text("n")]);
        to_next.context = vec![
            ContextChange::Op { word: 0, shift: 24, mask: 0xff00_0000, expr: seven },
            ContextChange::Commit { symbol: next, word: 0, mask: 0xff00_0000, flow: false },
        ];
        m.table(root, vec![flowing, at_top, to_next], vec![(0, first_byte(1)), (1, first_byte(2)), (2, first_byte(3))]);
        let lang = m.finish();
        let mut decoder = Decoder::new(Arc::clone(&lang));
        let var = lang.context_variable("cbyte").unwrap().clone();

        let mut db = lang.initial_context();
        decoder.prepare(ram(&lang, 0), &SliceBytes::new(0, &[1]), &mut db).unwrap();
        let scaled = 0x10 * word_size as u64;
        assert_eq!(db.variable(&var, ram(&lang, scaled - 1)), 0);
        assert_eq!(db.variable(&var, ram(&lang, scaled)), 7, "word size {word_size}");
        assert_eq!(db.variable(&var, ram(&lang, 0x1000)), 7, "flows");

        let mut db = lang.initial_context();
        decoder.prepare(ram(&lang, 0), &SliceBytes::new(0, &[2]), &mut db).unwrap();
        // The constant is scaled to bytes without wrapping, as in Ghidra.
        let highest = 0xffff_ffffu64 * word_size as u64;
        let points: Vec<u64> = db.split_points().map(|(a, _, _)| a.offset()).collect();
        if word_size == 1 {
            // At the top of the space the change-point form is used: one split.
            assert_eq!(points, [highest]);
        }
        assert_eq!(db.variable(&var, ram(&lang, highest)), 7);

        let mut db = lang.initial_context();
        decoder.prepare(ram(&lang, 0x40), &SliceBytes::new(0x40, &[3]), &mut db).unwrap();
        assert_eq!(db.variable(&var, ram(&lang, 0x41)), 7);
        assert_eq!(db.variable(&var, ram(&lang, 0x42)), 0, "no flow");
    }
    let _ = SpaceId::new(0);
}
