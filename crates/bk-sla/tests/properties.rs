//! Property tests (`features/sla.md` section 6): generated models round-trip
//! through both forms; arbitrary and damaged input never panics.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

mod common;

use bk_pcode::OpCode;
use bk_sla::{
    BlockDef, ConstTpl, ConstructorDef, DecisionDef, Expr, Field, HandleSelect, Header, Limits,
    MaskWord, Operand, PairDef, PatternDef, PrintDef, Sla, SlaBuilder, SpaceDef, SpaceKind,
    SymbolDef, SymbolId, TableDef, Template, VarnodeTpl,
};
use proptest::prelude::*;

/// What a generated constructor holds.
#[derive(Clone, Debug)]
struct CtorSpec {
    operands: usize,
    print: Vec<(bool, String)>,
    ops: Vec<(u8, bool, Vec<(u8, u64)>)>,
    labels: i32,
}

#[derive(Clone, Debug)]
struct ModelSpec {
    big_endian: bool,
    unique_base: u32,
    registers: Vec<(u64, i32)>,
    ctors: Vec<CtorSpec>,
    tree: TreeSpec,
}

#[derive(Clone, Debug)]
enum TreeSpec {
    Leaf(Vec<(u32, u8, Vec<(u32, u32)>, i32)>),
    Node(u8, i32, Vec<TreeSpec>),
}

fn text() -> impl Strategy<Value = String> {
    "[ -~\u{e9}\u{4e2d}]{0,6}"
}

fn tree(depth: u32) -> BoxedStrategy<TreeSpec> {
    let leaf = proptest::collection::vec(
        (
            0u32..4,
            0u8..3,
            proptest::collection::vec((any::<u32>(), any::<u32>()), 0..3),
            0i32..8,
        ),
        0..3,
    )
    .prop_map(TreeSpec::Leaf);
    if depth == 0 {
        return leaf.boxed();
    }
    prop_oneof![
        leaf,
        (1u8..3, 0i32..16).prop_flat_map(move |(size, start)| {
            proptest::collection::vec(tree(depth - 1), 1usize << size)
                .prop_map(move |children| TreeSpec::Node(size, start, children))
        })
    ]
    .boxed()
}

fn model_spec() -> impl Strategy<Value = ModelSpec> {
    let ctor = (
        0usize..4,
        proptest::collection::vec((any::<bool>(), text()), 0..5),
        proptest::collection::vec(
            (
                0u8..72,
                any::<bool>(),
                proptest::collection::vec((0u8..9, any::<u64>()), 0..4),
            ),
            0..5,
        ),
        0i32..3,
    )
        .prop_map(|(operands, print, ops, labels)| CtorSpec {
            operands,
            print,
            ops,
            labels,
        });
    (
        any::<bool>(),
        any::<u32>(),
        proptest::collection::vec((any::<u64>(), 1i32..16), 1..4),
        proptest::collection::vec(ctor, 4..6),
        tree(2),
    )
        .prop_map(
            |(big_endian, unique_base, registers, ctors, tree)| ModelSpec {
                big_endian,
                unique_base,
                registers,
                ctors,
                tree,
            },
        )
}

fn constant(kind: u8, value: u64, operands: usize, labels: i32) -> ConstTpl {
    match kind {
        0 => ConstTpl::Real(value),
        1 if operands > 0 => ConstTpl::Handle {
            index: (value % operands as u64) as u32,
            select: HandleSelect::from_number((value % 4) as i64).unwrap(),
            plus: if value % 4 == 3 { value >> 8 } else { 0 },
        },
        2 => ConstTpl::Space((value % 4) as u32),
        3 if labels > 0 => ConstTpl::Relative(value % labels as u64),
        4 => ConstTpl::Start,
        5 => ConstTpl::Next,
        6 => ConstTpl::CurSpace,
        7 => ConstTpl::FlowDest,
        _ => ConstTpl::Real(value >> 3),
    }
}

fn lower_tree(spec: &TreeSpec, ctors: u32) -> DecisionDef {
    match spec {
        TreeSpec::Leaf(pairs) => DecisionDef {
            number: pairs.len() as i32,
            pairs: pairs
                .iter()
                .map(|(ct, kind, words, offset)| {
                    let block = BlockDef {
                        offset: *offset,
                        nonzero: (words.len() * 4) as i32,
                        words: words
                            .iter()
                            .map(|&(mask, value)| MaskWord { mask, value })
                            .collect(),
                    };
                    let pattern = match kind {
                        0 => PatternDef::Instruction(block),
                        1 => PatternDef::Context(block),
                        _ => PatternDef::Combine(block.clone(), block),
                    };
                    PairDef {
                        constructor: ct % ctors,
                        pattern,
                    }
                })
                .collect(),
            ..DecisionDef::default()
        },
        TreeSpec::Node(size, start, children) => DecisionDef {
            number: 0,
            context: *start % 2 == 0,
            start_bit: *start,
            size: *size,
            pairs: vec![],
            children: children.iter().map(|c| lower_tree(c, ctors)).collect(),
        },
    }
}

fn build(spec: &ModelSpec) -> Sla {
    let mut b = SlaBuilder::new(Header {
        big_endian: spec.big_endian,
        unique_base: spec.unique_base,
        ..Header::default()
    });
    b.source_file("gen.sinc");
    let space = |kind, name: &str, index, size| SpaceDef {
        kind,
        name: name.to_owned(),
        index,
        big_endian: spec.big_endian,
        delay: i32::from(kind == SpaceKind::Processor && index == 3),
        size,
        word_size: 1,
        physical: true,
    };
    b.space(space(SpaceKind::Other, "OTHER", 1, 8));
    b.space(space(SpaceKind::Unique, "unique", 2, 4));
    b.space(space(SpaceKind::Processor, "ram", 3, 8));
    b.default_space("ram");
    let global = b.scope(None);
    let root = b.symbol("instruction", global, SymbolDef::Start);
    let first_register = SymbolId::new(1);
    for (i, &(offset, size)) in spec.registers.iter().enumerate() {
        b.symbol(
            &format!("r{i}"),
            global,
            SymbolDef::Varnode {
                space: 3,
                offset,
                size,
            },
        );
    }
    let field = b.field(Field {
        big_endian: spec.big_endian,
        sign_bit: false,
        start_bit: 0,
        end_bit: 3,
        start_byte: 0,
        end_byte: 0,
        shift: 0,
    });
    let mut ctors = Vec::new();
    for (ct, c) in spec.ctors.iter().enumerate() {
        let scope = b.scope(Some(global));
        let mut operands = Vec::new();
        for index in 0..c.operands {
            let local = b.expr(Expr::Operand {
                index: index as i32,
                table: root,
                ct: ct as u32,
            });
            let (defining_symbol, defining_expr) = if index % 2 == 0 {
                (Some(first_register), None)
            } else {
                (None, Some(b.expr(Expr::TokenField(field))))
            };
            operands.push(b.symbol(
                &format!("op{index}"),
                scope,
                SymbolDef::Operand(Operand {
                    index: index as i32,
                    offset: 0,
                    base: -1,
                    min_length: 0,
                    code: false,
                    defining_symbol,
                    local_expr: local,
                    defining_expr,
                }),
            ));
        }
        let mut template = Template::new();
        template.set_header(None, 0, c.labels);
        for (opcode, output, inputs) in &c.ops {
            let opcode = OpCode::from_u8(*opcode).filter(|op| {
                !matches!(
                    op,
                    OpCode::MultiEqual | OpCode::Indirect | OpCode::PtrAdd | OpCode::PtrSub
                )
            });
            let Some(opcode) = opcode else { continue };
            let vn = |k: u8, v: u64| VarnodeTpl {
                space: ConstTpl::Space(3),
                offset: constant(k, v, c.operands, c.labels),
                size: constant(k.wrapping_add(1), v.rotate_left(7), c.operands, c.labels),
            };
            let out = output.then(|| vn(0, 0x40));
            let ins: Vec<_> = inputs.iter().map(|&(k, v)| vn(k, v)).collect();
            template.push_op(opcode, out, &ins);
        }
        let print = c
            .print
            .iter()
            .map(|(op, text)| {
                if *op && c.operands > 0 {
                    PrintDef::Operand((text.len() % c.operands) as i32)
                } else {
                    PrintDef::Text(text.clone())
                }
            })
            .collect::<Vec<_>>();
        ctors.push(ConstructorDef {
            first: -1,
            length: 1,
            source: 0,
            line: ct as i32,
            operands,
            print,
            context: vec![],
            templates: vec![template],
        });
    }
    let count = ctors.len() as u32;
    b.set_symbol(
        root,
        SymbolDef::Subtable(TableDef {
            constructors: ctors,
            decision: lower_tree(&spec.tree, count),
        }),
    );
    b.finish().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn generated_models_round_trip(spec in model_spec()) {
        let sla = build(&spec);
        let limits = Limits::default();
        let packed = sla.encode_packed().unwrap();
        let back = Sla::decode_packed(&packed, &limits).unwrap();
        prop_assert_eq!(&back, &sla);
        prop_assert_eq!(back.encode_packed().unwrap(), packed);
        let xml = sla.encode_xml().unwrap();
        let back = Sla::decode_xml(&xml, &limits).unwrap();
        prop_assert_eq!(&back, &sla);
        prop_assert_eq!(back.encode_xml().unwrap(), xml);
        prop_assert_eq!(Sla::read(&sla.write().unwrap(), &limits).unwrap(), sla);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let limits = Limits::default();
        let _ = Sla::read(&bytes, &limits);
        let _ = Sla::decode_packed(&bytes, &limits);
        let _ = Sla::decode_xml(&String::from_utf8_lossy(&bytes), &limits);
        let mut file = b"sla\x04".to_vec();
        file.extend_from_slice(&bytes);
        let _ = Sla::read(&file, &limits);
    }

    #[test]
    fn damaged_streams_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8)) {
        let limits = Limits::default();
        let mut stream = common::full_model().encode_packed().unwrap();
        for (at, byte) in flips {
            let len = stream.len();
            stream[at % len] = byte;
        }
        if let Ok(sla) = Sla::decode_packed(&stream, &limits) {
            // Whatever decodes also re-encodes and decodes to the same model.
            let again = Sla::decode_packed(&sla.encode_packed().unwrap(), &limits).unwrap();
            prop_assert_eq!(again, sla);
        }
        let _ = Sla::decode_packed_using(&stream, &limits, bk_sla::PackedReader::Marshal);
    }

    #[test]
    fn damaged_xml_never_panics(cut in any::<usize>(), insert in "[<>/a-z=\" 0-9]{0,12}") {
        let xml = common::full_model().encode_xml().unwrap();
        let mut at = cut % xml.len();
        while !xml.is_char_boundary(at) {
            at -= 1;
        }
        let damaged = format!("{}{insert}{}", &xml[..at], &xml[at..]);
        let _ = Sla::decode_xml(&damaged, &Limits::default());
    }
}
