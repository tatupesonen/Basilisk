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
//! Spec 6, test 7: the opcode property table.
//!
//! * (G) against Ghidra's `TypeOp*` constructors in `typeop.cc`: the name,
//!   `opflags` and `addlflags` each constructor sets, for every opcode;
//! * (S) against the ops of the checked-in dumps (and, in `corpus.rs`, of
//!   the whole capture): each op's `setOpcode`-owned flag bits are the
//!   table's up to Ghidra's later marks (`support/opflags.rs`);
//! * `op_semantics` is total (unit test in `semantics.rs`).

mod support;

use std::collections::BTreeMap;

use bk_decomp_ir::flags::oflags;
use bk_decomp_ir::props::{addl, props};
use bk_pcode::OpCode;
use bk_testkit::oracle::{StateDump, read_text, sample_dir};
use bk_testkit::require_ghidra;

fn op_flag(name: &str) -> u32 {
    match name {
        "unary" => oflags::UNARY,
        "binary" => oflags::BINARY,
        "ternary" => oflags::TERNARY,
        "special" => oflags::SPECIAL,
        "nocollapse" => oflags::NOCOLLAPSE,
        "branch" => oflags::BRANCH,
        "call" => oflags::CALL,
        "returns" => oflags::RETURNS,
        "coderef" => oflags::CODEREF,
        "commutative" => oflags::COMMUTATIVE,
        "booloutput" => oflags::BOOLOUTPUT,
        "marker" => oflags::MARKER,
        "has_callspec" => oflags::HAS_CALLSPEC,
        "return_copy" => oflags::RETURN_COPY,
        other => panic!("unknown PcodeOp flag {other}"),
    }
}

fn addl_flag(name: &str) -> u32 {
    match name {
        "inherits_sign" => addl::INHERITS_SIGN,
        "inherits_sign_zero" => addl::INHERITS_SIGN_ZERO,
        "shift_op" => addl::SHIFT_OP,
        "arithmetic_op" => addl::ARITHMETIC_OP,
        "logical_op" => addl::LOGICAL_OP,
        "floatingpoint_op" => addl::FLOATINGPOINT_OP,
        "boolean_reorder" => addl::BOOLEAN_REORDER,
        other => panic!("unknown TypeOp flag {other}"),
    }
}

/// The value of `<field> = a | b | …;` in a constructor body (0 when the
/// constructor does not set it).
fn assigned(body: &str, field: &str, flag: fn(&str) -> u32) -> u32 {
    let Some((_, rest)) = body.split_once(&format!("{field} = ")) else {
        return 0;
    };
    let (expr, _) = rest.split_once(';').unwrap();
    expr.split('|')
        .map(|t| {
            let t = t.trim().trim_matches(|c| c == '(' || c == ')');
            flag(
                t.trim_start_matches("PcodeOp::")
                    .trim_start_matches("TypeOp::"),
            )
        })
        .fold(0, |a, b| a | b)
}

/// Every `TypeOp*` constructor of `typeop.cc`: opcode → (name, opflags,
/// addlflags). A definition starts at a line `TypeOpX::TypeOpX(` and its
/// body ends at the next line `}`.
fn constructors(src: &str) -> BTreeMap<String, (String, u32, u32)> {
    let mut out = BTreeMap::new();
    for def in src.split("\nTypeOp").skip(1) {
        let Some((head, after)) = def.split_once('{') else {
            continue;
        };
        let body = after.split_once("\n}").map_or(after, |(b, _)| b);
        let is_ctor = head
            .split_once("::")
            .is_some_and(|(cls, tail)| tail.starts_with(&format!("TypeOp{cls}(")));
        let Some((_, tail)) = head.split_once("CPUI_") else {
            continue;
        };
        if !is_ctor {
            continue;
        }
        let (opc, rest) = tail.split_once(',').unwrap();
        let (_, quoted) = rest.split_once('"').unwrap();
        let (name, _) = quoted.split_once('"').unwrap();
        out.insert(
            opc.to_owned(),
            (
                name.to_owned(),
                assigned(body, "opflags", op_flag),
                assigned(body, "addlflags", addl_flag),
            ),
        );
    }
    out
}

#[test]
fn table_equals_the_typeop_constructors() {
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let path = ghidra
        .root()
        .join("Ghidra/Features/Decompiler/src/decompile/cpp/typeop.cc");
    let src = std::fs::read_to_string(&path).unwrap();
    let ctors = constructors(&src);
    let mut checked = 0;
    let mut bad = Vec::new();
    for opc in OpCode::ALL {
        // The CPUI_ name: the mnemonic (`get_opname` gives the SLEIGH
        // directive for four slots), with `FLOAT_` for the conversions.
        let m = opc.mnemonic();
        let Some((name, flags, addlflags)) =
            ctors.get(m).or_else(|| ctors.get(&format!("FLOAT_{m}")))
        else {
            bad.push(format!("{m}: no constructor in typeop.cc"));
            continue;
        };
        checked += 1;
        let p = props(opc);
        if p.name != name || p.flags != *flags || p.addl != *addlflags {
            bad.push(format!(
                "{m}: ours {:?} {:#x} {:#x}, typeop.cc {name:?} {flags:#x} {addlflags:#x}",
                p.name, p.flags, p.addl
            ));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(checked, OpCode::ALL.len());
    eprintln!("opcode table: {checked} opcodes equal to typeop.cc");
}

#[test]
fn dumped_ops_carry_the_tables_flags() {
    let mut seen = std::collections::BTreeSet::new();
    for point in ["p1", "p2", "p3", "p4", "end"] {
        let path = sample_dir().join(format!("switchind.{point}.state.gz"));
        let dump = StateDump::parse(&read_text(&path).unwrap()).unwrap();
        for o in &dump.ops {
            let opc = OpCode::from_name(&o.opcode).unwrap();
            assert!(
                support::opflags::table_explains(opc, o.flags),
                "{point} {:?} {} {:#x}",
                o.seq,
                o.opcode,
                o.flags
            );
            seen.insert(opc);
        }
    }
    assert!(seen.len() > 5);
}
