//! Port of Ghidra's `ghidra.program.model.lang.PcodeParserTest`
//! (`Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/program/model/lang/
//! PcodeParserTest.java`, `testCompilePcode`): a snippet compiled against
//! x86 32-bit with operands `in1` (0) and `in2` (1), checked op by op.
//! The test's literal temporaries are `uniqueBase + n·0x100` (Java's step),
//! so the allocator is given step 0x100.
//!
//! It runs on the reference `x86.sla` when present, and always on the
//! fixture language, whose registers sit at x86's offsets.

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
use bk_sla::{ConstTpl, HandleSelect, Sla, VarnodeTpl};
use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler, TempAllocator};

const BODY: &str = "tmp:1 = inst_next;\nif (AX == 0) goto inst_next;\n\
tmp2:1 = inst_next2;\nif (BX == 0) goto inst_next2;\n\
call [ECX];\nif (BX != 1) goto <lab>;\nCX = 0;\n<lab>\n\
BX = CX << 2;\nin1 = in2 + 7;";

fn space(sla: &Sla, name: &str) -> ConstTpl {
    if name == "const" {
        return ConstTpl::Space(0);
    }
    let index = sla
        .space_records()
        .iter()
        .find(|s| sla.text(s.name) == name)
        .map(|s| s.index)
        .expect("space");
    ConstTpl::Space(index)
}

fn vn(space: ConstTpl, offset: ConstTpl, size: ConstTpl) -> VarnodeTpl {
    VarnodeTpl {
        space,
        offset,
        size,
    }
}

fn handle(index: u32, select: HandleSelect) -> ConstTpl {
    ConstTpl::Handle {
        index,
        select,
        plus: 0,
    }
}

fn check(sla: &Sla) {
    let compiler = SnippetCompiler::new(sla, &Options::default());
    let unique_base = TempAllocator::for_injection(sla.header().unique_base).next;
    let mut temps = TempAllocator {
        next: unique_base,
        step: 0x100,
    };
    let params = [Parameter::new("in1", 0), Parameter::new("in2", 1)];
    let compiled = compiler
        .compile(BODY, &params, &mut temps)
        .expect("compiles");
    let t = compiled.template.as_ref();
    assert_eq!(compiled.warnings, Vec::<String>::new());
    assert!(t.result().is_none());
    assert_eq!(t.header().labels, 1);
    let ops = t.ops();
    assert_eq!(ops.len(), 13);

    let real = |v: u64| ConstTpl::Real(v);
    let unique = |n: u64| {
        vn(
            space(sla, "unique"),
            real(u64::from(unique_base) + n * 0x100),
            real(1),
        )
    };
    let reg = |off: u64, size: u64| vn(space(sla, "register"), real(off), real(size));
    let konst = |v: u64, size: u64| vn(space(sla, "const"), real(v), real(size));
    let jump = |offset: ConstTpl| vn(ConstTpl::CurSpace, offset, ConstTpl::CurSpaceSize);
    let expected: [(OpCode, Option<VarnodeTpl>, Vec<VarnodeTpl>); 13] = [
        (
            OpCode::Copy,
            Some(unique(0)),
            vec![vn(space(sla, "const"), ConstTpl::Next, real(1))],
        ),
        (
            OpCode::IntEqual,
            Some(unique(1)),
            vec![reg(0, 2), konst(0, 2)],
        ),
        (OpCode::CBranch, None, vec![jump(ConstTpl::Next), unique(1)]),
        (
            OpCode::Copy,
            Some(unique(2)),
            vec![vn(space(sla, "const"), ConstTpl::Next2, real(1))],
        ),
        (
            OpCode::IntEqual,
            Some(unique(3)),
            vec![reg(0xc, 2), konst(0, 2)],
        ),
        (
            OpCode::CBranch,
            None,
            vec![jump(ConstTpl::Next2), unique(3)],
        ),
        (OpCode::CallInd, None, vec![reg(4, 4)]),
        (
            OpCode::IntNotEqual,
            Some(unique(4)),
            vec![reg(0xc, 2), konst(1, 2)],
        ),
        (
            OpCode::CBranch,
            None,
            vec![
                vn(space(sla, "const"), ConstTpl::Relative(0), real(4)),
                unique(4),
            ],
        ),
        (OpCode::Copy, Some(reg(4, 2)), vec![konst(0, 2)]),
        // The label directive (`PTRADD`).
        (OpCode::PtrAdd, None, vec![konst(0, 4)]),
        (
            OpCode::IntLeft,
            Some(reg(0xc, 2)),
            vec![reg(4, 2), konst(2, 4)],
        ),
        (
            OpCode::IntAdd,
            Some(vn(
                handle(0, HandleSelect::Space),
                handle(0, HandleSelect::Offset),
                handle(0, HandleSelect::Size),
            )),
            vec![
                vn(
                    handle(1, HandleSelect::Space),
                    handle(1, HandleSelect::Offset),
                    handle(1, HandleSelect::Size),
                ),
                vn(space(sla, "const"), real(7), handle(0, HandleSelect::Size)),
            ],
        ),
    ];
    for (i, (op, (opcode, output, inputs))) in ops.iter().zip(expected).enumerate() {
        assert_eq!(op.opcode, opcode, "op {i}");
        assert_eq!(t.output(op).copied(), output, "op {i} output");
        assert_eq!(t.inputs(op), inputs.as_slice(), "op {i} inputs");
    }
    // Seven temporaries: the two named ones, the three comparisons, and the
    // results of `<<` and `+` (replaced by the assignment targets but
    // allocated all the same).
    assert_eq!(temps.next, unique_base + 7 * 0x100);
}

#[test]
fn compile_pcode_on_the_fixture() {
    check(&common::fixture::sla());
}

#[test]
fn compile_pcode_on_x86() {
    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    let Some(sla) = common::reference_sla(&reference, "x86", "x86") else {
        return;
    };
    check(&sla);
}
