//! The tool wrappers against the real reference tools.
//!
//! Skipped when `../reference` (or `BASILISK_REFERENCE_DIR`) has not been
//! built by `scripts/build-reference.sh`.

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

use bk_testkit::tools::{DumpErrorKind, LiftErrorKind, ToolError, parse_dump};
use bk_testkit::{Tool, read_data_test};

/// x86-64: push rbp; mov rbp,rsp; mov eax,[rbp-4]; add eax,1; pop rbp; ret;
/// ud2; one byte that is no instruction in 64-bit mode; a truncated call.
const X86_64_BYTES: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x01, 0x5d, 0xc3, 0x0f, 0x0b, 0x06, 0xe8,
    0x00,
];

/// ARM (little endian): push {r11,lr}; add r11,sp,#4; mov r0,#42; pop {r11,pc}.
const ARM_BYTES: &[u8] = &[
    0x00, 0x48, 0x2d, 0xe9, 0x04, 0xb0, 0x8d, 0xe2, 0x2a, 0x00, 0xa0, 0xe3, 0x00, 0x88, 0xbd, 0xe8,
];

/// Thumb: push {r7,lr}; add r7,sp,#0; bx lr.
const THUMB_BYTES: &[u8] = &[0x80, 0xb5, 0x00, 0xaf, 0x70, 0x47];

/// MIPS (big endian): jal 0x400000 with `addiu sp,sp,-32` in its delay slot.
const MIPS_BYTES: &[u8] = &[0x0c, 0x10, 0x00, 0x00, 0x27, 0xbd, 0xff, 0xe0];

#[test]
fn sleigh_compiles_a_toy_specification() {
    let Some(reference) = bk_testkit::require_tool(Tool::Sleigh) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let out = tempfile::tempdir().unwrap();
    let sla = out.path().join("toy_be.sla");
    let spec = ghidra.language_dir("Toy").join("toy_be.slaspec");

    let output = reference.sleigh().compile(&spec, &sla).unwrap();
    assert!(output.success());
    let compiled = std::fs::read(&sla).unwrap();
    assert!(
        compiled.starts_with(b"sla\x04"),
        "a version-4 .sla: {:?}",
        &compiled[..4]
    );

    // The compiler is deterministic: the overlay's copy, built by the script
    // from the same source, is byte for byte the same.
    let overlay = std::fs::read(reference.sla_file("Toy", "toy_be")).unwrap();
    assert_eq!(compiled, overlay);

    // Nothing was written beside the specification.
    assert!(!ghidra.language_dir("Toy").join("toy_be.sla").exists());
}

#[test]
fn sleigh_reports_a_specification_that_does_not_compile() {
    let Some(reference) = bk_testkit::require_tool(Tool::Sleigh) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("broken.slaspec");
    std::fs::write(&spec, "define endian=big;\nthis is not sleigh\n").unwrap();

    let error = reference
        .sleigh()
        .compile(&spec, &dir.path().join("broken.sla"))
        .unwrap_err();
    let ToolError::Failed {
        tool,
        code,
        stdout,
        stderr,
    } = &error
    else {
        panic!("expected a failed compile, got {error:?}");
    };
    assert_eq!(*tool, Tool::Sleigh);
    assert_ne!(*code, Some(0));
    assert!(
        format!("{stdout}{stderr}").contains("broken.slaspec"),
        "the compiler's message is kept: {error}"
    );
    assert!(!dir.path().join("broken.sla").exists());
}

#[test]
fn pcodedump_decodes_x86_64() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    let dump = reference
        .pcodedump()
        .dump("x86:LE:64:default", 0x1000, X86_64_BYTES)
        .unwrap();
    assert_eq!(dump.language, "x86:LE:64:default");
    assert_eq!((dump.space.as_str(), dump.base), ("ram", 0x1000));
    assert_eq!(dump.byte_count, X86_64_BYTES.len() as u64);

    let listing: Vec<_> = dump
        .instructions()
        .map(|i| (i.address, i.length, i.mnemonic.as_str(), i.body.as_str()))
        .collect();
    assert_eq!(
        listing,
        [
            (0x1000, 1, "PUSH", "RBP"),
            (0x1001, 3, "MOV", "RBP,RSP"),
            (0x1004, 3, "MOV", "EAX,dword ptr [RBP + -0x4]"),
            (0x1007, 3, "ADD", "EAX,0x1"),
            (0x100a, 1, "POP", "RBP"),
            (0x100b, 1, "RET", ""),
            (0x100c, 2, "UD2", ""),
        ]
    );

    // Instructions tile the input: each starts where the last one ended and
    // carries exactly its own bytes.
    for instruction in dump.instructions() {
        let start = (instruction.address - dump.base) as usize;
        let end = start + instruction.length as usize;
        assert_eq!(instruction.bytes, X86_64_BYTES[start..end]);
        assert_eq!(
            instruction.flow_length, instruction.length,
            "x86 has no delay slots"
        );
        assert!(instruction.lift_error.is_none());
    }

    // mov rbp,rsp is one COPY between named registers.
    let mov = dump.instructions().nth(1).unwrap();
    assert_eq!(mov.pcode.len(), 1);
    let copy = &mov.pcode[0];
    assert_eq!(copy.opcode, "COPY");
    let output = copy.output.as_ref().unwrap();
    assert_eq!(
        (output.space.as_str(), output.size, output.name.as_deref()),
        ("register", 8, Some("RBP"))
    );
    assert_eq!(copy.inputs[0].name.as_deref(), Some("RSP"));

    // push rbp stores through a space-identifying constant.
    let push = dump.instructions().next().unwrap();
    let store = push.pcode.iter().find(|op| op.opcode == "STORE").unwrap();
    assert_eq!(store.output, None);
    assert_eq!(store.inputs[0].space, "const");
    assert_eq!(store.inputs[0].name.as_deref(), Some("ram"));

    // 0x06 (push es) does not exist in 64-bit mode; the call is cut off.
    let errors: Vec<_> = dump
        .errors()
        .map(|e| (e.address, e.length, e.kind))
        .collect();
    assert_eq!(
        errors,
        [
            (0x100e, 1, DumpErrorKind::BadData),
            (0x100f, 2, DumpErrorKind::Truncated)
        ]
    );
}

#[test]
fn pcodedump_decodes_arm_and_thumb() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    let arm = reference
        .pcodedump()
        .dump("ARM:LE:32:v8", 0x8000, ARM_BYTES)
        .unwrap();
    let mnemonics: Vec<_> = arm.instructions().map(|i| i.mnemonic.as_str()).collect();
    assert_eq!(mnemonics, ["stmdb", "add", "mov", "ldmia"]);
    assert!(arm.instructions().all(|i| i.length == 4));
    assert_eq!(arm.errors().count(), 0);

    // The same language decodes Thumb when the context says so.
    let thumb = reference
        .pcodedump()
        .context("TMode", 1)
        .dump("ARM:LE:32:v8", 0x8000, THUMB_BYTES)
        .unwrap();
    let listing: Vec<_> = thumb
        .instructions()
        .map(|i| (i.length, i.mnemonic.as_str(), i.body.as_str()))
        .collect();
    assert_eq!(
        listing,
        [
            (2, "push", "{r7,lr}"),
            (2, "add", "r7,sp,#0x0"),
            (2, "bx", "lr")
        ]
    );
}

#[test]
fn pcodedump_reports_delay_slots() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    let dump = reference
        .pcodedump()
        .dump("MIPS:BE:32:default", 0x40_0000, MIPS_BYTES)
        .unwrap();
    let listing: Vec<_> = dump
        .instructions()
        .map(|i| (i.mnemonic.as_str(), i.length, i.flow_length))
        .collect();
    // The jump's p-code covers its delay slot; the slot is also listed as an
    // instruction of its own, because the sweep advances by `length`.
    assert_eq!(listing, [("jal", 4, 8), ("addiu", 4, 4)]);
    let jal = dump.instructions().next().unwrap();
    assert!(
        jal.pcode.iter().any(|op| op.opcode == "INT_ADD"),
        "the slot's add is in the jump"
    );
    assert_eq!(jal.pcode.last().unwrap().opcode, "CALL");
}

#[test]
fn pcodedump_marks_unimplemented_instructions() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    // The Toy language has an instruction whose semantics are `unimpl`
    // (0xa800); 0xf400 is its `ret`.
    let dump = reference
        .pcodedump()
        .dump("Toy:BE:32:default", 0x100, &[0xa8, 0x00, 0xf4, 0x00])
        .unwrap();
    let instructions: Vec<_> = dump.instructions().collect();
    assert_eq!(instructions.len(), 2);

    assert_eq!(instructions[0].mnemonic, "unimpl");
    assert!(instructions[0].pcode.is_empty());
    let error = instructions[0].lift_error.as_ref().unwrap();
    assert_eq!(error.kind, LiftErrorKind::Unimplemented);
    assert!(
        error
            .message
            .starts_with("Instruction not implemented in pcode:\n"),
        "{error:?}"
    );

    // Decoding continues after it, and it is not a decode error.
    assert_eq!(
        (instructions[1].address, instructions[1].mnemonic.as_str()),
        (0x102, "ret")
    );
    assert_eq!(instructions[1].pcode.last().unwrap().opcode, "RETURN");
    assert_eq!(dump.errors().count(), 0);
}

#[test]
fn pcodedump_rejects_what_it_cannot_load() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    let error = reference
        .pcodedump()
        .dump("no:such:language", 0, &[0])
        .unwrap_err();
    let ToolError::Failed { code, stderr, .. } = &error else {
        panic!("{error:?}")
    };
    assert_eq!(*code, Some(1));
    assert!(stderr.contains("no:such:language"), "{stderr}");

    let error = reference
        .pcodedump()
        .context("NoSuchVariable", 1)
        .dump("x86:LE:64:default", 0, &[0x90])
        .unwrap_err();
    assert!(error.to_string().contains("NoSuchVariable"), "{error}");
}

#[test]
fn pcodedump_handles_empty_and_large_input() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    let empty = reference
        .pcodedump()
        .dump("x86:LE:64:default", 0, &[])
        .unwrap();
    assert!(empty.records.is_empty());

    // Enough output to fill the pipes many times over: 64 kB of nops.
    let nops = vec![0x90u8; 64_000];
    let dump = reference
        .pcodedump()
        .dump("x86:LE:64:default", 0x10_0000, &nops)
        .unwrap();
    assert_eq!(dump.instructions().count(), nops.len());
    assert_eq!(
        dump.instructions().last().unwrap().address,
        0x10_0000 + 63_999
    );
}

/// The listing format is a contract (`tools/reference/README.md`). An
/// `insta` snapshot pins the tool's text, and the same text goes through
/// the parser, so the tool, the parser and the documented format cannot
/// drift apart unnoticed.
#[test]
fn pcodedump_listing_matches_its_snapshot() {
    let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else {
        return;
    };
    let text = reference
        .pcodedump()
        .dump_text("x86:LE:64:default", 0x1000, X86_64_BYTES)
        .unwrap();

    let parsed = parse_dump(&text).unwrap();
    assert_eq!(parsed.instructions().count(), 7);
    assert_eq!(parsed.errors().count(), 2);
    assert_eq!(
        parsed.instructions().map(|i| i.pcode.len()).sum::<usize>(),
        27
    );

    insta::assert_snapshot!("pcodedump_x86_64", text);
}

#[test]
fn decomp_test_runs_one_data_test() {
    let Some(reference) = bk_testkit::require_tool(Tool::DecompTest) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let file = ghidra.data_tests_dir().join("deadvolatile.xml");
    let expected = read_data_test(&file).unwrap();

    let report = reference.decomp_test().run_data_test(&file).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.applied, expected.matches.len());
    // One outcome per <stringmatch>, in file order, under the same names.
    let reported: Vec<_> = report
        .checks
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    let declared: Vec<_> = expected
        .matches
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    assert_eq!(reported, declared);
    assert!(
        report.all_passed(),
        "{:?}",
        report.failures().collect::<Vec<_>>()
    );
    assert_eq!(report.output.code, Some(0));
}

#[test]
fn decomp_test_runs_named_unit_tests() {
    let Some(reference) = bk_testkit::require_tool(Tool::DecompTest) else {
        return;
    };
    let report = reference
        .decomp_test()
        .run_unit_tests(["float_opNan", "float_opNeg"])
        .unwrap();
    assert_eq!((report.passed, report.total), (2, 2));
    let names: Vec<_> = report.tests.iter().map(|test| test.name.as_str()).collect();
    assert_eq!(names.len(), 2);
    assert!(
        names.contains(&"float_opNan") && names.contains(&"float_opNeg"),
        "{names:?}"
    );
    assert_eq!(report.failures().count(), 0);
}

#[test]
fn decomp_runs_a_data_test_script_and_prints_c() {
    let Some(reference) = bk_testkit::require_tool(Tool::Decomp) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let test = read_data_test(&ghidra.data_tests_dir().join("floatprint.xml")).unwrap();
    let transcript = reference.decomp().run_data_test(&test).unwrap();

    // One step per command, after the load the wrapper adds.
    assert_eq!(transcript.steps.len(), test.script.len() + 1);
    assert!(transcript.steps[0].command.starts_with("load file "));
    assert!(transcript.steps[0].output.contains("successfully loaded"));

    let printed: Vec<_> = transcript.outputs_of("print C").collect();
    assert_eq!(printed.len(), 1);
    // Two of the lines this test's patterns look for (floatprint.xml).
    assert!(printed[0].contains("floatv2 = 2.0;"), "{}", printed[0]);
    assert!(printed[0].contains("floatv5 = INFINITY;"), "{}", printed[0]);
}

#[test]
fn decomp_reports_a_failing_script() {
    let Some(reference) = bk_testkit::require_tool(Tool::Decomp) else {
        return;
    };
    let error = reference
        .decomp()
        .run_script(["lo fu nosuchfunction"])
        .unwrap_err();
    let ToolError::Failed {
        tool, code, stdout, ..
    } = &error
    else {
        panic!("{error:?}")
    };
    assert_eq!((*tool, *code), (Tool::Decomp, Some(1)));
    assert!(stdout.contains("No image loaded"), "{stdout}");
}
