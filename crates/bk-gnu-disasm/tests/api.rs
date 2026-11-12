//! The safe API: names, undecodable and truncated bytes, blocks, options,
//! instruction information, sequence state, threads.

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
#![cfg(not(windows))]

mod common;

use bk_gnu_disasm::{
    Architecture, BlockEnd, Disassembler, Endian, Error, InstructionKind, is_available,
};

fn dis(name: &str, endian: Endian, options: Option<&str>) -> Disassembler {
    Disassembler::new(&Architecture::from_gnu_name(name).unwrap(), endian, options).unwrap()
}

fn texts(d: &mut Disassembler, bytes: &[u8], address: u64) -> Vec<(usize, String)> {
    d.block(bytes, address)
        .unwrap()
        .instructions
        .into_iter()
        .map(|i| (i.length, i.text))
        .collect()
}

#[test]
fn binutils_is_available() {
    assert!(is_available());
}

#[test]
fn names_resolve_as_gdis_resolves_them() {
    let a = Architecture::from_gnu_name("i386:x86-64").unwrap();
    assert_eq!(a.info().unwrap().printable_name, "i386:x86-64");
    // An alias bfd_scan_arch accepts, which gdis (exact list match) would not.
    let a = Architecture::from_gnu_name("tic4x").unwrap();
    assert_eq!(a.info().unwrap().printable_name, "tms320c4x");
    // Listed, but binutils cannot look these up by name; gdis crashes.
    for name in ["tms320c4x", "tms320c3x"] {
        assert_eq!(
            Architecture::from_gnu_name(name),
            Err(Error::UnresolvableArchitecture {
                name: name.to_owned()
            })
        );
    }
    let Err(Error::UnknownArchitecture { name, available }) =
        Architecture::from_gnu_name("no-such-cpu")
    else {
        panic!("expected an unknown architecture");
    };
    assert_eq!(name, "no-such-cpu");
    assert!(available.iter().any(|n| n == "aarch64"));
    assert!(available.len() > 400);
}

#[test]
fn an_unknown_architecture_number_has_no_disassembler() {
    let error = Disassembler::new(&Architecture::from_numbers(0xffff, 0), Endian::Little, None)
        .unwrap_err();
    assert_eq!(
        error,
        Error::Raw(bk_gnu_disasm::RawError::NoDisassembler {
            arch: 0xffff,
            mach: 0
        })
    );
}

#[test]
fn x86_64_in_att_and_intel_syntax() {
    let code = [0x55, 0x48, 0x89, 0xe5, 0x8b, 0x45, 0xfc, 0xc3];
    let mut att = dis("i386:x86-64", Endian::Little, None);
    assert_eq!(
        texts(&mut att, &code, 0x1000),
        [
            (1, "push   %rbp".to_owned()),
            (3, "mov    %rsp,%rbp".to_owned()),
            (3, "mov    -0x4(%rbp),%eax".to_owned()),
            (1, "ret".to_owned()),
        ]
    );
    let mut intel = dis("i386:x86-64", Endian::Little, Some("intel"));
    assert_eq!(
        texts(&mut intel, &code, 0x1000)[2],
        (3, "mov    eax,DWORD PTR [rbp-0x4]".to_owned())
    );
}

#[test]
fn undecodable_bytes_are_an_instruction_with_binutils_text() {
    // 0x06 (push %es) does not exist in 64-bit mode.
    let mut d = dis("i386:x86-64", Endian::Little, None);
    let insn = d.instruction(&[0x06, 0x90], 0).unwrap();
    assert_eq!((insn.length, insn.text.as_str()), (1, "(bad)"));
    assert_eq!(insn.read_fault, None);
}

#[test]
fn a_truncated_instruction_at_the_end() {
    // x86: "mov $imm32,%eax" with two of its five bytes. binutils prints the
    // first byte as data and records the refused read.
    let mut x86 = dis("i386:x86-64", Endian::Little, None);
    let insn = x86.instruction(&[0xb8, 0x01], 0x2000).unwrap();
    assert_eq!((insn.length, insn.text.as_str()), (1, ".byte 0xb8"));
    assert_eq!(insn.read_fault, Some(0x2001));

    // AArch64 needs four bytes: no instruction.
    let mut a64 = dis("aarch64", Endian::Little, None);
    assert_eq!(
        a64.instruction(&[0x1f, 0x20], 0x3000),
        Err(Error::NoInstruction {
            address: 0x3000,
            returned: -1,
            read_fault: Some(0x3000)
        })
    );
    // In a block, disassembly stops there, after what was decoded.
    let block = a64
        .block(&[0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20], 0x3000)
        .unwrap();
    assert_eq!(block.instructions.len(), 1);
    assert_eq!(block.instructions[0].text, "nop");
    assert_eq!(
        block.end,
        BlockEnd::NoInstruction {
            offset: 4,
            returned: -1,
            read_fault: Some(0x3004)
        }
    );
}

#[test]
fn offsets_outside_the_bytes_are_errors() {
    let mut d = dis("i386:x86-64", Endian::Little, None);
    assert_eq!(
        d.instruction(&[], 0),
        Err(Error::OffsetOutOfRange { offset: 0, len: 0 })
    );
    assert_eq!(
        d.instruction_at(&[0x90], 0, 1),
        Err(Error::OffsetOutOfRange { offset: 1, len: 1 })
    );
    let block = d.block(&[], 0).unwrap();
    assert!(block.instructions.is_empty());
    assert_eq!(block.end, BlockEnd::Complete);
}

#[test]
fn branch_targets_and_kinds() {
    // x86-64 "call +0" and "jne +0x10".
    let mut d = dis("i386:x86-64", Endian::Little, None);
    let block = d.block(&[0xe8, 0, 0, 0, 0, 0x75, 0x10], 0x1000).unwrap();
    let call = block.instructions[0].info.unwrap();
    assert_eq!((call.kind, call.target), (InstructionKind::Call, 0x1005));
    let jne = block.instructions[1].info.unwrap();
    assert_eq!(
        (jne.kind, jne.target),
        (InstructionKind::ConditionalBranch, 0x1017)
    );
}

#[test]
fn delay_slots_on_mips_and_sparc() {
    // MIPS big-endian "jal 0x40" (0c000010) then "nop".
    let mut mips = dis("mips:4000", Endian::Big, None);
    let block = mips.block(&[0x0c, 0, 0, 0x10, 0, 0, 0, 0], 0).unwrap();
    let jal = &block.instructions[0];
    assert_eq!(jal.text, "jal\t0x00000040");
    let info = jal.info.unwrap();
    assert_eq!(
        (info.kind, info.branch_delay_insns, info.target),
        (InstructionKind::Call, 1, 0x40)
    );
    // Little-endian: the same instruction, bytes reversed.
    let mut mipsel = dis("mips:4000", Endian::Little, None);
    assert_eq!(
        mipsel.instruction(&[0x10, 0, 0, 0x0c], 0).unwrap().text,
        "jal\t0x00000040"
    );

    // SPARC "call .+16" (40000004) then "nop" (01000000).
    let mut sparc = dis("sparc:v9b", Endian::Big, None);
    let block = sparc
        .block(&[0x40, 0, 0, 0x04, 0x01, 0, 0, 0], 0x2000)
        .unwrap();
    let call = block.instructions[0].info.unwrap();
    assert_eq!(
        (call.kind, call.branch_delay_insns, call.target),
        (InstructionKind::Call, 1, 0x2010)
    );
    // SPARC prints a trailing space, which Ghidra's form trims.
    assert_eq!(block.instructions[1].text, "nop ");
    assert_eq!(block.instructions[1].ghidra_text(), "nop");
}

#[test]
fn ghidra_shows_the_text_with_spaces_trimmed() {
    let mut d = dis("aarch64", Endian::Little, None);
    let insn = d.instruction(&[0xfd, 0x7b, 0xbf, 0xa9], 0).unwrap();
    assert_eq!(insn.text, "stp\tx29, x30, [sp, #-16]!");
    assert_eq!(insn.ghidra_text(), "stp x29, x30, [sp, #-16]!");
}

#[test]
fn it_blocks_carry_within_a_call_and_can_be_given_as_context() {
    // Thumb: nop; it eq; movs r0, #1 (moveq inside the IT block).
    let code = [0x00, 0xbf, 0x08, 0xbf, 0x01, 0x20];
    let mut d = dis("armv7", Endian::Little, Some("force-thumb"));
    let block = d.block(&code, 0x1000).unwrap();
    assert_eq!(block.instructions[2].text, "moveq\tr0, #1");
    // One instruction, with the bytes before it as context.
    assert_eq!(
        d.instruction_at(&code, 0x1000, 4).unwrap().text,
        "moveq\tr0, #1"
    );
    // Without them, a fresh call does not know it is in an IT block, even
    // straight after a call that ended inside one.
    let _ = d.block(&code[..4], 0x1000).unwrap();
    assert_eq!(
        d.instruction(&code[4..], 0x1004).unwrap().text,
        "movs\tr0, #1"
    );
}

#[test]
fn instruction_at_hands_binutils_a_window_and_widens_it_when_needed() {
    let mut code = common::noise(4096, 3);
    // An x86 "nop" deep inside, then a 15-byte instruction whose bytes all
    // lie within the window.
    code[3000] = 0x90;
    let mut d = dis("i386:x86-64", Endian::Little, None);
    let insn = d.instruction_at(&code, 0x40_0000, 3000).unwrap();
    assert_eq!(
        (insn.address, insn.length, insn.text.as_str()),
        (0x40_0bb8, 1, "nop")
    );
    // The same instruction decoded from the whole slice or a window agrees.
    for offset in [0, 100, 2000, 4000, 4095] {
        let windowed = d.instruction_at(&code, 0, offset);
        let tail = d.instruction_at(&code[offset..], offset as u64, 0);
        assert_eq!(windowed, tail, "offset {offset}");
    }
}

#[test]
fn options_reported_by_accessors() {
    let d = dis("arm", Endian::Big, Some("reg-names-raw"));
    assert_eq!(d.options(), Some("reg-names-raw"));
    assert_eq!(d.endian(), Endian::Big);
    assert_eq!(d.architecture().name(), "arm");
}

#[test]
fn disassemblers_work_from_several_threads() {
    let workers: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                let (name, code, text) = if i % 2 == 0 {
                    ("i386:x86-64", vec![0x48, 0x89, 0xe5], "mov    %rsp,%rbp")
                } else {
                    ("riscv:rv64", vec![0x13, 0x00, 0x00, 0x00], "nop")
                };
                let mut d = dis(name, Endian::Little, None);
                for _ in 0..300 {
                    assert_eq!(d.instruction(&code, 0).unwrap().text, text);
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
}

#[test]
fn disassemblers_are_send() {
    fn is_send<T: Send>() {}
    is_send::<Disassembler>();
}
