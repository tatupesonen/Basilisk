//! Golden disassembly across architectures (`insta` snapshots in
//! `snapshots/`), checked against GNU objdump of the same binutils.
//!
//! Each configuration disassembles some known instructions (where given)
//! and 64 bytes of seeded noise at address 0x10000. The snapshot holds, per
//! instruction, address, length, bytes, the text exactly as binutils
//! printed it, and the `Info:` fields gdis reports.
//!
//! Provenance: when `BK_GNU_OBJDUMP` names a GNU objdump built from
//! binutils 2.41 (the tag `binutils-2_41`), the test also runs
//! `objdump -D -z -w -b binary -m <arch> [-EB] [-M <options>]` over the
//! same bytes and requires the same instructions: same addresses and
//! lengths, and the same text once objdump's `<symbol+offset>` suffixes are
//! removed and `0x` numbers are compared without leading zeros (gdis'
//! address printer pads them, objdump's does not). Two differences between
//! gdis and `objdump -b binary` are expected and allowed for:
//!
//! * gdis prints a target address as the full 64-bit `bfd_vma`
//!   (`generic_print_address`), objdump cuts it to the architecture's
//!   address size: `0xffffffffffc4bb64` against `0xffc4bb64` on ARM;
//! * MIPS keeps the ISA-mode bit of jump targets only for a BFD of unknown
//!   flavour, which `-b binary` is and gdis' (PEF, here ELF) is not:
//!   `0x3db6924` against `0x3db6925`.
//!
//! Without objdump, only the snapshots are compared, and the reason is
//! printed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::format_collect,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]
#![cfg(not(windows))]

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use bk_gnu_disasm::{Architecture, Block, BlockEnd, Disassembler, Endian, Instruction};

const ADDRESS: u64 = 0x10000;

/// A golden configuration.
struct Case {
    /// Snapshot name.
    label: &'static str,
    /// GNU architecture name (for objdump's `-m` too).
    arch: &'static str,
    endian: Endian,
    options: Option<&'static str>,
    /// Known instructions, as hex.
    known: &'static str,
}

const fn case(
    label: &'static str,
    arch: &'static str,
    endian: Endian,
    options: Option<&'static str>,
    known: &'static str,
) -> Case {
    Case {
        label,
        arch,
        endian,
        options,
        known,
    }
}

use Endian::{Big as BE, Little as LE};

/// The spec's list, then every other architecture family behind a GNU name
/// in Ghidra's `.ldefs`. ARM is given as `arm`: gdis does not tell binutils
/// that the machine was chosen, so ARM ignores it (`armv4` decodes like
/// `arm`), while objdump `-m armv4` would honour it.
const CASES: &[Case] = &[
    case("i8086", "i8086", LE, None, "5589e58b4604c3"),
    case("i8086_intel", "i8086", LE, Some("intel"), "5589e58b4604c3"),
    case("i386", "i386", LE, None, "5589e58b4508e8000000005dc3"),
    case(
        "i386_intel",
        "i386:intel",
        LE,
        None,
        "5589e58b4508e8000000005dc3",
    ),
    case(
        "x86_64",
        "i386:x86-64",
        LE,
        None,
        "554889e5488b45f8e800000000c9c3",
    ),
    case(
        "x86_64_intel",
        "i386:x86-64",
        LE,
        Some("intel"),
        "554889e5488b45f8e800000000c9c3",
    ),
    case("arm", "arm", LE, None, "04e02de500d04de21eff2fe1"),
    case("arm_be", "arm", BE, None, "e52de004e24dd000e12fff1e"),
    case(
        "thumb",
        "arm",
        LE,
        Some("force-thumb"),
        "80b500af00bf08bf012080bd",
    ),
    case(
        "aarch64",
        "aarch64",
        LE,
        None,
        "fd7bbfa9fd030091e0031f2afd7bc1a8c0035fd6",
    ),
    case(
        "mips_be",
        "mips:4000",
        BE,
        None,
        "27bdffe8afbf00140c00001000000000",
    ),
    case("mips_le", "mips:4000", LE, None, "e8ffbd271400bfaf100000"),
    case("mips_micromips", "mips:micromips", BE, None, ""),
    case(
        "powerpc",
        "powerpc:common",
        BE,
        None,
        "9421fff07c0802a6480000054e800020",
    ),
    case(
        "powerpc64",
        "powerpc:common64",
        BE,
        None,
        "f821ff917c0802a64e800020",
    ),
    case("powerpc_e500", "powerpc:e500", BE, None, ""),
    case(
        "riscv32",
        "riscv:rv32",
        LE,
        None,
        "130101ff23261100ef0000006780000001000000",
    ),
    case(
        "riscv64",
        "riscv:rv64",
        LE,
        None,
        "130101ff233c1100ef00000067800000",
    ),
    case(
        "sparc",
        "sparc:v9b",
        BE,
        None,
        "9de3bfa0400000040100000081c7e00881e80000",
    ),
    case("m68k", "m68k", BE, None, "4e560000202e00084e5e4e75"),
    case("m68k_68020", "m68k:68020", BE, None, ""),
    case("avr", "avr:51", LE, None, "cf93df930e940000df91cf910895"),
    case("avr6", "avr:6", LE, None, ""),
    case("hppa", "hppa2.0w", BE, None, ""),
    case("loongarch64", "Loongarch64", LE, None, ""),
    case("loongarch32", "Loongarch32", LE, None, ""),
    case("m16c", "m16c", LE, None, ""),
    case("m68hc12", "m68hc12", BE, None, ""),
    case("m9s12x", "m9s12x", BE, None, ""),
    case("msp430", "msp:14", LE, None, ""),
    case("nds32", "n1h_v3m", LE, None, ""),
    case("sh4", "sh4", LE, None, ""),
    case("v850e2v4", "v850e2v4", LE, None, ""),
    case("v850e3v5", "v850e3v5", LE, None, ""),
    case("xtensa", "xtensa", LE, None, ""),
    case("z80", "z80", LE, None, "f5c5d5e5210000cd0000c9"),
    case("iwmmxt", "iwmmxt", LE, None, ""),
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_of(case: &Case, index: usize) -> Vec<u8> {
    let mut bytes = hex(case.known);
    bytes.extend(common::noise(64, 0x5eed_0000 + index as u64));
    bytes
}

fn render(block: &Block, bytes: &[u8]) -> String {
    let mut out = String::new();
    for insn in &block.instructions {
        let offset = (insn.address - ADDRESS) as usize;
        let raw: String = bytes
            .get(offset..(offset + insn.length).min(bytes.len()))
            .unwrap_or(&[])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let _ = write!(
            out,
            "{:08x} {:2} {raw:<16} {:?}",
            insn.address, insn.length, insn.text
        );
        if let Some(info) = insn.info {
            let _ = write!(
                out,
                "  [{:?} delay={} size={} target={:#x}]",
                info.kind, info.branch_delay_insns, info.data_size, info.target
            );
        }
        out.push('\n');
    }
    let _ = writeln!(out, "end: {:?}", block.end);
    out
}

#[test]
fn golden_disassembly() {
    let objdump = std::env::var_os("BK_GNU_OBJDUMP").map(PathBuf::from);
    if objdump.is_none() {
        eprintln!("objdump comparison skipped: BK_GNU_OBJDUMP is not set");
    }
    let mut mismatches = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        let bytes = bytes_of(case, index);
        let arch = Architecture::from_gnu_name(case.arch).unwrap();
        let mut dis = Disassembler::new(&arch, case.endian, case.options).unwrap();
        let block = dis.block(&bytes, ADDRESS).unwrap();
        insta::assert_snapshot!(case.label, render(&block, &bytes));
        if let Some(objdump) = &objdump {
            mismatches.extend(compare_with_objdump(objdump, case, &bytes, &block));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// `0x0012` → `0x12`, and objdump's ` <sym+off>` suffixes removed.
fn normalise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("0x") {
        out.push_str(&rest[..i + 2]);
        rest = &rest[i + 2..];
        let zeros = rest.len() - rest.trim_start_matches('0').len();
        let digits_after = rest[zeros..].starts_with(|c: char| c.is_ascii_hexdigit());
        if zeros > 0 && digits_after {
            rest = &rest[zeros..];
        } else if zeros > 0 {
            rest = &rest[zeros - 1..];
        }
    }
    out.push_str(rest);
    // " <.data+0x10>" and the like.
    while let (Some(open), Some(close)) = (out.find(" <"), out.find('>')) {
        if close < open {
            break;
        }
        out.replace_range(open..=close, "");
    }
    out.trim_end().to_owned()
}

/// (address, length, text) per instruction objdump printed.
fn objdump_listing(objdump: &PathBuf, case: &Case, bytes: &[u8]) -> Vec<(u64, usize, String)> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let file = dir.join(format!("golden-{}.bin", case.label));
    std::fs::write(&file, bytes).unwrap();
    let mut command = Command::new(objdump);
    // gdis never tells binutils that the machine was chosen, so ARM ignores
    // it and decodes every instruction ("arm", machine unknown); objdump's
    // -m does tell it.
    let family = Architecture::from_gnu_name(case.arch)
        .ok()
        .and_then(|a| a.info().map(|i| i.family.clone()));
    let machine = if family.as_deref() == Some("arm") {
        "arm"
    } else {
        case.arch
    };
    command.args(["-D", "-z", "-w", "-b", "binary", "-m", machine]);
    command.arg(format!("--adjust-vma={ADDRESS:#x}"));
    command.arg(if case.endian == Endian::Big {
        "-EB"
    } else {
        "-EL"
    });
    if let Some(options) = case.options {
        command.args(["-M", options]);
    }
    command.arg(&file);
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}: {output:?}", case.label);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<(u64, usize, String)> = Vec::new();
    for line in stdout.lines() {
        let Some((addr, rest)) = line.trim_start().split_once(":\t") else {
            continue;
        };
        let Ok(addr) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        let (raw, text) = rest.split_once('\t').unwrap_or((rest, ""));
        let len = raw.chars().filter(char::is_ascii_hexdigit).count() / 2;
        lines.push((addr, len, text.to_owned()));
    }
    lines
}

fn compare_with_objdump(
    objdump: &PathBuf,
    case: &Case,
    bytes: &[u8],
    block: &Block,
) -> Vec<String> {
    let theirs = objdump_listing(objdump, case, bytes);
    let end = ADDRESS + bytes.len() as u64;
    // Instructions that lie wholly within the bytes; at the end objdump and
    // gdis treat a truncated instruction differently (by design).
    let ours: Vec<&Instruction> = block
        .instructions
        .iter()
        .filter(|i| i.address + i.length as u64 <= end && i.read_fault.is_none())
        .collect();
    let mut problems = Vec::new();
    for insn in ours {
        let Some((_, len, text)) = theirs.iter().find(|(a, _, _)| *a == insn.address) else {
            problems.push(format!(
                "{}: objdump has no instruction at {:#x}",
                case.label, insn.address
            ));
            continue;
        };
        let ours = allow_known_differences(case, &normalise(&insn.text), &normalise(text));
        if *len != insn.length || ours != normalise(text) {
            problems.push(format!(
                "{} at {:#x}: ours {} {:?}, objdump {} {:?}",
                case.label, insn.address, insn.length, insn.text, len, text
            ));
        }
    }
    if let BlockEnd::Failed { offset, error } = &block.end {
        problems.push(format!("{}: failed at {offset}: {error}", case.label));
    }
    problems
}

/// Rewrites our text's `0x` numbers where they differ from objdump's only
/// in the two ways the module documentation explains.
fn allow_known_differences(case: &Case, ours: &str, theirs: &str) -> String {
    let numbers = |text: &str| -> Vec<u64> {
        text.split("0x")
            .skip(1)
            .filter_map(|s| {
                let digits: String = s.chars().take_while(char::is_ascii_hexdigit).collect();
                u64::from_str_radix(&digits, 16).ok()
            })
            .collect()
    };
    let (mine, others) = (numbers(ours), numbers(theirs));
    if mine.len() != others.len() {
        return ours.to_owned();
    }
    let mut out = ours.to_owned();
    for (a, b) in mine.into_iter().zip(others) {
        let wrapped_32 = a >> 32 == 0xffff_ffff && a & 0xffff_ffff == b;
        let isa_bit = case.arch.starts_with("mips") && a | 1 == b;
        if wrapped_32 || isa_bit {
            out = out.replacen(&format!("0x{a:x}"), &format!("0x{b:x}"), 1);
        }
    }
    out
}

#[test]
fn normalisation_only_touches_number_padding_and_symbols() {
    assert_eq!(normalise("call   0x00010005"), "call   0x10005");
    assert_eq!(normalise("call   0x10005 <.data+0x5>"), "call   0x10005");
    assert_eq!(normalise("mov    $0x0,%eax"), "mov    $0x0,%eax");
    assert_eq!(normalise("ld r1,0x00(r2)"), "ld r1,0x0(r2)");
    assert_eq!(normalise("nop "), "nop");
}
