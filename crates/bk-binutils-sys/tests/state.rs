//! libopcodes' static state: a disassembler created with given options
//! behaves the same whatever was created before it (`shim/bk_state.c`), and
//! instruction-sequence state lasts one request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]
#![cfg(any(unix, windows))]

mod common;

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use bk_binutils_sys::{RawError, architecture_names, scan_architecture};
use common::{CHILD_VAR, disassembler, listing, noise, report, run_child};

/// (GNU architecture name, big-endian, options).
type Config = (String, bool, Option<String>);

/// Options that change static state in binutils 2.41, per target, and one
/// default configuration of every architecture family.
fn configs() -> Vec<Config> {
    let with =
        |name: &str, big: bool, options: &str| (name.to_owned(), big, Some(options.to_owned()));
    let mut out = vec![
        with("arm", false, "force-thumb"),
        with("arm", false, "reg-names-raw"),
        with("arm", false, "reg-names-apcs,coproc0=cde,coproc3=cde"),
        with("aarch64", false, "no-aliases"),
        with("aarch64", false, "notes"),
        with("riscv:rv64", false, "numeric"),
        with("riscv:rv64", false, "no-aliases"),
        with("csky", false, "abi-names"),
        with("i386:x86-64", false, "intel"),
        with("i386", false, "intel,addr16"),
        with("mips:isa64r2", true, "gpr-names=32,reg-names=r3000"),
        with("powerpc:common64", true, "power10"),
        with("powerpc:common", true, "spe"),
        with("s390:64-bit", true, "esa,insnlength"),
        with("wasm32", false, "registers,globals"),
        with("cris", false, "nocase"),
        with("nfp", false, "no-pc,ctx8"),
    ];
    let mut families = BTreeMap::new();
    for name in architecture_names().unwrap() {
        if let Some(arch) = scan_architecture(&name).unwrap() {
            families.entry(arch.family).or_insert(name);
        }
    }
    for name in families.into_values() {
        out.push((name.clone(), false, None));
        out.push((name, true, None));
    }
    out
}

/// What a configuration prints for a fixed block of noise.
fn fingerprint(config: &Config) -> String {
    let (name, big, options) = config;
    let text = match disassembler(name, *big, options.as_deref()) {
        Ok(mut dis) => listing(&mut dis, &noise(512, 0x9e37_79b9_7f4a_7c15), 0x10_0000),
        Err(e) => format!("error: {e}"),
    };
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    format!(
        "{:016x} {}",
        hasher.finish(),
        text.lines().next().unwrap_or("")
    )
}

#[test]
fn child() {
    let Ok(scenario) = std::env::var(CHILD_VAR) else {
        return;
    };
    if let Some(index) = scenario.strip_prefix("fingerprint:") {
        let configs = configs();
        report(&fingerprint(&configs[index.parse::<usize>().unwrap()]));
    } else if scenario == "once" {
        once_scenario();
    } else {
        panic!("unknown scenario {scenario}");
    }
}

#[test]
fn options_do_not_leak_between_disassemblers() {
    if std::env::var(CHILD_VAR).is_ok() {
        return;
    }
    let configs = configs();
    // Each configuration alone in a fresh process: what binutils does when
    // nothing was created before.
    let fresh: Vec<String> = (0..configs.len())
        .map(|i| run_child(&format!("fingerprint:{i}"), &[]).concat())
        .collect();
    // All of them in one process, forwards and then backwards, so that each
    // follows configurations of its own architecture with other options.
    let order: Vec<usize> = (0..configs.len()).chain((0..configs.len()).rev()).collect();
    let mut leaks = Vec::new();
    for i in order {
        let got = fingerprint(&configs[i]);
        if got != fresh[i] {
            leaks.push(format!(
                "{:?}\n  fresh: {}\n  here:  {got}",
                configs[i], fresh[i]
            ));
        }
    }
    assert!(
        leaks.is_empty(),
        "{} leaks:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

/// Targets that apply options once per process: a second disassembler must
/// agree with the first, or be refused.
fn once_scenario() {
    let conflict = |name: &str, first: Option<&str>, second: Option<&str>| {
        let a = disassembler(name, false, first).unwrap();
        let arch = scan_architecture(name).unwrap().unwrap().arch;
        let same = disassembler(name, false, first);
        assert!(same.is_ok(), "{name}: the same options again are fine");
        let e = disassembler(name, false, second).unwrap_err();
        assert_eq!(e, RawError::OptionsConflict { arch });
        drop((a, same));
        // The first options stay the ones that count, after every
        // disassembler is gone.
        assert!(disassembler(name, false, second).is_err());
        assert!(disassembler(name, false, first).is_ok());
    };
    conflict("loongarch64", None, Some("no-aliases"));
    conflict("arc", Some("hex"), None);
    conflict("vax", None, Some("entry:0x100"));
    // RISC-V: only the privileged spec version is once-only.
    conflict("riscv:rv64", Some("priv-spec=1.11"), Some("priv-spec=1.10"));
    assert!(disassembler("riscv:rv64", false, Some("numeric,priv-spec=1.11")).is_ok());
    assert!(disassembler("riscv:rv64", false, None).is_err());
    report("ok");
}

#[test]
fn targets_that_take_options_once_refuse_different_ones() {
    if std::env::var(CHILD_VAR).is_ok() {
        return;
    }
    assert_eq!(run_child("once", &[]), ["ok"]);
}

#[test]
fn arm_it_block_state_lasts_one_request() {
    // Thumb: "it eq" (bf08), then "movs r0, #1" (2001), which is
    // "moveq r0, #1" inside the IT block.
    let mut dis = disassembler("arm", false, Some("force-thumb")).unwrap();
    let block = listing(&mut dis, &[0x08, 0xbf, 0x01, 0x20], 0x1000);
    assert_eq!(block, "2 it\teq\n2 moveq\tr0, #1\n");

    // A step that starts inside the IT block (as after a jump) finds the
    // state by scanning backwards through the request's bytes, given an
    // instruction boundary before the IT ("nop", bf00)...
    let mut request = dis
        .request(&[0x00, 0xbf, 0x08, 0xbf, 0x01, 0x20], 0x0ffe)
        .unwrap();
    assert_eq!(request.step(4).unwrap().text, b"moveq\tr0, #1");
    drop(request);
    // ...and without one, cannot tell and assumes no IT block.
    let mut request = dis.request(&[0x08, 0xbf, 0x01, 0x20], 0x1000).unwrap();
    assert_eq!(request.step(2).unwrap().text, b"movs\tr0, #1");
    drop(request);

    // A request that ends inside an IT block does not leave its state to the
    // next one, even at the very next address and from another disassembler
    // (binutils keeps this in statics; gdis carries it over).
    let _ = listing(&mut dis, &[0x08, 0xbf], 0x2000);
    let mut other = disassembler("arm", false, Some("force-thumb")).unwrap();
    assert_eq!(
        listing(&mut other, &[0x01, 0x20], 0x2002),
        "2 movs\tr0, #1\n"
    );
}

#[test]
fn sequence_state_lasts_one_request_on_every_architecture() {
    // B alone, then after unrelated requests A that end exactly where B
    // starts (the worst case for state kept by address), must print the
    // same. binutils keeps such state in statics in several targets (ARM IT
    // and VPT blocks, xgate's instruction pairs, CRIS case tables); patches
    // 0001 and 0003 reset it when a request begins.
    let b = noise(96, 0xb0b);
    let mut leaks = Vec::new();
    for name in architecture_names().unwrap() {
        if scan_architecture(&name).unwrap().is_none() {
            continue;
        }
        for big in [false, true] {
            let Ok(mut dis) = disassembler(&name, big, None) else {
                continue;
            };
            let reference = listing(&mut dis, &b, 0x2000);
            if reference.contains("error") {
                continue;
            }
            for seed in 1..=6 {
                let a = noise(96, seed);
                let _ = listing(&mut dis, &a, 0x2000 - 96);
                let again = listing(&mut dis, &b, 0x2000);
                if again != reference {
                    let first = reference
                        .lines()
                        .zip(again.lines())
                        .find(|(x, y)| x != y)
                        .map(|(x, y)| format!("{x:?} became {y:?}"))
                        .unwrap_or_default();
                    leaks.push(format!("{name} big={big} after seed {seed}: {first}"));
                    break;
                }
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "{} leaks:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

#[test]
fn a_cris_case_table_does_not_continue_into_the_next_request() {
    // "bound.d 3,$r0" then the case jump "adds.w [$pc+$r0.w],$pc": CRIS
    // prints what follows as case-table entries.
    let switch = [0xef, 0x0d, 3, 0, 0, 0, 0x5f, 0x05, 0x3f, 0xf8];
    let mut dis = disassembler("cris", false, None).unwrap();
    let mut table = switch.to_vec();
    table.extend([0x10, 0, 0x20, 0, 0x30, 0, 0x40, 0]);
    let full = listing(&mut dis, &table, 0);
    assert!(full.contains("case 0/default: -> "), "{full}");
    // A request that ends right after the case jump leaves the table open
    // in binutils' statics; the next request must not be read as its
    // entries (patch 0003), whichever disassembler makes it.
    let _ = listing(&mut dis, &switch, 0);
    let mut other = disassembler("cris", false, None).unwrap();
    let next = listing(&mut other, &[0x10, 0, 0x20, 0], 0x100);
    assert!(!next.contains("case"), "{next}");
}

#[test]
fn a_cr16_register_list_does_not_print_an_earlier_instructions_operand() {
    // storm/loadm with bit 7 of the first word set get an operand binutils
    // never decodes; it printed whatever an earlier instruction left in a
    // static (patch 0004 clears it per instruction).
    let mut dis = disassembler("cr16", false, None).unwrap();
    let word = (0u16..=0xffff)
        .filter(|w| w & 0x80 != 0)
        .find(|w| {
            let text = listing(&mut dis, &w.to_le_bytes(), 0);
            text.starts_with("2 storm") || text.starts_with("2 loadm")
        })
        .expect("a storm/loadm encoding with bit 7 set");
    let alone = listing(&mut dis, &word.to_le_bytes(), 0x100);
    for seed in 1..=8 {
        let _ = listing(&mut dis, &noise(64, seed), 0x1000);
        assert_eq!(
            listing(&mut dis, &word.to_le_bytes(), 0x100),
            alone,
            "{word:#06x}"
        );
    }
}
