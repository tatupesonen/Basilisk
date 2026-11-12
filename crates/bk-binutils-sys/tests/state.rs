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
#![cfg(not(windows))]

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
