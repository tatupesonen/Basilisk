//! The abort trap: `abort()`, `exit()` and failed assertions inside binutils
//! end the shim call with an error, the process carries on, and the family
//! whose static state the abort may have left half-updated is quarantined.
//!
//! The aborts here are binutils' own, reached through the public interface:
//! a CGEN target given a machine number BFD does not know
//! (`bfd_lookup_arch` fails, then `abort()` in `opcodes/m32c-dis.c`), and the
//! Xtensa configuration loader with `XTENSA_GNU_CONFIG` set
//! (`_bfd_error_handler` and `abort()` in `bfd/xtensa-dynconfig.c`). Each
//! runs in a child process, because the quarantine lasts for the process.

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

use bk_binutils_sys::{RawDisassembler, RawError, scan_architecture};
use common::{CHILD_VAR, disassembler, listing, report, run_child};

#[test]
fn child() {
    let Ok(scenario) = std::env::var(CHILD_VAR) else {
        return;
    };
    match scenario.as_str() {
        "cgen-unknown-machine" => cgen_unknown_machine(),
        "xtensa-config" => xtensa_config(),
        other => panic!("unknown scenario {other}"),
    }
}

fn is_child() -> bool {
    std::env::var(CHILD_VAR).is_ok()
}

fn cgen_unknown_machine() {
    let m16c = scan_architecture("m16c").unwrap().unwrap();
    // m16c and m32c are machines of BFD's m32c architecture; 0xdead is none.
    let mut bad = RawDisassembler::new(m16c.arch, 0xdead, false, None).unwrap();
    let mut x86 = disassembler("i386:x86-64", false, None).unwrap();
    {
        let mut request = bad.request(&[0x00, 0x00, 0x00, 0x00], 0x1000).unwrap();
        let error = request.step(0).unwrap_err();
        assert_eq!(
            error,
            RawError::Aborted {
                message: "binutils called abort()".to_owned()
            }
        );
        // The request is not continued after binutils gave up.
        assert!(matches!(request.step(0), Err(RawError::Aborted { .. })));
    }
    // The family is quarantined: the same disassembler, a new one, and a new
    // one of another machine of the family are refused...
    let quarantined = RawError::Quarantined { arch: m16c.arch };
    assert_eq!(bad.request(&[0; 4], 0).unwrap_err(), quarantined);
    assert_eq!(disassembler("m16c", false, None).unwrap_err(), quarantined);
    assert_eq!(disassembler("m32c", false, None).unwrap_err(), quarantined);
    // ...dropping it is fine (its target data is leaked, not freed)...
    drop(bad);
    // ...and the rest of binutils works as before, in this process.
    assert_eq!(listing(&mut x86, &[0x90, 0xc3], 0), "1 nop\n1 ret\n");
    let mut arm = disassembler("arm", false, None).unwrap();
    assert_eq!(
        listing(&mut arm, &[0x1e, 0xff, 0x2f, 0xe1], 0),
        "4 bx\tlr\n"
    );
    report("ok");
}

fn xtensa_config() {
    // binutils built without plugin support aborts when the variable names
    // a configuration library to load. Whether that happens when the
    // disassembler is created or at its first instruction is binutils'
    // business; either way it is an error, not the end of the process.
    let error = match disassembler("xtensa", false, None) {
        Err(error) => error,
        Ok(mut dis) => {
            let mut request = dis.request(&[0x00, 0x00, 0x00], 0).unwrap();
            request.step(0).unwrap_err()
        }
    };
    assert_eq!(
        error,
        RawError::Aborted {
            message: "XTENSA_GNU_CONFIG is defined but plugin support is disabled".to_owned()
        }
    );
    let xtensa = scan_architecture("xtensa").unwrap().unwrap().arch;
    assert_eq!(
        disassembler("xtensa", false, None).unwrap_err(),
        RawError::Quarantined { arch: xtensa }
    );
    let mut x86 = disassembler("i386:x86-64", false, None).unwrap();
    assert_eq!(listing(&mut x86, &[0xc3], 0), "1 ret\n");
    report("ok");
}

#[test]
fn an_abort_in_a_target_is_an_error_and_quarantines_its_family() {
    if is_child() {
        return;
    }
    assert_eq!(run_child("cgen-unknown-machine", &[]), ["ok"]);
}

#[test]
fn an_abort_in_bfd_during_setup_is_an_error() {
    if is_child() {
        return;
    }
    assert_eq!(
        run_child(
            "xtensa-config",
            &[("XTENSA_GNU_CONFIG", "/nonexistent/xtensa.so")]
        ),
        ["ok"]
    );
}
