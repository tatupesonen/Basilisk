//! Helpers shared by the integration tests.
//!
//! Some behaviour under test is process-wide (libopcodes' static state, the
//! quarantine after an abort), so those tests run a scenario in a child
//! process: the test binary is started again with only the test `child`
//! selected and the scenario named in `BK_SHIM_CHILD`. The child prints
//! result lines marked `BKOUT:`, which the parent collects.

#![allow(dead_code, reason = "each test binary uses a different part")]

use std::fmt::Write as _;
use std::process::Command;

use bk_binutils_sys::{RawDisassembler, scan_architecture};

/// The environment variable that names a child's scenario.
pub(crate) const CHILD_VAR: &str = "BK_SHIM_CHILD";

/// Runs `scenario` in a fresh process with extra environment `env` and
/// returns its `BKOUT:` lines. Panics if the child fails.
pub(crate) fn run_child(scenario: &str, env: &[(&str, &str)]) -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    command
        .args(["--exact", "child", "--nocapture", "--test-threads=1"])
        .env(CHILD_VAR, scenario);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child {scenario} failed: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        .filter_map(|line| line.split_once("BKOUT:").map(|(_, rest)| rest))
        .map(str::to_owned)
        .collect()
}

/// Prints a result line for the parent.
pub(crate) fn report(line: &str) {
    println!("BKOUT:{line}");
}

/// A disassembler for a GNU architecture name.
pub(crate) fn disassembler(
    name: &str,
    big_endian: bool,
    options: Option<&str>,
) -> Result<RawDisassembler, bk_binutils_sys::RawError> {
    let arch = scan_architecture(name)?.unwrap_or_else(|| panic!("unknown architecture {name}"));
    RawDisassembler::new(arch.arch, arch.mach, big_endian, options)
}

/// Deterministic pseudo-random bytes (xorshift).
pub(crate) fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 24) as u8
        })
        .collect()
}

/// Disassembles `bytes` from the start, stepping over undecodable bytes one
/// at a time, and returns one line per instruction (`length text`), or the
/// error.
pub(crate) fn listing(dis: &mut RawDisassembler, bytes: &[u8], address: u64) -> String {
    let mut out = String::new();
    let mut request = match dis.request(bytes, address) {
        Ok(request) => request,
        Err(e) => return format!("error: {e}"),
    };
    let mut offset = 0;
    while offset < bytes.len() {
        match request.step(offset) {
            Ok(step) => {
                let _ = writeln!(
                    out,
                    "{} {}",
                    step.length,
                    String::from_utf8_lossy(step.text)
                );
                offset += usize::try_from(step.length).unwrap_or(0).max(1);
            }
            Err(e) => {
                let _ = writeln!(out, "error: {e}");
                break;
            }
        }
    }
    out
}
