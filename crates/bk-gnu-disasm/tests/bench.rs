//! Throughput of GNU disassembly (docs/PERF.md). Ignored by default; run:
//!
//!     cargo test --release -p bk-gnu-disasm --test bench -- --ignored --nocapture

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    clippy::cast_precision_loss,
    reason = "test code"
)]
#![cfg(any(unix, windows))]

mod common;

use std::time::Instant;

use bk_gnu_disasm::{Architecture, Disassembler, Endian};

/// Code-like input: a real function's bytes repeated, so that most of it
/// decodes to ordinary instructions.
fn code(pattern: &[u8], len: usize) -> Vec<u8> {
    pattern.iter().copied().cycle().take(len).collect()
}

fn measure(name: &str, arch: &str, bytes: &[u8]) {
    let arch = Architecture::from_gnu_name(arch).unwrap();
    let mut dis = Disassembler::new(&arch, Endian::Little, None).unwrap();
    // Warm up (lazily built tables).
    let _ = dis.block(&bytes[..4096], 0x1000).unwrap();

    let start = Instant::now();
    let block = dis.block(bytes, 0x1000).unwrap();
    let block_time = start.elapsed();
    let n = block.instructions.len();

    let start = Instant::now();
    let mut offset = 0;
    let mut count = 0usize;
    while offset < bytes.len() && count < 100_000 {
        let insn = dis.instruction_at(bytes, 0x1000, offset).unwrap();
        offset += insn.length;
        count += 1;
    }
    let one_time = start.elapsed();
    println!(
        "{name}: block {n} instructions in {:.1} ms = {:.2} M instructions/s; \
         instruction_at {count} in {:.1} ms = {:.2} M instructions/s",
        block_time.as_secs_f64() * 1e3,
        n as f64 / block_time.as_secs_f64() / 1e6,
        one_time.as_secs_f64() * 1e3,
        count as f64 / one_time.as_secs_f64() / 1e6,
    );
}

#[test]
#[ignore = "benchmark; run in release"]
fn instructions_per_second() {
    // x86-64: push rbp; mov rbp,rsp; mov eax,[rbp-4]; add eax,0x10;
    // call; lea rdi,[rip+0x100]; leave; ret.
    let x86 = code(
        &[
            0x55, 0x48, 0x89, 0xe5, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x10, 0xe8, 0, 0, 0, 0, 0x48,
            0x8d, 0x3d, 0, 1, 0, 0, 0xc9, 0xc3,
        ],
        1 << 20,
    );
    measure("x86-64", "i386:x86-64", &x86);
    // AArch64: stp; mov; ldr; add; bl; ldp; ret; nop.
    let a64 = code(
        &[
            0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe0, 0x07, 0x40, 0xf9, 0x00, 0x40,
            0x00, 0x91, 0x00, 0x00, 0x00, 0x94, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
            0x1f, 0x20, 0x03, 0xd5,
        ],
        1 << 20,
    );
    measure("AArch64", "aarch64", &a64);
}
