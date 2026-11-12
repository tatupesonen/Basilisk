//! Benchmarks (ADR-012). Ignored by default; run
//!
//! ```text
//! cargo test -p bk-elf --release --test bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! A 64-bit file with a million symbols (spec §6) is written by the fixture
//! builder; the numbers go in `docs/PERF.md`.

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

#[allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses part of the support code"
)]
mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use bk_bin::{FileProvider, MemoryProvider};
use bk_elf::ElfFile;
use common::builder::{ElfBuilder, Enc, StrTab, Sym, sht};

const SYMBOLS: u32 = 1_000_000;

fn million_symbol_file() -> Vec<u8> {
    let mut b = ElfBuilder::new(Enc::LE64);
    let mut strings = StrTab::default();
    let symbols: Vec<Sym> = (0..SYMBOLS)
        .map(|i| Sym {
            name: strings.add(&format!("function_{i:07}")),
            value: 0x40_0000 + u64::from(i) * 16,
            size: 16,
            info: 0x12,
            shndx: 1,
            ..Sym::default()
        })
        .collect();
    let strtab = b.strtab(".strtab", &strings, false);
    b.symtab(".symtab", sht::SYMTAB, strtab, &symbols);
    b.build().bytes
}

fn best_of<T>(runs: usize, mut f: impl FnMut() -> T) -> Duration {
    (0..runs)
        .map(|_| {
            let start = Instant::now();
            black_box(f());
            start.elapsed()
        })
        .min()
        .unwrap()
}

fn report(what: &str, time: Duration, items: u64) {
    let ns = time.as_nanos() as f64 / items as f64;
    eprintln!(
        "{what:58} {:>9.2} ms  {ns:>7.2} ns/item",
        time.as_secs_f64() * 1e3
    );
}

#[test]
#[ignore = "benchmark"]
fn million_symbols() {
    let bytes = million_symbol_file();
    eprintln!("file: {} bytes, {SYMBOLS} symbols", bytes.len());
    let provider = MemoryProvider::new(&bytes[..]);

    let open = best_of(20, || ElfFile::parse(&provider).unwrap());
    report("open (headers, tables located; symbols not read)", open, 1);

    let elf = ElfFile::parse(&provider).unwrap();
    let table = &elf.symbol_tables()[0];
    assert_eq!(table.symbol_count, SYMBOLS + 1);
    let n = u64::from(table.symbol_count);
    let decode = best_of(5, || elf.symbols(table).map(|s| s.st_value).sum::<u64>());
    report("decode every symbol (memory)", decode, n);
    let named = best_of(5, || {
        elf.symbols(table)
            .map(|s| elf.symbol_name(table, &s).unwrap().unwrap().len())
            .sum::<usize>()
    });
    report("decode every symbol and borrow its name (memory)", named, n);
    let owned = best_of(5, || {
        elf.symbols(table)
            .map(|s| elf.symbol_name(table, &s).unwrap().unwrap().into_owned())
            .collect::<Vec<String>>()
    });
    report(
        "decode every symbol, collect owned names (memory)",
        owned,
        n,
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("million.elf");
    std::fs::write(&path, &bytes).unwrap();
    let file = FileProvider::open(&path).unwrap();
    let elf = ElfFile::parse(&file).unwrap();
    let table = &elf.symbol_tables()[0];
    let decode = best_of(3, || elf.symbols(table).map(|s| s.st_value).sum::<u64>());
    report("decode every symbol (FileProvider)", decode, n);
    let named = best_of(3, || {
        elf.symbols(table)
            .map(|s| elf.symbol_name(table, &s).unwrap().unwrap().len())
            .sum::<usize>()
    });
    report(
        "decode every symbol and read its name (FileProvider)",
        named,
        n,
    );
}
