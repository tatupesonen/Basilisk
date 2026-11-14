//! Benchmarks for the reader's hot paths (ADR-012). Ignored by default; run
//!
//! ```text
//! cargo test -p bk-bin --release --test bench -- --ignored --nocapture
//! ```
//!
//! and record the numbers in `docs/PERF.md`.

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

use std::hint::black_box;
use std::time::Instant;

use bk_bin::{BinaryReader, ByteProvider, Endian, FileProvider, MemoryProvider, Result};

const SIZE: usize = 64 * 1024 * 1024;

fn data() -> Vec<u8> {
    (0..SIZE)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect()
}

/// Runs `f` three times and reports the best throughput in MB/s (10⁶ bytes).
fn report(name: &str, bytes: usize, mut f: impl FnMut() -> u64) -> u64 {
    let mut best = f64::MAX;
    let mut checksum = 0;
    for _ in 0..3 {
        let start = Instant::now();
        checksum = black_box(f());
        best = best.min(start.elapsed().as_secs_f64());
    }
    eprintln!(
        "{name:<44} {:>9.0} MB/s  {:>6.2} ns/read",
        bytes as f64 / 1e6 / best,
        best * 1e9 / (bytes / 4) as f64
    );
    checksum
}

fn sum_u32(mut reader: BinaryReader<'_>) -> u64 {
    let mut sum = 0u64;
    while let Ok(value) = reader.read_u32() {
        sum = sum.wrapping_add(u64::from(value));
    }
    sum
}

/// A provider that hides its slice, to measure the virtual-call path.
#[derive(Debug)]
struct Opaque(MemoryProvider);

impl ByteProvider for Opaque {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read_into(offset, buf)
    }
}

#[test]
#[ignore = "benchmark"]
fn bench_reader_integer_throughput() {
    let bytes = data();
    let expected: u64 = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&c| u64::from(u32::from_le_bytes(c)))
        .fold(0, u64::wrapping_add);

    let memory = MemoryProvider::new(bytes.clone());
    let got = report("read_u32, slice (from_slice)", SIZE, || {
        sum_u32(BinaryReader::from_slice(&bytes, Endian::Little))
    });
    assert_eq!(got, expected);
    let got = report("read_u32, MemoryProvider", SIZE, || {
        sum_u32(BinaryReader::new(&memory, Endian::Little))
    });
    assert_eq!(got, expected);
    report("read_u32 big-endian, MemoryProvider", SIZE, || {
        sum_u32(BinaryReader::new(&memory, Endian::Big))
    });
    let got = report("read_u32_array (one call), MemoryProvider", SIZE, || {
        let reader = BinaryReader::new(&memory, Endian::Little);
        let values = reader.read_u32_array_at(0, SIZE / 4).unwrap();
        values
            .iter()
            .fold(0u64, |s, &v| s.wrapping_add(u64::from(v)))
    });
    assert_eq!(got, expected);

    let opaque = Opaque(memory.clone());
    let got = report("read_u32, provider without a slice (dyn)", SIZE, || {
        sum_u32(BinaryReader::new(&opaque, Endian::Little))
    });
    assert_eq!(got, expected);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.bin");
    std::fs::write(&path, &bytes).unwrap();
    let file = FileProvider::open(&path).unwrap();
    let got = report("read_u32, FileProvider (block cache)", SIZE, || {
        sum_u32(BinaryReader::new(&file, Endian::Little))
    });
    assert_eq!(got, expected);
}

#[test]
#[ignore = "benchmark"]
fn bench_reader_strings() {
    // 4 million NUL-terminated 15-character strings.
    let count = 4_000_000usize;
    let mut bytes = Vec::with_capacity(count * 16);
    for i in 0..count {
        bytes.extend_from_slice(format!("symbol_{i:08}").as_bytes());
        bytes.push(0);
    }
    let memory = MemoryProvider::new(bytes.clone());
    let total = bytes.len();
    let raw = report("read_terminated_bytes_at (borrowed)", total, || {
        let reader = BinaryReader::new(&memory, Endian::Little);
        let mut offset = 0u64;
        let mut sum = 0u64;
        while let Ok(s) = reader.read_terminated_bytes_at(offset, 1) {
            sum += s.len() as u64;
            offset += s.len() as u64 + 1;
        }
        sum
    });
    assert_eq!(raw, (count * 15) as u64);
    let decoded = report("read_utf8 (allocating a String)", total, || {
        let mut reader = BinaryReader::new(&memory, Endian::Little);
        let mut sum = 0u64;
        while let Ok(s) = reader.read_utf8() {
            sum += s.len() as u64;
        }
        sum
    });
    assert_eq!(decoded, raw);
}
