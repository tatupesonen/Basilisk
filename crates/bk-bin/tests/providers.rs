//! Ports of Ghidra's provider tests: `ByteArrayProviderTest` (2 tests),
//! `FileByteProviderTest` (4) and `RangeMappedByteProviderTest` (12).

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

use bk_bin::{
    BinaryReader, ByteProvider, Endian, FileProvider, MemoryProvider, RangeMappedProvider,
};

/// Ghidra's `patternedBAP`: `count` blocks of `bs` bytes,
/// "NN 01 NN 03 NN 05 …" where NN is the block number and the odd bytes are
/// their offset in the block.
fn patterned(bs: usize, count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; bs * count];
    for (block, chunk) in bytes.chunks_mut(bs).enumerate() {
        chunk.fill(block as u8);
        for i in (1..bs).step_by(2) {
            chunk[i] = (i % 256) as u8;
        }
    }
    bytes
}

fn patterned_provider(bs: usize, count: usize) -> MemoryProvider {
    MemoryProvider::new(patterned(bs, count))
}

// ---------------------------------------------------------------------------
// ByteArrayProviderTest
// ---------------------------------------------------------------------------

/// `testInputStream`. A Java `InputStream` over a provider is, here, a
/// reader positioned at the start index; "`read()` returns -1" is "no next".
#[test]
fn byte_array_provider_test_input_stream() {
    let provider = MemoryProvider::new(vec![1u8, 2, 3, 4, 5, 6]);
    let mut is = BinaryReader::new(&provider, Endian::Little);
    assert_eq!(is.read_u8().unwrap(), 1);
    assert_eq!(is.read_u8().unwrap(), 2);

    let mut is2 = BinaryReader::new(&provider, Endian::Little).at(4);
    assert_eq!(is2.read_u8().unwrap(), 5);
    assert_eq!(is2.read_u8().unwrap(), 6);
    assert!(!is2.has_next());
    assert!(is2.read_u8().is_err());

    let is3 = BinaryReader::new(&provider, Endian::Little).at(6);
    assert!(!is3.has_next());
}

/// `testReadBytes_EOFBoundary`.
#[test]
fn byte_array_provider_test_read_bytes_eof_boundary() {
    let provider = MemoryProvider::new(vec![1u8, 2, 3, 4, 5, 6]);
    // Reading up to, but not past, the end succeeds.
    provider.read_bytes(0, 6).unwrap();
    provider.read_bytes(5, 1).unwrap();
    provider.read_bytes(6, 0).unwrap();
    // Reading past the end fails.
    assert!(provider.read_bytes(6, 1).is_err());
}

// ---------------------------------------------------------------------------
// FileByteProviderTest
// ---------------------------------------------------------------------------

const BS: usize = FileProvider::BLOCK_SIZE;

fn temp_file(bytes: &[u8]) -> (tempfile::TempDir, FileProvider) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file1");
    std::fs::write(&path, bytes).unwrap();
    let provider = FileProvider::open(&path).unwrap();
    (dir, provider)
}

/// `testSmallRead`.
#[test]
fn file_byte_provider_test_small_read() {
    let (_dir, provider) = temp_file(b"testing\0second line\0");
    let reader = BinaryReader::new(&provider, Endian::Little);
    assert_eq!(reader.read_ascii_at(0).unwrap(), "testing");
    assert_eq!(reader.read_ascii_at(8).unwrap(), "second line");
}

/// `testReadAtBuffersBoundaries`.
#[test]
fn file_byte_provider_test_read_at_buffers_boundaries() {
    let (_dir, provider) = temp_file(&patterned(BS, 5));
    let reader = BinaryReader::new(&provider, Endian::Big);
    let bs = BS as u64;
    assert_eq!(provider.len(), 5 * bs);
    assert_eq!(reader.read_u16_at(0).unwrap(), 0x0001);
    assert_eq!(reader.read_u16_at(bs - 2).unwrap(), 0x00ff);
    assert_eq!(reader.read_u16_at(bs).unwrap(), 0x0101);
    assert_eq!(reader.read_u16_at(bs + bs - 2).unwrap(), 0x01ff);
    assert_eq!(reader.read_u16_at(bs * 4).unwrap(), 0x0401);
}

/// `testReadStraddleBuffersBoundaries`.
#[test]
fn file_byte_provider_test_read_straddle_buffers_boundaries() {
    let (_dir, provider) = temp_file(&patterned(BS, 5));
    let reader = BinaryReader::new(&provider, Endian::Big);
    let bs = BS as u64;
    assert_eq!(provider.len(), 5 * bs);
    assert_eq!(reader.read_u32_at(bs - 2).unwrap(), 0x00ff_0101);
    assert_eq!(reader.read_u32_at(bs + bs - 2).unwrap(), 0x01ff_0201);
}

/// `testReadMultiStraddleBuffersBoundaries`.
#[test]
fn file_byte_provider_test_read_multi_straddle_buffers_boundaries() {
    let (_dir, provider) = temp_file(&patterned(BS, 5));
    assert_eq!(provider.len(), 5 * BS as u64);
    // Three adjacent blocks: 2 + bs + 2 bytes.
    let bytes = provider.read_bytes(BS as u64 - 2, BS + 4).unwrap();
    let reader = BinaryReader::from_slice(&bytes, Endian::Big);
    assert_eq!(reader.read_u32_at(0).unwrap(), 0x00ff_0101);
    assert_eq!(reader.read_u32_at(BS as u64).unwrap(), 0x01ff_0201);
}

// ---------------------------------------------------------------------------
// RangeMappedByteProviderTest
// ---------------------------------------------------------------------------

/// `testEmptyRangeMappedBP`.
#[test]
fn range_mapped_test_empty() {
    let delegate = MemoryProvider::new(vec![55u8]);
    let provider = RangeMappedProvider::new(&delegate);
    assert!(provider.read_byte(0).is_err());
}

/// The provider most tests use: delegate block 1, then one byte of block 0,
/// then block 0.
fn three_ranges(delegate: &MemoryProvider) -> RangeMappedProvider<&MemoryProvider> {
    let mut provider = RangeMappedProvider::new(delegate);
    provider.add_range(10, 10);
    provider.add_range(0, 1);
    provider.add_range(0, 10);
    provider
}

/// `testRangeMapppedBP_SingleByteRead`.
#[test]
fn range_mapped_test_single_byte_read() {
    let delegate = patterned_provider(10, 10);
    let provider = three_ranges(&delegate);
    assert_eq!(provider.len(), 21);
    let expected = [
        (0, 1),
        (1, 1),
        (2, 1),
        (3, 3),
        (9, 9),
        (11, 0),
        (12, 1),
        (13, 0),
        (14, 3),
        (20, 9),
    ];
    for (index, value) in expected {
        assert_eq!(provider.read_byte(index).unwrap(), value, "index {index}");
    }
    assert!(provider.read_byte(21).is_err());
}

/// `testRangeMapppedBP_MultiByteRead`.
#[test]
fn range_mapped_test_multi_byte_read() {
    let delegate = patterned_provider(10, 10);
    let provider = three_ranges(&delegate);
    assert_eq!(provider.len(), 21);
    let bytes = provider.read_bytes(0, 21).unwrap();
    let expected = [
        (0, 1),
        (1, 1),
        (2, 1),
        (3, 3),
        (9, 9),
        (11, 0),
        (12, 1),
        (13, 0),
        (14, 3),
        (20, 9),
    ];
    for (index, value) in expected {
        assert_eq!(bytes[index], value, "index {index}");
    }
}

/// `testRangeMapppedBP_MisalignedMultiByteRead`.
#[test]
fn range_mapped_test_misaligned_multi_byte_read() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 10);
    provider.add_range(0, 10);
    assert_eq!(provider.len(), 20);
    let bytes = provider.read_bytes(5, 10).unwrap();
    assert_eq!(
        &*bytes,
        &[0x05, 0x01, 0x07, 0x01, 0x09, 0x00, 0x01, 0x00, 0x03, 0x00]
    );
}

/// `testSmallRangeMapppedBP`.
#[test]
fn range_mapped_test_small() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 1);
    provider.add_range(0, 1);
    assert_eq!(provider.len(), 2);
    assert_eq!(provider.read_byte(0).unwrap(), 0x01);
    assert_eq!(provider.read_byte(1).unwrap(), 0x00);
    assert!(provider.read_byte(3).is_err());
}

/// `testRangeMapppedBP_SparseMultiByteRead`.
#[test]
fn range_mapped_test_sparse_multi_byte_read() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_sparse_range(5);
    assert_eq!(provider.len(), 5);
    assert_eq!(&*provider.read_bytes(0, 5).unwrap(), &[0u8; 5]);
}

/// `testRangeMapppedBP_SparseSingleByteRead`.
#[test]
fn range_mapped_test_sparse_single_byte_read() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_sparse_range(5);
    assert_eq!(provider.len(), 5);
    for index in 0..5 {
        assert_eq!(provider.read_byte(index).unwrap(), 0);
    }
}

/// `testRangeMapppedBP_MixedSparseMultiByteRead`.
#[test]
fn range_mapped_test_mixed_sparse_multi_byte_read() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 10);
    provider.add_sparse_range(5);
    provider.add_range(0, 10);
    assert_eq!(provider.len(), 25);
    let bytes = provider.read_bytes(0, 25).unwrap();
    let expected = [
        (0, 1),
        (1, 1),
        (2, 1),
        (3, 3),
        (9, 9),
        (10, 0),
        (11, 0),
        (12, 0),
        (13, 0),
        (14, 0),
        (15, 0),
        (16, 1),
        (17, 0),
        (18, 3),
        (24, 9),
    ];
    for (index, value) in expected {
        assert_eq!(bytes[index], value, "index {index}");
    }
}

/// `testMergeAdjacentRanges`.
#[test]
fn range_mapped_test_merge_adjacent_ranges() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 10);
    provider.add_range(20, 5);
    provider.add_range(25, 5);
    assert_eq!(provider.len(), 20);
    assert_eq!(provider.range_count(), 1);
}

/// `testDontMergeAlmostAdjacentRanges`.
#[test]
fn range_mapped_test_dont_merge_almost_adjacent_ranges() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 10);
    provider.add_range(21, 5);
    assert_eq!(provider.len(), 15);
    assert_eq!(provider.range_count(), 2);
}

/// `testDontMergeAlmostAdjacentRanges2`.
#[test]
fn range_mapped_test_dont_merge_almost_adjacent_ranges2() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 10);
    provider.add_range(19, 5); // overlaps the previous range: a boundary case
    assert_eq!(provider.len(), 15);
    assert_eq!(provider.range_count(), 2);
}

/// `testMergeAdjacentSparseRanges`.
#[test]
fn range_mapped_test_merge_adjacent_sparse_ranges() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_range(10, 10);
    provider.add_sparse_range(5);
    provider.add_sparse_range(5);
    assert_eq!(provider.len(), 20);
    assert_eq!(provider.range_count(), 2);
}

/// Not in Ghidra's test, and a place where basilisk deliberately differs:
/// Ghidra marks a sparse range with offset −1, so a real range starting at
/// `sparse_len − 1` satisfies its "continues the previous range" check and
/// is swallowed by the sparse range (its bytes then read as zeros).
#[test]
fn range_mapped_sparse_range_does_not_swallow_a_following_range() {
    let delegate = patterned_provider(10, 10);
    let mut provider = RangeMappedProvider::new(&delegate);
    provider.add_sparse_range(5);
    provider.add_range(4, 2);
    assert_eq!(provider.range_count(), 2);
    assert_eq!(&*provider.read_bytes(0, 7).unwrap(), &[0, 0, 0, 0, 0, 0, 5]);
}
