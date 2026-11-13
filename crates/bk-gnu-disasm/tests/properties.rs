//! Properties over arbitrary bytes on any architecture binutils knows: no
//! panic, no crash, and blocks that are consistent with themselves.

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
#![cfg(any(unix, windows))]

use std::sync::OnceLock;

use bk_gnu_disasm::{Architecture, BlockEnd, Disassembler, Endian, Error, RawError};
use proptest::prelude::*;

/// Every architecture name binutils can resolve.
fn architectures() -> &'static [Architecture] {
    static ALL: OnceLock<Vec<Architecture>> = OnceLock::new();
    ALL.get_or_init(|| {
        Architecture::names()
            .unwrap()
            .iter()
            .filter_map(|n| Architecture::from_gnu_name(n).ok())
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn blocks_are_consistent(
        index in any::<prop::sample::Index>(),
        big in any::<bool>(),
        address in any::<u64>(),
        bytes in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let arch = index.get(architectures());
        let endian = if big { Endian::Big } else { Endian::Little };
        let mut dis = match Disassembler::new(arch, endian, None) {
            Ok(dis) => dis,
            // Architectures without a disassembler in libopcodes.
            Err(Error::Raw(RawError::NoDisassembler { .. })) => return Ok(()),
            Err(e) => panic!("{}: {e}", arch.name()),
        };
        let block = dis.block(&bytes, address).unwrap();
        let mut expected = address;
        for insn in &block.instructions {
            prop_assert_eq!(insn.address, expected);
            prop_assert!(insn.length >= 1);
            expected = expected.wrapping_add(insn.length as u64);
        }
        let consumed: usize = block.instructions.iter().map(|i| i.length).sum();
        match &block.end {
            BlockEnd::Complete => prop_assert!(consumed >= bytes.len()),
            BlockEnd::NoInstruction { offset, returned, .. } => {
                prop_assert_eq!(*offset, consumed);
                prop_assert!(*returned <= 0);
            }
            BlockEnd::Failed { error, .. } => {
                // Only binutils giving up is an acceptable failure.
                prop_assert!(
                    matches!(error, Error::Raw(RawError::Aborted { .. } | RawError::Quarantined { .. })),
                    "{}: {error}", arch.name()
                );
            }
            other => panic!("{other:?}"),
        }
        // The first instruction alone is the block's first instruction.
        if let (Some(first), false) = (block.instructions.first(), bytes.is_empty()) {
            prop_assert_eq!(&dis.instruction(&bytes, address).unwrap(), first);
        }
    }
}
