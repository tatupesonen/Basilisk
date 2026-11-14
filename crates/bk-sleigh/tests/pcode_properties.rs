//! Property tests of p-code generation (`features/sleigh-pcode.md` 6.5) on
//! the fixture languages: lifting arbitrary bytes and context never panics
//! and is deterministic; every relative branch lands inside the
//! instruction's own op list or one past its end; varnodes have non-zero
//! sizes; lifting after disassembling gives the same instruction length.
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

mod common;
mod fixture;

use std::sync::{Arc, OnceLock};

use bk_core::{Address, SpaceKind};
use bk_pcode::OpCode;
use bk_sleigh::{Decoder, Language, PcodeCollector, SliceBytes};
use proptest::prelude::*;

fn languages() -> &'static [Arc<Language>; 2] {
    static LANGS: OnceLock<[Arc<Language>; 2]> = OnceLock::new();
    LANGS.get_or_init(|| {
        [
            Arc::new(Language::from_sla(Arc::new(fixture::pcode::build_sla())).unwrap()),
            Arc::new(Language::from_sla(Arc::new(fixture::build())).unwrap()),
        ]
    })
}

/// Lifts at `offset` and checks the properties; returns a summary for the
/// determinism check.
fn check(lang: &Arc<Language>, offset: u64, bytes: &[u8], words: &[u32]) -> String {
    let mut db = lang.empty_context();
    for (i, &w) in words.iter().enumerate().take(lang.context_words()) {
        db.set_default(i, u32::MAX, w);
    }
    let addr = Address::new(lang.default_space(), offset);
    let source = SliceBytes::new(offset, bytes);
    let mut decoder = Decoder::new(Arc::clone(lang));
    let length = decoder
        .disassemble(addr, &source, &db)
        .map(|d| d.length)
        .ok();
    let mut ops = PcodeCollector::new();
    let lifted = decoder.lift(addr, &source, &mut db, &mut ops);
    let flow = match &lifted {
        Ok(flow) => *flow,
        Err(e) => return format!("error {e}"),
    };
    let length = length.expect("lift succeeded where disassembly failed");
    assert_eq!(decoder.parse().length(), length, "same instruction length");
    assert!(flow >= length);
    let n = ops.ops().len() as i64;
    for (i, op) in ops.ops().iter().enumerate() {
        let inputs = ops.inputs(op);
        for vn in op.output.iter().chain(inputs) {
            assert!(vn.size > 0, "zero-size varnode in {:?}", op.opcode);
        }
        let is_branch = matches!(op.opcode, OpCode::Branch | OpCode::CBranch);
        let Some(target) = inputs.first().filter(|_| is_branch) else {
            continue;
        };
        let constant = target
            .space()
            .and_then(|s| lang.spaces().space(s))
            .is_some_and(|s| matches!(s.kind(), SpaceKind::Constant));
        if constant {
            let bits = 8 * target.size.min(8);
            let disp = ((target.offset << (64 - bits)) as i64) >> (64 - bits);
            let to = i as i64 + disp;
            assert!((0..=n).contains(&to), "branch from {i} to {to} of {n}");
        }
    }
    format!("flow {flow} ops {n}")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(common::proptest_cases(2000)))]

    #[test]
    fn lifting_never_panics_and_keeps_branches_inside(
        which in 0usize..2,
        offset in any::<u32>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..24),
        words in proptest::collection::vec(any::<u32>(), 0..3),
    ) {
        let lang = &languages()[which];
        let a = check(lang, u64::from(offset), &bytes, &words);
        let b = check(lang, u64::from(offset), &bytes, &words);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn valid_opcodes_lift(
        offset in (0u32..0x8000).prop_map(|o| o * 2),
        ops in proptest::collection::vec((1u8..=0x14, any::<u8>()), 1..8),
    ) {
        let bytes: Vec<u8> = ops.iter().flat_map(|&(a, b)| [a, b]).collect();
        let lang = &languages()[0];
        let a = check(lang, u64::from(offset), &bytes, &[]);
        let b = check(lang, u64::from(offset), &bytes, &[]);
        prop_assert_eq!(a, b);
    }
}
