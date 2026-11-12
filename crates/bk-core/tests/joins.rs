//! Join records: creation and reuse, merging of contiguous pieces, float
//! extensions, wrapping ranges, renormalisation, stripping, overlap through
//! pieces, and the text forms of join addresses.

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

use std::sync::Arc;

use bk_core::space::{CONSTANT_SPACE, MAX_JOIN_READ_DEPTH};
use bk_core::{Address, Space, SpaceError, SpaceManager, VarnodeData};
use common::{JOIN, RAM, REGISTER, STACK, UNIQUE, manager, vn};

const EAX: VarnodeData = VarnodeData::new(REGISTER, 0, 4);
const ECX: VarnodeData = VarnodeData::new(REGISTER, 4, 4);
const EDX: VarnodeData = VarnodeData::new(REGISTER, 8, 4);
const EBX: VarnodeData = VarnodeData::new(REGISTER, 12, 4);
const ESP: VarnodeData = VarnodeData::new(REGISTER, 16, 4);

#[test]
fn find_add_join_checks_its_arguments() {
    let m = manager(false);
    assert_eq!(
        m.find_add_join(vec![], 0).unwrap_err(),
        SpaceError::JoinWithoutPieces
    );
    assert_eq!(
        m.find_add_join(vec![EAX], 0).unwrap_err(),
        SpaceError::JoinWithoutLogicalSize
    );
    assert_eq!(
        m.find_add_join(vec![EDX, EAX], 12).unwrap_err(),
        SpaceError::JoinLogicalSizeWithPieces
    );
    assert_eq!(
        m.find_add_join(vec![vn(REGISTER, 0, 0), vn(REGISTER, 4, 0)], 0)
            .unwrap_err(),
        SpaceError::ZeroSizeJoin
    );
    let mut bare = SpaceManager::new();
    bare.insert_space(Space::constant()).unwrap();
    assert_eq!(
        bare.find_add_join(vec![EDX, EAX], 0).unwrap_err(),
        SpaceError::NoJoinSpace
    );
}

#[test]
fn records_are_reused_and_offsets_rounded_to_16() {
    let m = manager(false);
    let first = m.find_add_join(vec![EDX, EAX], 0).unwrap();
    assert_eq!(*first.unified(), vn(JOIN, 0, 8));
    let second = m.find_add_join(vec![EBX, ECX], 0).unwrap();
    assert_eq!(second.unified().offset, 16);
    let five = m
        .find_add_join(vec![ESP, EBX, EDX, ECX, vn(REGISTER, 0, 4)], 0)
        .unwrap();
    assert_eq!(*five.unified(), vn(JOIN, 32, 20));
    let ext = m.find_add_join(vec![EAX], 10).unwrap();
    assert_eq!(ext.unified().offset, 64);
    // The same pieces give the same record; a different logical size does not.
    assert!(Arc::ptr_eq(
        &first,
        &m.find_add_join(vec![EDX, EAX], 0).unwrap()
    ));
    assert!(Arc::ptr_eq(&ext, &m.find_add_join(vec![EAX], 10).unwrap()));
    assert_eq!(m.find_add_join(vec![EAX], 12).unwrap().unified().offset, 80);
    assert_eq!(m.join_records().len(), 5);

    assert!(Arc::ptr_eq(&m.find_join(16).unwrap(), &second));
    assert_eq!(m.find_join(17).unwrap_err(), SpaceError::UnlinkedJoin);
    assert!(Arc::ptr_eq(&m.find_join_covering(51).unwrap(), &five));
    assert!(m.find_join_covering(52).is_none());
}

#[test]
fn padding_records() {
    let m = manager(false);
    m.find_add_join(vec![EDX, EAX], 0).unwrap();
    let pad = m.find_add_join(vec![vn(CONSTANT_SPACE, 0, 4)], 0).unwrap();
    assert!(pad.is_pure_padding() && !pad.is_float_extension());
    m.find_add_join(vec![EAX], 8).unwrap();
    let padding = m.padding_join_records();
    assert_eq!(padding.len(), 1);
    assert!(Arc::ptr_eq(&padding[0], &pad));
}

#[test]
fn contiguous_pieces_merge_into_a_register() {
    // Little endian: ecx follows eax, so ecx:eax is rax.
    let m = manager(false);
    assert_eq!(
        m.construct_join_address(ECX.addr(), 4, EAX.addr(), 4)
            .unwrap(),
        Address::new(REGISTER, 0)
    );
    // edx:ebx would merge into 8 bytes at 8, which is no register: kept apart.
    let joined = m
        .construct_join_address(EBX.addr(), 4, EDX.addr(), 4)
        .unwrap();
    assert!(joined.is_join(&m));
    assert_eq!(m.find_join(joined.offset()).unwrap().pieces(), [EBX, EDX]);
    // Not contiguous at all.
    let joined = m
        .construct_join_address(EDX.addr(), 4, EAX.addr(), 4)
        .unwrap();
    assert_eq!(m.find_join(joined.offset()).unwrap().pieces(), [EDX, EAX]);

    // Big endian: eax is followed by ecx.
    let m = manager(true);
    assert_eq!(
        m.construct_join_address(EAX.addr(), 4, ECX.addr(), 4)
            .unwrap(),
        Address::new(REGISTER, 0)
    );
    let mut seq = vec![EAX, ECX, EBX];
    m.merge_join_sequence(&mut seq);
    assert_eq!(seq, [vn(REGISTER, 0, 8), EBX]);
}

#[test]
fn merging_skips_constants_and_spacebase_names() {
    let m = manager(false);
    // Padding is never merged.
    let mut seq = vec![vn(CONSTANT_SPACE, 4, 4), vn(CONSTANT_SPACE, 0, 4)];
    m.merge_join_sequence(&mut seq);
    assert_eq!(seq.len(), 2);
    // Stack pieces merge without needing a register name.
    let mut seq = vec![vn(STACK, 8, 4), vn(STACK, 4, 4)];
    m.merge_join_sequence(&mut seq);
    assert_eq!(seq, [vn(STACK, 4, 8)]);
}

#[test]
fn float_extension() {
    let m = manager(false);
    let real = EAX.addr();
    assert_eq!(
        m.construct_float_extension_address(real, 4, 4).unwrap(),
        real
    );
    let ext = m.construct_float_extension_address(real, 4, 10).unwrap();
    let record = m.find_join(ext.offset()).unwrap();
    assert!(record.is_float_extension());
    assert_eq!(record.unified().size, 10);
    assert_eq!(record.pieces(), [EAX]);
}

#[test]
fn wrapping_addresses() {
    // The stack allows wrapped ranges; ram does not.
    let m = manager(false);
    let near_end = Address::new(STACK, 0xffff_fffe);
    assert_eq!(m.construct_wrapping_address(near_end, 2).unwrap(), near_end);
    let wrapped = m.construct_wrapping_address(near_end, 4).unwrap();
    assert_eq!(
        m.find_join(wrapped.offset()).unwrap().pieces(),
        [vn(STACK, 0, 2), vn(STACK, 0xffff_fffe, 2)]
    );
    assert_eq!(
        m.construct_wrapping_address(Address::new(RAM, 0xffff_ffff), 2),
        Err(SpaceError::RangeBeyondSpace("ram".into()))
    );
    // A space that is not heritaged ignores the size.
    let c = Address::new(CONSTANT_SPACE, u64::MAX);
    assert_eq!(m.construct_wrapping_address(c, 16).unwrap(), c);
    let big = manager(true);
    let wrapped = big.construct_wrapping_address(near_end, 4).unwrap();
    assert_eq!(
        big.find_join(wrapped.offset()).unwrap().pieces(),
        [vn(STACK, 0xffff_fffe, 2), vn(STACK, 0, 2)]
    );
}

#[test]
fn equivalent_addresses_follow_memory_order() {
    let le = manager(false);
    let record = le.find_add_join(vec![EDX, EAX], 0).unwrap();
    // Little endian: the join's low bytes are eax.
    assert_eq!(
        record.equivalent_address(&le, 1),
        Some((Address::new(REGISTER, 1), 1, 1))
    );
    assert_eq!(
        record.equivalent_address(&le, 6),
        Some((Address::new(REGISTER, 10), 0, 2))
    );
    assert_eq!(record.equivalent_address(&le, 8), None);
    let be = manager(true);
    let record = be.find_add_join(vec![EDX, EAX], 0).unwrap();
    assert_eq!(
        record.equivalent_address(&be, 1),
        Some((Address::new(REGISTER, 9), 0, 1))
    );
    assert_eq!(
        record.equivalent_address(&be, 6),
        Some((Address::new(REGISTER, 2), 1, 2))
    );
}

#[test]
fn renormalize() {
    let m = manager(false);
    let join = m
        .construct_join_address(EDX.addr(), 4, EAX.addr(), 4)
        .unwrap();
    let at = |delta: u64| Address::new(JOIN, join.offset() + delta);
    // The whole join is already normal.
    assert_eq!(join.renormalize(&m, 8).unwrap(), join);
    // Within one piece: that piece's address.
    assert_eq!(at(0).renormalize(&m, 4).unwrap(), Address::new(REGISTER, 0));
    assert_eq!(at(5).renormalize(&m, 2).unwrap(), Address::new(REGISTER, 9));
    // Across both pieces: a new join of the parts.
    let mid = at(2).renormalize(&m, 4).unwrap();
    assert!(mid.is_join(&m));
    assert_eq!(
        m.find_join(mid.offset()).unwrap().pieces(),
        [vn(REGISTER, 8, 2), vn(REGISTER, 2, 2)]
    );
    assert_eq!(
        at(6).renormalize(&m, 4),
        Err(SpaceError::JoinRangeNotCovered)
    );
    assert_eq!(
        Address::new(JOIN, 0x1000).renormalize(&m, 4),
        Err(SpaceError::JoinNotCovered)
    );
    // Other addresses are left alone.
    assert_eq!(EAX.addr().renormalize(&m, 4).unwrap(), EAX.addr());

    let be = manager(true);
    let join = be
        .construct_join_address(EDX.addr(), 4, EAX.addr(), 4)
        .unwrap();
    let mid = Address::new(JOIN, join.offset() + 2)
        .renormalize(&be, 4)
        .unwrap();
    assert_eq!(
        be.find_join(mid.offset()).unwrap().pieces(),
        [vn(REGISTER, 10, 2), vn(REGISTER, 0, 2)]
    );
}

#[test]
fn strip_pieces() {
    let m = manager(false);
    let three = m.find_add_join(vec![ESP, EDX, EAX], 0).unwrap();
    let rest = m.strip_join_piece(&three, 0).unwrap();
    assert_eq!(m.find_join(rest.offset).unwrap().pieces(), [EDX, EAX]);
    let rest = m.strip_join_piece(&three, 2).unwrap();
    assert_eq!(m.find_join(rest.offset).unwrap().pieces(), [ESP, EDX]);
    assert_eq!(
        m.strip_join_piece(&three, 1),
        Err(SpaceError::StripMiddlePiece)
    );
    let two = m.find_add_join(vec![EDX, EAX], 0).unwrap();
    assert_eq!(m.strip_join_piece(&two, 0).unwrap(), EAX);
    assert_eq!(m.strip_join_piece(&two, 1).unwrap(), EDX);
    let one = m.find_add_join(vec![EAX], 10).unwrap();
    assert_eq!(
        m.strip_join_piece(&one, 0),
        Err(SpaceError::JoinWithoutPieces)
    );
}

#[test]
fn overlap_through_join_pieces() {
    let m = manager(false);
    let join = m
        .construct_join_address(EDX.addr(), 4, EAX.addr(), 4)
        .unwrap();
    // edx holds the join's bytes 4..8 in a little-endian space.
    assert_eq!(
        Address::new(REGISTER, 9).overlap_join(&m, 0, join, 8),
        Some(5)
    );
    assert_eq!(
        Address::new(REGISTER, 1).overlap_join(&m, 1, join, 8),
        Some(2)
    );
    assert_eq!(Address::new(REGISTER, 9).overlap_join(&m, 0, join, 5), None);
    assert_eq!(
        Address::new(REGISTER, 20).overlap_join(&m, 0, join, 8),
        None
    );
    // A point in the join space itself.
    assert_eq!(
        Address::new(JOIN, join.offset() + 3).overlap_join(&m, 0, join, 8),
        Some(3)
    );
    assert_eq!(
        Address::new(JOIN, join.offset()).overlap_join(&m, -1, join, 8),
        None
    );
    // Constants never overlap.
    assert_eq!(
        Address::new(CONSTANT_SPACE, 0).overlap_join(&m, 0, join, 8),
        None
    );
    assert_eq!(
        Address::new(RAM, 0).overlap_join(&m, 0, Address::new(CONSTANT_SPACE, 0), 8),
        None
    );
    // Ordinary spaces behave like overlap.
    let base = Address::new(RAM, 0x100);
    assert_eq!(
        Address::new(RAM, 0x105).overlap_join(&m, 0, base, 8),
        Some(5)
    );
    assert_eq!(Address::new(RAM, 0x105).overlap(&m, 0, base, 4), None);
    assert_eq!(Address::new(RAM, 0x0ff).overlap(&m, 2, base, 4), Some(1));
    assert_eq!(Address::new(UNIQUE, 0x105).overlap(&m, 0, base, 8), None);
    // In big endian the pieces are walked from the most significant.
    let be = manager(true);
    let join = be
        .construct_join_address(EDX.addr(), 4, EAX.addr(), 4)
        .unwrap();
    assert_eq!(
        Address::new(REGISTER, 9).overlap_join(&be, 0, join, 8),
        Some(1)
    );
}

#[test]
fn join_text_forms() {
    let m = manager(false);
    let join = m
        .construct_join_address(EDX.addr(), 4, EAX.addr(), 4)
        .unwrap();
    assert_eq!(join.raw(&m).to_string(), "{edx,eax}");
    let ext = m
        .construct_float_extension_address(EAX.addr(), 4, 10)
        .unwrap();
    assert_eq!(ext.raw(&m).to_string(), "{eax:10}");
    let pad = m.find_add_join(vec![vn(CONSTANT_SPACE, 0, 3)], 0).unwrap();
    assert_eq!(pad.unified().addr().raw(&m).to_string(), "{pad:3:3}");
    let unnamed = m
        .find_add_join(vec![vn(RAM, 0x1000, 4), vn(RAM, 0x2000, 4)], 0)
        .unwrap();
    assert_eq!(
        unnamed.unified().addr().raw(&m).to_string(),
        "{r0x00001000,r0x00002000}"
    );
    assert_eq!(
        Address::new(JOIN, 0x999).raw(&m).to_string(),
        "{unlinked:0x999}"
    );

    // Reading: register names, or shortcut and offset.
    assert_eq!(m.read(JOIN, "edx,eax").unwrap(), (join.offset(), 8));
    assert_eq!(m.read(JOIN, "%0x8:4,%0x0:4").unwrap(), (join.offset(), 8));
    assert_eq!(
        m.read(JOIN, "r0x1000,r0x2000").unwrap(),
        (unnamed.unified().offset, 8)
    );
    assert_eq!(m.read(JOIN, ""), Err(SpaceError::JoinWithoutPieces));
    assert_eq!(m.read(JOIN, "eax"), Err(SpaceError::JoinWithoutLogicalSize));
    assert_eq!(m.read(JOIN, "?12,eax"), Err(SpaceError::BadJoinString));
    // A piece naming the join space recurses; the depth is bounded.
    assert_eq!(m.read(JOIN, "jj"), Err(SpaceError::JoinWithoutPieces));
    let deep = "j".repeat(MAX_JOIN_READ_DEPTH + 2);
    assert_eq!(m.read(JOIN, &deep), Err(SpaceError::BadJoinString));
}
