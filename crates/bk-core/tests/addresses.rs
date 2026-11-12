//! Addresses against a manager: arithmetic, containment, contiguity, and the
//! `printRaw`/`read` text forms of each kind of space.

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

use bk_core::space::{CONSTANT_SPACE, OTHER_SPACE};
use bk_core::{Address, Space, SpaceError, SpaceId, SpaceManager};
use common::{FSPEC, JOIN, RAM, REGISTER, STACK, UNIQUE, manager, vn};
use rstest::rstest;

const CODE: SpaceId = SpaceId::new(10);
const WIDE: SpaceId = SpaceId::new(11);

/// The fixture plus a word-addressed space and an 8-byte space.
fn with_extra_spaces() -> SpaceManager {
    let mut m = manager(false);
    m.insert_space(Space::processor("code", false, 2, 2, CODE.index(), true, 1, 1).unwrap())
        .unwrap();
    m.insert_space(Space::processor("wide", true, 8, 1, WIDE.index(), true, 1, 1).unwrap())
        .unwrap();
    m
}

#[test]
fn arithmetic_wraps_at_the_space() {
    let m = manager(false);
    let a = Address::new(RAM, 0xffff_fffe);
    assert_eq!(a.add(&m, 4), Address::new(RAM, 2));
    assert_eq!(
        Address::new(RAM, 1).sub(&m, 2),
        Address::new(RAM, 0xffff_ffff)
    );
    assert_eq!(a.add(&m, -2), Address::new(RAM, 0xffff_fffc));
    assert_eq!(Address::INVALID.add(&m, 3).offset(), 3);
    assert!(a.is_valid_range(&m, 2));
    assert!(!a.is_valid_range(&m, 3));
    assert!(!Address::INVALID.is_valid_range(&m, 1));
    assert_eq!(a.addr_size(&m), 4);
    assert_eq!(Address::constant(1).addr_size(&m), 8);
    assert_eq!(Address::INVALID.addr_size(&m), 0);
    assert_eq!(a.shortcut(&m), Some('r'));
    assert!(!a.is_big_endian(&m));
    assert!(Address::new(RAM, 0).is_big_endian(&manager(true)));
    assert!(Address::new(JOIN, 0).is_join(&m));
    assert!(!a.is_join(&m));
}

#[test]
fn justified_containment() {
    let le = manager(false);
    let be = manager(true);
    let word = Address::new(REGISTER, 0);
    let byte1 = Address::new(REGISTER, 1);
    // Little endian: distance from the start.
    assert_eq!(word.justified_contain(&le, 4, byte1, 1, false), Some(1));
    // Big endian: distance from the least significant (last) byte.
    assert_eq!(word.justified_contain(&be, 4, byte1, 1, false), Some(2));
    assert_eq!(word.justified_contain(&be, 4, byte1, 1, true), Some(1));
    assert_eq!(word.justified_contain(&le, 4, byte1, 4, false), None);
    assert_eq!(byte1.justified_contain(&le, 1, word, 1, false), None);
    assert_eq!(
        word.justified_contain(&le, 4, Address::new(RAM, 1), 1, false),
        None
    );
    assert!(byte1.contained_by(1, word, 4));
}

#[test]
fn contiguity() {
    let le = manager(false);
    let be = manager(true);
    let lo = Address::new(REGISTER, 0);
    let hi = Address::new(REGISTER, 4);
    assert!(hi.is_contiguous(&le, 4, lo, 4));
    assert!(!lo.is_contiguous(&le, 4, hi, 4));
    assert!(lo.is_contiguous(&be, 4, hi, 4));
    assert!(!hi.is_contiguous(&be, 4, lo, 4));
    assert!(!hi.is_contiguous(&le, 4, Address::new(RAM, 0), 4));
    // Wrapping: the last bytes of the space precede offset 0.
    assert!(Address::new(RAM, 0).is_contiguous(&le, 4, Address::new(RAM, 0xffff_fffc), 4));
    assert!(vn(REGISTER, 4, 4).is_contiguous(&le, &vn(REGISTER, 0, 4)));
    assert!(vn(REGISTER, 0, 8).contains(&vn(REGISTER, 4, 4)));
    assert!(!vn(REGISTER, 0, 8).contains(&vn(REGISTER, 6, 4)));
}

#[rstest]
#[case(RAM, 0x1234, "0x00001234")]
#[case(RAM, 0, "0x00000000")]
#[case(REGISTER, 0x10, "0x00000010")]
#[case(UNIQUE, 0x100, "0x00000100")]
#[case(STACK, 0xffff_fff0, "0xfffffff0")]
#[case(CONSTANT_SPACE, 0x1f, "0x1f")]
#[case(OTHER_SPACE, 0x10, "0x10")]
#[case(FSPEC, 0x10, "0x00000010")]
#[case(CODE, 0x20, "0x0010")]
#[case(CODE, 0x21, "0x0010+1")]
#[case(WIDE, 0x10, "0x00000010")]
#[case(WIDE, 0x1_0000_0000, "0x000100000000")]
#[case(WIDE, 0x1_0000_0000_0000, "0x0001000000000000")]
fn print_raw(#[case] space: SpaceId, #[case] offset: u64, #[case] expected: &str) {
    let m = with_extra_spaces();
    assert_eq!(Address::new(space, offset).raw(&m).to_string(), expected);
    assert_eq!(m.raw_offset(space, offset).unwrap().to_string(), expected);
}

#[test]
fn print_raw_extremes_and_sized() {
    let m = manager(false);
    assert_eq!(Address::INVALID.raw(&m).to_string(), "invalid_addr");
    assert_eq!(Address::MAXIMAL.raw(&m).to_string(), "maximal_addr");
    assert!(m.raw_offset(SpaceId::new(40), 0).is_err());
    // Registers by name, with an offset into them.
    assert_eq!(
        Address::new(REGISTER, 0).raw_sized(&m, 4).to_string(),
        "eax"
    );
    assert_eq!(Address::new(REGISTER, 0).raw_sized(&m, 2).to_string(), "ax");
    assert_eq!(
        Address::new(REGISTER, 2).raw_sized(&m, 1).to_string(),
        "eax+2"
    );
    assert_eq!(vn(REGISTER, 8, 4).raw(&m).to_string(), "edx");
    // Otherwise the shortcut and the raw offset.
    assert_eq!(
        Address::new(REGISTER, 0x40).raw_sized(&m, 4).to_string(),
        "%0x00000040"
    );
    assert_eq!(vn(RAM, 0x1000, 4).raw(&m).to_string(), "r0x00001000");
    assert_eq!(vn(CONSTANT_SPACE, 5, 4).raw(&m).to_string(), "#0x5");
    assert_eq!(
        Address::INVALID.raw_sized(&m, 4).to_string(),
        "invalid_addr"
    );
    assert_eq!(m.space(RAM).unwrap().print_offset(255), "0xff");
}

#[rstest]
#[case(RAM, "0x1000", (0x1000, 4))]
#[case(RAM, "4096", (0x1000, 4))]
#[case(RAM, "010", (8, 4))]
#[case(RAM, "0x1000:2", (0x1000, 2))]
#[case(RAM, "0x1000:2+0x10", (0x1010, 2))]
#[case(RAM, "0x1000+4", (0x1004, 4))]
#[case(RAM, "0x1000zz", (0x1000, 4))]
#[case(RAM, "junk", (0, 4))]
#[case(REGISTER, "eax", (0, 4))]
#[case(REGISTER, "ax", (0, 2))]
#[case(REGISTER, "eax:2", (0, 2))]
#[case(REGISTER, "eax+2", (2, 4))]
#[case(REGISTER, "ecx:1+3", (7, 1))]
#[case(CODE, "0x10", (0x20, 4))]
#[case(CODE, "0x10+1", (0x21, 4))]
fn read(#[case] space: SpaceId, #[case] text: &str, #[case] expected: (u64, u32)) {
    let m = with_extra_spaces();
    assert_eq!(m.read(space, text).unwrap(), expected, "{text}");
}

#[test]
fn read_needs_a_default_space_for_numbers() {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    assert_eq!(m.read(CONSTANT_SPACE, "5"), Err(SpaceError::NoDefaultSpace));
    let mut a = Address::new(CONSTANT_SPACE, 0);
    assert!(a.read(&m, "1").is_err());
    let mut invalid = Address::INVALID;
    assert_eq!(invalid.read(&m, "1"), Err(SpaceError::InvalidAddress));
    let m = manager(false);
    let mut a = Address::new(RAM, 0);
    assert_eq!(a.read(&m, "0x40:2").unwrap(), 2);
    assert_eq!(a, Address::new(RAM, 0x40));
}

#[test]
fn print_and_read_round_trip() {
    let m = with_extra_spaces();
    for (space, offset) in [
        (RAM, 0x1234_u64),
        (REGISTER, 0x40),
        (UNIQUE, 0x10_0000),
        (CODE, 0x20),
        (CODE, 0x21),
        (WIDE, 0x1234_5678_9abc),
    ] {
        let text = m.raw_offset(space, offset).unwrap().to_string();
        assert_eq!(m.read(space, &text).unwrap().0, offset, "{text}");
    }
}
