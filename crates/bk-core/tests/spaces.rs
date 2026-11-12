//! Spaces and the space manager: construction, insertion rules, lookups,
//! shortcuts, truncation, base registers, pointer bounds, text forms.

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

use bk_core::space::{CONSTANT_SPACE, MAX_SPACE_INDEX, OTHER_SPACE};
use bk_core::{
    Address, AddressResolver, Range, Space, SpaceError, SpaceFlags, SpaceId, SpaceKind,
    SpaceManager, SpaceType, TruncationTag,
};
use bk_marshal::SpaceResolver;
use common::{FSPEC, IOP, JOIN, RAM, REGISTER, STACK, UNIQUE, manager, vn};
use rstest::rstest;

#[test]
fn special_spaces_have_ghidras_constants() {
    let c = Space::constant();
    assert_eq!((c.name(), c.index(), c.addr_size()), ("const", 0, 8));
    assert_eq!(c.space_type(), SpaceType::Constant);
    assert!(!c.is_heritaged() && !c.does_deadcode() && !c.is_big_endian());
    assert!(c.no_high_ptr_possible());

    let o = Space::other();
    assert_eq!((o.name(), o.index(), o.addr_size()), ("OTHER", 1, 8));
    assert_eq!(o.space_type(), SpaceType::Processor);
    assert!(o.is_other_space() && !o.is_heritaged());

    let u = Space::unique(4, true).unwrap();
    assert_eq!((u.name(), u.addr_size()), ("unique", 4));
    assert_eq!(u.space_type(), SpaceType::Internal);
    assert!(u.has_physical() && u.is_heritaged() && u.is_big_endian());

    let j = Space::join(5, false).unwrap();
    assert_eq!((j.name(), j.addr_size()), ("join", 4));
    assert!(!j.is_heritaged() && j.does_deadcode());

    for (s, name, ty) in [
        (Space::fspec(7).unwrap(), "fspec", SpaceType::Fspec),
        (Space::iop(8).unwrap(), "iop", SpaceType::Iop),
    ] {
        assert_eq!((s.name(), s.addr_size(), s.space_type()), (name, 8, ty));
        assert!(!s.is_heritaged() && !s.does_deadcode() && !s.is_big_endian());
        assert!(s.flags().contains(SpaceFlags::ADDRESSABLE_ALL));
    }
}

#[test]
fn processor_space_derived_values() {
    let ram = Space::processor("ram", true, 4, 1, 2, true, 1, 2).unwrap();
    assert_eq!(ram.highest(), 0xffff_ffff);
    assert_eq!(ram.pointer_lower_bound(), 0x1000);
    assert_eq!(ram.pointer_upper_bound(), 0xffff_efff);
    assert_eq!((ram.delay(), ram.deadcode_delay()), (1, 2));
    assert!(ram.flags().contains(SpaceFlags::ADDRESSABLE_ALL));
    let small = Space::processor("io", false, 2, 1, 3, false, 0, 0).unwrap();
    assert_eq!(small.pointer_lower_bound(), 0x100);
    assert!(small.no_high_ptr_possible());
    // Word-addressed: 2-byte words, 2-byte addresses.
    let code = Space::processor("code", false, 2, 2, 4, true, 1, 1).unwrap();
    assert_eq!(code.highest(), 0x1_ffff);
    assert_eq!(code.address_to_byte(0x10), 0x20);
    assert_eq!(code.byte_to_address(0x21), 0x10);
    assert_eq!(code.address_to_byte_int(-3), -6);
    assert_eq!(code.byte_to_address_int(-6), -3);
    let wide = Space::processor("wide", false, 8, 1, 5, true, 1, 1).unwrap();
    assert_eq!(wide.highest(), u64::MAX);
}

#[test]
fn constructors_reject_bad_arguments() {
    assert!(matches!(
        Space::processor("x", false, 4, 0, 2, true, 1, 1),
        Err(SpaceError::ZeroWordSize { .. })
    ));
    assert!(matches!(
        Space::processor("x", false, 4, 1, MAX_SPACE_INDEX + 1, true, 1, 1),
        Err(SpaceError::IndexTooLarge { .. })
    ));
    assert!(Space::processor("x", false, 4, 1, MAX_SPACE_INDEX, true, 1, 1).is_ok());
}

#[rstest]
#[case(4, 0x1234, 0x1234)]
#[case(4, 0x1_0000_0005, 5)]
#[case(2, 0x1_0005, 5)]
#[case(8, u64::MAX, u64::MAX)]
#[case(1, 0x1ff, 0xff)]
fn wrap_offset(#[case] size: u32, #[case] offset: u64, #[case] wrapped: u64) {
    let space = Space::processor("s", false, size, 1, 2, true, 1, 1).unwrap();
    assert_eq!(space.wrap_offset(offset), wrapped);
}

#[test]
fn wrap_offset_follows_ghidras_signed_remainder() {
    // Ghidra takes the remainder of the offset as a signed number, so an
    // offset with the top bit set wraps as a negative value. It shows only
    // when the modulus is not a power of two: 1-byte addresses of 3-byte
    // words give a modulus of 0x300.
    let space = Space::processor("s", false, 1, 3, 2, true, 1, 1).unwrap();
    assert_eq!(space.highest(), 0xff * 3 + 2);
    let modulus = 0x300_i64;
    let expected = (-1_i64).rem_euclid(modulus) as u64;
    assert_eq!(space.wrap_offset(u64::MAX), expected);
}

#[test]
fn manager_lookups() {
    let m = manager(false);
    assert_eq!(m.num_spaces(), 9);
    assert_eq!(m.space_by_name("ram").unwrap().id(), RAM);
    assert!(m.space_by_name("nope").is_none());
    assert_eq!(m.constant_space().unwrap().id(), CONSTANT_SPACE);
    assert_eq!(m.unique_space().unwrap().id(), UNIQUE);
    assert_eq!(m.join_space().unwrap().id(), JOIN);
    assert_eq!(m.stack_space().unwrap().id(), STACK);
    assert_eq!(m.fspec_space().unwrap().id(), FSPEC);
    assert_eq!(m.iop_space().unwrap().id(), IOP);
    assert_eq!(m.default_code_space().unwrap().id(), RAM);
    assert_eq!(m.default_data_space().unwrap().id(), RAM);
    assert_eq!(m.default_size().unwrap(), 4);
    assert_eq!(m.first_space(), Some(CONSTANT_SPACE));
    assert_eq!(m.next_space_after(RAM), Some(REGISTER));
    assert_eq!(m.next_space_after(IOP), None);
    assert_eq!(m.space_at(3).unwrap().name(), "register");
    let names: Vec<&str> = m.spaces().map(Space::name).collect();
    assert_eq!(
        names,
        [
            "const", "OTHER", "ram", "register", "unique", "join", "stack", "fspec", "iop"
        ]
    );
    // As a resolver.
    assert_eq!(SpaceResolver::space_by_name(&m, "register"), Some(REGISTER));
    assert_eq!(m.space_by_index(4), Some(UNIQUE));
    assert_eq!(m.space_by_index(99), None);
    assert_eq!(m.space_count(), 9);
    assert_eq!(SpaceResolver::stack_space(&m), Some(STACK));
    assert_eq!(SpaceResolver::join_space(&m), Some(JOIN));
    // Overlay containment.
    assert_eq!(m.space(STACK).unwrap().contain(), Some(RAM));
}

#[test]
fn shortcuts() {
    let m = manager(false);
    let shortcut = |id| m.space(id).unwrap().shortcut().unwrap();
    assert_eq!(shortcut(CONSTANT_SPACE), '#');
    assert_eq!(shortcut(OTHER_SPACE), 'o');
    assert_eq!(shortcut(RAM), 'r');
    assert_eq!(shortcut(REGISTER), '%');
    assert_eq!(shortcut(UNIQUE), 'u');
    assert_eq!(shortcut(JOIN), 'j');
    assert_eq!(shortcut(STACK), 's');
    assert_eq!(shortcut(FSPEC), 'f');
    assert_eq!(shortcut(IOP), 'i');
    assert_eq!(m.space_by_shortcut('%').unwrap().id(), REGISTER);
    assert!(m.space_by_shortcut('q').is_none());
}

#[test]
fn shortcut_collisions_move_to_the_next_letter() {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    // "Rom" lowercases to r; "rx" collides and gets s; "zed" gets z, then
    // "z2" wraps to a.
    for (i, name) in ["Rom", "rx", "zed", "z2"].into_iter().enumerate() {
        m.insert_space(Space::processor(name, false, 4, 1, i as u32 + 2, true, 1, 1).unwrap())
            .unwrap();
    }
    let shortcut = |name| m.space_by_name(name).unwrap().shortcut().unwrap();
    assert_eq!(
        [
            shortcut("Rom"),
            shortcut("rx"),
            shortcut("zed"),
            shortcut("z2")
        ],
        ['r', 's', 'z', 'a']
    );
    // After every letter is taken, the 27th collision gives z unregistered.
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    for i in 0..27u32 {
        m.insert_space(Space::processor(&format!("a{i}"), false, 4, 1, i + 2, true, 1, 1).unwrap())
            .unwrap();
    }
    assert_eq!(m.space_at(28).unwrap().shortcut(), Some('z'));
    assert_eq!(m.space_by_shortcut('z').unwrap().index(), 27);
}

#[test]
fn insertion_rules() {
    let fresh = || {
        let mut m = SpaceManager::new();
        m.insert_space(Space::constant()).unwrap();
        m
    };
    let ram = Space::processor("ram", false, 4, 1, 2, true, 1, 1).unwrap();

    // Reserved names must match their kinds, and vice versa.
    let mut m = fresh();
    assert!(matches!(
        m.insert_space(Space::processor("const", false, 4, 1, 3, true, 1, 1).unwrap()),
        Err(SpaceError::DuplicateSpace { .. })
    ));
    // One of each special space.
    m.insert_space(Space::unique(3, false).unwrap()).unwrap();
    assert!(matches!(
        m.insert_space(Space::unique(4, false).unwrap()),
        Err(SpaceError::DuplicateSpace { .. })
    ));
    m.insert_space(Space::join(5, false).unwrap()).unwrap();
    assert!(matches!(
        m.insert_space(Space::join(6, false).unwrap()),
        Err(SpaceError::DuplicateSpace { .. })
    ));
    // Indices and names are unique.
    m.insert_space(ram.clone()).unwrap();
    assert!(matches!(
        m.insert_space(Space::processor("rom", false, 4, 1, 2, true, 1, 1).unwrap()),
        Err(SpaceError::DuplicateIndex { ref existing, .. }) if existing == "ram"
    ));
    assert!(matches!(
        m.insert_space(Space::processor("ram", false, 4, 1, 9, true, 1, 1).unwrap()),
        Err(SpaceError::DuplicateSpace { .. })
    ));
    // Index 0 is the constant space's alone.
    assert!(matches!(
        fresh().insert_space(Space::processor("x", false, 4, 1, 0, true, 1, 1).unwrap()),
        Err(SpaceError::ReservedIndexZero { .. })
    ));
    let mut empty = SpaceManager::new();
    assert!(matches!(
        empty.insert_space(Space::processor("x", false, 4, 1, 0, true, 1, 1).unwrap()),
        Err(SpaceError::ReservedIndexZero { .. })
    ));
    // OTHER must be at index 1: it is built there, so a failure needs index 1
    // taken by something else first.
    let mut m = fresh();
    m.insert_space(Space::processor("x", false, 4, 1, 1, true, 1, 1).unwrap())
        .unwrap();
    assert!(matches!(
        m.insert_space(Space::other()),
        Err(SpaceError::DuplicateIndex { .. })
    ));
    // A second stack.
    let mut m = fresh();
    m.insert_space(ram.clone()).unwrap();
    m.insert_space(Space::spacebase("stack", 3, 4, &ram, 1, true, false).unwrap())
        .unwrap();
    assert!(matches!(
        m.insert_space(Space::spacebase("stack", 4, 4, &ram, 1, true, false).unwrap()),
        Err(SpaceError::DuplicateSpace { .. })
    ));
    // A failed insertion leaves nothing behind.
    assert_eq!(m.num_spaces(), 4);
    assert!(m.space_at(4).is_none());
    // An overlay of a space the manager does not have.
    let mut m = fresh();
    assert!(matches!(
        m.insert_space(Space::overlay("ov", 3, &ram).unwrap()),
        Err(SpaceError::NoSuchSpace(_))
    ));
}

#[test]
fn overlays_copy_their_base_and_mark_it() {
    let mut m = manager(true);
    let ram = m.space(RAM).unwrap().clone();
    let ov = Space::overlay("ov", 12, &ram).unwrap();
    assert_eq!(ov.space_type(), SpaceType::Processor);
    assert!(matches!(ov.kind(), SpaceKind::Overlay { base } if *base == RAM));
    assert!(ov.is_overlay() && ov.is_big_endian() && ov.has_physical());
    assert_eq!((ov.addr_size(), ov.delay()), (4, 1));
    m.insert_space(ov).unwrap();
    assert!(m.space(RAM).unwrap().is_overlay_base());
    // Index gaps are allowed.
    assert_eq!(m.num_spaces(), 13);
    assert!(m.space_at(10).is_none());
    assert_eq!(m.next_space_after(IOP), Some(SpaceId::new(12)));
}

#[test]
fn default_spaces() {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    assert_eq!(m.default_size(), Err(SpaceError::NoDefaultSpace));
    assert_eq!(
        m.set_default_data_space(CONSTANT_SPACE),
        Err(SpaceError::DataSpaceBeforeCodeSpace)
    );
    assert_eq!(
        m.set_default_code_space(RAM),
        Err(SpaceError::BadDefaultSpaceIndex)
    );
    m.set_default_code_space(CONSTANT_SPACE).unwrap();
    assert_eq!(
        m.set_default_code_space(CONSTANT_SPACE),
        Err(SpaceError::DefaultSpaceSetTwice)
    );
    assert_eq!(
        m.set_default_data_space(RAM),
        Err(SpaceError::BadDefaultDataSpaceIndex)
    );
}

#[test]
fn copy_spaces_clones_the_layout() {
    let mut original = manager(false);
    original.set_default_data_space(REGISTER).unwrap();
    let mut copy = SpaceManager::new();
    copy.copy_spaces(&original).unwrap();
    assert_eq!(copy.num_spaces(), original.num_spaces());
    assert_eq!(copy.default_data_space().unwrap().id(), REGISTER);
    assert_eq!(copy.space(RAM).unwrap().shortcut(), Some('r'));
    // Unlike Ghidra, the spaces are not shared.
    original
        .truncate_space(&TruncationTag::new("ram", 2))
        .unwrap();
    assert_eq!(copy.space(RAM).unwrap().addr_size(), 4);
}

#[test]
fn truncation() {
    let mut m = manager(false);
    m.truncate_space(&TruncationTag::new("ram", 2)).unwrap();
    let ram = m.space(RAM).unwrap();
    assert!(ram.is_truncated());
    assert_eq!((ram.addr_size(), ram.minimum_pointer_size()), (2, 2));
    assert_eq!(ram.highest(), 0xffff);
    assert_eq!(
        m.truncate_space(&TruncationTag::new("nope", 2)),
        Err(SpaceError::UnknownTruncatedSpace("nope".into()))
    );
}

#[test]
fn base_registers() {
    let mut m = manager(true);
    let stack = m.space(STACK).unwrap();
    assert_eq!(stack.num_spacebase(), 0);
    assert!(matches!(
        stack.spacebase_register(0),
        Err(SpaceError::NoBaseRegister { .. })
    ));
    assert!(matches!(
        m.space(RAM).unwrap().spacebase_register(0),
        Err(SpaceError::NotVirtual { .. })
    ));
    assert!(m.space(RAM).unwrap().stack_grows_negative());
    // An 8-byte register truncated to 4 bytes: big endian keeps the low end.
    let rsp = vn(REGISTER, 0x20, 8);
    m.add_spacebase_pointer(STACK, rsp, 4, true).unwrap();
    let stack = m.space(STACK).unwrap();
    assert_eq!(stack.num_spacebase(), 1);
    assert_eq!(stack.spacebase_register(0).unwrap(), vn(REGISTER, 0x24, 4));
    assert_eq!(stack.spacebase_register_full(0).unwrap(), rsp);
    assert!(matches!(
        stack.spacebase_register(1),
        Err(SpaceError::NoBaseRegister { .. })
    ));
    // Ghidra compares a new register with the truncated one, so attaching the
    // same register again fails...
    assert!(matches!(
        m.add_spacebase_pointer(STACK, rsp, 4, true),
        Err(SpaceError::SecondBaseRegister { .. })
    ));
    // ...while attaching the truncated form succeeds.
    m.add_spacebase_pointer(STACK, vn(REGISTER, 0x24, 4), 4, true)
        .unwrap();
    assert!(matches!(
        m.add_spacebase_pointer(STACK, vn(REGISTER, 0x24, 4), 4, false),
        Err(SpaceError::SecondBaseRegister { .. })
    ));
    assert!(matches!(
        m.add_spacebase_pointer(RAM, rsp, 4, true),
        Err(SpaceError::NotVirtual { .. })
    ));
    // Little endian keeps the offset.
    let mut m = manager(false);
    m.add_spacebase_pointer(STACK, rsp, 4, false).unwrap();
    let stack = m.space(STACK).unwrap();
    assert_eq!(stack.spacebase_register(0).unwrap(), vn(REGISTER, 0x20, 4));
    assert!(!stack.stack_grows_negative());
}

#[test]
fn space_flag_setters() {
    let mut m = manager(false);
    m.set_reverse_justified(REGISTER).unwrap();
    assert!(m.space(REGISTER).unwrap().is_reverse_justified());
    m.mark_near_pointers(RAM, 2).unwrap();
    let ram = m.space(RAM).unwrap();
    assert!(ram.has_near_pointers());
    assert_eq!(ram.minimum_pointer_size(), 2);
    m.mark_near_pointers(RAM, 1).unwrap();
    assert_eq!(m.space(RAM).unwrap().minimum_pointer_size(), 2);
    m.set_deadcode_delay(RAM, 7).unwrap();
    assert_eq!(m.space(RAM).unwrap().deadcode_delay(), 7);
    m.set_infer_ptr_bounds(&Range::new(RAM, 0x40_0000, 0x80_0000))
        .unwrap();
    let ram = m.space(RAM).unwrap();
    assert_eq!(
        (ram.pointer_lower_bound(), ram.pointer_upper_bound()),
        (0x40_0000, 0x80_0000)
    );
    let missing = SpaceId::new(77);
    assert_eq!(
        m.set_deadcode_delay(missing, 1),
        Err(SpaceError::NoSuchSpace(missing))
    );
}

#[test]
fn high_pointers() {
    let mut m = manager(false);
    let a = Address::new(RAM, 0x1000);
    assert!(m.high_ptr_possible(a, 4));
    assert!(!m.high_ptr_possible(Address::new(REGISTER, 0), 4));
    assert!(!m.high_ptr_possible(Address::INVALID, 4));
    m.add_no_high_ptr(&Range::new(RAM, 0x1000, 0x1fff)).unwrap();
    assert!(
        !m.space(RAM)
            .unwrap()
            .flags()
            .contains(SpaceFlags::ADDRESSABLE_ALL)
    );
    assert!(!a.high_ptr_possible(&m, 4));
    assert!(Address::new(RAM, 0x2000).high_ptr_possible(&m, 4));
    assert!(m.high_ptr_possible(Address::new(RAM, 0x1ffe), 4));
    m.add_no_high_ptr(&Range::new(RAM, 0, 0xffff_ffff)).unwrap();
    assert!(m.space(RAM).unwrap().no_high_ptr_possible());
    assert!(!m.high_ptr_possible(Address::new(RAM, 0x5000_0000), 1));
}

#[derive(Debug)]
struct Segmented;

impl AddressResolver for Segmented {
    fn resolve(&self, value: u64, _size: u32, point: Address) -> (Address, u64) {
        let full = (point.offset() & 0xffff_0000) | value;
        (Address::new(RAM, full), full)
    }
}

#[test]
fn constant_resolution() {
    let mut m = manager(false);
    let point = Address::new(RAM, 0x1234_0000);
    assert_eq!(
        m.resolve_constant(RAM, 0x1_0000_0010, 4, point).unwrap(),
        (Address::new(RAM, 0x10), 0x1_0000_0010)
    );
    m.insert_resolver(RAM, Box::new(Segmented)).unwrap();
    assert_eq!(
        m.resolve_constant(RAM, 0x10, 2, point).unwrap(),
        (Address::new(RAM, 0x1234_0010), 0x1234_0010)
    );
    assert!(
        m.insert_resolver(SpaceId::new(50), Box::new(Segmented))
            .is_err()
    );
    assert_eq!(Address::constant(5), Address::new(CONSTANT_SPACE, 5));
    let as_const = Address::const_from_space(RAM);
    assert!(as_const.is_constant());
    assert_eq!(
        bk_core::VarnodeData::from_address(as_const, 8).space_from_const(),
        Some(RAM)
    );
}

#[test]
fn registers_are_consulted() {
    let m = manager(false);
    assert_eq!(m.register("eax").unwrap(), vn(REGISTER, 0, 4));
    assert_eq!(
        m.register("zz"),
        Err(SpaceError::UnknownRegister("zz".into()))
    );
    let bare = SpaceManager::new();
    assert!(bare.register("eax").is_err());
    let mut m2 = SpaceManager::new();
    m2.set_registers(Arc::new(common::registers()));
    assert!(m2.registers().register("esp").is_some());
}

#[test]
fn parse_address_simple() {
    let mut m = manager(false);
    assert_eq!(
        m.parse_address_simple("ram:0x1000").unwrap(),
        Address::new(RAM, 0x1000)
    );
    assert_eq!(
        m.parse_address_simple("1f").unwrap(),
        Address::new(RAM, 0x1f)
    );
    assert_eq!(
        m.parse_address_simple("register:10").unwrap(),
        Address::new(REGISTER, 0x10)
    );
    assert_eq!(
        m.parse_address_simple("rom:10"),
        Err(SpaceError::UnknownSpaceName("rom".into()))
    );
    // Word-addressed spaces scale to bytes.
    m.insert_space(Space::processor("code", false, 2, 2, 20, true, 1, 1).unwrap())
        .unwrap();
    assert_eq!(
        m.parse_address_simple("code:0x10").unwrap(),
        Address::new(SpaceId::new(20), 0x20)
    );
}
