//! Fixtures shared by the integration tests: managers laid out like a small
//! processor's, and a register table.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses a different part of the fixtures"
)]

use std::sync::Arc;

use bk_core::{RegisterLookup, Space, SpaceId, SpaceManager, VarnodeData};

pub const RAM: SpaceId = SpaceId::new(2);
pub const REGISTER: SpaceId = SpaceId::new(3);
pub const UNIQUE: SpaceId = SpaceId::new(4);
pub const JOIN: SpaceId = SpaceId::new(5);
pub const STACK: SpaceId = SpaceId::new(6);
pub const FSPEC: SpaceId = SpaceId::new(7);
pub const IOP: SpaceId = SpaceId::new(8);

/// Registers by name and location; lookups by location find the smallest
/// register containing the bytes.
#[derive(Debug, Default)]
pub struct Registers {
    entries: Vec<(&'static str, VarnodeData)>,
}

impl Registers {
    pub fn with(entries: &[(&'static str, SpaceId, u64, u32)]) -> Self {
        Self {
            entries: entries
                .iter()
                .map(|&(name, space, offset, size)| (name, VarnodeData::new(space, offset, size)))
                .collect(),
        }
    }
}

impl RegisterLookup for Registers {
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.entries
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, data)| *data)
    }

    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        let wanted = VarnodeData::new(space, offset, size);
        self.entries
            .iter()
            .filter(|(_, data)| data.contains(&wanted))
            .min_by_key(|(_, data)| data.size)
            .map(|(name, _)| *name)
    }

    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        let wanted = VarnodeData::new(space, offset, size);
        self.entries
            .iter()
            .find(|(_, data)| *data == wanted)
            .map(|(name, _)| *name)
    }
}

/// The registers of the fixture processor: `eax` with its halves, `ebx`,
/// `esp`, and the 8-byte pair `edx:eax` named `edxeax` in big-endian
/// layouts.
pub fn registers() -> Registers {
    Registers::with(&[
        ("eax", REGISTER, 0, 4),
        ("ax", REGISTER, 0, 2),
        ("ecx", REGISTER, 4, 4),
        ("edx", REGISTER, 8, 4),
        ("ebx", REGISTER, 12, 4),
        ("esp", REGISTER, 16, 4),
        ("rax", REGISTER, 0, 8),
    ])
}

/// A 32-bit processor: const, OTHER, ram (4 bytes), register, unique, join,
/// stack (on ram, base register esp), fspec and iop; default space ram.
pub fn manager(big_endian: bool) -> SpaceManager {
    let mut m = SpaceManager::new();
    m.set_registers(Arc::new(registers()));
    m.insert_space(Space::constant()).unwrap();
    m.insert_space(Space::other()).unwrap();
    let ram = Space::processor("ram", big_endian, 4, 1, RAM.index(), true, 1, 1).unwrap();
    m.insert_space(ram.clone()).unwrap();
    m.insert_space(
        Space::processor("register", big_endian, 4, 1, REGISTER.index(), true, 0, 0).unwrap(),
    )
    .unwrap();
    m.insert_space(Space::unique(UNIQUE.index(), big_endian).unwrap())
        .unwrap();
    m.insert_space(Space::join(JOIN.index(), big_endian).unwrap())
        .unwrap();
    m.insert_space(Space::spacebase("stack", STACK.index(), 4, &ram, 1, true, big_endian).unwrap())
        .unwrap();
    m.insert_space(Space::fspec(FSPEC.index()).unwrap())
        .unwrap();
    m.insert_space(Space::iop(IOP.index()).unwrap()).unwrap();
    m.set_default_code_space(RAM).unwrap();
    m
}

/// A varnode in the given space.
pub fn vn(space: SpaceId, offset: u64, size: u32) -> VarnodeData {
    VarnodeData::new(space, offset, size)
}
