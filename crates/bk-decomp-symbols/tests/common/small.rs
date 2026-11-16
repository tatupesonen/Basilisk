//! A small architecture built in test code (spec 6.1): const, OTHER,
//! unique, ram (8-byte), register (4-byte, registers r0..r3 and sp), fspec,
//! iop, join, stack; a type factory with Ghidra's default core types.

use std::sync::Arc;

use bk_core::{Space, SpaceId, SpaceManager, VarnodeData};
use bk_decomp_symbols::{ArchEnv, Database};
use bk_decomp_types::{DataOrganization, SpaceInfo, TypeEnv, TypeFactory};

pub const RAM: SpaceId = SpaceId::new(3);
pub const REG: SpaceId = SpaceId::new(4);
pub const JOIN: SpaceId = SpaceId::new(7);
pub const STACK: SpaceId = SpaceId::new(8);

pub fn spaces(big_endian: bool) -> SpaceManager {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    m.insert_space(Space::other()).unwrap();
    m.insert_space(Space::unique(2, big_endian).unwrap())
        .unwrap();
    let ram = Space::processor("ram", big_endian, 8, 1, 3, true, 0, 0).unwrap();
    m.insert_space(ram.clone()).unwrap();
    m.insert_space(Space::processor("register", big_endian, 4, 1, 4, false, 0, 0).unwrap())
        .unwrap();
    m.insert_space(Space::fspec(5).unwrap()).unwrap();
    m.insert_space(Space::iop(6).unwrap()).unwrap();
    m.insert_space(Space::join(7, big_endian).unwrap()).unwrap();
    m.insert_space(Space::spacebase("stack", 8, 8, &ram, 0, true, big_endian).unwrap())
        .unwrap();
    m.set_default_code_space(RAM).unwrap();
    m.set_default_data_space(RAM).unwrap();
    let regs = ["r0", "r1", "r2", "r3", "sp"]
        .iter()
        .enumerate()
        .map(|(i, n)| ((*n).to_owned(), VarnodeData::new(REG, 8 * i as u64, 8)))
        .collect();
    m.set_registers(Arc::new(Regs(regs)));
    m
}

/// Registers by name (the architecture's `getRegister` and
/// `getRegisterName`).
#[derive(Debug)]
pub struct Regs(pub Vec<(String, VarnodeData)>);

impl bk_core::RegisterLookup for Regs {
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
    }
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.exact_register_name(space, offset, size)
    }
    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.0
            .iter()
            .find(|(_, v)| v.space() == Some(space) && v.offset == offset && v.size == size)
            .map(|(n, _)| n.as_str())
    }
}

impl bk_decomp_symbols::RegisterNames for Regs {
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        bk_core::RegisterLookup::register_name(self, space, offset, size)
    }
}

pub fn types(m: &SpaceManager) -> TypeFactory {
    let info = |s: &Space| SpaceInfo {
        id: s.id(),
        name: s.name().to_owned(),
        addr_size: s.addr_size() as i32,
        word_size: s.word_size(),
        big_endian: s.is_big_endian(),
    };
    let mut env = TypeEnv::simple(8, false);
    env.data_space = info(m.space(RAM).unwrap());
    env.other_spaces = m.spaces().filter(|s| s.id() != RAM).map(info).collect();
    TypeFactory::with_core_types(env, DataOrganization::default()).unwrap()
}

/// A fresh database over the small architecture.
pub fn db() -> (Database, TypeFactory) {
    let m = spaces(false);
    let t = types(&m);
    (Database::new(ArchEnv::new(Arc::new(m)), true), t)
}

/// The environment alone.
pub fn env() -> (ArchEnv, TypeFactory) {
    let m = spaces(false);
    let t = types(&m);
    (ArchEnv::new(Arc::new(m)), t)
}
