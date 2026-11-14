//! Shared test support: the test type model, a tiny C parser, a register
//! table, the Toy-like architecture of `testfuncproto.cc`, and Ghidra's
//! storage-string parser (`parseStore`).

#![allow(dead_code, reason = "each test crate uses part of the support")]

pub(crate) mod cparse;
pub(crate) mod testtypes;

use std::sync::Arc;

use bk_core::{Address, RegisterLookup, Space, SpaceId, SpaceManager, VarnodeData};
use bk_cspec::proto::ParameterPieces;
use bk_cspec::types::{Metatype, ParamTypes};
use bk_cspec::{CompilerSpec, ReadOptions};

/// Registers from a table (stands for the SLEIGH register source).
#[derive(Clone, Debug, Default)]
pub(crate) struct TableRegisters {
    regs: Vec<(String, VarnodeData)>,
}

impl TableRegisters {
    pub(crate) fn new(regs: Vec<(String, VarnodeData)>) -> Self {
        Self { regs }
    }
    pub(crate) fn all(&self) -> &[(String, VarnodeData)] {
        &self.regs
    }
}

impl RegisterLookup for TableRegisters {
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.regs.iter().find(|(n, _)| n == name).map(|r| r.1)
    }
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        let probe = VarnodeData::new(space, offset, size);
        self.regs
            .iter()
            .filter(|(_, v)| v.contains(&probe))
            .min_by_key(|(_, v)| v.size)
            .map(|(n, _)| n.as_str())
    }
    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.regs
            .iter()
            .find(|(_, v)| *v == VarnodeData::new(space, offset, size))
            .map(|(n, _)| n.as_str())
    }
}

pub(crate) const RAM: SpaceId = SpaceId::new(2);
pub(crate) const REGISTER: SpaceId = SpaceId::new(3);

/// The spaces of Toy:LE:32 (const, OTHER, ram, register, unique) plus the
/// decompiler's fspec, iop and join, and its registers r0–r12, sp, lr, pc
/// and the half registers (offsets from `Toy/data/languages/toy.sinc`:
/// `rN` at 0x1000 + 4N; on little endian `rNl` is the low half at the same
/// offset).
pub(crate) fn toy_manager() -> SpaceManager {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    m.insert_space(Space::other()).unwrap();
    m.insert_space(Space::processor("ram", false, 4, 1, 2, true, 0, 0).unwrap())
        .unwrap();
    m.insert_space(Space::processor("register", false, 2, 1, 3, false, 0, 0).unwrap())
        .unwrap();
    m.insert_space(Space::unique(4, false).unwrap()).unwrap();
    m.insert_space(Space::fspec(5).unwrap()).unwrap();
    m.insert_space(Space::iop(6).unwrap()).unwrap();
    m.insert_space(Space::join(7, false).unwrap()).unwrap();
    m.set_default_code_space(RAM).unwrap();
    let mut regs = Vec::new();
    let names = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
        "lr", "pc",
    ];
    for (i, n) in names.iter().enumerate() {
        let off = 0x1000 + 4 * i as u64;
        regs.push(((*n).to_owned(), VarnodeData::new(REGISTER, off, 4)));
        let base = n.to_string();
        regs.push((format!("{base}l"), VarnodeData::new(REGISTER, off, 2)));
        regs.push((format!("{base}h"), VarnodeData::new(REGISTER, off + 2, 2)));
    }
    m.set_registers(Arc::new(TableRegisters::new(regs)));
    m
}

/// The three models of `testfuncproto.cc`, as its `<specextensions>`.
pub(crate) const FUNCPROTO_MODELS: &str = include_str!("funcproto_models.xml");

/// The Toy-like architecture with the three test models.
pub(crate) fn funcproto_spec() -> (CompilerSpec, SpaceManager) {
    let mut m = toy_manager();
    let text = r#"<compiler_spec><stackpointer register="sp" space="ram"/></compiler_spec>"#;
    let opts = ReadOptions {
        extensions: Some(FUNCPROTO_MODELS.to_owned()),
        ..ReadOptions::default()
    };
    let spec = CompilerSpec::read(text, &mut m, opts).unwrap();
    (spec, m)
}

/// Ghidra's `parseStore`/`parseStores` (`testparamstore.cc`): `void`,
/// `stackXX[:size]`, `join A B …`, `pad:N`, `REG[:size]`. Returns the
/// location or `None` for `void`.
pub(crate) fn parse_store(m: &SpaceManager, name: &str) -> Option<VarnodeData> {
    let name = name.trim();
    if name == "void" {
        return None;
    }
    if let Some(rest) = name.strip_prefix("stack") {
        let (off, size) = rest.split_once(':').unwrap_or((rest, "1"));
        let stack = m.stack_space().unwrap().id();
        return Some(VarnodeData::new(
            stack,
            u64::from_str_radix(off, 16).unwrap(),
            size.parse().unwrap(),
        ));
    }
    if let Some(rest) = name.strip_prefix("join") {
        let pieces: Vec<VarnodeData> = rest
            .split_whitespace()
            .map(|p| parse_store(m, p).unwrap())
            .collect();
        let logical = if pieces.len() == 1 { 4 } else { 0 };
        let rec = m.find_add_join(pieces, logical).unwrap();
        return Some(*rec.unified());
    }
    if let Some(rest) = name.strip_prefix("pad:") {
        let sz: u32 = rest.parse().unwrap();
        if sz != 0 {
            return Some(VarnodeData::new(bk_core::space::CONSTANT_SPACE, 0, sz));
        }
    }
    let (reg, sz) = match name.split_once(':') {
        Some((r, s)) => (r, s.parse::<u32>().unwrap()),
        None => (name, 0),
    };
    let mut v = m
        .registers()
        .register(reg)
        .unwrap_or_else(|| panic!("register {reg}"));
    if sz != 0 {
        if v.addr().is_big_endian(m) {
            v.offset += u64::from(v.size - sz);
        }
        v.size = sz;
    }
    Some(v)
}

/// Ghidra's `comparePiece`: a `void` entry matches a void type, otherwise
/// the address and the type's size must match.
pub(crate) fn compare_piece(
    types: &dyn ParamTypes,
    want: Option<VarnodeData>,
    piece: &ParameterPieces,
) -> bool {
    match want {
        None => types.metatype(piece.ty) == Metatype::Void,
        Some(v) => piece.addr == v.addr() && i64::from(v.size) == i64::from(types.size(piece.ty)),
    }
}

/// Whether a piece sits at the register `name`.
pub(crate) fn at_register(m: &SpaceManager, piece: &ParameterPieces, name: &str) -> bool {
    piece.addr == m.registers().register(name).unwrap().addr()
}

/// The stack address at `off`.
pub(crate) fn stack_addr(m: &SpaceManager, off: u64) -> Address {
    Address::new(m.stack_space().unwrap().id(), off)
}
