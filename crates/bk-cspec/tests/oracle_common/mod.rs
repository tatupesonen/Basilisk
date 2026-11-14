//! Reading the oracle table and rebuilding each pair's architecture: the
//! spaces and registers Ghidra had, a test type model with the pair's
//! alignment, and the record formats of `tests/oracle/cspec_oracle.cc`.

#![allow(dead_code, reason = "shared by several test crates, each using a part")]

pub(crate) mod describe;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bk_core::{Address, Space, SpaceId, SpaceManager, TruncationTag, VarnodeData};
use bk_cspec::types::{Metatype, ParamTypes, TypeHandle};

use crate::common::TableRegisters;
use crate::common::testtypes::{CSizes, TestTypes};

/// The oracle table, decompressed.
pub(crate) fn table() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/cspec_oracle.txt.gz");
    let bytes = std::fs::read(path).unwrap();
    let mut out = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut out)
        .unwrap();
    out
}

/// The records of one pair, by record kind, each as its fields after the
/// pair column.
#[derive(Default, Debug)]
pub(crate) struct Pair {
    pub(crate) id: String,
    pub(crate) cspec: String,
    pub(crate) heavy: bool,
    pub(crate) records: BTreeMap<String, Vec<Vec<String>>>,
}

impl Pair {
    pub(crate) fn get(&self, kind: &str) -> &[Vec<String>] {
        self.records.get(kind).map_or(&[], Vec::as_slice)
    }
}

/// Splits the table into pairs, in table order, plus the failing pairs.
pub(crate) fn pairs(text: &str) -> (Vec<Pair>, Vec<(String, String)>) {
    let mut out: Vec<Pair> = Vec::new();
    let mut errs = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f[0] {
            "PAIR" => out.push(Pair {
                id: f[1].to_owned(),
                cspec: f[2].to_owned(),
                heavy: f[3] == "1",
                records: BTreeMap::new(),
            }),
            "PAIRERR" => errs.push((f[1].to_owned(), f[2].to_owned())),
            kind => {
                let p = out.last_mut().unwrap();
                assert_eq!(p.id, f[1], "record outside its pair: {line}");
                p.records
                    .entry(kind.to_owned())
                    .or_default()
                    .push(f[2..].iter().map(|s| (*s).to_owned()).collect());
            }
        }
    }
    (out, errs)
}

/// Every `.cspec` under `Processors/*/data/languages/`, by file name.
pub(crate) fn cspec_files(processors: &Path) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for proc_dir in std::fs::read_dir(processors).unwrap().flatten() {
        let langs = proc_dir.path().join("data").join("languages");
        let Ok(rd) = std::fs::read_dir(&langs) else {
            continue;
        };
        for f in rd.flatten() {
            let p = f.path();
            if p.extension().is_some_and(|e| e == "cspec") {
                out.insert(p.file_name().unwrap().to_string_lossy().into_owned(), p);
            }
        }
    }
    out
}

/// The space manager Ghidra had before reading the `.cspec`: every space
/// but the register-relative ones, the default spaces and the registers.
pub(crate) fn manager(pair: &Pair) -> SpaceManager {
    let mut m = SpaceManager::new();
    let mut truncate = Vec::new();
    for s in pair.get("SPACE") {
        let index: u32 = s[0].parse().unwrap();
        let name = &s[1];
        let ty: u32 = s[2].parse().unwrap();
        let addr_size: u32 = s[3].parse().unwrap();
        let word_size: u32 = s[4].parse().unwrap();
        let be = s[5] == "1";
        let delay: i32 = s[6].parse().unwrap();
        let dead: i32 = s[7].parse().unwrap();
        let space = match ty {
            0 => Space::constant(),
            1 if index == 1 && name == "OTHER" => Space::other(),
            1 => {
                Space::processor(name, be, addr_size, word_size, index, true, delay, dead).unwrap()
            }
            3 => Space::unique(index, be).unwrap(),
            4 => Space::fspec(index).unwrap(),
            5 => Space::iop(index).unwrap(),
            6 => Space::join(index, be).unwrap(),
            _ => continue,
        };
        m.insert_space(space).unwrap();
        if s[8] == "1" {
            truncate.push(TruncationTag::new(name.clone(), addr_size));
        }
    }
    for t in &truncate {
        m.truncate_space(t).unwrap();
    }
    let def = &pair.get("DEFSPACE")[0];
    m.set_default_code_space(SpaceId::new(def[0].parse().unwrap()))
        .unwrap();
    m.set_default_data_space(SpaceId::new(def[1].parse().unwrap()))
        .unwrap();
    let regs = pair
        .get("REG")
        .iter()
        .map(|r| (r[0].clone(), parse_vn(&r[1]).unwrap()))
        .collect();
    m.set_registers(Arc::new(TableRegisters::new(regs)));
    m
}

/// The test type model with the pair's alignment map and pointer size.
pub(crate) fn types(pair: &Pair) -> TestTypes {
    let org = &pair.get("ORG")[0];
    // Ghidra's C parser makes pointers the size of the default data space
    // (`PointerModifier::modType`), not the data organisation's.
    let data = &pair.get("DEFSPACE")[0][1];
    let pointer: i32 = pair
        .get("SPACE")
        .iter()
        .find(|s| &s[0] == data)
        .map(|s| s[3].parse().unwrap())
        .unwrap();
    let map: Vec<i32> = org[1].split(',').map(|v| v.parse().unwrap()).collect();
    TestTypes::new(
        map,
        CSizes {
            pointer,
            ..CSizes::default()
        },
    )
}

/// `index:hexoffset:size`, or `None` for `-`.
pub(crate) fn parse_vn(text: &str) -> Option<VarnodeData> {
    if text == "-" {
        return None;
    }
    let mut it = text.split(':');
    let s: u32 = it.next()?.parse().ok()?;
    let o = u64::from_str_radix(it.next()?, 16).ok()?;
    let z: u32 = it.next()?.parse().ok()?;
    Some(VarnodeData::new(SpaceId::new(s), o, z))
}

/// Ghidra's `addr` format of the generator.
pub(crate) fn addr(a: Address, size: impl std::fmt::Display) -> String {
    match a.space() {
        None => "-".into(),
        Some(s) => format!("{}:{:x}:{size}", s.index(), a.offset()),
    }
}

/// [`addr`] of a location.
pub(crate) fn vn(v: &VarnodeData) -> String {
    addr(v.addr(), v.size)
}

/// The generator's `desc` of a type.
#[expect(
    clippy::many_single_char_names,
    reason = "short names mirror the C++ generator"
)]
pub(crate) fn desc(t: &TestTypes, h: TypeHandle) -> String {
    let m = t.metatype(h);
    let sz = t.size(h);
    match m {
        Metatype::Ptr => format!("ptr{sz}({})", desc(t, t.pointed_to(h).unwrap())),
        Metatype::Array => {
            let (e, n) = t.array_element(h).unwrap();
            format!("array{sz}({}x{n})", desc(t, e))
        }
        Metatype::Struct | Metatype::Union => format!("{}{sz}:{}", m.name(), t.name(h)),
        Metatype::Void => "void".into(),
        _ => format!("{}{sz}", m.name()),
    }
}

pub(crate) fn b(v: bool) -> &'static str {
    if v { "1" } else { "0" }
}

/// The architecture of one pair, rebuilt from the table and the pair's
/// `.cspec` in the spec root: spec, manager and a type model with the
/// file's C sizes (`integer_size`, `long_size`, `long_long_size`,
/// `long_double_size`, defaults as Java's `DataOrganizationImpl`).
pub(crate) fn arch(
    ghidra: &bk_testkit::GhidraDir,
    pair_id: &str,
) -> (bk_cspec::CompilerSpec, SpaceManager, TestTypes) {
    let text = table();
    let (pairs, _) = pairs(&text);
    let pair = pairs.iter().find(|p| p.id == pair_id).unwrap();
    let files = cspec_files(&ghidra.processors_dir());
    let cspec = std::fs::read_to_string(&files[&pair.cspec]).unwrap();
    let mut m = manager(pair);
    let spec =
        bk_cspec::CompilerSpec::read(&cspec, &mut m, bk_cspec::ReadOptions::default()).unwrap();
    let mut t = types(pair);
    let size = |tag: &str, default: i32| {
        cspec
            .split(&format!("<{tag} value=\""))
            .nth(1)
            .and_then(|r| r.split('"').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let c = CSizes {
        int: size("integer_size", 4),
        long: size("long_size", 4),
        long_long: size("long_long_size", 8),
        long_double: size("long_double_size", 8),
        pointer: t.c_sizes.pointer,
    };
    let map = t.align_map.clone();
    t = TestTypes::new(map, c);
    (spec, m, t)
}
