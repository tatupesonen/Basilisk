//! Reading the oracle tables and rebuilding the architecture they were made
//! on from their header rows (spec 6.2): spaces from `P` rows, the type
//! factory from the `C` row, checked against the `T` rows.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bk_core::{Space, SpaceId, SpaceManager};
use bk_decomp_symbols::{ArchEnv, ids};
use bk_decomp_types::{DataOrganization, SpaceInfo, TypeEnv, TypeFactory};
use bk_marshal::{Document, XmlDecoder};

/// The directory of the checked-in tables.
pub fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

/// The text of a gzipped table.
pub fn read_table(name: &str) -> String {
    let path = data_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .unwrap();
    text
}

/// One row: case number, kind, text.
pub fn split_row(line: &str) -> (i64, &str, &str) {
    let mut parts = line.splitn(3, '\t');
    let case = parts.next().unwrap().parse().unwrap();
    let kind = parts.next().unwrap();
    let text = parts.next().unwrap_or("");
    (case, kind, text)
}

/// The architecture of a table.
pub struct Arch {
    pub env: ArchEnv,
    pub types: TypeFactory,
    pub ram: SpaceId,
    pub stack: SpaceId,
    pub register: Option<SpaceId>,
}

/// Rebuilds the spaces and types from the header rows (`P`, `C`, `T`).
pub fn arch_from_header(rows: &[(i64, &str, &str)]) -> Arch {
    let mut m = SpaceManager::new();
    let mut ram_space: Option<Space> = None;
    let mut shortcuts = Vec::new();
    for (_, kind, text) in rows.iter().filter(|r| r.1 == "P") {
        let _ = kind;
        let f: Vec<&str> = text.split(' ').collect();
        let (index, name, ty): (u32, &str, u32) =
            (f[0].parse().unwrap(), f[1], f[2].parse().unwrap());
        let size: u32 = f[3].parse().unwrap();
        let word: u32 = f[4].parse().unwrap();
        let big = f[5] == "1";
        if let Some(sc) = f.get(7) {
            shortcuts.push((index, (*sc).to_owned()));
        }
        let space = match (ty, name) {
            (0, _) => Space::constant(),
            (1, "OTHER") => Space::other(),
            (1, _) => Space::processor(name, big, size, word, index, true, 0, 0).unwrap(),
            (3, _) => Space::unique(index, big).unwrap(),
            (4, _) => Space::fspec(index).unwrap(),
            (5, _) => Space::iop(index).unwrap(),
            (6, _) => Space::join(index, big).unwrap(),
            (2, _) => {
                Space::spacebase(name, index, size, ram_space.as_ref().unwrap(), 0, true, big)
                    .unwrap()
            }
            _ => panic!("unknown space type {ty}"),
        };
        if name == "ram" {
            ram_space = Some(space.clone());
        }
        m.insert_space(space).unwrap();
    }
    let ram = m.space_by_name("ram").unwrap().id();
    m.set_default_code_space(ram).unwrap();
    m.set_default_data_space(ram).unwrap();
    for (index, shortcut) in &shortcuts {
        let got = m
            .space_at(*index)
            .and_then(Space::shortcut)
            .map(String::from)
            .unwrap_or_default();
        assert_eq!(&got, shortcut, "shortcut of space {index}");
    }
    let stack = m.space_by_name("stack").unwrap().id();
    let register = m.space_by_name("register").map(Space::id);
    let spaces = Arc::new(m);
    let info = |id: SpaceId| {
        let s = spaces.space(id).unwrap();
        SpaceInfo {
            id,
            name: s.name().to_owned(),
            addr_size: s.addr_size() as i32,
            word_size: s.word_size(),
            big_endian: s.is_big_endian(),
        }
    };
    let mut tenv = TypeEnv::simple(8, false);
    tenv.data_space = info(ram);
    tenv.other_spaces = spaces
        .spaces()
        .filter(|s| s.id() != ram)
        .map(|s| info(s.id()))
        .collect();
    let mut types = TypeFactory::new(tenv, DataOrganization::default());
    let core = rows.iter().find(|r| r.1 == "C").unwrap().2;
    let doc = Document::parse(core).unwrap();
    let table = ids::id_table();
    let mut dec = XmlDecoder::new(&doc, &table, &*spaces);
    types.decode_core_types(&mut dec).unwrap();
    let env = ArchEnv::new(Arc::clone(&spaces));
    Arch {
        env,
        types,
        ram,
        stack,
        register,
    }
}

/// Escapes a row's text as the generators do.
pub fn esc(s: &str) -> String {
    s.replace('\n', "\\n").replace('\t', "\\t")
}

/// FNV-1a 64 of some bytes (pins a table's content).
pub fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}
