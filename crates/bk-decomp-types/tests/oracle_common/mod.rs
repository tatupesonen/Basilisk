//! Reading the oracle tables and rebuilding the environment they record.

use std::io::Read as _;
use std::path::Path;

use bk_decomp_types::{DataOrganization, SpaceInfo, TypeEnv};
use bk_marshal::SpaceId;

/// Escapes a string as the oracle does (`\t`, `\n`, `\\`).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

/// The lines of a gzip-compressed table under `tests/data`.
pub fn table(name: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap();
    text.lines().map(str::to_owned).collect()
}

/// A [`TypeEnv`] from the ENV fields: space addrsize wordsize bigendian
/// codeaddrsize spsize farinner farbase model maxbase.
pub fn env_from(fields: &[&str]) -> TypeEnv {
    let n = |i: usize| fields[i].parse::<i32>().unwrap();
    TypeEnv {
        max_basetype_size: n(9),
        data_space: SpaceInfo {
            id: SpaceId::new(1),
            name: fields[0].to_owned(),
            addr_size: n(1),
            word_size: n(2) as u32,
            big_endian: n(3) != 0,
        },
        code_addr_size: n(4),
        stack_pointer_size: (n(5) >= 0).then(|| n(5)),
        far_pointer: (n(6) >= 0).then(|| (n(6), n(7))),
        other_spaces: Vec::new(),
        default_model: Some(fields[8].to_owned()),
    }
}

/// A [`DataOrganization`] from the ORG fields.
pub fn org_from(fields: &[&str]) -> DataOrganization {
    let n = |i: usize| fields[i].parse::<i32>().unwrap();
    DataOrganization {
        size_of_int: n(0),
        size_of_long: n(1),
        size_of_char: n(2),
        size_of_wchar: n(3),
        size_of_pointer: n(4),
        size_of_alt_pointer: n(5),
        enum_size: n(6),
        enum_signed: n(7) != 0,
        align_map: fields[8].split(',').map(|v| v.parse().unwrap()).collect(),
    }
}

/// The ORG fields as the oracle prints them.
pub fn org_fields(org: &DataOrganization) -> String {
    let map: Vec<String> = org.align_map.iter().map(i32::to_string).collect();
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        org.size_of_int,
        org.size_of_long,
        org.size_of_char,
        org.size_of_wchar,
        org.size_of_pointer,
        org.size_of_alt_pointer,
        org.enum_size,
        i32::from(org.enum_signed),
        map.join(",")
    )
}
