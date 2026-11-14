//! Checked-in oracle tables: gzip-compressed text, one row per case, fields
//! separated by tabs, text fields escaped (`\\`, `\t`, `\n`).

#![allow(dead_code, reason = "each test binary uses a part")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

/// The crate's `tests/data` directory.
pub(crate) fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("data")
}

pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

/// Reads a gzip-compressed text table, or `None` when the file is absent.
pub(crate) fn read_gz(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut text = String::new();
    GzDecoder::new(&bytes[..]).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Writes a gzip-compressed text table (reproducible: no timestamp).
pub(crate) fn write_gz(path: &Path, text: &str) {
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(text.as_bytes()).unwrap();
    let bytes = enc.finish().unwrap();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
}
