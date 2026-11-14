//! Which reference build produced a capture, and comparing the captures of
//! two builds in ADR-040's form: lines where the builds agree must be equal,
//! and every line where they disagree must be recognised by a named cause,
//! with the count per cause pinned by the caller, so that a new cause or a
//! moved count fails (`docs/features/decomp-oracle.md` 4.11).

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use crate::paths::ReferenceDir;

/// The C++ library a reference build uses, which decides how `std::sort`
/// breaks ties (ADR-040). Captures are named `*.libcxx.*` or `*.libstdcxx.*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Library {
    /// LLVM's libc++ (the macOS reference build).
    Libcxx,
    /// GNU libstdc++ (the x86-64 Linux reference build).
    Libstdcxx,
}

impl Library {
    /// The name used in file names.
    pub fn name(self) -> &'static str {
        match self {
            Self::Libcxx => "libcxx",
            Self::Libstdcxx => "libstdcxx",
        }
    }

    /// The library named in a file name (`captures.libstdcxx.txt`).
    pub fn of_file_name(name: &str) -> Option<Self> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.contains(&"libstdcxx") {
            Some(Self::Libstdcxx)
        } else if parts.contains(&"libcxx") {
            Some(Self::Libcxx)
        } else {
            None
        }
    }

    /// The library of a reference build, from its `STAMP` (`host: Darwin …`
    /// is Apple clang with libc++; anything else is taken as g++ with
    /// libstdc++, which is how `scripts/build-reference.sh` is run on Linux).
    pub fn of_reference(reference: &ReferenceDir) -> Option<Self> {
        let stamp = std::fs::read_to_string(reference.stamp_file()).ok()?;
        let host = stamp.lines().find_map(|l| l.strip_prefix("host: "))?;
        Some(if host.starts_with("Darwin") {
            Self::Libcxx
        } else {
            Self::Libstdcxx
        })
    }
}

impl fmt::Display for Library {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// FNV-1a over 64 bits: a fixed, platform-independent digest for noticing
/// that a capture changed (not a cryptographic hash).
pub fn digest(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The digest of every file under `dir`, by relative path (`/`-separated),
/// in byte order of the paths.
pub fn digest_tree(dir: &Path) -> std::io::Result<BTreeMap<String, u64>> {
    let mut out = BTreeMap::new();
    for entry in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let entry = entry.map_err(std::io::Error::other)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(dir)
            .map_err(std::io::Error::other)?
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        out.insert(rel, digest(&std::fs::read(entry.path())?));
    }
    Ok(out)
}

/// The kind of a capture file, from its name: `state`, `raw`, `trace`,
/// `structure` or `pcoderec`; `other` for anything else.
pub fn capture_kind(name: &str) -> &'static str {
    const KINDS: [(&str, &str); 6] = [
        (".state", "state"),
        (".raw", "raw"),
        (".trace.gz", "trace"),
        (".bkg", "structure"),
        (".bks", "structure"),
        (".pcoderec", "pcoderec"),
    ];
    KINDS
        .iter()
        .find(|(suffix, _)| {
            name.rsplit_once('.').is_some() && name.to_ascii_lowercase().ends_with(suffix)
        })
        .map_or("other", |(_, kind)| kind)
}

/// A capture file's group: `<corpus>/<script>.<kind>` — the script being the
/// name before its first all-digit component (`zerotop.0.p1.state` →
/// `zerotop`), or before `.pcoderec`.
pub fn capture_group(path: &str) -> String {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let parts: Vec<&str> = name.split('.').collect();
    let cut = parts
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .map_or_else(|| parts.len().saturating_sub(1), |(i, _)| i);
    let script = parts.get(..cut).unwrap_or(&[]).join(".");
    let kind = capture_kind(name);
    if dir.is_empty() {
        format!("{script}.{kind}")
    } else {
        format!("{dir}/{script}.{kind}")
    }
}

/// One digest per capture group (`capture_group`), over the group's file
/// paths and digests in order: the fixture table (a few hundred lines
/// where the files number thousands).
pub fn group_digests(files: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    let mut parts: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (path, d) in files {
        let bytes = parts.entry(capture_group(path)).or_default();
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&d.to_le_bytes());
    }
    parts.into_iter().map(|(g, b)| (g, digest(&b))).collect()
}

/// A digest table as text: `<digest, 16 hex digits>  <path>` per line.
pub fn write_digests(table: &BTreeMap<String, u64>) -> String {
    let mut s = String::new();
    for (path, d) in table {
        let _ = writeln!(s, "{d:016x}  {path}");
    }
    s
}

/// Read a digest table; `None` when a line is not `<16 hex>  <path>`.
pub fn read_digests(text: &str) -> Option<BTreeMap<String, u64>> {
    text.lines()
        .map(|line| {
            let (d, path) = line.split_once("  ")?;
            (d.len() == 16 && !path.is_empty()).then_some(())?;
            Some((path.to_owned(), u64::from_str_radix(d, 16).ok()?))
        })
        .collect()
}

/// The paths whose digests differ, and those present in only one table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableDiff {
    /// In both, with different digests.
    pub changed: Vec<String>,
    /// Only in the first table.
    pub only_first: Vec<String>,
    /// Only in the second table.
    pub only_second: Vec<String>,
}

impl TableDiff {
    /// Whether the tables are equal.
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.only_first.is_empty() && self.only_second.is_empty()
    }
}

/// Compare two digest tables.
pub fn diff_tables(a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>) -> TableDiff {
    let mut d = TableDiff::default();
    for (path, da) in a {
        match b.get(path) {
            Some(db) if db != da => d.changed.push(path.clone()),
            Some(_) => {}
            None => d.only_first.push(path.clone()),
        }
    }
    d.only_second = b.keys().filter(|p| !a.contains_key(*p)).cloned().collect();
    d
}

/// A pair of differing lines and the whole outputs they come from.
#[derive(Debug, Clone, Copy)]
pub struct LinePair<'a> {
    /// The first build's line.
    pub first: &'a str,
    /// The second build's line.
    pub second: &'a str,
    /// The first build's whole output.
    pub first_text: &'a str,
    /// The second build's whole output.
    pub second_text: &'a str,
}

/// A named cause of a difference between two builds' outputs: recognises a
/// pair of differing lines.
#[derive(Debug, Clone, Copy)]
pub struct HostCause {
    /// The cause's name, as counts are keyed.
    pub name: &'static str,
    /// Whether the pair of lines differ by this cause.
    pub recognise: fn(&LinePair<'_>) -> bool,
}

/// Why two outputs could not be reconciled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostDiffError {
    /// The outputs have different line counts.
    #[error("{first} lines against {second}: a difference of shape, not of named cause")]
    Shape {
        /// Lines of the first output.
        first: usize,
        /// Lines of the second.
        second: usize,
    },
    /// A differing line no cause recognises.
    #[error("line {line} differs by no known cause:\n  {first}\n  {second}")]
    Unrecognised {
        /// The 1-based line.
        line: usize,
        /// The first build's line.
        first: String,
        /// The second build's line.
        second: String,
    },
}

/// Compare two builds' outputs line by line: every line pair that differs
/// must be recognised by one of `causes` (the first that does counts it).
/// Returns the count per cause name.
pub fn classify(
    first: &str,
    second: &str,
    causes: &[HostCause],
) -> Result<BTreeMap<&'static str, usize>, HostDiffError> {
    let a: Vec<&str> = first.lines().collect();
    let b: Vec<&str> = second.lines().collect();
    if a.len() != b.len() {
        return Err(HostDiffError::Shape {
            first: a.len(),
            second: b.len(),
        });
    }
    let mut counts = BTreeMap::new();
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        if x == y {
            continue;
        }
        let pair = LinePair {
            first: x,
            second: y,
            first_text: first,
            second_text: second,
        };
        let cause = causes
            .iter()
            .find(|c| (c.recognise)(&pair))
            .ok_or_else(|| HostDiffError::Unrecognised {
                line: i + 1,
                first: (*x).to_owned(),
                second: (*y).to_owned(),
            })?;
        *counts.entry(cause.name).or_insert(0) += 1;
    }
    Ok(counts)
}

/// ADR-021's known case: the sign of a NaN that the host's floating point
/// produced while Ghidra folded constants — the default quiet NaN is
/// positive on AArch64 (`0x7fc00000`, `0x7ff8000000000000`) and negative on
/// x86-64 (`0xffc00000`, `0xfff8000000000000`) — and how `print C` shows
/// it (`NAN` against `-NAN`).
pub fn nan_sign(pair: &LinePair<'_>) -> bool {
    nan_sign_lines(pair.first, pair.second)
}

fn nan_sign_lines(a: &str, b: &str) -> bool {
    fn positive(line: &str) -> String {
        line.replace("-NAN", "NAN")
            .replace("0xfff8000000000000", "0x7ff8000000000000")
            .replace("0xffc00000", "0x7fc00000")
    }
    a != b && positive(a) == positive(b)
}

/// The varnodes of a state dump whose `V` records differ between the two
/// outputs by a NaN sign.
fn nan_varnodes(first: &str, second: &str) -> std::collections::BTreeSet<String> {
    let v = |text: &str| -> BTreeMap<String, String> {
        text.lines()
            .filter_map(|l| l.strip_prefix("V\t"))
            .filter_map(|l| Some((l.split('\t').next()?.to_owned(), l.to_owned())))
            .collect()
    };
    let (a, b) = (v(first), v(second));
    a.iter()
        .filter(|(id, la)| b.get(*id).is_some_and(|lb| nan_sign_lines(la, lb)))
        .map(|(id, _)| id.clone())
        .collect()
}

/// A consequence of [`nan_sign`] in a state dump: a bank order (`O` record of
/// `@locorder`/`@deforder`) that differs only in where the NaN constants
/// whose value differs stand (constants are ordered by value).
pub fn nan_order(pair: &LinePair<'_>) -> bool {
    let (Some(a), Some(b)) = (
        pair.first.strip_prefix("O\t"),
        pair.second.strip_prefix("O\t"),
    ) else {
        return false;
    };
    let moved = nan_varnodes(pair.first_text, pair.second_text);
    if moved.is_empty() {
        return false;
    }
    let keep = |list: &str| -> Vec<String> {
        list.split(',')
            .filter(|v| !moved.contains(*v))
            .map(str::to_owned)
            .collect()
    };
    let (mut sa, mut sb): (Vec<&str>, Vec<&str>) = (a.split(',').collect(), b.split(',').collect());
    sa.sort_unstable();
    sb.sort_unstable();
    sa == sb && keep(a) == keep(b)
}

/// The causes this oracle knows of between the macOS (libc++) and x86-64
/// Linux (libstdc++) reference builds.
pub const KNOWN_CAUSES: [HostCause; 2] = [
    HostCause {
        name: "nan-sign",
        recognise: nan_sign,
    },
    HostCause {
        name: "nan-order",
        recognise: nan_order,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libraries_and_file_names() {
        assert_eq!(
            Library::of_file_name("captures.libcxx.txt"),
            Some(Library::Libcxx)
        );
        assert_eq!(
            Library::of_file_name("x.libstdcxx.gz"),
            Some(Library::Libstdcxx)
        );
        assert_eq!(Library::of_file_name("summary.txt"), None);
    }

    #[test]
    fn digests_are_fixed_and_tables_round_trip() {
        assert_eq!(digest(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(digest(b"a"), 0xaf63_dc4c_8601_ec8c);
        let mut t = BTreeMap::new();
        t.insert("a/b.state".to_owned(), 7_u64);
        t.insert("c".to_owned(), u64::MAX);
        let text = write_digests(&t);
        assert_eq!(read_digests(&text), Some(t.clone()));
        let mut u = t.clone();
        u.insert("c".into(), 1);
        u.insert("d".into(), 1);
        u.remove("a/b.state");
        let d = diff_tables(&t, &u);
        assert_eq!(d.changed, ["c"]);
        assert_eq!(d.only_first, ["a/b.state"]);
        assert_eq!(d.only_second, ["d"]);
    }

    #[test]
    fn capture_files_are_grouped_by_script_and_kind() {
        assert_eq!(
            capture_group("datatests/zerotop.0.p1.state"),
            "datatests/zerotop.state"
        );
        assert_eq!(
            capture_group("datatests/zerotop.0.0.blocks.bkg"),
            "datatests/zerotop.structure"
        );
        assert_eq!(
            capture_group("research/a01.x64-gcc-O2.3.trace.gz"),
            "research/a01.x64-gcc-O2.trace"
        );
        assert_eq!(
            capture_group("research/a01.x64-gcc-O2.pcoderec"),
            "research/a01.x64-gcc-O2.pcoderec"
        );
        let mut files = BTreeMap::new();
        files.insert("d/t.0.p1.state".to_owned(), 1_u64);
        files.insert("d/t.0.end.state".to_owned(), 2);
        files.insert("d/t.pcoderec".to_owned(), 3);
        let groups = group_digests(&files);
        assert_eq!(
            groups.keys().collect::<Vec<_>>(),
            ["d/t.pcoderec", "d/t.state"]
        );
        files.insert("d/t.0.end.state".to_owned(), 4);
        assert_ne!(
            group_digests(&files).get("d/t.state"),
            groups.get("d/t.state")
        );
    }

    #[test]
    fn differences_are_counted_by_cause() {
        let counts = classify(
            "x\n  y = NAN;\nXMM0 = #0x7fc00000:4\n",
            "x\n  y = -NAN;\nXMM0 = #0xffc00000:4\n",
            &KNOWN_CAUSES,
        )
        .unwrap();
        assert_eq!(counts.get("nan-sign"), Some(&2));
        let a = "V\tv1\tconst\t0x7fc00000\nV\tv2\tconst\t0x3\nO\tv2,v1\n";
        let b = "V\tv1\tconst\t0xffc00000\nV\tv2\tconst\t0x3\nO\tv1,v2\n";
        let counts = classify(a, b, &KNOWN_CAUSES).unwrap();
        assert_eq!(counts.get("nan-order"), Some(&1));
        assert_eq!(counts.get("nan-sign"), Some(&1));
        assert!(matches!(
            classify("a\n", "b\n", &KNOWN_CAUSES),
            Err(HostDiffError::Unrecognised { line: 1, .. })
        ));
        assert!(matches!(
            classify("a\n", "a\nb\n", &KNOWN_CAUSES),
            Err(HostDiffError::Shape { .. })
        ));
    }
}
