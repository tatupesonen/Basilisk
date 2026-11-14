//! The checks of `docs/features/decomp-oracle.md` 6.2 (a dump is complete
//! against the console's own listings) and 6.6 (`decomp_dbg` prints what
//! `decomp` prints).

use std::collections::{BTreeMap, BTreeSet};

use crate::oracle::state::{StateDump, VarnodeOffset};

/// What the completeness check counted for one decompilation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Completeness {
    /// Ops in `print raw`.
    pub ops: usize,
    /// Varnodes in `print tree varnode`.
    pub varnodes: usize,
    /// Varnodes whose offset is a host pointer (their order is Ghidra's heap order).
    pub pointer_valued: usize,
}

/// `print tree varnode`'s flag words and the varnode flags they show
/// (`Varnode::printInfo`, `varnode.cc`).
const FLAG_WORDS: [(&str, u32); 10] = [
    ("tied", 0x8000),
    ("mapped", 0x0020_0000),
    ("persistent", 0x4000),
    ("tlock", 0x100),
    ("nlock", 0x200),
    ("base", 0x0002_0000),
    ("unaff", 0x0001_0000),
    ("implied", 0x40),
    ("addrforce", 0x0010_0000),
    ("readonly", 0x2000),
];

/// The value of a `(<key>=0x…)` item of a `print tree varnode` line.
fn paren_hex(line: &str, key: &str) -> Option<u64> {
    let start = line.rfind(&format!("({key}=0x"))? + key.len() + 4;
    let rest = line.get(start..)?;
    let end = rest.find(')')?;
    u64::from_str_radix(rest.get(..end)?, 16).ok()
}

/// Check a state dump against the console's `print raw` and `print tree
/// varnode` at the same stop: every op of `print raw` is in `@ops` with the
/// same time and text; every varnode of `print tree varnode` is in
/// `@varnodes` with the same create index, flag words and consumed mask;
/// the two sets are the same; and `@deforder` is the console's order once
/// the pointer-valued varnodes (whose console order follows heap
/// addresses) are left out.
pub fn check_completeness(dump: &StateDump, raw: &str, tree: &str) -> Result<Completeness, String> {
    let mut found = Completeness::default();
    let by_time: BTreeMap<u64, &str> = dump
        .ops
        .iter()
        .map(|o| (o.seq.time, o.text.as_str()))
        .collect();
    for line in raw.lines() {
        // BlockGraph::printRaw's header (the graph's index), block headers,
        // implied gotos, and Funcdata::printRaw's header before blocks exist.
        let header = line.starts_with("Basic Block ")
            || line.starts_with("Raw operations")
            || line.contains(":   \t[ goto ")
            || line.trim().is_empty()
            || line.bytes().all(|b| b.is_ascii_digit());
        if header {
            continue;
        }
        let (seq, text) = line
            .split_once(":\t")
            .ok_or_else(|| format!("print raw line not understood: {line}"))?;
        let time = seq
            .rsplit_once(':')
            .and_then(|(_, t)| u64::from_str_radix(t, 16).ok())
            .ok_or_else(|| format!("print raw sequence number not understood: {seq}"))?;
        match by_time.get(&time) {
            Some(dumped) if *dumped == text => found.ops += 1,
            Some(dumped) => return Err(format!("op {seq}: print raw `{text}`, dump `{dumped}`")),
            None => return Err(format!("op {seq} of print raw is not in the dump")),
        }
    }
    let mut console_order = Vec::new();
    for line in tree.lines().filter(|l| l.contains("(create=0x")) {
        let create =
            paren_hex(line, "create").ok_or_else(|| format!("no create index in: {line}"))?;
        let create =
            u32::try_from(create).map_err(|e| format!("create index too large ({e}): {line}"))?;
        let consumed =
            paren_hex(line, "consumed").ok_or_else(|| format!("no consumed mask in: {line}"))?;
        let v = dump
            .varnode(crate::oracle::state::VarnodeId(create))
            .ok_or_else(|| {
                format!("varnode v{create:x} of print tree varnode is not in the dump")
            })?;
        if v.consumed != consumed {
            return Err(format!(
                "v{create:x}: consumed {consumed:#x} in the console, {:#x} in the dump",
                v.consumed
            ));
        }
        // The flag words come last before the consumed mask, in a fixed order.
        let head = line.split(" (consumed=").next().unwrap_or("");
        let shown: BTreeSet<&str> = head
            .rsplit(' ')
            .map_while(|w| {
                FLAG_WORDS
                    .iter()
                    .find(|(word, _)| *word == w)
                    .map(|(word, _)| *word)
            })
            .collect();
        let expected: BTreeSet<&str> = FLAG_WORDS
            .iter()
            .filter(|(_, bit)| v.flags & bit != 0)
            .map(|(word, _)| *word)
            .collect();
        if shown != expected {
            return Err(format!(
                "v{create:x}: flag words {shown:?} in the console, {expected:?} from the dump"
            ));
        }
        console_order.push(create);
        found.varnodes += 1;
    }
    let dumped: BTreeSet<u32> = dump.varnodes.iter().map(|v| v.id.0).collect();
    let shown: BTreeSet<u32> = console_order.iter().copied().collect();
    if dumped != shown || shown.len() != console_order.len() {
        return Err(format!(
            "print tree varnode lists {} varnodes ({} distinct), the dump {}",
            console_order.len(),
            shown.len(),
            dumped.len()
        ));
    }
    let pointer: BTreeSet<u32> = dump
        .varnodes
        .iter()
        .filter(|v| !matches!(v.offset, VarnodeOffset::Plain(_)))
        .map(|v| v.id.0)
        .collect();
    found.pointer_valued = pointer.len();
    let plain = |order: &mut dyn Iterator<Item = u32>| -> Vec<u32> {
        order.filter(|c| !pointer.contains(c)).collect()
    };
    let console = plain(&mut console_order.iter().copied());
    let canonical = plain(&mut dump.def_order.varnodes.iter().map(|v| v.0));
    if console != canonical {
        return Err(
            "@deforder differs from print tree varnode's order outside the pointer-valued varnodes"
                .into(),
        );
    }
    Ok(found)
}

/// Whether a line carries a host pointer: a constant or `iop` offset of
/// eight or more hex digits (runs R5, R6).
fn has_pointer(line: &str) -> bool {
    for marker in ["#0x", "i0x"] {
        let mut rest = line;
        while let Some(at) = rest.find(marker) {
            let digits = rest
                .get(at + 3..)
                .map_or(0, |r| r.bytes().take_while(u8::is_ascii_hexdigit).count());
            if digits >= 8 {
                return true;
            }
            rest = rest.get(at + 3..).unwrap_or("");
        }
    }
    false
}

/// A console transcript with what depends on heap addresses removed, for
/// comparing two consoles' output (R8: `internal=` values, lines that carry
/// host pointers, and the `fspec` varnode lines whose order follows them).
pub fn without_pointers(transcript: &str) -> String {
    let mut out = String::new();
    for line in transcript.lines() {
        if has_pointer(line) || (line.contains(" = f") && line.contains("(free)")) {
            continue;
        }
        let line = match line.find(" (internal=0x") {
            Some(at) => {
                let tail = line.get(at + 1..).unwrap_or("");
                let close = tail.find(')').map_or(tail.len(), |c| c + 1);
                format!(
                    "{}{}",
                    line.get(..at).unwrap_or(""),
                    tail.get(close..).unwrap_or("")
                )
            }
            None => line.to_owned(),
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointers_are_recognised() {
        assert!(has_pointer("u0x1 = LOAD #0x104b42900:8"));
        assert!(has_pointer("i0x600001234567:4c"));
        assert!(!has_pointer("EAX = #0x1234567:4"));
        assert_eq!(
            without_pointers(
                "a (consumed=0x1) (internal=0x6000) (create=0x2)\nb #0x123456789\nc\n"
            ),
            "a (consumed=0x1) (create=0x2)\nc\n"
        );
    }

    #[test]
    fn tree_items_are_read() {
        let line = "int4 = EAX(i) tied (consumed=0xff) (internal=0x1) (create=0x2a)";
        assert_eq!(paren_hex(line, "create"), Some(0x2a));
        assert_eq!(paren_hex(line, "consumed"), Some(0xff));
    }
}
