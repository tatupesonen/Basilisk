//! Ghidra's "next instruction / data / label / function" navigation: scan
//! the listing from the cursor for the next row of a kind, on a worker.

use crate::model::{Address, ProgramSource, RowContent, RowIndex};

/// Rows scanned per request to the source.
const CHUNK: u32 = 512;
/// Rows scanned before giving up.
const LIMIT: u64 = 1_000_000;

/// What to look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitKind {
    /// An instruction at a different address.
    Instruction,
    /// A defined data item.
    Data,
    /// A label.
    Label,
    /// A function (its signature row).
    Function,
}

/// A scan from a row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Find {
    pub kind: UnitKind,
    pub forward: bool,
}

impl Find {
    fn matches(self, c: &RowContent) -> bool {
        match self.kind {
            UnitKind::Instruction => matches!(c, RowContent::Instruction { .. }),
            UnitKind::Data => matches!(c, RowContent::Data { .. }),
            UnitKind::Label => matches!(c, RowContent::Label { .. }),
            UnitKind::Function => matches!(c, RowContent::Signature(_)),
        }
    }

    /// The address of the next matching row after (or before) `from`.
    pub(crate) fn run(self, s: &dyn ProgramSource, from: u64) -> Option<Address> {
        let total = s.listing_len().ok()?;
        let here = s.listing_rows(RowIndex(from), 1).ok()?.first()?.address;
        let mut scanned = 0;
        if self.forward {
            let mut r = from + 1;
            while r < total && scanned < LIMIT {
                let rows = s.listing_rows(RowIndex(r), CHUNK).ok()?;
                if rows.is_empty() {
                    return None;
                }
                if let Some(x) = rows
                    .iter()
                    .find(|x| x.address != here && self.matches(&x.content))
                {
                    return Some(x.address);
                }
                r += rows.len() as u64;
                scanned += rows.len() as u64;
            }
        } else {
            let mut end = from;
            // Skip back over the current function's own header first.
            let mut skip_here = true;
            while end > 0 && scanned < LIMIT {
                let start = end.saturating_sub(u64::from(CHUNK));
                let rows = s.listing_rows(RowIndex(start), (end - start) as u32).ok()?;
                for x in rows.iter().rev() {
                    if x.address != here {
                        skip_here = false;
                    }
                    if !skip_here && self.matches(&x.content) {
                        return Some(x.address);
                    }
                }
                scanned += end - start;
                end = start;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::DemoProgram;

    #[test]
    fn finds_the_next_and_previous_function() {
        let p = DemoProgram::licd().unwrap();
        let main = p.info().entry;
        let span = p.rows_for_address(main).unwrap();
        let next = Find {
            kind: UnitKind::Function,
            forward: true,
        }
        .run(&p, span.unit.0)
        .unwrap();
        assert!(next > main);
        let prev = Find {
            kind: UnitKind::Function,
            forward: false,
        }
        .run(&p, span.unit.0)
        .unwrap();
        assert!(prev < main);
        let insn = Find {
            kind: UnitKind::Instruction,
            forward: true,
        }
        .run(&p, span.unit.0)
        .unwrap();
        assert!(insn > main);
    }
}
