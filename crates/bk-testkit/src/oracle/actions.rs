//! Action lists (format `bkactions 1`, `docs/features/decomp-oracle.md`
//! 4.10): what `bk list actions` prints — every action and rule of the
//! console's current root in `list action` order, with the position
//! `bk break` takes and the full path that tells duplicated names apart.
//!
//! (`→` stands for one tab.)
//!
//! ```text
//! H → bkactions → 1 → <root name> → <line count>
//! <list action line> → <path>
//! T
//! ```

use super::text::{Lines, ParseError, ParseErrorKind, parse_u32, push_display, shown};

/// The most lines an action list may have.
const MAX_ACTIONS: usize = 100_000;

/// A whole action list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionList {
    /// The current root's name (`decompile`, …).
    pub root: String,
    /// The lines, in order; a line's position is its index.
    pub entries: Vec<ActionLine>,
}

/// One action or rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionLine {
    /// The line as `Action::print` / `ActionPool::print` render it.
    pub line: String,
    /// The full path, `universal:fullloop:mainloop:heritage`.
    pub path: String,
}

impl ActionLine {
    /// The position `list action` prints (the number at the start of the line).
    pub fn position(&self) -> Option<u32> {
        self.line.get(..4).and_then(|n| parse_u32(n.trim_start()))
    }

    /// The action's or rule's own name (the last path component).
    pub fn name(&self) -> &str {
        self.path.rsplit(':').next().unwrap_or(&self.path)
    }

    /// Nesting depth: 0 for the root.
    pub fn depth(&self) -> usize {
        self.path.matches(':').count()
    }
}

impl ActionList {
    /// Read the output of `bk list actions` (a step's output, from its `H`
    /// line to its `T` line; anything else is an error).
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Lines::new("bkactions", text)?;
        let h = lines.next_line("the header")?;
        if h.tag() != "H" || h.field(1) != "bkactions" {
            return Err(h.error(ParseErrorKind::UnexpectedRecord {
                expected: "the bkactions header",
                found: shown(h.text),
            }));
        }
        h.expect("H", 5, "the header")?;
        if h.field(2) != "1" {
            return Err(h.error(ParseErrorKind::UnsupportedVersion {
                version: shown(h.field(2)),
            }));
        }
        let root = h.field(3);
        if root.is_empty() {
            return Err(h.bad("root name", root));
        }
        let count = h.u32_at(4, "line count")? as usize;
        if count > MAX_ACTIONS {
            return Err(h.error(ParseErrorKind::TooMany {
                what: "actions",
                limit: MAX_ACTIONS,
            }));
        }
        let mut entries = Vec::with_capacity(count.min(4096));
        for position in 0..count {
            let r = lines.next_line("an action line")?;
            let [line, path] = r.fields.as_slice() else {
                return Err(r.error(ParseErrorKind::FieldCount {
                    record: "action",
                    expected: 2,
                    found: r.fields.len(),
                }));
            };
            let entry = ActionLine {
                line: (*line).to_owned(),
                path: (*path).to_owned(),
            };
            let named = entry.line.trim_end().ends_with(entry.name());
            if entry.position() != u32::try_from(position).ok() || !named || path.is_empty() {
                return Err(r.bad("action line (position, name and path must agree)", r.text));
            }
            entries.push(entry);
        }
        lines.finish()?;
        Ok(Self {
            root: root.to_owned(),
            entries,
        })
    }

    /// The text `bk list actions` printed.
    pub fn write(&self) -> String {
        let mut s = format!("H\tbkactions\t1\t{}\t", self.root);
        push_display(&mut s, &self.entries.len());
        s.push('\n');
        for e in &self.entries {
            s.push_str(&e.line);
            s.push('\t');
            s.push_str(&e.path);
            s.push('\n');
        }
        s.push_str("T\n");
        s
    }

    /// The position of the action or rule with this full path.
    pub fn position_of(&self, path: &str) -> Option<u32> {
        let i = self.entries.iter().position(|e| e.path == path)?;
        u32::try_from(i).ok()
    }

    /// The positions of every action or rule with this name, in order (a
    /// name can occur more than once: `blockstructure` at 0168 and 0231).
    pub fn positions_named(&self, name: &str) -> Vec<u32> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.name() == name)
            .filter_map(|(i, _)| u32::try_from(i).ok())
            .collect()
    }

    /// The entry after `position` that is not inside it — the action that
    /// runs next once the one at `position` (and everything it contains)
    /// has finished, if the list has one.
    pub fn next_after(&self, position: u32) -> Option<u32> {
        let i = position as usize;
        let prefix = format!("{}:", self.entries.get(i)?.path);
        let j = self
            .entries
            .iter()
            .enumerate()
            .skip(i + 1)
            .find(|(_, e)| !e.path.starts_with(&prefix))?
            .0;
        u32::try_from(j).ok()
    }
}

#[cfg(test)]
mod tests;
