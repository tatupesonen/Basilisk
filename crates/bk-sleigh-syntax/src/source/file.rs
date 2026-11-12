//! One source file and its lines.

use std::ops::Range;
use std::path::{Path, PathBuf};

/// One source file read during preprocessing.
#[derive(Debug)]
pub struct SourceFile {
    path: PathBuf,
    name: String,
    text: String,
    /// Byte offset of the start of each line, plus the text length at the end.
    line_starts: Vec<u32>,
}

impl SourceFile {
    pub(crate) fn new(path: PathBuf, text: String) -> Self {
        let name = path.file_name().map_or_else(
            || path.to_string_lossy().into_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        let line_starts = split_lines(&text);
        Self {
            path,
            name,
            text,
            line_starts,
        }
    }

    /// The path the file was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file name without directories. This is what Ghidra reports in
    /// messages and stores in `.sla` source-file tables.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The whole text of the file.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Number of lines, counted as Java's `BufferedReader.readLine` does:
    /// `\n`, `\r\n` and `\r` end a line, and a final line needs no terminator.
    pub fn line_count(&self) -> u32 {
        u32::try_from(self.line_starts.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// Byte range of line `line` (1-based) in [`Self::text`], without its
    /// terminator.
    pub fn line_range(&self, line: u32) -> Option<Range<usize>> {
        let index = (line as usize).checked_sub(1)?;
        let start = *self.line_starts.get(index)? as usize;
        let next = *self.line_starts.get(index + 1)? as usize;
        let bytes = self.text.as_bytes().get(start..next)?;
        let end = match bytes {
            [.., b'\r', b'\n'] => next - 2,
            [.., b'\n' | b'\r'] => next - 1,
            _ => next,
        };
        Some(start..end)
    }

    /// The text of line `line` (1-based), without its terminator.
    pub fn line(&self, line: u32) -> Option<&str> {
        self.text.get(self.line_range(line)?)
    }
}

/// Start offsets of the lines of `text`, followed by `text.len()`.
fn split_lines(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    let mut starts = Vec::with_capacity(bytes.len() / 32 + 2);
    let mut pos = 0usize;
    while pos < bytes.len() {
        starts.push(pos as u32);
        let rest = bytes.get(pos..).unwrap_or(&[]);
        match memchr::memchr2(b'\n', b'\r', rest) {
            Some(i) => {
                let two = rest.get(i) == Some(&b'\r') && rest.get(i + 1) == Some(&b'\n');
                pos += i + if two { 2 } else { 1 };
            }
            None => pos = bytes.len(),
        }
    }
    starts.push(bytes.len() as u32);
    starts
}
