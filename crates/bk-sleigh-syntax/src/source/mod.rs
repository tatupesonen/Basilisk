//! The preprocessed text and the map from it back to the original files.
//!
//! Ghidra's Java preprocessor writes position markers (`\bfile###line\b`)
//! into its output and the lexer re-reads them. Here the preprocessor
//! produces plain text plus a [`SourceMap`]: for every output line, the
//! inclusion and line it came from, and for every `$(NAME)` expansion, where
//! the reference stood. A [`Span`] in the preprocessed text resolves to a
//! [`Location`] in an original file through [`SourceMap::locate`].

use std::fmt::Write as _;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use crate::diag::Diagnostic;
use crate::span::{FileId, IncludeId, Location, Span};

mod file;
mod indexer;

pub use file::SourceFile;
pub use indexer::SourceFileIndexer;

/// What the preprocessor did with one input line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    /// Copied to the output (after `$(NAME)` expansion).
    Text,
    /// A preprocessor directive; its output line is empty.
    Directive,
    /// Inside a false conditional; its output line is empty.
    Skipped,
}

#[derive(Clone, Copy, Debug)]
struct Include {
    file: FileId,
    /// The inclusion and line of the `@include` directive, if not the root.
    parent: Option<(IncludeId, u32)>,
}

/// Consecutive output lines that come from consecutive lines of one inclusion.
#[derive(Clone, Copy, Debug)]
struct LineRun {
    first_out_line: u32,
    include: IncludeId,
    first_src_line: u32,
}

/// The character the preprocessor puts in front of every expanded value.
///
/// Ghidra's preprocessor writes a `\b$(NAME)\b` marker there, which its
/// lexer skips; the marker therefore ends whatever token precedes the
/// value (`export$(X)` is the word `export` followed by the tokens of `X`),
/// while the end of the value joins the text after it. One U+0008 keeps
/// that behaviour: the lexer skips it everywhere and no token spans it.
pub const EXPANSION_MARK: char = '\u{8}';

/// One `$(NAME)` reference replaced by its value.
#[derive(Clone, Copy, Debug)]
struct Expansion {
    /// Offset of the mark that precedes the value in the preprocessed text.
    out_start: u32,
    /// Length of the mark plus the value.
    out_len: u32,
    /// Byte column of the `$` within its source line.
    src_col: u32,
    /// Length of the `$(NAME)` reference.
    src_len: u32,
}

/// The preprocessed text of a specification and its origin map.
#[derive(Debug, Default)]
pub struct SourceMap {
    text: String,
    files: Vec<Arc<SourceFile>>,
    includes: Vec<Include>,
    line_starts: Vec<u32>,
    runs: Vec<LineRun>,
    kinds: Vec<LineKind>,
    expansions: Vec<Expansion>,
    /// Start of the output line currently being written.
    line_begin: u32,
}

impl SourceMap {
    /// A map over `text` that came from a single in-memory source with no
    /// directives, named `name`. Used for standalone snippets.
    pub fn from_text(name: &str, text: &str) -> Self {
        let mut map = Self::default();
        let file = map.add_file(PathBuf::from(name), text.to_owned());
        let include = map.add_include(file, None);
        map.start_run(include, 1);
        let source = map.file_arc(file);
        if let Some(source) = source {
            for line in 1..=source.line_count() {
                map.push_text(source.line(line).unwrap_or(""));
                map.end_line(LineKind::Text);
            }
        }
        map
    }

    // ----- construction (used by the preprocessor) -----

    pub(crate) fn add_file(&mut self, path: PathBuf, text: String) -> FileId {
        let id = FileId(self.files.len() as u32);
        self.files.push(Arc::new(SourceFile::new(path, text)));
        id
    }

    pub(crate) fn file_arc(&self, file: FileId) -> Option<Arc<SourceFile>> {
        self.files.get(file.0 as usize).cloned()
    }

    pub(crate) fn add_include(
        &mut self,
        file: FileId,
        parent: Option<(IncludeId, u32)>,
    ) -> IncludeId {
        let id = IncludeId(self.includes.len() as u32);
        self.includes.push(Include { file, parent });
        id
    }

    pub(crate) fn include_count(&self) -> usize {
        self.includes.len()
    }

    /// Following output lines come from `include`, starting at `src_line`.
    pub(crate) fn start_run(&mut self, include: IncludeId, src_line: u32) {
        let first_out_line = self.kinds.len() as u32;
        self.runs.push(LineRun {
            first_out_line,
            include,
            first_src_line: src_line,
        });
    }

    /// Appends text to the current output line.
    pub(crate) fn push_text(&mut self, text: &str) {
        self.text.push_str(text);
    }

    /// Appends the value of a `$(NAME)` reference that stood at byte column
    /// `src_col` of its source line and was `src_len` bytes long. The value
    /// is preceded by [`EXPANSION_MARK`].
    pub(crate) fn push_expansion(&mut self, value: &str, src_col: u32, src_len: u32) {
        self.expansions.push(Expansion {
            out_start: self.text.len() as u32,
            out_len: value.len() as u32 + 1,
            src_col,
            src_len,
        });
        self.text.push(EXPANSION_MARK);
        self.text.push_str(value);
    }

    /// Ends the current output line.
    pub(crate) fn end_line(&mut self, kind: LineKind) {
        self.line_starts.push(self.line_begin);
        self.kinds.push(kind);
        self.text.push('\n');
        self.line_begin = self.text.len() as u32;
    }

    /// Offset at which the current (unfinished) output line starts.
    pub(crate) fn current_line_start(&self) -> u32 {
        self.line_begin
    }

    /// Current length of the preprocessed text.
    pub(crate) fn out_len(&self) -> usize {
        self.text.len()
    }

    // ----- queries -----

    /// The preprocessed text: what the lexer reads. Each expanded
    /// `$(NAME)` value is preceded by [`EXPANSION_MARK`].
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The preprocessed text covered by `span`; empty if out of range.
    pub fn snippet(&self, span: Span) -> &str {
        self.text.get(span.range()).unwrap_or("")
    }

    /// The source files, indexed by [`FileId`], in order of first use.
    pub fn files(&self) -> impl ExactSizeIterator<Item = &SourceFile> {
        self.files.iter().map(|f| &**f)
    }

    /// The file with the given id.
    pub fn file(&self, file: FileId) -> Option<&SourceFile> {
        self.files.get(file.0 as usize).map(|f| &**f)
    }

    /// Number of lines in the preprocessed text (one per input line read,
    /// except `@include` lines that were expanded).
    pub fn line_count(&self) -> usize {
        self.kinds.len()
    }

    /// Number of inclusions: the root file plus every expanded `@include`.
    pub fn inclusion_count(&self) -> usize {
        self.includes.len()
    }

    /// The file an inclusion refers to.
    pub fn include_file(&self, include: IncludeId) -> Option<FileId> {
        self.includes.get(include.0 as usize).map(|i| i.file)
    }

    /// The `@include` directives that led to `include`, innermost first:
    /// each entry is the file and line of one directive. Empty for the root.
    pub fn include_chain(&self, include: IncludeId) -> Vec<(FileId, u32)> {
        let mut chain = Vec::new();
        let mut current = self.includes.get(include.0 as usize).and_then(|i| i.parent);
        while let Some((parent, line)) = current {
            let Some(inc) = self.includes.get(parent.0 as usize) else {
                break;
            };
            chain.push((inc.file, line));
            current = inc.parent;
            if chain.len() > self.includes.len() {
                break;
            }
        }
        chain
    }

    /// Index of the output line containing `offset`, and that line's start.
    fn out_line(&self, offset: u32) -> Option<(usize, u32)> {
        let index = self
            .line_starts
            .partition_point(|&s| s <= offset)
            .checked_sub(1)?;
        Some((index, *self.line_starts.get(index)?))
    }

    fn run_of(&self, out_line: usize) -> Option<&LineRun> {
        let index = self
            .runs
            .partition_point(|r| r.first_out_line as usize <= out_line)
            .checked_sub(1)?;
        self.runs.get(index)
    }

    /// Maps a byte offset in the preprocessed text to (inclusion, source
    /// line, byte column in that line, inside-expansion flag).
    fn origin(&self, offset: u32) -> Option<(IncludeId, u32, u32, bool)> {
        let offset = offset.min(self.text.len() as u32);
        let (line_index, line_start) = self.out_line(offset)?;
        let run = self.run_of(line_index)?;
        let src_line = run.first_src_line + (line_index as u32 - run.first_out_line);
        let mut column = i64::from(offset - line_start);
        let mut in_expansion = false;
        let first = self
            .expansions
            .partition_point(|e| e.out_start < line_start);
        for exp in self.expansions.get(first..).unwrap_or(&[]) {
            if exp.out_start > offset {
                break;
            }
            if offset < exp.out_start + exp.out_len {
                column = i64::from(exp.src_col);
                in_expansion = true;
                break;
            }
            column += i64::from(exp.src_len) - i64::from(exp.out_len);
        }
        Some((
            run.include,
            src_line,
            u32::try_from(column).unwrap_or(0),
            in_expansion,
        ))
    }

    /// The original position of byte `offset` of the preprocessed text.
    pub fn locate(&self, offset: u32) -> Option<Location> {
        let (include, line, byte_col, in_expansion) = self.origin(offset)?;
        let file = self.include_file(include)?;
        let column = self
            .file(file)
            .and_then(|f| f.line(line))
            .and_then(|text| text.get(..byte_col as usize))
            .map_or(byte_col, |prefix| prefix.chars().count() as u32);
        Some(Location {
            file,
            include,
            line,
            column: column + 1,
            in_expansion,
        })
    }

    /// The original position of the start of `span`.
    pub fn span_start(&self, span: Span) -> Option<Location> {
        self.locate(span.start)
    }

    /// The byte range `span` covers in its original file, for renderers that
    /// draw source snippets. `None` if the span crosses a line or touches a
    /// `$(NAME)` expansion, whose text is not in the file.
    pub fn source_range(&self, span: Span) -> Option<(FileId, Range<usize>)> {
        let (include, line, start_col, start_exp) = self.origin(span.start)?;
        let (end_include, end_line, end_col, end_exp) = self.origin(span.end)?;
        if start_exp || end_exp || include != end_include || line != end_line {
            return None;
        }
        let file = self.include_file(include)?;
        let line_range = self.file(file)?.line_range(line)?;
        let start = line_range.start + start_col as usize;
        let end = line_range.start + end_col as usize;
        (start <= end && end <= line_range.end).then_some((file, start..end))
    }

    /// Formats a diagnostic as `path:line:column: severity: message`,
    /// followed by one `included from path:line` line per enclosing
    /// `@include`.
    pub fn render(&self, diagnostic: &Diagnostic) -> String {
        let severity = diagnostic.severity.as_str();
        let Some(loc) = self.locate(diagnostic.span.start) else {
            return format!("{severity}: {}", diagnostic.message);
        };
        let path = self
            .file(loc.file)
            .map_or_else(String::new, |f| f.path().display().to_string());
        let mut out = format!(
            "{path}:{}:{}: {severity}: {}",
            loc.line, loc.column, diagnostic.message
        );
        for (file, line) in self.include_chain(loc.include) {
            let path = self
                .file(file)
                .map_or_else(String::new, |f| f.path().display().to_string());
            let _ = write!(out, "\n    included from {path}:{line}");
        }
        out
    }

    /// The preprocessed text in the form Ghidra's `SleighPreprocessor`
    /// writes it: a `\bfile###line\b` marker wherever the origin changes,
    /// `\b$(NAME)\b` before each expanded value, and directive and skipped
    /// lines kept as `#` comments. Used to compare against Ghidra's output.
    pub fn to_ghidra_text(&self) -> String {
        let mut out = String::with_capacity(self.text.len() + self.kinds.len() * 2);
        let mut expansions = self.expansions.iter().peekable();
        let mut run_index = 0usize;
        for (line_index, kind) in self.kinds.iter().enumerate() {
            while let Some(run) = self.runs.get(run_index) {
                if run.first_out_line as usize > line_index {
                    break;
                }
                self.push_marker(&mut out, run);
                run_index += 1;
            }
            let run = self.run_of(line_index);
            let source_line = run.and_then(|run| {
                let line = run.first_src_line + (line_index as u32 - run.first_out_line);
                self.file(self.include_file(run.include)?)?.line(line)
            });
            let start = self.line_starts.get(line_index).copied().unwrap_or(0) as usize;
            let end = self
                .line_starts
                .get(line_index + 1)
                .map_or(self.text.len(), |&next| next as usize)
                .saturating_sub(1);
            match kind {
                LineKind::Directive => {
                    out.push('#');
                    out.push_str(source_line.unwrap_or(""));
                }
                LineKind::Skipped => {
                    out.push('#');
                    let line = source_line.unwrap_or("");
                    if !crate::preprocess::is_comment_line(line) {
                        out.push_str(line);
                    }
                }
                LineKind::Text => {
                    let mut pos = start;
                    while let Some(exp) = expansions.peek() {
                        let exp_start = exp.out_start as usize;
                        if exp_start > end {
                            break;
                        }
                        out.push_str(self.text.get(pos..exp_start).unwrap_or(""));
                        let reference = source_line
                            .and_then(|l| {
                                l.get(exp.src_col as usize..(exp.src_col + exp.src_len) as usize)
                            })
                            .unwrap_or("");
                        out.push('\u{8}');
                        out.push_str(reference);
                        out.push('\u{8}');
                        // Skip our own one-character mark.
                        pos = exp_start + EXPANSION_MARK.len_utf8();
                        expansions.next();
                    }
                    out.push_str(self.text.get(pos..end).unwrap_or(""));
                }
            }
            out.push('\n');
        }
        for run in self.runs.get(run_index..).unwrap_or(&[]) {
            self.push_marker(&mut out, run);
        }
        out.push('\n');
        out
    }

    fn push_marker(&self, out: &mut String, run: &LineRun) {
        let name = self
            .include_file(run.include)
            .and_then(|f| self.file(f))
            .map_or("", |f| f.name());
        out.push('\u{8}');
        out.push_str(name);
        out.push_str("###");
        out.push_str(&run.first_src_line.to_string());
        out.push('\u{8}');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_like_java_read_line() {
        let f = SourceFile::new(
            PathBuf::from("dir/a.sinc"),
            "one\ntwo\r\nthree\rfour".to_owned(),
        );
        assert_eq!(f.name(), "a.sinc");
        assert_eq!(f.line_count(), 4);
        assert_eq!(f.line(1), Some("one"));
        assert_eq!(f.line(2), Some("two"));
        assert_eq!(f.line(3), Some("three"));
        assert_eq!(f.line(4), Some("four"));
        assert_eq!(f.line(5), None);
        assert_eq!(f.line(0), None);

        let g = SourceFile::new(PathBuf::from("b"), "x\n\n".to_owned());
        assert_eq!(g.line_count(), 2);
        assert_eq!(g.line(2), Some(""));
        assert_eq!(
            SourceFile::new(PathBuf::from("c"), String::new()).line_count(),
            0
        );
    }

    #[test]
    fn from_text_maps_offsets_to_lines_and_columns() {
        let map = SourceMap::from_text("snippet", "ab\n  cd\n");
        assert_eq!(map.text(), "ab\n  cd\n");
        let loc = map.locate(5).unwrap();
        assert_eq!((loc.line, loc.column, loc.in_expansion), (2, 3, false));
        let first = map.locate(0).unwrap();
        assert_eq!((first.line, first.column), (1, 1));
        assert_eq!(map.source_range(Span::new(5, 7)), Some((FileId(0), 5..7)));
        assert_eq!(map.snippet(Span::new(5, 7)), "cd");
        assert!(map.include_chain(loc.include).is_empty());
    }

    #[test]
    fn columns_count_characters_not_bytes() {
        let map = SourceMap::from_text("s", "\"é\" x\n");
        let offset = map.text().find('x').unwrap() as u32;
        assert_eq!(map.locate(offset).unwrap().column, 5);
    }
}
