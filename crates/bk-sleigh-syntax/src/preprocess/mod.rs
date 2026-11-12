//! The SLEIGH preprocessor.
//!
//! Line-oriented, run before lexing, following Ghidra's
//! `SleighPreprocessor.java`:
//!
//! * A line whose first character is `@` is a directive: `@include`,
//!   `@define`, `@undef`, `@ifdef`, `@ifndef`, `@if`, `@elif`, `@else`,
//!   `@endif` (forms in the `directive` module).
//! * A line that is only a `#` comment is blanked.
//! * In every other line, `$(NAME)` is replaced by the value of `NAME`.
//!   Replacement is textual and not recursive.
//! * Lines inside a false conditional are dropped. Conditional directives
//!   are still tracked there, and the expressions of `@if`/`@elif` are still
//!   evaluated (so an undefined name in them is still an error), but
//!   `@include`, `@define` and `@undef` have no effect.
//! * Conditionals do not span files: each included file starts with a fresh
//!   conditional stack, and one left open at the end of a file is closed
//!   silently.
//!
//! The output is plain text with one line per input line read, plus a
//! [`SourceMap`] that records where each line and each expansion came from.
//! Each expanded value is preceded by one U+0008
//! ([`crate::source::EXPANSION_MARK`]), which the lexer skips: like the
//! marker Ghidra writes there, it separates the value from the token
//! before it, so `export$(X)` is `export` followed by the tokens of `X`.

mod defines;
mod directive;
mod expand;
pub mod expr;
mod include;

use std::path::{Path, PathBuf};

pub use defines::Defines;

use crate::diag::Diagnostic;
use crate::loader::{FileLoader, LoadError};
use crate::source::{LineKind, SourceMap};
use crate::span::{IncludeId, Span};
use directive::Directive;

/// Deepest nesting of `@include` accepted.
pub const MAX_INCLUDE_DEPTH: usize = 64;

/// Largest number of inclusions (root file plus expanded `@include`s) in one
/// run. Bounds the work a specification can cause by including the same
/// files over and over.
pub const MAX_INCLUSIONS: usize = 10_000;

/// Largest preprocessed text accepted, in bytes (1 GiB). Spans are 32-bit.
pub const MAX_OUTPUT_BYTES: usize = 1 << 30;

/// The result of preprocessing a specification.
#[derive(Debug)]
pub struct Preprocessed {
    /// The preprocessed text and its origin map.
    pub sources: SourceMap,
    /// The definitions in effect at the end of the root file.
    pub defines: Defines,
    /// Problems found. Any error means Ghidra would have refused the input.
    pub diagnostics: Vec<Diagnostic>,
}

/// Preprocesses the specification at `root`, reading it and the files it
/// includes through `loader`, starting from the definitions in `defines`.
pub fn preprocess(root: &Path, defines: &Defines, loader: &mut dyn FileLoader) -> Preprocessed {
    preprocess_limited(root, defines, loader, MAX_OUTPUT_BYTES)
}

/// [`preprocess`] with a smaller output limit, so tests can reach it.
pub(crate) fn preprocess_limited(
    root: &Path,
    defines: &Defines,
    loader: &mut dyn FileLoader,
    max_output: usize,
) -> Preprocessed {
    let mut pp = Preprocessor {
        map: SourceMap::default(),
        defines: defines.clone(),
        diagnostics: Vec::new(),
        loader,
        stack: Vec::new(),
        known: std::collections::HashMap::new(),
        stopped: false,
        max_output: max_output.min(MAX_OUTPUT_BYTES),
    };
    pp.file(root.to_path_buf(), None);
    Preprocessed {
        sources: pp.map,
        defines: pp.defines,
        diagnostics: pp.diagnostics,
    }
}

/// Whether `line` holds nothing but a `#` comment (Ghidra's `^\s*#.*`).
pub(crate) fn is_comment_line(line: &str) -> bool {
    line.bytes().find(|b| !directive::is_space(*b)) == Some(b'#')
}

/// One level of `@if` nesting (Ghidra's `ConditionalHelper`).
#[derive(Clone, Copy, Debug)]
struct Conditional {
    /// False only for the bottom entry, which stands for "not in an `@if`".
    in_if: bool,
    /// An `@else` has been seen at this level.
    saw_else: bool,
    /// Some branch at this level has already been taken.
    handled: bool,
    /// Lines at this level are copied (if every enclosing level copies too).
    copy: bool,
}

impl Conditional {
    /// The state after an `@if`, `@ifdef` or `@ifndef`.
    const fn opened(copy: bool, handled: bool) -> Self {
        Self {
            in_if: true,
            saw_else: false,
            handled,
            copy,
        }
    }
}

struct Preprocessor<'a> {
    map: SourceMap,
    defines: Defines,
    diagnostics: Vec<Diagnostic>,
    loader: &'a mut dyn FileLoader,
    /// The files currently being read, outermost first: each path as
    /// spelled (includes resolve against it) and its identity
    /// ([`FileLoader::identity`], for cycle detection).
    stack: Vec<(PathBuf, PathBuf)>,
    /// The file already read under each identity.
    known: std::collections::HashMap<PathBuf, crate::span::FileId>,
    /// Set when a limit was hit; no more input is read.
    stopped: bool,
    /// Largest output accepted ([`MAX_OUTPUT_BYTES`] outside tests).
    max_output: usize,
}

impl Preprocessor<'_> {
    /// Reports an error located at the start of the current output line.
    fn error(&mut self, message: impl Into<String>) {
        let at = Span::at(self.map.current_line_start());
        self.diagnostics.push(Diagnostic::error(at, message));
    }

    /// Reads one file and appends its preprocessed lines. `parent` is the
    /// inclusion and line of the `@include` that named it.
    fn file(&mut self, path: PathBuf, parent: Option<(IncludeId, u32)>) {
        let identity = self.loader.identity(&path);
        let file_id = match self.known.get(&identity) {
            Some(id) => *id,
            None => match self.loader.load(&path) {
                Ok(text) if text.len() >= self.max_output => {
                    let err = LoadError::TooLarge {
                        size: text.len() as u64,
                        limit: self.max_output as u64,
                    };
                    self.load_failed(&path, parent.is_some(), &err);
                    return;
                }
                Ok(text) => {
                    let id = self.map.add_file(path.clone(), text);
                    self.known.insert(identity.clone(), id);
                    id
                }
                Err(err) => {
                    self.load_failed(&path, parent.is_some(), &err);
                    return;
                }
            },
        };
        let Some(source) = self.map.file_arc(file_id) else {
            return;
        };
        let include = self.map.add_include(file_id, parent);
        self.map.start_run(include, 1);
        self.stack.push((path, identity));

        let mut conditionals = vec![Conditional {
            in_if: false,
            saw_else: false,
            handled: false,
            copy: true,
        }];
        let line_count = source.line_count();
        let mut line_no = 1;
        while line_no <= line_count && !self.stopped {
            let line = source.line(line_no).unwrap_or("");
            if self.map.out_len() + line.len() >= self.max_output {
                self.too_large();
                break;
            }
            let copying = conditionals.iter().all(|c| c.copy);
            if line.starts_with('@') {
                let included = self.directive(line, include, line_no, copying, &mut conditionals);
                if included {
                    // The include directive itself produces no output line.
                    self.map.start_run(include, line_no + 1);
                } else {
                    self.map.end_line(LineKind::Directive);
                }
            } else if !copying {
                self.map.end_line(LineKind::Skipped);
            } else {
                if !is_comment_line(line) {
                    self.expand_into_output(line);
                }
                self.map.end_line(LineKind::Text);
            }
            line_no += 1;
        }
        // A conditional still open here is silently closed, as in both of
        // Ghidra's front ends (ARMv8.sinc relies on it).
        self.stack.pop();
    }

    /// Reports that the output limit was reached and stops reading input.
    fn too_large(&mut self) {
        let limit = self.max_output;
        self.error(format!(
            "specification is too large to preprocess (over {limit} bytes)"
        ));
        self.stopped = true;
    }

    fn load_failed(&mut self, path: &Path, is_include: bool, err: &LoadError) {
        if is_include {
            self.error(format!("included file \"{}\": {err}", path.display()));
        } else {
            self.error(format!("cannot read \"{}\": {err}", path.display()));
        }
    }

    /// Acts on a directive line. Returns true if it was an `@include` that
    /// was expanded (and so has no output line of its own).
    fn directive(
        &mut self,
        line: &str,
        include: IncludeId,
        line_no: u32,
        copying: bool,
        conditionals: &mut Vec<Conditional>,
    ) -> bool {
        match directive::parse(line) {
            Directive::Include(name) => {
                if copying {
                    return self.include(name, include, line_no);
                }
            }
            Directive::Define { name, value } => {
                if copying {
                    self.defines.set(name, value);
                }
            }
            Directive::Undef(name) => {
                if copying {
                    self.defines.undefine(name);
                }
            }
            Directive::Ifdef(name) => {
                let taken = self.defines.is_defined(name);
                conditionals.push(Conditional::opened(copying && taken, taken));
            }
            Directive::Ifndef(name) => {
                let taken = !self.defines.is_defined(name);
                conditionals.push(Conditional::opened(copying && taken, taken));
            }
            Directive::If(expression) => {
                let taken = self.condition(expression);
                conditionals.push(Conditional::opened(taken, taken));
            }
            Directive::Elif(expression) => match conditionals.last().copied() {
                Some(top) if !top.in_if => self.error("elif outside of IF* directive"),
                Some(top) if top.saw_else => self.error("already saw else directive"),
                Some(top) => {
                    // Not evaluated once a branch has been taken.
                    let taken = !top.handled && self.condition(expression);
                    if let Some(top) = conditionals.last_mut() {
                        top.copy = taken;
                        top.handled |= taken;
                    }
                }
                None => {}
            },
            Directive::Else => match conditionals.last_mut() {
                Some(top) if !top.in_if => self.error("else outside of IF* directive"),
                Some(top) if top.saw_else => self.error("duplicate else directive"),
                Some(top) => {
                    top.saw_else = true;
                    top.copy = !top.handled;
                }
                None => {}
            },
            Directive::Endif => {
                if conditionals.last().is_some_and(|top| top.in_if) {
                    conditionals.pop();
                } else {
                    self.error("not in IF* directive");
                }
            }
            Directive::Unrecognized => self.error("unrecognized preprocessor directive"),
        }
        false
    }

    /// Evaluates an `@if`/`@elif` expression, reporting its problems.
    fn condition(&mut self, expression: &str) -> bool {
        match expr::evaluate(expression, &self.defines) {
            Ok(result) => {
                for name in &result.undefined {
                    self.error(format!("Macro: {name} is undefined"));
                }
                result.value
            }
            Err(err) => {
                self.error(format!("malformed preprocessor expression: {err}"));
                false
            }
        }
    }

    /// Expands an `@include`. Returns whether the file was read.
    fn include(&mut self, name: &str, include: IncludeId, line_no: u32) -> bool {
        let mut expanded = String::new();
        if let Err(unknown) = expand::expand(name, &self.defines, |piece| match piece {
            expand::Piece::Text(text) | expand::Piece::Value { value: text, .. } => {
                expanded.push_str(text);
            }
        }) {
            self.error(format!("unknown variable: {unknown}"));
            return false;
        }
        let Some((current, _)) = self.stack.last() else {
            return false;
        };
        let path = include::resolve(current, &expanded);
        let identity = self.loader.identity(&path);
        if self.stack.iter().any(|(_, open)| *open == identity) {
            self.error(format!(
                "included file \"{}\": includes itself",
                path.display()
            ));
            return false;
        }
        if self.stack.len() >= MAX_INCLUDE_DEPTH {
            self.error(format!(
                "included file \"{}\": includes nested deeper than {MAX_INCLUDE_DEPTH}",
                path.display()
            ));
            return false;
        }
        if self.map.include_count() >= MAX_INCLUSIONS {
            self.error(format!("more than {MAX_INCLUSIONS} files included"));
            self.stopped = true;
            return false;
        }
        let files_before = self.map.include_count();
        self.file(path, Some((include, line_no)));
        self.map.include_count() > files_before
    }

    /// Appends `line` to the output with `$(NAME)` references replaced.
    fn expand_into_output(&mut self, line: &str) {
        if memchr::memchr(b'$', line.as_bytes()).is_none() {
            self.map.push_text(line);
            return;
        }
        let Self {
            map,
            defines,
            diagnostics,
            max_output,
            ..
        } = self;
        let mut unknown: Vec<(u32, String)> = Vec::new();
        // Expansion can multiply a line's size (many references to a long
        // value), so the limit is checked for every piece.
        let mut overflow = false;
        let mut fits = |map: &SourceMap, len: usize| {
            overflow |= map.out_len() + len + 1 >= *max_output;
            !overflow
        };
        expand::expand_lenient(line, defines, |piece| match piece {
            expand::LenientPiece::Text(text) => {
                if fits(map, text.len()) {
                    map.push_text(text);
                }
            }
            expand::LenientPiece::Value {
                value,
                src_col,
                src_len,
            } => {
                if fits(map, value.len()) {
                    map.push_expansion(value, src_col, src_len);
                }
            }
            expand::LenientPiece::Unknown {
                name,
                src_col,
                src_len,
            } => {
                unknown.push((map.out_len() as u32, name.to_owned()));
                if fits(map, 0) {
                    map.push_expansion("", src_col, src_len);
                }
            }
        });
        for (at, name) in unknown {
            diagnostics.push(Diagnostic::error(
                Span::at(at),
                format!("unknown variable: {name}"),
            ));
        }
        if overflow {
            self.too_large();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::MemoryLoader;

    fn limited(files: &[(&str, &str)], limit: usize) -> Preprocessed {
        let mut loader = MemoryLoader::new();
        for (name, text) in files {
            loader.add(*name, *text);
        }
        preprocess_limited(Path::new(files[0].0), &Defines::new(), &mut loader, limit)
    }

    #[test]
    fn output_limit_stops_repeated_inclusion() {
        let text = "0123456789\n".repeat(30);
        let p = limited(
            &[("a", "@include \"b\"\n@include \"b\"\n"), ("b", &text)],
            500,
        );
        assert_eq!(p.diagnostics.len(), 1);
        assert_eq!(
            p.diagnostics[0].message,
            "specification is too large to preprocess (over 500 bytes)"
        );
        assert!(p.sources.text().len() < 500);
    }

    #[test]
    fn output_limit_bounds_expansion() {
        // One line whose references multiply a long value: the limit holds
        // within the line, not only between lines.
        let value = "x".repeat(100);
        let refs = "$(V)".repeat(1000);
        let text = format!("@define V \"{value}\"\n{refs}\nafter\n");
        let p = limited(&[("a", &text)], 2000);
        assert_eq!(p.diagnostics.len(), 1, "{:?}", p.diagnostics);
        assert!(p.diagnostics[0].message.contains("too large"));
        assert!(p.sources.text().len() < 2000);
        assert!(!p.sources.text().contains("after"));
    }

    #[test]
    fn a_file_over_the_limit_is_not_read() {
        let text = "x".repeat(600);
        let p = limited(&[("a", "@include \"b\"\n"), ("b", &text)], 500);
        assert_eq!(p.diagnostics.len(), 1);
        assert!(
            p.diagnostics[0]
                .message
                .contains("file is too large (600 bytes; the limit is 500)"),
            "{}",
            p.diagnostics[0].message
        );
    }
}
