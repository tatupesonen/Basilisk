//! Diagnostics of the compiler (spec 4.4).
//!
//! A diagnostic carries the text Ghidra's C++ compiler prints, its severity,
//! the span of the construct it is about (when there is one), and whether
//! Ghidra puts a `FILE:LINE: ` location in front of the text
//! (`SleighCompile::formatStatusMessage`). Rendering as Ghidra prints them
//! (`FILE:LINE - ERROR TEXT`, `WARN  TEXT`) belongs to the command line.

use bk_sleigh_syntax::Span;

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// The specification is rejected; nothing is produced.
    Error,
    /// A potential problem; output is still produced.
    Warning,
}

/// One message of the compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Error or warning.
    pub severity: Severity,
    /// The construct the message is about, in the preprocessed text of the
    /// specification, if the message is about one.
    pub span: Option<Span>,
    /// Whether Ghidra prefixes the text with the location of `span` as
    /// `FILE:LINE: ` (for constructors: the file and line of the
    /// constructor).
    pub located: bool,
    /// The message text exactly as Ghidra builds it, without location.
    pub message: String,
}

impl Diagnostic {
    /// An error about `span`, printed by Ghidra without an inner location.
    pub fn error(span: Option<Span>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            span,
            located: false,
            message: message.into(),
        }
    }

    /// A warning about `span`, printed by Ghidra without an inner location.
    pub fn warning(span: Option<Span>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            span,
            located: false,
            message: message.into(),
        }
    }

    /// The same diagnostic, marked as printed with Ghidra's inner
    /// `FILE:LINE: ` location.
    #[must_use]
    pub fn located(mut self) -> Self {
        self.located = self.span.is_some();
        self
    }

    /// Whether this is an error.
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// The diagnostics of one compile, with Ghidra's error count.
#[derive(Clone, Debug, Default)]
pub(crate) struct Diagnostics {
    pub(crate) list: Vec<Diagnostic>,
    errors: usize,
}

impl Diagnostics {
    /// Adds a diagnostic.
    pub(crate) fn push(&mut self, diagnostic: Diagnostic) {
        if diagnostic.is_error() {
            self.errors = self.errors.saturating_add(1);
        }
        self.list.push(diagnostic);
    }

    /// Adds an error.
    pub(crate) fn error(&mut self, span: Option<Span>, message: impl Into<String>) {
        self.push(Diagnostic::error(span, message));
    }

    /// Adds an error printed with an inner location.
    pub(crate) fn error_at(&mut self, span: Span, message: impl Into<String>) {
        self.push(Diagnostic::error(Some(span), message).located());
    }

    /// Adds a warning.
    pub(crate) fn warning(&mut self, span: Option<Span>, message: impl Into<String>) {
        self.push(Diagnostic::warning(span, message));
    }

    /// Adds a warning printed with an inner location.
    pub(crate) fn warning_at(&mut self, span: Span, message: impl Into<String>) {
        self.push(Diagnostic::warning(Some(span), message).located());
    }

    /// The number of errors so far.
    pub(crate) fn errors(&self) -> usize {
        self.errors
    }
}
