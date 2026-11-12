//! Diagnostics: errors and warnings with a source span.

use crate::span::Span;

/// How serious a [`Diagnostic`] is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Severity {
    /// The input is not valid SLEIGH; Ghidra would refuse it.
    Error,
    /// The input is accepted but suspicious.
    Warning,
}

impl Severity {
    /// Lower-case name, as printed in rendered diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// A message about the input, located by a span in the preprocessed text.
///
/// Use [`crate::SourceMap::render`] to print it with the original file, line
/// and include chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Diagnostic {
    /// Error or warning.
    pub severity: Severity,
    /// Where the problem is.
    pub span: Span,
    /// What the problem is.
    pub message: String,
}

impl Diagnostic {
    /// An error at `span`.
    pub fn error(span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            span,
            message: message.into(),
        }
    }

    /// A warning at `span`.
    pub fn warning(span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            span,
            message: message.into(),
        }
    }

    /// Whether this is an error.
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}
