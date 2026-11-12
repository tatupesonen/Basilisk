//! Error and diagnostic types shared by the readers and the registry.

use std::{fmt, io, path::PathBuf, sync::Arc};

use crate::id::{CompilerSpecId, LanguageId};

/// A 1-based line and column in a spec file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Position {
    /// Line number, starting at 1.
    pub line: u32,
    /// Column number in characters, starting at 1.
    pub column: u32,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

/// How a reader treats content that the file's RELAX NG schema does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Mode {
    /// A schema violation is an error naming the position. This is what
    /// Ghidra does for `.ldefs` and `.pspec` files, which it validates
    /// before reading.
    #[default]
    Strict,
    /// A schema violation becomes a [`Warning`] and reading continues with
    /// the fallback Ghidra's own reader would use. Meant for user-supplied
    /// processor modules.
    Lenient,
}

/// One way a document departs from its schema.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Violation {
    /// An element that the schema does not allow at this place.
    #[error("element <{name}> is not allowed in <{parent}>")]
    UnknownElement {
        /// The enclosing element.
        parent: &'static str,
        /// The offending element's name.
        name: String,
    },
    /// An attribute that the schema does not define for the element.
    #[error("attribute \"{name}\" is not allowed on <{element}>")]
    UnknownAttribute {
        /// The element carrying the attribute.
        element: &'static str,
        /// The offending attribute's name.
        name: String,
    },
    /// A required attribute is absent.
    #[error("<{element}> is missing required attribute \"{name}\"")]
    MissingAttribute {
        /// The element that lacks the attribute.
        element: &'static str,
        /// The attribute's name.
        name: &'static str,
    },
    /// An attribute whose value is outside the set the schema allows.
    #[error("<{element}> attribute {name}=\"{value}\": expected {expected}")]
    InvalidAttributeValue {
        /// The element carrying the attribute.
        element: &'static str,
        /// The attribute's name.
        name: &'static str,
        /// The value found.
        value: String,
        /// What the schema allows.
        expected: &'static str,
    },
    /// A required child element is absent.
    #[error("<{parent}> is missing required element <{name}>")]
    MissingElement {
        /// The enclosing element.
        parent: &'static str,
        /// The missing child's name.
        name: &'static str,
    },
    /// A child element that may occur at most once occurs again.
    #[error("<{parent}> has more than one <{name}>")]
    RepeatedElement {
        /// The enclosing element.
        parent: &'static str,
        /// The repeated child's name.
        name: &'static str,
    },
    /// A child element appears after one that the schema places later.
    #[error("<{name}> is out of order in <{parent}>")]
    OutOfOrder {
        /// The enclosing element.
        parent: &'static str,
        /// The misplaced child's name.
        name: &'static str,
    },
    /// Character data in an element that may only hold elements.
    #[error("<{element}> may not contain text")]
    UnexpectedText {
        /// The element holding the text.
        element: &'static str,
    },
    /// A rule the schema states that is not about a single name.
    #[error("<{element}>: {rule}")]
    Rule {
        /// The element the rule applies to.
        element: &'static str,
        /// The rule that was broken.
        rule: &'static str,
    },
}

/// A schema violation tolerated in [`Mode::Lenient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Where the violation is.
    pub position: Position,
    /// What the violation is.
    pub violation: Violation,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.position, self.violation)
    }
}

/// Why a document could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// The text is not well-formed XML.
    #[error("malformed XML: {0}")]
    Xml(String),
    /// The document element is not the one this file type has.
    #[error("expected root element <{expected}>, found <{found}>")]
    WrongRoot {
        /// The root element the file type requires.
        expected: &'static str,
        /// The root element found.
        found: String,
    },
    /// A schema violation, in [`Mode::Strict`].
    #[error("{0}")]
    Schema(Violation),
    /// A required attribute is absent (an error in both modes: the reader
    /// has nothing to build the value from).
    #[error("<{element}> is missing required attribute \"{attribute}\"")]
    MissingAttribute {
        /// The element that lacks the attribute.
        element: &'static str,
        /// The attribute's name.
        attribute: &'static str,
    },
    /// An attribute value that cannot be decoded (an error in both modes;
    /// Ghidra's reader throws here).
    #[error("<{element}> attribute {attribute}=\"{value}\": expected {expected}")]
    InvalidValue {
        /// The element carrying the attribute.
        element: &'static str,
        /// The attribute's name.
        attribute: &'static str,
        /// The value found.
        value: String,
        /// What was expected.
        expected: &'static str,
    },
    /// Content that is well-formed and schema-valid but that Ghidra's
    /// reader rejects.
    #[error("<{element}>: {message}")]
    Rejected {
        /// The element concerned.
        element: &'static str,
        /// Why it is rejected.
        message: String,
    },
}

/// A failure to read a document, with its position.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{position}: {kind}")]
pub struct ParseError {
    /// Where the problem is.
    pub position: Position,
    /// What the problem is.
    pub kind: ParseErrorKind,
}

/// A failure to read a spec file from disk.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The file could not be read.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: io::Error,
    },
    /// The file is not UTF-8 text.
    #[error("{}: not UTF-8 text: {source}", path.display())]
    Encoding {
        /// The file.
        path: PathBuf,
        /// Where the first invalid byte sequence is.
        #[source]
        source: std::str::Utf8Error,
    },
    /// The file's content is not acceptable.
    #[error("{}: {source}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// The position and reason.
        #[source]
        source: ParseError,
    },
}

/// A failure of a registry lookup or of building the registry.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// No language has this id (Ghidra: `LanguageNotFoundException`).
    #[error("language not found for '{0}'")]
    LanguageNotFound(LanguageId),
    /// No language exists for this processor.
    #[error("language not found for processor: {0}")]
    ProcessorNotFound(String),
    /// The language has no such compiler spec (Ghidra:
    /// `CompilerSpecNotFoundException`).
    #[error("compiler spec not found for '{language}/{compiler}'")]
    CompilerSpecNotFound {
        /// The language that was asked.
        language: LanguageId,
        /// The compiler spec id it does not have.
        compiler: CompilerSpecId,
    },
    /// The language's `.pspec` file could not be read.
    #[error("processor spec of '{language}': {source}")]
    ProcessorSpec {
        /// The language whose spec failed.
        language: LanguageId,
        /// The read failure, shared with other languages using the file.
        #[source]
        source: Arc<ReadError>,
    },
    /// A directory given to the registry builder could not be listed.
    #[error("cannot scan {}: {message}", path.display())]
    Scan {
        /// The directory.
        path: PathBuf,
        /// The I/O error text.
        message: String,
    },
    /// Two modules share a name (Ghidra: "Multiple modules collided with
    /// same name").
    #[error("multiple modules named '{name}': {} and {}", first.display(), second.display())]
    DuplicateModule {
        /// The module name.
        name: String,
        /// The module directory seen first.
        first: PathBuf,
        /// The colliding module directory.
        second: PathBuf,
    },
}
