//! SLEIGH front end: preprocessor, modal lexer and parser.
//!
//! SLEIGH is the language Ghidra's processors are specified in. This crate
//! turns `.slaspec` source and its `.sinc` includes into a symbol-free
//! syntax tree in which every node carries a span that resolves to the
//! original file, line and column, through `@include` and `$(NAME)`
//! expansion. The SLEIGH compiler builds on it.
//!
//! It corresponds to Ghidra's Java front end
//! (`Ghidra/Framework/SoftwareModeling`: `SleighPreprocessor`, the ANTLR
//! grammars `BaseLexer.g`, `DisplayLexer.g`, `SemanticLexer.g`,
//! `SleighParser.g`, `DisplayParser.g`, `SemanticParser.g`,
//! `BooleanExpression.g`) and to the C++ one (`slghscan.l`, `slghparse.y`),
//! which accept the same language.
//!
//! ```
//! use bk_sleigh_syntax::{Defines, MemoryLoader, ast::Item, parse_file};
//!
//! let mut loader = MemoryLoader::new()
//!     .with("toy.slaspec", "define endian=big;\n@include \"toy.sinc\"\n")
//!     .with("toy.sinc", ":NOP is epsilon { }\n");
//! let parsed = parse_file("toy.slaspec".as_ref(), &Defines::new(), &mut loader);
//! assert!(parsed.diagnostics.is_empty());
//! let Item::Constructor(nop) = &parsed.spec.items[0] else { panic!() };
//! let at = parsed.sources.locate(nop.span.start).unwrap();
//! assert_eq!(parsed.sources.file(at.file).unwrap().name(), "toy.sinc");
//! assert_eq!((at.line, at.column), (1, 1));
//! ```
//!
//! The pieces can be used on their own: [`preprocess()`] runs only the
//! preprocessor, [`lex::Lexer`] only the lexer, and
//! [`parse_semantic_body`] parses a standalone p-code snippet (the
//! statement language of a semantic section without a constructor).

pub mod ast;
pub mod diag;
pub mod intern;
pub mod lex;
pub mod loader;
mod parse;
pub mod preprocess;
pub mod source;
pub mod span;

use std::path::Path;

pub use diag::{Diagnostic, Severity};
pub use intern::{Interner, Symbol, kw};
pub use loader::{FileLoader, FsLoader, LoadError, MemoryLoader};
pub use parse::{MAX_DEPTH, MAX_ERRORS};
pub use preprocess::{Defines, Preprocessed, preprocess};
pub use source::{LineKind, SourceFile, SourceFileIndexer, SourceMap};
pub use span::{FileId, IncludeId, Location, Span};

/// A parsed specification with everything needed to interpret it.
#[derive(Debug)]
pub struct Parsed {
    /// The syntax tree.
    pub spec: ast::Spec,
    /// The names the tree's [`Symbol`]s stand for.
    pub names: Interner,
    /// The preprocessed text and the map from spans to original files.
    pub sources: SourceMap,
    /// The definitions in effect at the end of preprocessing.
    pub defines: Defines,
    /// Preprocessor, lexer and parser problems, in the order found. If any
    /// is an error, Ghidra would have refused the specification.
    pub diagnostics: Vec<Diagnostic>,
    /// Number of tokens the parser consumed.
    pub token_count: u64,
}

impl Parsed {
    /// Whether any diagnostic is an error.
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(Diagnostic::is_error)
    }

    /// The diagnostics rendered with file, line, column and include chain.
    pub fn rendered_diagnostics(&self) -> Vec<String> {
        self.diagnostics
            .iter()
            .map(|d| self.sources.render(d))
            .collect()
    }
}

/// Preprocesses and parses the specification at `path`, reading it and its
/// includes through `loader`, with `defines` as the initial preprocessor
/// definitions.
pub fn parse_file(path: &Path, defines: &Defines, loader: &mut dyn FileLoader) -> Parsed {
    parse_preprocessed(preprocess(path, defines, loader))
}

/// Parses text that has already been preprocessed.
pub fn parse_preprocessed(preprocessed: Preprocessed) -> Parsed {
    let Preprocessed {
        sources,
        defines,
        mut diagnostics,
    } = preprocessed;
    let parser = parse::Parser::new(sources.text(), lex::Mode::Base, Interner::new());
    let output = parser.spec();
    let mut spec = output.tree;
    spec.nodes = output.nodes;
    diagnostics.extend(output.diagnostics);
    Parsed {
        spec,
        names: output.names,
        sources,
        defines,
        diagnostics,
        token_count: output.tokens,
    }
}

/// Parses a specification held in memory, with no includes available.
/// `name` is the file name used in locations.
pub fn parse_str(name: &str, text: &str, defines: &Defines) -> Parsed {
    let mut loader = MemoryLoader::new().with(name, text);
    parse_file(Path::new(name), defines, &mut loader)
}

/// A parsed standalone semantic body.
#[derive(Debug)]
pub struct ParsedBody {
    /// The statements.
    pub body: ast::SemanticBody,
    /// The expression nodes the statements refer to.
    pub nodes: ast::Nodes,
    /// The names the tree's [`Symbol`]s stand for.
    pub names: Interner,
    /// Maps spans to line and column in `text`.
    pub sources: SourceMap,
    /// Problems found.
    pub diagnostics: Vec<Diagnostic>,
}

/// Parses the statements of a semantic section given without its braces:
/// the p-code snippet language used for injected p-code, which is the
/// statement language of a constructor body. The text is not preprocessed.
pub fn parse_semantic_body(text: &str) -> ParsedBody {
    let sources = SourceMap::from_text("<p-code>", text);
    let parser = parse::Parser::new(sources.text(), lex::Mode::Semantic, Interner::new());
    let output = parser.snippet();
    ParsedBody {
        body: output.tree,
        nodes: output.nodes,
        names: output.names,
        sources,
        diagnostics: output.diagnostics,
    }
}
