//! Compiles the p-code snippets of compiler and processor specifications —
//! call fix-ups, `uponentry`/`uponreturn` injections, `CALLOTHER` fix-ups,
//! segment operators, jump-table helpers — against an already compiled
//! language, into a template the runtime expands at the injection site
//! (`bk_sleigh`'s `Decoder::build_template`).
//!
//! It corresponds to Ghidra's C++ `PcodeSnippet` (`pcodeparse.y`: its own
//! lexer, grammar and symbol lookup) driven as
//! `PcodeInjectLibrarySleigh::parseInject` (`inject_sleigh.cc`) drives it;
//! the template construction is `PcodeCompile`'s, shared with the SLEIGH
//! compiler as [`bk_sleigh_compiler::pcode::Builder`]. The C++ is
//! authoritative. Specification: `docs/features/sleigh-snippet.md`.
//!
//! ```no_run
//! use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler, TempAllocator};
//!
//! # fn demo(sla: &bk_sla::Sla) -> Result<(), bk_sleigh_snippet::SnippetError> {
//! let compiler = SnippetCompiler::new(sla, &Options::default());
//! let mut temps = TempAllocator::for_injection(sla.header().unique_base);
//! let params = [Parameter::new("dest", 0), Parameter::new("src", 1)];
//! let compiled = compiler.compile("dest = src + 1;", &params, &mut temps)?;
//! let xml = compiled.template.encode_xml(compiler.space_table());
//! # let _ = xml;
//! # Ok(())
//! # }
//! ```
//!
//! What a snippet can name: the language's address spaces, `inst_dest`
//! and `inst_ref`, its parameters (as operands with their indices), its
//! own labels and temporaries, and from the language only user ops,
//! registers and `inst_start`/`inst_next`/`inst_next2`.

mod compile;
mod error;
mod lex;
mod options;
mod parse;
mod scope;

pub use compile::{Compiled, SnippetCompiler};
pub use error::SnippetError;
pub use options::{ExtraSpace, Options, Parameter, TempAllocator};

/// Compiles one snippet `text` against the language `sla`: the one-shot
/// form of [`SnippetCompiler::compile`]. Prefer a [`SnippetCompiler`] when
/// compiling several snippets for one language.
pub fn compile(
    text: &str,
    sla: &bk_sla::Sla,
    params: &[Parameter],
    temps: &mut TempAllocator,
    options: &Options,
) -> Result<bk_sla::Template, SnippetError> {
    SnippetCompiler::new(sla, options)
        .compile(text, params, temps)
        .map(|compiled| compiled.template)
}
