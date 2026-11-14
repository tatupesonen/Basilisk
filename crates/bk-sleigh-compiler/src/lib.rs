//! The SLEIGH compiler, part 1: from the syntax tree `bk-sleigh-syntax`
//! produces to an *elaborated specification* — address spaces, the symbol
//! table with final ids, tables and constructors (display, operands with
//! their definitions, context changes, source positions), and the p-code
//! templates of every section after macro expansion, size checks,
//! truncation fix-up, optimisation and the crossbuild shift — together with
//! the diagnostics of all of this.
//!
//! It corresponds to the front half of Ghidra's C++ SLEIGH compiler:
//! `SleighCompile` and `ConsistencyChecker` (`slgh_compile.cc`), the grammar
//! actions of `slghparse.y`, `PcodeCompile` (`pcodecompile.cc`), the symbol
//! table of `slghsymbol.cc` and the templates of `semantics.cc`. The C++
//! compiler is authoritative. What is derived from bit patterns (patterns,
//! operand offsets and order, decision trees) and writing the `.sla` file
//! are the back half (`docs/features/sleigh-compiler-back.md`).
//!
//! - [`elaborate`]: compile a parsed specification.
//! - [`pcode::Builder`] over a [`pcode::SymbolResolver`]: the public
//!   template builder, also used for p-code snippets.
//! - [`canon`]: the canonical form used to compare an elaboration with a
//!   compiled `.sla` file.

pub mod canon;
mod check;
mod compiler;
pub mod diag;
pub mod elaborated;
pub mod ids;
pub mod options;
pub mod pattern;
pub mod pcode;
mod purge;
pub mod spaces;
pub mod symbols;
pub mod template;

pub use diag::{Diagnostic, Severity};
pub use elaborated::{Constructor, ContextChange, Elaborated, Outcome, PrintPiece, Table};
pub use options::Options;

/// Elaborates a parsed specification with Ghidra's checks.
///
/// The parse's own diagnostics are not repeated. The result holds every
/// diagnostic of this half and, if there was no error (none in the parse
/// either), the elaborated specification.
pub fn elaborate(parsed: &bk_sleigh_syntax::Parsed, options: &Options) -> Outcome {
    let mut compiler = compiler::Compiler::new(parsed, *options);
    compiler.run();
    if !compiler.fatal {
        compiler.post_parse();
    }
    let failed = compiler.fatal || compiler.diags.errors() > 0 || parsed.has_errors();
    let spec = if failed { None } else { Some(purge::finish(&compiler)) };
    Outcome {
        diagnostics: std::mem::take(&mut compiler.diags.list),
        spec,
    }
}
