//! The whole compile: parse, elaborate, build patterns and decision trees,
//! lower to `bk_sla` (`SleighCompile::run_compilation` up to writing).

use std::path::Path;

use bk_sla::Sla;
use bk_sleigh_syntax::{Defines, FileLoader, LoadError, Parsed, parse_file};

use crate::diag::Diagnostic;
use crate::options::Options;

/// What [`compile`] and [`compile_parsed`] return.
#[derive(Debug)]
pub struct Compiled {
    /// The compiled language, if there was no error.
    pub sla: Option<Sla>,
    /// The diagnostics of the compiler (the parser's are in the
    /// [`Parsed`] value).
    pub diagnostics: Vec<Diagnostic>,
}

/// Compiles a parsed specification.
pub fn compile_parsed(parsed: &Parsed, options: Options) -> Compiled {
    let outcome = crate::elaborate(parsed, options);
    let mut diagnostics = outcome.diagnostics;
    let sla = match outcome.spec {
        Some(spec) => match crate::lower::lower(&spec) {
            Ok(sla) => Some(sla),
            Err(e) => {
                diagnostics.push(Diagnostic::error(None, format!("Unrecoverable error: {e}")));
                None
            }
        },
        None => None,
    };
    Compiled { sla, diagnostics }
}

/// A loader that drops a UTF-8 byte-order mark at the start of each file
/// (spec 4.7; `bk-sleigh-syntax` reads it as a character).
struct WithoutBom<'l>(&'l mut dyn FileLoader);

impl FileLoader for WithoutBom<'_> {
    fn load(&mut self, path: &Path) -> Result<String, LoadError> {
        let text = self.0.load(path)?;
        Ok(match text.strip_prefix('\u{feff}') {
            Some(rest) => rest.to_owned(),
            None => text,
        })
    }

    fn identity(&mut self, path: &Path) -> std::path::PathBuf {
        self.0.identity(path)
    }
}

/// Reads, preprocesses (with `defines`), parses and compiles a
/// specification; a UTF-8 byte-order mark at the start of a file is
/// ignored. Returns the parse too: its diagnostics come first, and
/// its sources locate every diagnostic's span.
pub fn compile(
    path: &Path,
    defines: &Defines,
    options: Options,
    loader: &mut dyn FileLoader,
) -> (Parsed, Compiled) {
    let parsed = parse_file(path, defines, &mut WithoutBom(loader));
    if parsed.has_errors() {
        return (
            parsed,
            Compiled {
                sla: None,
                diagnostics: Vec::new(),
            },
        );
    }
    let compiled = compile_parsed(&parsed, options);
    (parsed, compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plugin binding constraints 2 and 6: the results can be held and
    /// moved across threads.
    #[test]
    fn results_are_send_and_sync() {
        fn check<T: Send + Sync + 'static>() {}
        check::<Compiled>();
        check::<Sla>();
        check::<Diagnostic>();
        check::<Parsed>();
        check::<crate::lower::LowerError>();
    }

    #[test]
    fn a_byte_order_mark_is_ignored() {
        let text = "define endian=little;\ndefine space ram type=ram_space size=2 default;\ndefine token t(8) op=(0,7);\n:nop is op=0 { }\n";
        let mut plain = bk_sleigh_syntax::MemoryLoader::new().with("a.slaspec", text);
        let mut bom = bk_sleigh_syntax::MemoryLoader::new()
            .with("a.slaspec", format!("\u{feff}{text}").as_str());
        let (_, a) = compile(
            Path::new("a.slaspec"),
            &Defines::new(),
            Options::default(),
            &mut plain,
        );
        let (_, b) = compile(
            Path::new("a.slaspec"),
            &Defines::new(),
            Options::default(),
            &mut bom,
        );
        let (a, b) = (a.sla.unwrap(), b.sla.unwrap());
        assert_eq!(a.encode_packed().unwrap(), b.encode_packed().unwrap());
    }
}
