//! The driver (`PcodeSnippet::parseStream` as `parseInject` calls it).

use bk_sla::{SpaceTable, Template};
use bk_sleigh_compiler::pcode::{BuildEnv, Builder, Stop, propagate_size};
use bk_sleigh_syntax::ast::Statement;

use crate::error::SnippetError;
use crate::options::{Options, Parameter, TempAllocator};
use crate::parse::parse;
use crate::scope::{Language, Local, Locals, Resolver, unmangle_message};

/// A compiled snippet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    /// The template: label count set, no export, no section.
    pub template: Template,
    /// Errors Ghidra reports but does not fail on (a bit range it cannot
    /// build, an integer that overflows and reads as 0, a label placed
    /// twice, a duplicate parameter name), in order. Ghidra uses the
    /// template regardless.
    pub warnings: Vec<String>,
}

/// A snippet compiler for one language: the visible names and address
/// spaces are computed once and shared by every compile. Immutable,
/// `Send + Sync`.
#[derive(Clone, Debug)]
pub struct SnippetCompiler {
    language: Language,
    env: BuildEnv,
    spaces: SpaceTable,
    max_text_len: usize,
    max_depth: u32,
}

impl SnippetCompiler {
    /// A compiler for snippets of the language `sla`.
    pub fn new(sla: &bk_sla::Sla, options: &Options) -> Self {
        let language = Language::new(sla, options);
        let env = BuildEnv {
            spaces: language.spaces.clone(),
            default_space: Some(language.default_space),
            enforce_local_key: false,
        };
        let mut spaces = SpaceTable::new();
        for space in language.spaces.iter().filter(|s| s.index != 0) {
            spaces.insert(&space.name, space.index);
        }
        Self {
            language,
            env,
            spaces,
            max_text_len: options.max_text_len,
            max_depth: options.max_depth,
        }
    }

    /// The address spaces templates of this compiler may name, for
    /// [`Template::encode_xml`] and its kin: the language's and the extra
    /// ones.
    pub fn space_table(&self) -> &SpaceTable {
        &self.spaces
    }

    /// Compiles `text` with the given parameters, taking temporaries from
    /// `temps`. On success `temps` has advanced past the snippet's
    /// temporaries; on failure it is unchanged.
    pub fn compile(
        &self,
        text: &str,
        params: &[Parameter],
        temps: &mut TempAllocator,
    ) -> Result<Compiled, SnippetError> {
        if text.len() > self.max_text_len {
            return Err(SnippetError::TooLong {
                len: text.len(),
                limit: self.max_text_len,
            });
        }
        let mut messages = Vec::new();
        let mut locals = Locals::new(&self.language);
        for param in params {
            if !locals.insert(&param.name, Local::Operand(param.index)) {
                messages.push(format!("Duplicate symbol name: {}", param.name));
            }
        }
        let parsed = parse(
            text.as_bytes(),
            &self.language,
            locals.clone(),
            self.max_depth,
        );

        // On a parse failure, Ghidra has run the actions of the complete
        // statements and of the failing statement's reduced expressions;
        // evaluate those too, for their errors.
        let mut statements = parsed.statements;
        for &target in &parsed.pending {
            let span = parsed.nodes[target].span();
            statements.push(Statement::Return { target, span });
        }
        let mut resolver = Resolver {
            language: &self.language,
            locals,
            temps: *temps,
        };
        let mut builder = Builder::new(&self.env, &mut resolver, &parsed.names, &parsed.nodes);
        let built = builder.section(&statements, false);
        messages.extend(
            builder
                .take_diagnostics()
                .into_iter()
                .filter(bk_sleigh_compiler::Diagnostic::is_error)
                .map(|d| unmangle_message(d.message)),
        );
        let mut tpl = match built {
            Err(Stop::Fatal(message)) => {
                return Err(SnippetError::Aborted {
                    message: unmangle_message(message),
                    earlier: messages,
                });
            }
            Err(Stop::Abort) => {
                // The grammar accepted what the builder refuses: should not
                // happen; its message is among `messages`.
                tracing::warn!("p-code snippet accepted by the parser but refused by the builder");
                messages.extend(parsed.failure);
                if messages.is_empty() {
                    messages.push("syntax error".to_owned());
                }
                return Err(SnippetError::Rejected { messages });
            }
            Ok(tpl) => tpl,
        };
        if let Some(failure) = parsed.failure {
            messages.push(failure);
            return Err(SnippetError::Rejected { messages });
        }
        match propagate_size(&mut tpl.ops) {
            Err(mismatch) => {
                return Err(SnippetError::Aborted {
                    message: mismatch.to_string(),
                    earlier: messages,
                });
            }
            Ok(false) => {
                messages.push("Could not resolve at least 1 variable size".to_owned());
                return Err(SnippetError::Rejected { messages });
            }
            Ok(true) => {}
        }
        *temps = resolver.temps;
        for warning in &messages {
            tracing::debug!(warning, "p-code snippet compiled with an error Ghidra ignores");
        }
        Ok(Compiled {
            template: tpl.to_template(None),
            warnings: messages,
        })
    }
}
