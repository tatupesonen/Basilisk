//! Compiling a standalone semantic body (a p-code snippet) with the
//! builder: the use `bk-sleigh-snippet` makes of it.

use bk_sleigh_syntax::ParsedBody;

use super::{BuildEnv, Builder, Stop, SymbolResolver, propagate_size};
use crate::diag::Diagnostic;
use crate::template::Tpl;

/// The result of [`compile_snippet`].
#[derive(Clone, Debug)]
pub struct SnippetResult {
    /// The template, if compilation succeeded (sizes resolved, labels
    /// placed and used).
    pub template: Option<Tpl>,
    /// Everything reported, the parser's diagnostics first.
    pub diagnostics: Vec<Diagnostic>,
}

/// Compiles the statements of a parsed snippet into one template: the
/// statements are compiled as one section without `export`, labels are
/// checked, and sizes are propagated.
pub fn compile_snippet<R: SymbolResolver>(body: &ParsedBody, env: &BuildEnv, resolver: &mut R) -> SnippetResult {
    let mut diagnostics: Vec<Diagnostic> = body
        .diagnostics
        .iter()
        .map(|d| match d.severity {
            bk_sleigh_syntax::Severity::Error => Diagnostic::error(Some(d.span), d.message.clone()),
            bk_sleigh_syntax::Severity::Warning => Diagnostic::warning(Some(d.span), d.message.clone()),
        })
        .collect();
    let failed_parse = diagnostics.iter().any(Diagnostic::is_error);
    let mut builder = Builder::new(env, resolver, &body.names, &body.nodes);
    let result = builder.section(&body.body.statements, false);
    let labels = builder.label_problems();
    diagnostics.extend(builder.take_diagnostics());
    let template = match result {
        Ok(mut tpl) => {
            if !labels.is_empty() {
                diagnostics.push(Diagnostic::error(Some(body.body.span), labels));
                None
            } else {
                match propagate_size(&mut tpl.ops) {
                    Ok(true) => Some(tpl),
                    Ok(false) => {
                        diagnostics.push(Diagnostic::error(Some(body.body.span), "Could not resolve at least 1 variable size"));
                        None
                    }
                    Err(e) => {
                        diagnostics.push(Diagnostic::error(Some(body.body.span), e.to_string()));
                        None
                    }
                }
            }
        }
        Err(Stop::Abort) => None,
        Err(Stop::Fatal(message)) => {
            diagnostics.push(Diagnostic::error(Some(body.body.span), message));
            None
        }
    };
    let template = template.filter(|_| !failed_parse && !diagnostics.iter().any(Diagnostic::is_error));
    SnippetResult { template, diagnostics }
}
