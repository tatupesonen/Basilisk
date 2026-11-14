//! The semantic sections of a constructor (`rtlbody`, `rtl`, `rtlmid`,
//! `section_def` of `slghparse.y`; `standaloneSection`, `firstNamedSection`,
//! `nextNamedSection`, `finalNamedSection`, `recordNop`).

use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{SemanticBody, Statement};

use super::Compiler;
use super::resolver::CtorResolver;
use crate::pcode::{Builder, NameRef, Stop, SymbolResolver};
use crate::template::Tpl;

/// One compiled section with its label problems (`checkSymbols`).
#[derive(Clone, Debug)]
pub(crate) struct Section {
    pub(crate) tpl: Tpl,
    pub(crate) labels: String,
}

/// The sections of one constructor body.
#[derive(Clone, Debug)]
pub(crate) struct Sections {
    pub(crate) main: Section,
    /// Named sections by number; a later section of the same number
    /// replaces an earlier one.
    pub(crate) named: Vec<Option<Section>>,
}

/// Where Ghidra's parser is when it reduces the main section: at the first
/// `<<name>>` marker, or else at the closing brace.
fn nop_position(body: &SemanticBody) -> Span {
    body.statements
        .iter()
        .find_map(|s| match s {
            Statement::Section { span, .. } => Some(*span),
            _ => None,
        })
        .unwrap_or_else(|| Span::at(body.span.end.saturating_sub(1)))
}

impl Compiler<'_> {
    /// Compiles the sections of a constructor body. `Err` abandons the
    /// constructor.
    pub(crate) fn sections(&mut self, body: &SemanticBody) -> Result<Sections, ()> {
        let env = self.build_env();
        let parsed = self.parsed;
        let mut resolver = CtorResolver { compiler: self };
        let mut builder = Builder::new(&env, &mut resolver, &parsed.names, &parsed.spec.nodes);
        let result = compile_sections(&mut builder, body);
        let diagnostics = builder.take_diagnostics();
        for d in diagnostics {
            self.diags.push(d);
        }
        match result {
            Ok(sections) => Ok(sections),
            Err(Stop::Abort) => Err(()),
            Err(Stop::Fatal(message)) => {
                self.diags.error(Some(body.span), message);
                self.fatal = true;
                Err(())
            }
        }
    }
}

fn compile_sections(builder: &mut Builder<'_, CtorResolver<'_, '_>>, body: &SemanticBody) -> Result<Sections, Stop> {
    let mut parts = body.sections();
    let main_statements = parts.next().map_or(&[][..], |(_, s)| s);
    let main = builder.section(main_statements, true)?;
    let main_number = builder.current_section();
    if main.ops.is_empty() && main.result.is_none() {
        builder.resolver().compiler.nops.push(nop_position(body));
    }
    let mut named: Vec<(usize, Tpl, u32)> = Vec::new();
    let mut first = true;
    for (name, statements) in parts {
        let Some(name) = name else { continue };
        let text = builder_name(builder, name);
        let number = match builder.resolver().lookup(&text) {
            NameRef::Section(n) => n,
            NameRef::Unknown => {
                let compiler = &mut *builder.resolver().compiler;
                compiler.new_section_symbol(name.name, name.span)
            }
            _ => {
                builder.resolver().compiler.syntax_error(name.span);
                return Err(Stop::Abort);
            }
        };
        let compiler = &mut *builder.resolver().compiler;
        if !first {
            compiler.symbols.pop_scope();
        }
        first = false;
        if compiler.symbols.add_scope().is_err() {
            return Err(Stop::Fatal("Too many scopes".to_owned()));
        }
        let tpl = builder.section(statements, false)?;
        named.push((number as usize, tpl, builder.current_section()));
    }
    if !first {
        builder.resolver().compiler.symbols.pop_scope();
    }
    let main = Section {
        tpl: main,
        labels: builder.label_problems_in(main_number),
    };
    let mut slots: Vec<Option<Section>> = Vec::new();
    for (number, tpl, section) in named {
        if slots.len() <= number {
            slots.resize(number + 1, None);
        }
        let labels = builder.label_problems_in(section);
        if let Some(slot) = slots.get_mut(number) {
            *slot = Some(Section { tpl, labels });
        }
    }
    Ok(Sections { main, named: slots })
}

fn builder_name(builder: &mut Builder<'_, CtorResolver<'_, '_>>, ident: bk_sleigh_syntax::ast::Ident) -> String {
    builder.resolver().compiler.text(ident.name).to_owned()
}
