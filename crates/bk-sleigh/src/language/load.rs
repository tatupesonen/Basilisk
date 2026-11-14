//! Loading a language (Ghidra `Sleigh::initialize`, `SleighBase::buildXrefs`,
//! and the set-up `SleighArchitecture` applies from the `.ldefs` and
//! `.pspec`; inventory section 3).

use std::sync::Arc;

use bk_core::{RegisterLookup, SpaceId, TruncationTag};
use bk_lang::pspec::ProcessorSpec;
use bk_lang::{LanguageId, LanguageRegistry};
use bk_pcode::FloatFormats;
use bk_sla::{Expr, Limits, ScopeId, Sla, SymbolKind};

use super::{Language, RegisterTable, setup, tables::Tables};
use crate::context::ContextVar;
use crate::error::LoadError;

impl Language {
    /// Builds a language from a compiled model alone: spaces, registers,
    /// user ops, context variables and the decoder's tables. No `.ldefs` or
    /// `.pspec` set-up is applied (see [`Language::load`]).
    pub fn from_sla(sla: Arc<Sla>) -> Result<Self, LoadError> {
        let mut spaces = sla.build_spaces()?;
        let default_space = SpaceId::new(sla.default_space());

        // Ghidra walks the global scope in name order.
        let mut globals: Vec<_> = sla
            .symbols()
            .iter()
            .filter(|symbol| symbol.scope == ScopeId::new(0))
            .map(|symbol| (sla.text(symbol.name), symbol.kind))
            .collect();
        globals.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut registers = RegisterTable::default();
        let mut user_ops: Vec<Option<Box<str>>> = Vec::new();
        let mut context_vars = Vec::new();
        let mut context_words = sla.context_words() as usize;
        for (name, kind) in globals {
            match kind {
                SymbolKind::Varnode {
                    space,
                    offset,
                    size,
                } => {
                    registers
                        .insert(name, SpaceId::new(space), offset, size.max(0) as u32)
                        .map_err(|dup| LoadError::DuplicateRegister {
                            first: dup.first,
                            second: dup.second,
                        })?;
                }
                SymbolKind::UserOp { index } => {
                    let Ok(slot) = usize::try_from(index) else {
                        continue;
                    };
                    if user_ops.len() <= slot {
                        user_ops.resize(slot + 1, None);
                    }
                    if let Some(entry) = user_ops.get_mut(slot) {
                        *entry = Some(name.into());
                    }
                }
                SymbolKind::Context { expr, .. } => {
                    let Some(Expr::ContextField(field)) = sla.expr(expr) else {
                        continue;
                    };
                    let Some(field) = sla.field(*field) else {
                        continue;
                    };
                    let var = u32::try_from(field.start_bit)
                        .ok()
                        .zip(u32::try_from(field.end_bit).ok())
                        .and_then(|(start, end)| ContextVar::new(name, start, end))
                        .ok_or_else(|| LoadError::ContextVariableTooWide(name.to_owned()))?;
                    context_words = context_words.max(var.word() + 1);
                    context_vars.push(var);
                }
                _ => {}
            }
        }
        // Ghidra keeps the variables in a map by name.
        context_vars.sort_by(|a: &ContextVar, b: &ContextVar| a.name().cmp(b.name()));

        let registers = Arc::new(registers);
        spaces.set_registers(Arc::clone(&registers) as Arc<dyn RegisterLookup>);
        let space_text = Self::compute_space_text(&spaces);
        let tables = Tables::build(&sla);
        Ok(Self {
            id: None,
            sla,
            spaces,
            registers,
            user_ops,
            context_vars,
            context_words,
            default_space,
            space_text,
            initial: Vec::new(),
            float_formats: FloatFormats::DEFAULT,
            tables,
        })
    }

    /// Truncates an address space (an `.ldefs` `<truncate_space>`).
    pub fn truncate_space(&mut self, space: &str, size: u32) -> Result<(), LoadError> {
        self.spaces
            .truncate_space(&TruncationTag::new(space.to_owned(), size))?;
        self.space_text = Self::compute_space_text(&self.spaces);
        Ok(())
    }

    /// Takes the context defaults of a processor specification's
    /// `<context_data>`, replacing any taken before.
    pub fn apply_processor_spec(&mut self, pspec: &ProcessorSpec) -> Result<(), LoadError> {
        self.initial = setup::resolve(pspec, &self.spaces, &self.registers, &self.context_vars)?;
        Ok(())
    }

    /// Loads a language as `pcodedump` and Ghidra's `SleighArchitecture` do:
    /// the `.sla` the registry names, then the `.ldefs` entry's
    /// `<truncate_space>`s and the `.pspec`'s `<context_data>`.
    pub fn load(registry: &LanguageRegistry, id: &LanguageId) -> Result<Self, LoadError> {
        let description = registry.language(id)?;
        let path = registry
            .sla_file(id)?
            .ok_or_else(|| LoadError::MissingSla {
                language: id.clone(),
                expected: description.files().sla.clone(),
            })?;
        let sla = Sla::read_file(&path, &Limits::default()).map_err(|source| LoadError::Sla {
            path: path.clone(),
            source: Box::new(source),
        })?;
        let mut language = Self::from_sla(Arc::new(sla))?;
        for truncation in description.truncated_spaces() {
            language.truncate_space(&truncation.space, truncation.size)?;
        }
        let pspec = registry.processor_spec(id)?;
        language.apply_processor_spec(&pspec)?;
        language.id = Some(id.clone());
        Ok(language)
    }
}
