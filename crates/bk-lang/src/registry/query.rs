//! Lookups and queries over a built registry (Ghidra:
//! `DefaultLanguageService`, and `QueryOpinionService` for opinions).

use std::{fmt, path::PathBuf, sync::Arc};

use super::{
    CompilerSpecDescription, LanguageDescription, LanguageRegistry, LoadFailure, Opinions,
};
use crate::error::ReadError;
use crate::{
    endian::Endian,
    error::RegistryError,
    id::{CompilerSpecId, LanguageCompilerSpecPair, LanguageId, Processor},
    opinion::{self, Constraint, OpinionDatabase, QueryResult},
    pspec::{self, ProcessorSpec},
};

/// A query for language/compiler pairs by the language's properties.
/// Every field is optional; an absent field matches anything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LanguageCompilerSpecQuery {
    /// The processor name.
    pub processor: Option<String>,
    /// The byte order.
    pub endian: Option<Endian>,
    /// The address size in bits.
    pub size: Option<u32>,
    /// The processor variant.
    pub variant: Option<String>,
    /// The compiler spec id.
    pub compiler_spec_id: Option<CompilerSpecId>,
}

/// Writes `value`, or `null` as Java prints an absent one.
fn or_null<T: fmt::Display>(value: Option<&T>) -> String {
    value.map_or_else(|| "null".to_owned(), ToString::to_string)
}

impl fmt::Display for LanguageCompilerSpecQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "processor={}; endian={}; size={}; variant={}; compiler={}",
            or_null(self.processor.as_ref()),
            or_null(self.endian.as_ref()),
            or_null(self.size.as_ref()),
            or_null(self.variant.as_ref()),
            or_null(self.compiler_spec_id.as_ref()),
        )
    }
}

/// A query for language/compiler pairs by the name another tool uses for
/// the processor (IDA Pro's `metapc`, GNU's `i386:x86-64`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalLanguageCompilerSpecQuery {
    /// The external tool's name for the processor, compared without regard
    /// to letter case. When absent, every language matches.
    pub external_processor_name: Option<String>,
    /// The external tool (`IDA-PRO`, `gnu`, …). When a processor name is
    /// given without a tool, nothing matches.
    pub external_tool: Option<String>,
    /// The byte order.
    pub endian: Option<Endian>,
    /// The address size in bits.
    pub size: Option<u32>,
    /// The compiler spec to pick where a language has it; languages that
    /// lack it contribute all their compiler specs.
    pub compiler_spec_id: Option<CompilerSpecId>,
}

impl fmt::Display for ExternalLanguageCompilerSpecQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "externalProcessorName={}; externalTool={}; endian={}; size={}; compiler={}",
            or_null(self.external_processor_name.as_ref()),
            or_null(self.external_tool.as_ref()),
            or_null(self.endian.as_ref()),
            or_null(self.size.as_ref()),
            or_null(self.compiler_spec_id.as_ref()),
        )
    }
}

fn pair(
    language: &LanguageDescription,
    compiler: &CompilerSpecDescription,
) -> LanguageCompilerSpecPair {
    LanguageCompilerSpecPair::new(language.id.clone(), compiler.id.clone())
}

impl LanguageRegistry {
    /// Every language, deprecated ones included, in load order: modules by
    /// name, `.ldefs` files by path within a module, languages in file
    /// order.
    #[must_use]
    pub fn languages(&self) -> &[LanguageDescription] {
        &self.languages
    }

    /// The languages in load order, with or without the deprecated ones.
    pub fn language_descriptions(
        &self,
        include_deprecated: bool,
    ) -> impl Iterator<Item = &LanguageDescription> {
        self.languages
            .iter()
            .filter(move |l| include_deprecated || !l.deprecated)
    }

    /// The language with the given id, deprecated or not.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&LanguageDescription> {
        self.by_id
            .get(id)
            .and_then(|slot| self.languages.get(*slot as usize))
    }

    /// The language with the given id, deprecated or not.
    pub fn language(&self, id: &LanguageId) -> Result<&LanguageDescription, RegistryError> {
        self.find(id.as_str())
            .ok_or_else(|| RegistryError::LanguageNotFound(id.clone()))
    }

    /// The compiler spec `compiler` of the language `language`.
    pub fn compiler_spec(
        &self,
        language: &LanguageId,
        compiler: &CompilerSpecId,
    ) -> Result<&CompilerSpecDescription, RegistryError> {
        self.language(language)?
            .compiler_spec(compiler)
            .ok_or_else(|| RegistryError::CompilerSpecNotFound {
                language: language.clone(),
                compiler: compiler.clone(),
            })
    }

    /// The processor names, in order of first appearance.
    pub fn processors(&self) -> impl Iterator<Item = &str> {
        self.processors.iter().map(|name| &**name)
    }

    /// The processor called `name` (letter case matters).
    #[must_use]
    pub fn processor(&self, name: &str) -> Option<Processor> {
        self.processor_ids.get(name).copied()
    }

    /// The name of a processor of this registry.
    #[must_use]
    pub fn processor_name(&self, processor: Processor) -> Option<&str> {
        self.processors.get(processor.index()).map(|name| &**name)
    }

    /// The languages matching every given property, in load order.
    /// Deprecated languages are included.
    pub fn matching<'a>(
        &'a self,
        processor: Option<&str>,
        endian: Option<Endian>,
        size: Option<u32>,
        variant: Option<&'a str>,
    ) -> impl Iterator<Item = &'a LanguageDescription> {
        // A processor name no language uses matches nothing.
        let processor = processor.map(|name| self.processor(name));
        self.languages.iter().filter(move |l| {
            processor.is_none_or(|p| p == Some(l.processor))
                && endian.is_none_or(|e| e == l.endian)
                && size.is_none_or(|s| s == l.size)
                && variant.is_none_or(|v| v == l.variant)
        })
    }

    /// The languages of a processor, in load order, deprecated ones
    /// included.
    pub fn for_processor<'a>(
        &'a self,
        processor: &str,
    ) -> impl Iterator<Item = &'a LanguageDescription> {
        self.matching(Some(processor), None, None, None)
    }

    /// The default language of a processor: its first language in load
    /// order.
    pub fn default_language(&self, processor: &str) -> Result<&LanguageDescription, RegistryError> {
        self.for_processor(processor)
            .next()
            .ok_or_else(|| RegistryError::ProcessorNotFound(processor.to_owned()))
    }

    /// The language/compiler pairs matching `query`: for each matching
    /// language that is not deprecated, in load order, its compiler specs
    /// in file order — all of them, or the one the query names.
    #[must_use]
    pub fn pairs(&self, query: &LanguageCompilerSpecQuery) -> Vec<LanguageCompilerSpecPair> {
        self.matching(
            query.processor.as_deref(),
            query.endian,
            query.size,
            query.variant.as_deref(),
        )
        .filter(|l| !l.deprecated)
        .flat_map(|l| {
            l.compiler_specs
                .iter()
                .filter(|c| query.compiler_spec_id.as_ref().is_none_or(|id| *id == c.id))
                .map(move |c| pair(l, c))
        })
        .collect()
    }

    /// The languages an external tool's processor name stands for, in load
    /// order, deprecated ones included.
    ///
    /// Without a name every language matches. With a name, a language
    /// matches when `tool` is given and one of the names the language
    /// lists for that tool equals `name`, ignoring letter case.
    pub fn external_descriptions<'a>(
        &'a self,
        name: Option<&'a str>,
        tool: Option<&'a str>,
        endian: Option<Endian>,
        size: Option<u32>,
    ) -> impl Iterator<Item = &'a LanguageDescription> {
        self.languages.iter().filter(move |l| {
            let named = match (name, tool) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(name), Some(tool)) => l
                    .external_names(tool)
                    .any(|n| n.to_lowercase() == name.to_lowercase()),
            };
            named && endian.is_none_or(|e| e == l.endian) && size.is_none_or(|s| s == l.size)
        })
    }

    /// The language/compiler pairs matching an external-name query: for
    /// each matching language that is not deprecated, the compiler spec
    /// the query names if the language has it, otherwise all of the
    /// language's compiler specs.
    #[must_use]
    pub fn external_pairs(
        &self,
        query: &ExternalLanguageCompilerSpecQuery,
    ) -> Vec<LanguageCompilerSpecPair> {
        let mut pairs = Vec::new();
        let languages = self.external_descriptions(
            query.external_processor_name.as_deref(),
            query.external_tool.as_deref(),
            query.endian,
            query.size,
        );
        for language in languages.filter(|l| !l.deprecated) {
            let preferred = query
                .compiler_spec_id
                .as_ref()
                .and_then(|id| language.compiler_spec(id));
            match preferred {
                Some(compiler) => pairs.push(pair(language, compiler)),
                None => pairs.extend(language.compiler_specs.iter().map(|c| pair(language, c))),
            }
        }
        pairs
    }

    /// The names `tool` uses for the language `language_id`
    /// (`DefaultLanguageService.getDefinedExternalToolNames`). `None` when
    /// either argument is empty, the language is unknown (or deprecated
    /// and not included), or it lists no name for the tool.
    #[must_use]
    pub fn defined_external_tool_names(
        &self,
        language_id: &str,
        tool: &str,
        include_deprecated: bool,
    ) -> Option<Vec<&str>> {
        if language_id.is_empty() || tool.is_empty() {
            return None;
        }
        let language = self
            .find(language_id)
            .filter(|l| include_deprecated || !l.deprecated)?;
        let names: Vec<&str> = language
            .external_names
            .iter()
            .filter(|e| e.tool == tool)
            .map(|e| e.name.as_str())
            .collect();
        (!names.is_empty()).then_some(names)
    }

    /// The parsed `.pspec` of a language. The file is read on first use
    /// and shared by every language that names it.
    pub fn processor_spec(
        &self,
        language: &LanguageId,
    ) -> Result<Arc<ProcessorSpec>, RegistryError> {
        let description = self.language(language)?;
        let failed = |source: &Arc<ReadError>| RegistryError::ProcessorSpec {
            language: language.clone(),
            source: Arc::clone(source),
        };
        let Some(slot) = self.pspecs.get(description.pspec_slot as usize) else {
            return Err(RegistryError::LanguageNotFound(language.clone()));
        };
        slot.spec
            .get_or_init(|| match pspec::read_file(&slot.path, self.mode) {
                Ok(parsed) => {
                    for warning in &parsed.warnings {
                        tracing::warn!(file = %slot.path.display(), %warning, "processor spec");
                    }
                    Ok(Arc::new(parsed.value))
                }
                Err(error) => Err(Arc::new(error)),
            })
            .as_ref()
            .map(Arc::clone)
            .map_err(failed)
    }

    /// The compiled `.sla` file of a language, if one exists: beside the
    /// `.slaspec`, or else in the first overlay that has it. Checked on
    /// every call, since compiling creates the file.
    pub fn sla_file(&self, language: &LanguageId) -> Result<Option<PathBuf>, RegistryError> {
        let description = self.language(language)?;
        if description.files.sla.is_file() {
            return Ok(Some(description.files.sla.clone()));
        }
        Ok(description.sla_overlay_path.as_ref().and_then(|relative| {
            self.sla_overlays
                .iter()
                .map(|root| root.join(relative))
                .find(|path| path.is_file())
        }))
    }

    /// The pairs a resolved opinion constraint selects: all compiler specs
    /// of every non-deprecated language matching its processor, endian,
    /// size and variant.
    #[must_use]
    pub fn pairs_for_constraint(&self, constraint: &Constraint) -> Vec<LanguageCompilerSpecPair> {
        let size = match constraint.size.map(u32::try_from) {
            None => None,
            Some(Ok(size)) => Some(size),
            // No language has a negative size.
            Some(Err(_)) => return Vec::new(),
        };
        self.pairs(&LanguageCompilerSpecQuery {
            processor: constraint.processor.clone(),
            endian: constraint.endian,
            size,
            variant: constraint.variant.clone(),
            compiler_spec_id: None,
        })
    }

    fn loaded_opinions(&self) -> &Opinions {
        self.opinions.get_or_init(|| {
            let mut database = OpinionDatabase::new();
            let mut failures = Vec::new();
            for file in &self.opinion_files {
                match opinion::read_file(file, self.mode) {
                    Ok(parsed) => {
                        for warning in &parsed.warnings {
                            tracing::warn!(file = %file.display(), %warning, "opinions");
                        }
                        database.add(&parsed.value, |c| self.pairs_for_constraint(c));
                    }
                    Err(error) => failures.push(LoadFailure::Opinions(error)),
                }
            }
            Opinions { database, failures }
        })
    }

    /// The opinion database, built from every `.opinion` file on first
    /// use.
    #[must_use]
    pub fn opinions(&self) -> &OpinionDatabase {
        &self.loaded_opinions().database
    }

    /// The `.opinion` files that could not be read.
    #[must_use]
    pub fn opinion_failures(&self) -> &[LoadFailure] {
        &self.loaded_opinions().failures
    }

    /// The language/compiler pairs the opinions give a loader for a file;
    /// see [`OpinionDatabase::query`].
    #[must_use]
    pub fn query_opinions(
        &self,
        loader: &str,
        primary: Option<&str>,
        secondary: Option<&str>,
    ) -> Vec<QueryResult> {
        self.opinions().query(loader, primary, secondary)
    }
}
