//! The language registry: every language found under a set of module
//! directories, with lookups and queries (Ghidra: `SleighLanguageProvider`
//! for discovery, `DefaultLanguageService` for queries).

mod paths;
mod query;
mod scan;

use std::{
    collections::HashMap,
    env, fmt,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

pub use query::{ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecQuery};

use crate::{
    endian::Endian,
    error::{Mode, ReadError, RegistryError},
    id::{CompilerSpecId, LanguageId, Processor},
    ldefs::{ExternalName, LanguageVersion, TruncatedSpace},
    opinion::OpinionDatabase,
    pspec::ProcessorSpec,
};

/// The environment variable naming the spec root: a Ghidra source tree or
/// installation whose `Ghidra/Processors/*/data` trees hold the language
/// files.
pub const SPEC_ROOT_ENV: &str = "BASILISK_GHIDRA_DIR";

/// The spec root named by [`SPEC_ROOT_ENV`], or `None` when the variable
/// is unset or empty.
///
/// There is deliberately no fallback here. The project's convention,
/// "`../ghidra` beside the Basilisk checkout", is about a source checkout,
/// which a library cannot locate: a path relative to the current directory
/// means something different for every process (under `cargo test` it is
/// the crate's directory), and a path fixed at compile time is wrong for an
/// installed program. So each caller supplies its own default: a program
/// its bundled `Processors` data or a command-line option, and the tests
/// the directory beside the workspace (`crates/bk-lang/tests/common`).
#[must_use]
pub fn spec_root_from_env() -> Option<PathBuf> {
    env::var_os(SPEC_ROOT_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The files a language is made of, as resolved paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageFiles {
    /// The `.ldefs` file that defines the language.
    pub ldefs: PathBuf,
    /// The SLEIGH source. It exists unless the module ships only a
    /// compiled `.sla`.
    pub slaspec: PathBuf,
    /// Where the compiled SLEIGH file belongs: beside the `.slaspec`. It
    /// need not exist yet; see [`LanguageRegistry::sla_file`].
    pub sla: PathBuf,
    /// The processor specification.
    pub pspec: PathBuf,
    /// The processor manual index, when the language names one that
    /// exists.
    pub manual_index: Option<PathBuf>,
}

/// One compiler specification of a language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerSpecDescription {
    /// The compiler spec id.
    pub id: CompilerSpecId,
    /// The name shown to users.
    pub name: String,
    /// The `.cspec` file.
    pub file: PathBuf,
}

impl fmt::Display for CompilerSpecDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// What is known about a language without loading it: its identity, its
/// compiler specs and its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageDescription {
    pub(crate) id: LanguageId,
    pub(crate) processor: Processor,
    pub(crate) processor_name: Arc<str>,
    pub(crate) endian: Endian,
    pub(crate) instruction_endian: Endian,
    pub(crate) size: u32,
    pub(crate) variant: String,
    pub(crate) version: LanguageVersion,
    pub(crate) deprecated: bool,
    pub(crate) description: String,
    pub(crate) truncated_spaces: Vec<TruncatedSpace>,
    pub(crate) compiler_specs: Vec<CompilerSpecDescription>,
    pub(crate) external_names: Vec<ExternalName>,
    pub(crate) files: LanguageFiles,
    pub(crate) pspec_slot: u32,
    /// The `.sla` path relative to the installation root, for overlays.
    pub(crate) sla_overlay_path: Option<PathBuf>,
}

impl LanguageDescription {
    /// The language id.
    #[must_use]
    pub fn id(&self) -> &LanguageId {
        &self.id
    }

    /// The processor family.
    #[must_use]
    pub fn processor(&self) -> Processor {
        self.processor
    }

    /// The processor family's name.
    #[must_use]
    pub fn processor_name(&self) -> &str {
        &self.processor_name
    }

    /// The byte order of data.
    #[must_use]
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// The byte order of instructions.
    #[must_use]
    pub fn instruction_endian(&self) -> Endian {
        self.instruction_endian
    }

    /// The size of an address in bits.
    #[must_use]
    pub fn size(&self) -> u32 {
        self.size
    }

    /// The processor variant.
    #[must_use]
    pub fn variant(&self) -> &str {
        &self.variant
    }

    /// The language version.
    #[must_use]
    pub fn version(&self) -> LanguageVersion {
        self.version
    }

    /// Whether the language is kept only for programs that already use it.
    /// Deprecated languages are found by id but left out of queries.
    #[must_use]
    pub fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    /// The description text.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The compiler specs, in file order.
    #[must_use]
    pub fn compiler_specs(&self) -> &[CompilerSpecDescription] {
        &self.compiler_specs
    }

    /// The compiler spec with the given id. There is no fallback: an id
    /// the language does not list is not found, `default` included.
    #[must_use]
    pub fn compiler_spec(&self, id: &CompilerSpecId) -> Option<&CompilerSpecDescription> {
        self.compiler_specs.iter().find(|c| c.id == *id)
    }

    /// The language's default compiler spec: the first one listed.
    #[must_use]
    pub fn default_compiler_spec(&self) -> Option<&CompilerSpecDescription> {
        self.compiler_specs.first()
    }

    /// The names the external tool `tool` uses for this language, in file
    /// order.
    pub fn external_names<'a>(&'a self, tool: &'a str) -> impl Iterator<Item = &'a str> {
        self.external_names
            .iter()
            .filter(move |e| e.tool == tool)
            .map(|e| e.name.as_str())
    }

    /// Every external name, in file order.
    #[must_use]
    pub fn all_external_names(&self) -> &[ExternalName] {
        &self.external_names
    }

    /// The address spaces the language truncates.
    #[must_use]
    pub fn truncated_spaces(&self) -> &[TruncatedSpace] {
        &self.truncated_spaces
    }

    /// The truncated address size in bytes of the space `name`, if the
    /// language truncates it.
    #[must_use]
    pub fn truncated_space_size(&self, name: &str) -> Option<u32> {
        self.truncated_spaces
            .iter()
            .find(|t| t.space == name)
            .map(|t| t.size)
    }

    /// The language's files.
    #[must_use]
    pub fn files(&self) -> &LanguageFiles {
        &self.files
    }
}

impl fmt::Display for LanguageDescription {
    /// `processor/endian/size/variant`, as Ghidra prints a description.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.processor_name, self.endian, self.size, self.variant
        )
    }
}

/// Something that went wrong while building a registry. The registry is
/// still built from everything else.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadFailure {
    /// A `.ldefs` file could not be read; none of its languages exist.
    #[error("problem loading language definitions: {0}")]
    LanguageDefinitions(#[source] ReadError),
    /// A `.opinion` file could not be read; it contributes no opinions.
    #[error("problem loading opinions: {0}")]
    Opinions(#[source] ReadError),
    /// A file a language names does not exist (with that exact letter
    /// case); the language is left out.
    #[error("language {language} in {}: missing sleigh file({extension}): {}", ldefs.display(), file.display())]
    MissingFile {
        /// The language left out.
        language: LanguageId,
        /// The `.ldefs` file defining it.
        ldefs: PathBuf,
        /// The file that was looked for.
        file: PathBuf,
        /// The kind of file, as its extension.
        extension: &'static str,
    },
    /// A language's manual index does not exist; the language is kept
    /// without one.
    #[error("language {language}: missing manual index {}", file.display())]
    MissingManualIndex {
        /// The language.
        language: LanguageId,
        /// The file that was looked for.
        file: PathBuf,
    },
    /// A language id is defined twice; the later definition replaces the
    /// earlier one.
    #[error("duplicate language id {language}: {} replaces the definition in {}", ldefs.display(), previous.display())]
    DuplicateLanguage {
        /// The id defined twice.
        language: LanguageId,
        /// The file whose definition is kept.
        ldefs: PathBuf,
        /// The file whose definition is dropped.
        previous: PathBuf,
    },
}

/// A processor spec file shared by the languages that name it, read on
/// first use.
#[derive(Debug)]
struct PspecSlot {
    path: PathBuf,
    spec: OnceLock<Result<Arc<ProcessorSpec>, Arc<ReadError>>>,
}

/// The opinions, read on first use.
#[derive(Debug)]
struct Opinions {
    database: OpinionDatabase,
    failures: Vec<LoadFailure>,
}

/// Every language found under a set of modules.
///
/// Building a registry reads the `.ldefs` files and checks that the files
/// they name exist; processor specs and opinions are read when first asked
/// for and cached. A built registry is immutable and can be shared between
/// threads.
#[derive(Debug)]
pub struct LanguageRegistry {
    languages: Vec<LanguageDescription>,
    by_id: HashMap<LanguageId, u32>,
    processors: Vec<Arc<str>>,
    processor_ids: HashMap<Arc<str>, Processor>,
    pspecs: Vec<PspecSlot>,
    ldefs_files: Vec<PathBuf>,
    opinion_files: Vec<PathBuf>,
    opinions: OnceLock<Opinions>,
    sla_overlays: Vec<PathBuf>,
    failures: Vec<LoadFailure>,
    mode: Mode,
}

/// Collects the places to look for languages, then builds a
/// [`LanguageRegistry`].
#[derive(Debug, Clone, Default)]
pub struct RegistryBuilder {
    ghidra_roots: Vec<PathBuf>,
    modules: Vec<PathBuf>,
    sla_overlays: Vec<PathBuf>,
    mode: Mode,
    include_hidden: bool,
}

impl RegistryBuilder {
    /// Adds a Ghidra source tree or installation: every module under its
    /// `Ghidra` (and `GPL`) directory is searched, as Ghidra itself does.
    #[must_use]
    pub fn ghidra_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.ghidra_roots.push(root.into());
        self
    }

    /// Adds one module directory — a user's own processor module — whose
    /// `data` tree is searched.
    #[must_use]
    pub fn module(mut self, directory: impl Into<PathBuf>) -> Self {
        self.modules.push(directory.into());
        self
    }

    /// Adds a root that mirrors a Ghidra root's layout and holds compiled
    /// `.sla` files (the reference overlay). It contributes no languages;
    /// [`LanguageRegistry::sla_file`] looks there when a `.sla` is not
    /// beside its `.slaspec`.
    #[must_use]
    pub fn sla_overlay(mut self, root: impl Into<PathBuf>) -> Self {
        self.sla_overlays.push(root.into());
        self
    }

    /// Sets how schema violations in the files are treated. The default is
    /// [`Mode::Strict`], which is Ghidra's behaviour for `.ldefs` and
    /// `.pspec` files; a file with a violation is then reported as a
    /// [`LoadFailure`] and skipped.
    #[must_use]
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Includes languages marked `hidden`, which Ghidra offers only in a
    /// development environment. Off by default.
    #[must_use]
    pub fn include_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }

    /// Scans the modules and builds the registry.
    ///
    /// Unreadable or inconsistent spec files do not fail the build; they
    /// are listed in [`LanguageRegistry::failures`]. The build fails only
    /// when a root is not a Ghidra tree or two modules share a name.
    ///
    /// Every directory given to the builder is first made canonical
    /// (absolute, `.`, `..` and symbolic links resolved), so the paths the
    /// registry reports are the same however a root was spelled.
    pub fn build(self) -> Result<LanguageRegistry, RegistryError> {
        let canonical = |paths: &[PathBuf]| -> Vec<PathBuf> {
            paths.iter().map(|p| paths::canonical_root(p)).collect()
        };
        let mut modules = Vec::new();
        for root in &canonical(&self.ghidra_roots) {
            scan::modules_under(root, &mut modules)?;
        }
        for directory in &canonical(&self.modules) {
            let name = directory
                .file_name()
                .map(|n| n.to_string_lossy().into_owned());
            modules.push(scan::Module {
                name: name.unwrap_or_default(),
                root: directory.clone(),
                install_root: None,
            });
        }
        scan::order_modules(&mut modules)?;
        let mut index = scan::index_modules(&modules);
        let mut found = scan::Languages::default();
        found.load(&mut index, &modules, self.mode, self.include_hidden);
        Ok(LanguageRegistry {
            languages: found.descriptions,
            by_id: found.by_id,
            processors: found.processors,
            processor_ids: found.processor_ids,
            pspecs: found
                .pspec_files
                .into_iter()
                .map(|path| PspecSlot {
                    path,
                    spec: OnceLock::new(),
                })
                .collect(),
            ldefs_files: found.ldefs_files,
            opinion_files: index.files(".opinion").to_vec(),
            opinions: OnceLock::new(),
            sla_overlays: canonical(&self.sla_overlays),
            failures: found.failures,
            mode: self.mode,
        })
    }
}

impl LanguageRegistry {
    /// Starts describing where to look for languages.
    #[must_use]
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::default()
    }

    /// Builds a registry from one Ghidra source tree or installation, in
    /// strict mode.
    pub fn from_ghidra_root(root: impl AsRef<Path>) -> Result<Self, RegistryError> {
        Self::builder().ghidra_root(root.as_ref()).build()
    }

    /// What went wrong while the registry was built.
    #[must_use]
    pub fn failures(&self) -> &[LoadFailure] {
        &self.failures
    }

    /// The `.ldefs` files that were read (or attempted), in search order.
    #[must_use]
    pub fn ldefs_files(&self) -> &[PathBuf] {
        &self.ldefs_files
    }

    /// The `.opinion` files, in search order.
    #[must_use]
    pub fn opinion_files(&self) -> &[PathBuf] {
        &self.opinion_files
    }

    /// The `.pspec` files the languages use, each once, in order of first
    /// use.
    pub fn pspec_files(&self) -> impl Iterator<Item = &Path> {
        self.pspecs.iter().map(|slot| slot.path.as_path())
    }
}
