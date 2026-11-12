//! Discovery: finding modules, their spec files, and building the
//! language descriptions (Ghidra: `GModule`, `ModuleUtilities`,
//! `SleighLanguageProvider`).

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use walkdir::WalkDir;

use super::{
    CompilerSpecDescription, LanguageDescription, LanguageFiles, LoadFailure,
    paths::{FileIndex, normalize},
};
use crate::{
    error::{Mode, RegistryError},
    id::{LanguageId, Processor},
    ldefs::{self, LanguageDefinition},
};

/// Directory names Ghidra never searches inside a module's `data` tree.
const EXCLUDED_DIRECTORIES: [&str; 10] = [
    ".svn",
    "bin",
    "classes",
    "developer_scripts",
    "ghidra_scripts",
    "help",
    "os",
    "resources",
    "src",
    "test",
];

/// How deep below an application root a module may sit.
const MAX_MODULE_DEPTH: usize = 3;

/// A Ghidra module: a directory with a `data` tree of spec files.
#[derive(Debug)]
pub(crate) struct Module {
    /// The directory name, which orders modules.
    pub(crate) name: String,
    /// The module directory.
    pub(crate) root: PathBuf,
    /// The installation root the module was found under, if any.
    pub(crate) install_root: Option<PathBuf>,
}

fn scan_error(path: &Path, error: impl std::fmt::Display) -> RegistryError {
    RegistryError::Scan {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

/// Finds the modules under a Ghidra source tree or installation: the
/// directories holding a `Module.manifest`, at most three levels below
/// `<root>/Ghidra` and `<root>/GPL`.
pub(crate) fn modules_under(root: &Path, modules: &mut Vec<Module>) -> Result<(), RegistryError> {
    let application = root.join("Ghidra");
    if !application.is_dir() {
        return Err(scan_error(&application, "not a directory"));
    }
    for base in [root.join("GPL"), application] {
        if !base.is_dir() {
            continue;
        }
        let mut walk = WalkDir::new(&base)
            .min_depth(1)
            .max_depth(MAX_MODULE_DEPTH)
            .follow_links(true)
            .into_iter();
        while let Some(entry) = walk.next() {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            if name == "build" {
                walk.skip_current_dir();
            } else if name != "bin" && entry.path().join("Module.manifest").exists() {
                modules.push(Module {
                    name: name.into_owned(),
                    root: entry.path().to_owned(),
                    install_root: Some(root.to_owned()),
                });
                walk.skip_current_dir();
            }
        }
    }
    Ok(())
}

/// Orders modules by name, as Ghidra's module map does, and rejects two
/// modules with one name.
pub(crate) fn order_modules(modules: &mut [Module]) -> Result<(), RegistryError> {
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    for pair in modules.windows(2) {
        if let [first, second] = pair
            && first.name == second.name
        {
            return Err(RegistryError::DuplicateModule {
                name: first.name.clone(),
                first: first.root.clone(),
                second: second.root.clone(),
            });
        }
    }
    Ok(())
}

/// The directory names a module's manifest excludes from its data search
/// (`DATA SEARCH IGNORE DIR:` lines).
fn ignored_directories(module: &Path) -> Vec<String> {
    let Ok(manifest) = fs::read_to_string(module.join("Module.manifest")) else {
        return Vec::new();
    };
    manifest
        .lines()
        .filter_map(|line| line.trim().strip_prefix("DATA SEARCH IGNORE DIR:"))
        .map(|name| name.trim().to_owned())
        .collect()
}

/// Indexes the spec files of every module, in Ghidra's search order:
/// modules by name; within a module its own `data` tree, then
/// `build/data`; within a tree depth first, entries by name.
pub(crate) fn index_modules(modules: &[Module]) -> FileIndex {
    let mut index = FileIndex::default();
    for module in modules {
        let ignored = ignored_directories(&module.root);
        for search_root in [module.root.clone(), module.root.join("build")] {
            let data = search_root.join("data");
            if !data.is_dir() {
                continue;
            }
            let walk = WalkDir::new(&data)
                .min_depth(1)
                .follow_links(true)
                .sort_by_file_name()
                .into_iter()
                .filter_entry(|entry| {
                    let name = entry.file_name().to_string_lossy();
                    !(entry.file_type().is_dir()
                        && (EXCLUDED_DIRECTORIES.contains(&&*name)
                            || ignored.iter().any(|i| **i == *name)))
                });
            for entry in walk {
                match entry {
                    Ok(entry) => index.record(entry.path(), !entry.file_type().is_dir()),
                    Err(error) => tracing::warn!(%error, "skipping unreadable module data entry"),
                }
            }
        }
    }
    index
}

/// The descriptions built from the `.ldefs` files, with the processor
/// table and whatever went wrong.
#[derive(Debug, Default)]
pub(crate) struct Languages {
    pub(crate) descriptions: Vec<LanguageDescription>,
    pub(crate) by_id: HashMap<LanguageId, u32>,
    pub(crate) processors: Vec<Arc<str>>,
    pub(crate) processor_ids: HashMap<Arc<str>, Processor>,
    pub(crate) pspec_files: Vec<PathBuf>,
    pub(crate) ldefs_files: Vec<PathBuf>,
    pub(crate) failures: Vec<LoadFailure>,
}

impl Languages {
    fn processor(&mut self, name: &str) -> (Processor, Arc<str>) {
        if let Some((name, id)) = self.processor_ids.get_key_value(name) {
            return (*id, Arc::clone(name));
        }
        let id = Processor(u32::try_from(self.processors.len()).unwrap_or(u32::MAX));
        let name: Arc<str> = Arc::from(name);
        self.processors.push(Arc::clone(&name));
        self.processor_ids.insert(Arc::clone(&name), id);
        (id, name)
    }

    fn pspec_slot(&mut self, path: &Path) -> u32 {
        let slot = self
            .pspec_files
            .iter()
            .position(|p| p == path)
            .unwrap_or_else(|| {
                self.pspec_files.push(path.to_owned());
                self.pspec_files.len() - 1
            });
        u32::try_from(slot).unwrap_or(u32::MAX)
    }

    /// Reads every indexed `.ldefs` file and registers its languages.
    pub(crate) fn load(
        &mut self,
        index: &mut FileIndex,
        modules: &[Module],
        mode: Mode,
        include_hidden: bool,
    ) {
        let files = index.files(".ldefs").to_vec();
        for file in files {
            match ldefs::read_file(&file, mode) {
                Ok(parsed) => {
                    for warning in &parsed.warnings {
                        tracing::warn!(file = %file.display(), %warning, "language definitions");
                    }
                    let install_root = modules
                        .iter()
                        .find(|m| file.starts_with(&m.root))
                        .and_then(|m| m.install_root.as_deref());
                    for definition in parsed.value.languages {
                        if definition.hidden && !include_hidden {
                            continue;
                        }
                        self.register(index, &file, install_root, definition);
                    }
                }
                Err(error) => self.failures.push(LoadFailure::LanguageDefinitions(error)),
            }
            self.ldefs_files.push(file);
        }
    }

    /// Resolves a definition's files and adds its description. A language
    /// whose files are missing is reported and left out.
    fn register(
        &mut self,
        index: &mut FileIndex,
        ldefs: &Path,
        install_root: Option<&Path>,
        definition: LanguageDefinition,
    ) {
        let directory = ldefs.parent().unwrap_or_else(|| Path::new(""));
        let id = definition.id.clone();
        let missing = |name: &str, extension: &'static str| LoadFailure::MissingFile {
            language: id.clone(),
            ldefs: ldefs.to_owned(),
            file: normalize(&directory.join(name)),
            extension,
        };

        let mut compiler_specs = Vec::with_capacity(definition.compilers.len());
        for compiler in definition.compilers {
            let Some(file) = index.resolve(directory, &compiler.spec, ".cspec") else {
                self.failures.push(missing(&compiler.spec, ".cspec"));
                return;
            };
            compiler_specs.push(CompilerSpecDescription {
                id: compiler.id,
                name: compiler.name,
                file,
            });
        }
        let Some(pspec) = index.resolve(directory, &definition.processor_spec, ".pspec") else {
            self.failures
                .push(missing(&definition.processor_spec, ".pspec"));
            return;
        };
        let Some((slaspec, sla)) = index.resolve_sla(directory, &definition.sla_file) else {
            let stem = definition
                .sla_file
                .strip_suffix(".sla")
                .unwrap_or(&definition.sla_file);
            self.failures
                .push(missing(&format!("{stem}.slaspec"), ".slaspec"));
            return;
        };
        // A missing manual is reported but does not stop the language.
        let manual_index = definition.manual_index_file.as_deref().and_then(|name| {
            let found = index.resolve(directory, name, ".idx");
            if found.is_none() {
                self.failures.push(LoadFailure::MissingManualIndex {
                    language: id.clone(),
                    file: normalize(&directory.join(name)),
                });
            }
            found
        });

        let (processor, processor_name) = self.processor(&definition.processor);
        let description = LanguageDescription {
            id: id.clone(),
            processor,
            processor_name,
            endian: definition.endian,
            instruction_endian: definition.instruction_endian,
            size: definition.size,
            variant: definition.variant,
            version: definition.version,
            deprecated: definition.deprecated,
            description: definition.description,
            truncated_spaces: definition.truncated_spaces,
            compiler_specs,
            external_names: definition.external_names,
            sla_overlay_path: install_root
                .and_then(|root| sla.strip_prefix(root).ok())
                .map(Path::to_owned),
            pspec_slot: self.pspec_slot(&pspec),
            files: LanguageFiles {
                ldefs: ldefs.to_owned(),
                slaspec,
                sla,
                pspec,
                manual_index,
            },
        };
        let existing = self
            .by_id
            .get(&id)
            .and_then(|slot| self.descriptions.get_mut(*slot as usize));
        if let Some(existing) = existing {
            // Ghidra reports a repeated id and lets the later definition
            // take the earlier one's place.
            self.failures.push(LoadFailure::DuplicateLanguage {
                language: id,
                ldefs: ldefs.to_owned(),
                previous: existing.files.ldefs.clone(),
            });
            *existing = description;
        } else {
            let slot = u32::try_from(self.descriptions.len()).unwrap_or(u32::MAX);
            self.by_id.insert(id, slot);
            self.descriptions.push(description);
        }
    }
}
