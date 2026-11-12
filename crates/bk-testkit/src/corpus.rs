//! Iterating what Ghidra ships: every language directory, every SLEIGH
//! specification, every decompiler data test.
//!
//! Results are sorted by path, so a test that walks the corpus visits it in
//! the same order on every machine.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::paths::{GhidraDir, ReferenceDir};

/// A processor module's `data/languages` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageDir {
    /// The processor module, for example `x86`.
    pub module: String,
    /// The directory.
    pub path: PathBuf,
}

/// A file of a language directory, such as a `.slaspec` or a `.sla`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageFile {
    /// The processor module, for example `x86`.
    pub module: String,
    /// The file name without its extension, for example `x86-64`.
    pub name: String,
    /// The file.
    pub path: PathBuf,
}

/// A directory of the corpus could not be listed.
#[derive(Debug, thiserror::Error)]
#[error("cannot list the corpus: {0}")]
pub struct CorpusError(#[from] walkdir::Error);

/// The `<module>/data/languages` directories below a `Ghidra/Processors`
/// directory, in module order.
pub fn language_dirs(processors_dir: &Path) -> Result<Vec<LanguageDir>, CorpusError> {
    let mut dirs = Vec::new();
    let walk = WalkDir::new(processors_dir)
        .min_depth(3)
        .max_depth(3)
        .follow_links(true)
        .sort_by_file_name();
    for entry in walk {
        let entry = entry?;
        if !entry.file_type().is_dir() || !entry.path().ends_with("data/languages") {
            continue;
        }
        let module = entry
            .path()
            .strip_prefix(processors_dir)
            .ok()
            .and_then(|relative| relative.components().next())
            .map(|component| component.as_os_str().to_string_lossy().into_owned());
        if let Some(module) = module {
            dirs.push(LanguageDir {
                module,
                path: entry.into_path(),
            });
        }
    }
    Ok(dirs)
}

/// The files with the given extension directly inside each language
/// directory below `processors_dir`, in module then file-name order.
pub fn language_files(
    processors_dir: &Path,
    extension: &str,
) -> Result<Vec<LanguageFile>, CorpusError> {
    let mut files = Vec::new();
    for dir in language_dirs(processors_dir)? {
        for path in files_with_extension(&dir.path, extension)? {
            let name = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned());
            if let Some(name) = name {
                files.push(LanguageFile {
                    module: dir.module.clone(),
                    name,
                    path,
                });
            }
        }
    }
    Ok(files)
}

/// The files with the given extension directly inside `dir`, by file name.
pub fn files_with_extension(dir: &Path, extension: &str) -> Result<Vec<PathBuf>, CorpusError> {
    let mut files = Vec::new();
    for entry in WalkDir::new(dir)
        .min_depth(1)
        .max_depth(1)
        .follow_links(true)
        .sort_by_file_name()
    {
        let entry = entry?;
        let matches = entry
            .path()
            .extension()
            .is_some_and(|found| found == extension);
        if matches && entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

impl GhidraDir {
    /// Every processor module's language directory.
    pub fn language_dirs(&self) -> Result<Vec<LanguageDir>, CorpusError> {
        language_dirs(&self.processors_dir())
    }

    /// Every `.slaspec` file: one per SLEIGH language.
    pub fn slaspec_files(&self) -> Result<Vec<LanguageFile>, CorpusError> {
        language_files(&self.processors_dir(), "slaspec")
    }

    /// Every decompiler data-test file.
    pub fn data_tests(&self) -> Result<Vec<PathBuf>, CorpusError> {
        files_with_extension(&self.data_tests_dir(), "xml")
    }
}

impl ReferenceDir {
    /// Every language directory of the overlay.
    pub fn language_dirs(&self) -> Result<Vec<LanguageDir>, CorpusError> {
        language_dirs(&self.processors_dir())
    }

    /// Every compiled `.sla` file of the overlay.
    pub fn sla_files(&self) -> Result<Vec<LanguageFile>, CorpusError> {
        language_files(&self.processors_dir(), "sla")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature Ghidra tree: two modules with languages, one without.
    fn tree() -> (tempfile::TempDir, GhidraDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let touch = |relative: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        };
        touch("Ghidra/Processors/x86/data/languages/x86-64.slaspec");
        touch("Ghidra/Processors/x86/data/languages/x86.slaspec");
        touch("Ghidra/Processors/x86/data/languages/x86.sla");
        touch("Ghidra/Processors/x86/data/languages/ia.sinc");
        touch("Ghidra/Processors/x86/data/languages/old/gone.slaspec");
        touch("Ghidra/Processors/x86/data/patterns/x86.slaspec");
        touch("Ghidra/Processors/ARM/data/languages/ARM8_le.slaspec");
        touch("Ghidra/Processors/NoLanguages/data/manuals/readme.txt");
        touch("Ghidra/Processors/stray.slaspec");
        touch("Ghidra/Features/Decompiler/src/decompile/datatests/b.xml");
        touch("Ghidra/Features/Decompiler/src/decompile/datatests/a.xml");
        touch("Ghidra/Features/Decompiler/src/decompile/datatests/notes.txt");
        std::fs::create_dir(
            root.join("Ghidra/Features/Decompiler/src/decompile/datatests/dir.xml"),
        )
        .unwrap();
        let ghidra = GhidraDir::at(root).unwrap();
        (dir, ghidra)
    }

    #[test]
    fn language_dirs_are_one_per_module_in_order() {
        let (_dir, ghidra) = tree();
        let dirs = ghidra.language_dirs().unwrap();
        let modules: Vec<_> = dirs.iter().map(|dir| dir.module.as_str()).collect();
        assert_eq!(modules, ["ARM", "x86"]);
        assert_eq!(dirs[1].path, ghidra.language_dir("x86"));
    }

    #[test]
    fn slaspec_files_are_only_those_directly_in_language_dirs() {
        let (_dir, ghidra) = tree();
        let specs = ghidra.slaspec_files().unwrap();
        let names: Vec<_> = specs
            .iter()
            .map(|spec| (spec.module.as_str(), spec.name.as_str()))
            .collect();
        // By file name: "x86-64.slaspec" sorts before "x86.slaspec".
        assert_eq!(
            names,
            [("ARM", "ARM8_le"), ("x86", "x86-64"), ("x86", "x86")]
        );
        assert_eq!(
            specs[1].path,
            ghidra.language_dir("x86").join("x86-64.slaspec")
        );
    }

    #[test]
    fn data_tests_are_the_xml_files_in_order() {
        let (_dir, ghidra) = tree();
        let tests = ghidra.data_tests().unwrap();
        let names: Vec<_> = tests.iter().map(|path| path.file_name().unwrap()).collect();
        assert_eq!(names, ["a.xml", "b.xml"]);
    }

    #[test]
    fn overlay_lists_compiled_languages() {
        let (dir, _ghidra) = tree();
        std::fs::write(dir.path().join("STAMP"), "").unwrap();
        let reference = ReferenceDir::at(dir.path()).unwrap();
        let slas = reference.sla_files().unwrap();
        assert_eq!(slas.len(), 1);
        assert_eq!(
            (slas[0].module.as_str(), slas[0].name.as_str()),
            ("x86", "x86")
        );
        assert_eq!(slas[0].path, reference.sla_file("x86", "x86"));
        assert_eq!(reference.language_dirs().unwrap().len(), 2);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_corpus() {
        let dir = tempfile::tempdir().unwrap();
        let error = files_with_extension(&dir.path().join("absent"), "xml").unwrap_err();
        assert!(error.to_string().contains("absent"), "{error}");
        assert!(language_dirs(&dir.path().join("absent")).is_err());
    }
}
