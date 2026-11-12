//! Finding the files a language definition names.
//!
//! Ghidra looks a file up beside the `.ldefs` file first and, failing
//! that, anywhere in the application by file name
//! (`SleighLanguageFile.getLanguageResourceFile`). It also insists that
//! the name's letter case matches the file system's
//! (`FileUtilities.existsAndIsCaseDependent`), so that a module that works
//! on a case-insensitive file system works everywhere. Both are answered
//! here from one listing of the modules' `data` trees.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
};

/// The file-name suffixes that are indexed for application-wide lookup.
pub(crate) const INDEXED_EXTENSIONS: [&str; 7] = [
    ".ldefs", ".opinion", ".pspec", ".cspec", ".slaspec", ".sla", ".idx",
];

/// The spec files of every module, and the names in every directory seen.
#[derive(Debug, Default)]
pub(crate) struct FileIndex {
    /// Files by indexed extension, in application search order.
    by_extension: HashMap<&'static str, Vec<PathBuf>>,
    /// The entry names of each listed directory, exactly as stored.
    directories: HashMap<PathBuf, HashSet<OsString>>,
}

/// Resolves `.` and `..` components without touching the file system.
pub(crate) fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// The last component of a `/`- or `\`-separated name
/// (`FilenameUtils.getName`).
fn file_name(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

/// A file name without its last extension (`FilenameUtils.removeExtension`).
pub(crate) fn remove_extension(name: &str) -> &str {
    name.rfind('.')
        .and_then(|dot| name.get(..dot))
        .unwrap_or(name)
}

/// Removes the first relative-path prefix from `name`, as Ghidra's
/// `RELATIVE_PATHS_PATTERN.matcher(name).replaceFirst("")` does. The
/// pattern is `.*[/\\]\.\.?[/\\]|\.[/\\]|\.\.[/\\]`: everything up to the
/// last `/./` or `/../`, else the first `./` or `../`.
fn discard_relative_path(name: &str) -> String {
    let is_separator = |c: Option<char>| matches!(c, Some('/' | '\\'));
    let chars: Vec<char> = name.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    // First alternative, greedy: the last separator-dots-separator.
    let last = (0..chars.len()).rev().find_map(|i| {
        if !is_separator(at(i)) || at(i + 1) != Some('.') {
            return None;
        }
        if at(i + 2) == Some('.') && is_separator(at(i + 3)) {
            Some(i + 4)
        } else if is_separator(at(i + 2)) {
            Some(i + 3)
        } else {
            None
        }
    });
    if let Some(end) = last {
        return chars.iter().skip(end).collect();
    }
    // Other alternatives: the leftmost "./" or "../".
    for i in 0..chars.len() {
        if at(i) != Some('.') {
            continue;
        }
        let length = if is_separator(at(i + 1)) {
            2
        } else if at(i + 1) == Some('.') && is_separator(at(i + 2)) {
            3
        } else {
            continue;
        };
        return chars
            .iter()
            .take(i)
            .chain(chars.iter().skip(i + length))
            .collect();
    }
    name.to_owned()
}

impl FileIndex {
    /// Records one directory entry found while walking a module.
    pub(crate) fn record(&mut self, path: &Path, is_file: bool) {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return;
        };
        match self.directories.get_mut(parent) {
            Some(names) => {
                names.insert(name.to_owned());
            }
            None => {
                self.directories
                    .insert(parent.to_owned(), HashSet::from([name.to_owned()]));
            }
        }
        if !is_file {
            return;
        }
        let Some(name) = name.to_str() else {
            return;
        };
        // Ghidra skips macOS resource-fork files.
        if name.starts_with("._") {
            return;
        }
        for extension in INDEXED_EXTENSIONS {
            if name.ends_with(extension) {
                self.by_extension
                    .entry(extension)
                    .or_default()
                    .push(path.to_owned());
            }
        }
    }

    /// Every indexed file with the given extension, in search order.
    pub(crate) fn files(&self, extension: &str) -> &[PathBuf] {
        self.by_extension.get(extension).map_or(&[], Vec::as_slice)
    }

    /// Whether `path` exists with exactly this spelling of its last
    /// component.
    fn exists_exact(&mut self, path: &Path) -> bool {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return false;
        };
        if !self.directories.contains_key(parent) {
            // A directory outside the walked trees: list it once.
            let names = fs::read_dir(parent)
                .map(|entries| entries.flatten().map(|e| e.file_name()).collect())
                .unwrap_or_default();
            self.directories.insert(parent.to_owned(), names);
        }
        self.directories
            .get(parent)
            .is_some_and(|names| names.contains(name))
    }

    /// Finds the file `name` (a file name or relative path) that a
    /// definition in `directory` refers to: beside the definition, or else
    /// the indexed file of that name with the given extension.
    pub(crate) fn resolve(
        &mut self,
        directory: &Path,
        name: &str,
        extension: &'static str,
    ) -> Option<PathBuf> {
        let candidate = normalize(&directory.join(name));
        if self.exists_exact(&candidate) {
            return Some(candidate);
        }
        let wanted = file_name(name);
        let mut matches = self
            .files(extension)
            .iter()
            .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some(wanted));
        let first = matches.next()?;
        if matches.next().is_none() {
            return Some(first.clone());
        }
        // Several files share the name. Ghidra then takes the first one,
        // provided the path it was looking for ends with the name it was
        // given minus any leading relative part.
        let relative = discard_relative_path(name);
        candidate
            .to_string_lossy()
            .ends_with(&relative)
            .then(|| first.clone())
    }

    /// Finds the `.slaspec` and `.sla` paths for a `slafile` attribute
    /// (`SleighLanguageFile.fromSlaFilename`): the `.slaspec` of that stem
    /// with the `.sla` expected beside it, or, when only a compiled `.sla`
    /// exists, that with the `.slaspec` expected beside it.
    pub(crate) fn resolve_sla(
        &mut self,
        directory: &Path,
        sla_file: &str,
    ) -> Option<(PathBuf, PathBuf)> {
        let stem = sla_file.strip_suffix(".sla").unwrap_or(sla_file);
        let sibling = |found: &Path, extension: &str| {
            let name = found
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())?;
            Some(found.with_file_name(format!("{}{extension}", remove_extension(&name))))
        };
        if let Some(slaspec) = self.resolve(directory, &format!("{stem}.slaspec"), ".slaspec") {
            let sla = sibling(&slaspec, ".sla")?;
            return Some((slaspec, sla));
        }
        let sla = self.resolve(directory, &format!("{stem}.sla"), ".sla")?;
        let slaspec = sibling(&sla, ".slaspec")?;
        Some((slaspec, sla))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("x86.cspec", "x86.cspec")]
    #[case("../manuals/x86.idx", "manuals/x86.idx")]
    #[case("./x86.cspec", "x86.cspec")]
    #[case("a/../b/./c.cspec", "c.cspec")]
    #[case("a/b/../c.cspec", "c.cspec")]
    #[case("..\\manuals\\x86.idx", "manuals\\x86.idx")]
    #[case("foo../bar", "foobar")]
    #[case("a./b", "ab")]
    #[case("plain/dir/file", "plain/dir/file")]
    fn discards_relative_prefix_like_ghidras_pattern(#[case] name: &str, #[case] expected: &str) {
        assert_eq!(discard_relative_path(name), expected);
    }

    #[test]
    fn normalizes_dot_components() {
        assert_eq!(
            normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(normalize(Path::new("a/../../b")), PathBuf::from("../b"));
    }

    #[test]
    fn name_helpers() {
        assert_eq!(file_name("../manuals/x86.idx"), "x86.idx");
        assert_eq!(file_name("a\\b.cspec"), "b.cspec");
        assert_eq!(file_name("b.cspec"), "b.cspec");
        assert_eq!(remove_extension("riscv.lp64d.slaspec"), "riscv.lp64d");
        assert_eq!(remove_extension("noext"), "noext");
    }
}
