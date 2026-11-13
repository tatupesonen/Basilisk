//! File access for the preprocessor.
//!
//! The preprocessor never touches the file system itself: it asks a
//! [`FileLoader`], so tests and tools can supply sources from memory.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::path::{Component, Path, PathBuf, Prefix};

/// Why a source file could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file does not exist.
    #[error("file not found")]
    NotFound,
    /// The file exists but could not be read.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The file is larger than the preprocessor accepts.
    #[error("file is too large ({size} bytes; the limit is {limit})")]
    TooLarge {
        /// Size of the file in bytes.
        size: u64,
        /// The largest accepted size in bytes.
        limit: u64,
    },
}

/// Supplies the text of source files.
pub trait FileLoader {
    /// Returns the text of the file at `path`.
    fn load(&mut self, path: &Path) -> Result<String, LoadError>;

    /// A key that is the same for every spelling of the path of one file
    /// (`a/./b`, `a/x/../b`, or a link to it). The preprocessor uses it to
    /// recognise a file it has already read and to detect include cycles,
    /// so nothing depends on how the root path was written. The default
    /// normalises `.` and `..` lexically.
    fn identity(&mut self, path: &Path) -> PathBuf {
        normalize(path)
    }
}

/// `path` with `.` components removed and each `..` cancelling the
/// component before it, where there is one.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => out.push(component),
            },
            other => out.push(other),
        }
    }
    out.iter().collect()
}

/// Loads files from the file system.
///
/// Ghidra reads specifications as ISO-8859-1. `FsLoader` reads valid UTF-8
/// as UTF-8 (so non-ASCII text in comments and strings survives) and falls
/// back to ISO-8859-1 for anything else, so no file is ever rejected for
/// its encoding.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsLoader;

impl FileLoader for FsLoader {
    fn load(&mut self, path: &Path) -> Result<String, LoadError> {
        let bytes = std::fs::read(windows_spelling(path)).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                LoadError::NotFound
            } else {
                LoadError::Io(e)
            }
        })?;
        Ok(decode(bytes))
    }

    /// The canonical path, which also resolves symbolic links; the lexical
    /// form if the file cannot be resolved.
    fn identity(&mut self, path: &Path) -> PathBuf {
        let path = windows_spelling(path);
        std::fs::canonicalize(&path).unwrap_or_else(|_| normalize(&path))
    }
}

/// The spelling of `path` that Windows itself would use for it. Elsewhere
/// a path has no prefix and comes back unchanged.
///
/// A verbatim path (`\\?\C:\…`) reaches the file system exactly as
/// written: `/` is then part of a name and `.` and `..` are names, so
/// `\\?\C:\a\..\b.slaspec` names no file although `C:\a\..\b.slaspec`
/// does. Windows removes them lexically from every other spelling; doing
/// the same here, and writing the drive letter in upper case (as a
/// canonical path does), makes every spelling of a file reach it, and two
/// spellings of a missing file compare equal.
///
/// The file loader reads and identifies files through it, and include
/// names are resolved against it. `bk-lang` has the same function for its
/// registry roots; the two crates share no dependency to hold it.
pub(crate) fn windows_spelling(path: &Path) -> Cow<'_, Path> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Cow::Borrowed(path);
    };
    let kind = prefix.kind();
    let letter = match kind {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(letter),
        _ => None,
    };
    if !kind.is_verbatim() && !letter.is_some_and(|l| l.is_ascii_lowercase()) {
        return Cow::Borrowed(path);
    }
    let mut out = match letter {
        Some(letter) => {
            let verbatim = if kind.is_verbatim() { r"\\?\" } else { "" };
            PathBuf::from(format!(
                "{verbatim}{}:",
                char::from(letter.to_ascii_uppercase())
            ))
        }
        None => PathBuf::from(prefix.as_os_str()),
    };
    let rest = components.as_path();
    if !kind.is_verbatim() {
        out.push(rest);
        return Cow::Owned(out);
    }
    // Read without the prefix, the rest is split at `/` as well as `\`.
    for component in rest.components() {
        match component {
            Component::CurDir => {}
            // `..` at the root stays there, as Windows has it.
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    Cow::Owned(out)
}

/// Decodes file bytes: UTF-8 when valid, otherwise ISO-8859-1.
pub fn decode(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => err.into_bytes().iter().map(|&b| char::from(b)).collect(),
    }
}

/// Serves files from memory, keyed by path (normalised, so `a/./b` and
/// `a/x/../b` name the file added as `a/b`).
#[derive(Clone, Debug, Default)]
pub struct MemoryLoader {
    files: HashMap<PathBuf, String>,
}

impl MemoryLoader {
    /// A loader with no files.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) a file.
    pub fn add(&mut self, path: impl Into<PathBuf>, text: impl Into<String>) -> &mut Self {
        self.files.insert(normalize(&path.into()), text.into());
        self
    }

    /// Builder form of [`Self::add`].
    #[must_use]
    pub fn with(mut self, path: impl Into<PathBuf>, text: impl Into<String>) -> Self {
        self.add(path, text);
        self
    }
}

impl FileLoader for MemoryLoader {
    fn load(&mut self, path: &Path) -> Result<String, LoadError> {
        self.files
            .get(&normalize(path))
            .cloned()
            .ok_or(LoadError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_prefers_utf8_and_falls_back_to_latin1() {
        assert_eq!(decode("naïve – ok".as_bytes().to_vec()), "naïve – ok");
        assert_eq!(decode(vec![b'a', 0xE9, b'b']), "aéb");
        assert_eq!(decode(Vec::new()), "");
    }

    #[test]
    fn memory_loader_serves_what_it_was_given() {
        let mut loader = MemoryLoader::new().with("a/b.sinc", "text");
        assert_eq!(loader.load(Path::new("a/b.sinc")).unwrap(), "text");
        assert!(matches!(
            loader.load(Path::new("missing")),
            Err(LoadError::NotFound)
        ));
    }

    #[test]
    fn paths_normalise_lexically() {
        assert_eq!(normalize(Path::new("a/./b/../c")), Path::new("a/c"));
        assert_eq!(normalize(Path::new("../a/..")), Path::new(".."));
        assert_eq!(normalize(Path::new("/../a")), Path::new("/a"));
        assert_eq!(normalize(Path::new("x/y/../../..")), Path::new(".."));
        let mut loader = MemoryLoader::new().with("d/b.sinc", "t");
        assert_eq!(loader.load(Path::new("d/x/.././b.sinc")).unwrap(), "t");
    }

    #[test]
    fn paths_without_a_prefix_keep_their_spelling() {
        for path in ["/a/./b/../c", "a//b/", "../x"] {
            assert!(matches!(
                windows_spelling(Path::new(path)),
                Cow::Borrowed(p) if p == Path::new(path)
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_spellings() {
        for (path, expected) in [
            (r"C:\a\b", r"C:\a\b"),
            (r"c:\a\b", r"C:\a\b"),
            (r"c:/a/b", r"C:/a/b"),
            (r"\\?\C:\a\b", r"\\?\C:\a\b"),
            (r"\\?\c:\a\b", r"\\?\C:\a\b"),
            (r"\\?\C:\a\.\x\..\b", r"\\?\C:\a\b"),
            (r"\\?\C:\a/x/../b/", r"\\?\C:\a\b"),
            (r"\\?\C:\..\a", r"\\?\C:\a"),
            (r"\\?\UNC\server\share\a\..\b", r"\\?\UNC\server\share\b"),
            (r"\\server\share\a", r"\\server\share\a"),
        ] {
            let spelled = windows_spelling(Path::new(path));
            assert_eq!(
                spelled.as_os_str(),
                std::ffi::OsStr::new(expected),
                "{path}"
            );
        }
    }

    #[test]
    fn fs_loader_reports_missing_files() {
        let mut loader = FsLoader;
        let missing = Path::new("/nonexistent-dir-for-bk-sleigh-syntax/x.slaspec");
        assert!(matches!(loader.load(missing), Err(LoadError::NotFound)));
    }
}
