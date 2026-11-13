//! Resolution of `@include` file names.

use std::path::{Path, PathBuf};

use crate::loader::windows_spelling;

/// Whether an include name is taken as is rather than relative to the
/// including file: it starts with `/` or `\`, or with a drive or scheme
/// prefix (`[A-Za-z0-9_]+:`), as in Ghidra's `SleighPreprocessor`.
pub(crate) fn is_absolute(name: &str) -> bool {
    if name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    let prefix = name
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    prefix > 0 && name.as_bytes().get(prefix) == Some(&b':')
}

/// The path of `name` included from the file at `including`.
///
/// The directory of `including` is taken from the spelling Windows would
/// use: in a verbatim path such as `\\?\C:\d/a.slaspec` the `/` is not
/// a separator, so its parent would otherwise be `\\?\C:\`.
pub(crate) fn resolve(including: &Path, name: &str) -> PathBuf {
    if is_absolute(name) {
        PathBuf::from(name)
    } else {
        windows_spelling(including)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_names_resolve_against_the_including_file() {
        assert_eq!(
            resolve(Path::new("a/b/x.slaspec"), "y.sinc"),
            Path::new("a/b/y.sinc")
        );
        assert_eq!(
            resolve(Path::new("x.slaspec"), "sub/y.sinc"),
            Path::new("sub/y.sinc")
        );
        assert_eq!(
            resolve(Path::new("a/x.slaspec"), "../c/y.sinc"),
            Path::new("a/../c/y.sinc")
        );
    }

    #[test]
    fn absolute_names_are_kept() {
        assert_eq!(
            resolve(Path::new("a/x.slaspec"), "/abs/y.sinc"),
            Path::new("/abs/y.sinc")
        );
        assert!(is_absolute("\\\\server\\y.sinc"));
        assert!(is_absolute("C:\\y.sinc"));
        assert!(is_absolute("file:y.sinc"));
        assert!(!is_absolute("dir/C:y"));
        assert!(!is_absolute(":y"));
        assert!(!is_absolute("y.sinc"));
    }
}
