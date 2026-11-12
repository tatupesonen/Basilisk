//! Golden files: expected output kept beside the tests that produce it.
//!
//! A golden file lives under the calling crate's `tests/golden/`. A test
//! compares what it produced with the file; on a mismatch it fails with a
//! unified diff. Running the tests with `UPDATE_GOLDEN=1` rewrites the files
//! instead, and the change is reviewed like any other diff before it is
//! committed (`docs/LOOP.md`, Testing rules).
//!
//! ```no_run
//! let golden = bk_testkit::golden!();
//! golden.assert_text("x86/prologue.pcode", "…what the test produced…");
//! ```

use std::fmt::Write as _;
use std::io;
use std::path::{Component, Path, PathBuf};

use similar::TextDiff;

/// Environment variable that makes comparisons rewrite the golden files when
/// set to anything but the empty string or `0`.
pub const UPDATE_VAR: &str = "UPDATE_GOLDEN";

/// Lines of unchanged text shown around each change in a diff.
const DIFF_CONTEXT: usize = 3;

/// Longest diff put in an error message, in lines. Golden files can be
/// large; a failure should say what changed, not scroll the terminal away.
const DIFF_LINE_LIMIT: usize = 200;

/// A directory of golden files and whether to rewrite them.
#[derive(Debug, Clone)]
pub struct Golden {
    dir: PathBuf,
    update: bool,
}

/// What a comparison did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoldenOutcome {
    /// The golden file holds exactly the actual content.
    Matched,
    /// Update mode: the golden file was created or rewritten.
    Updated,
}

/// Why actual content is not what the golden file says.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GoldenError {
    /// The name does not stay inside the golden directory.
    #[error("golden file name {name:?} must be a relative path without `..`")]
    InvalidName {
        /// The offending name.
        name: String,
    },
    /// There is no golden file yet.
    #[error("golden file {} does not exist; run the test with {UPDATE_VAR}=1 to create it", path.display())]
    Missing {
        /// Where the file would be.
        path: PathBuf,
    },
    /// The golden file could not be read or written.
    #[error("golden file {}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// Text differs. `diff` is a unified diff from the golden file to the
    /// actual text.
    #[error(
        "golden file {} does not match (run with {UPDATE_VAR}=1 to accept the change):\n{diff}",
        path.display()
    )]
    TextMismatch {
        /// The golden file.
        path: PathBuf,
        /// The differences, shortened when very long.
        diff: String,
    },
    /// Bytes differ.
    #[error(
        "golden file {} does not match (run with {UPDATE_VAR}=1 to accept the change): \
         {description}",
        path.display()
    )]
    BytesMismatch {
        /// The golden file.
        path: PathBuf,
        /// Where and how the bytes differ.
        description: String,
    },
}

impl Golden {
    /// The golden files of the crate whose manifest directory is given
    /// (`<manifest dir>/tests/golden`), rewriting them when
    /// [`UPDATE_VAR`] is set. Use the [`golden!`](crate::golden) macro to
    /// pass the calling crate's directory.
    pub fn new(manifest_dir: impl AsRef<Path>) -> Self {
        let update =
            std::env::var_os(UPDATE_VAR).is_some_and(|value| !value.is_empty() && value != "0");
        Self::in_dir(manifest_dir.as_ref().join("tests").join("golden"), update)
    }

    /// Golden files in an explicit directory, with update mode chosen by the
    /// caller.
    pub fn in_dir(dir: impl Into<PathBuf>, update: bool) -> Self {
        Self {
            dir: dir.into(),
            update,
        }
    }

    /// The path of a golden file. `name` is relative to the golden directory
    /// and may have subdirectories.
    pub fn path(&self, name: &str) -> Result<PathBuf, GoldenError> {
        let relative = Path::new(name);
        let stays_inside = !name.is_empty()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
        if stays_inside {
            Ok(self.dir.join(relative))
        } else {
            Err(GoldenError::InvalidName {
                name: name.to_owned(),
            })
        }
    }

    /// Compare text with a golden file, or rewrite the file in update mode.
    pub fn check_text(&self, name: &str, actual: &str) -> Result<GoldenOutcome, GoldenError> {
        let path = self.path(name)?;
        self.check(&path, actual.as_bytes(), |expected| {
            // A golden file that is not UTF-8 cannot equal a `&str`.
            let expected = String::from_utf8_lossy(expected);
            GoldenError::TextMismatch {
                diff: text_diff(&expected, actual),
                path: path.clone(),
            }
        })
    }

    /// Compare bytes with a golden file, or rewrite the file in update mode.
    pub fn check_bytes(&self, name: &str, actual: &[u8]) -> Result<GoldenOutcome, GoldenError> {
        let path = self.path(name)?;
        self.check(&path, actual, |expected| GoldenError::BytesMismatch {
            description: bytes_difference(expected, actual),
            path: path.clone(),
        })
    }

    /// Like [`Self::check_text`], failing the calling test on a mismatch.
    #[track_caller]
    pub fn assert_text(&self, name: &str, actual: &str) {
        if let Err(error) = self.check_text(name, actual) {
            panic!("{error}");
        }
    }

    /// Like [`Self::check_bytes`], failing the calling test on a mismatch.
    #[track_caller]
    pub fn assert_bytes(&self, name: &str, actual: &[u8]) {
        if let Err(error) = self.check_bytes(name, actual) {
            panic!("{error}");
        }
    }

    fn check(
        &self,
        path: &Path,
        actual: &[u8],
        mismatch: impl FnOnce(&[u8]) -> GoldenError,
    ) -> Result<GoldenOutcome, GoldenError> {
        let io_error = |source| GoldenError::Io {
            path: path.to_path_buf(),
            source,
        };
        let expected = match std::fs::read(path) {
            Ok(expected) => Some(expected),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(error)),
        };
        if expected.as_deref() == Some(actual) {
            return Ok(GoldenOutcome::Matched);
        }
        if self.update {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(io_error)?;
            }
            std::fs::write(path, actual).map_err(io_error)?;
            return Ok(GoldenOutcome::Updated);
        }
        match expected {
            Some(expected) => Err(mismatch(&expected)),
            None => Err(GoldenError::Missing {
                path: path.to_path_buf(),
            }),
        }
    }
}

/// The golden files of the crate this macro is used in: `tests/golden`
/// under its manifest directory.
#[macro_export]
macro_rules! golden {
    () => {
        $crate::Golden::new(::core::env!("CARGO_MANIFEST_DIR"))
    };
}

/// A unified diff from `expected` to `actual`, cut off after
/// [`DIFF_LINE_LIMIT`] lines.
fn text_diff(expected: &str, actual: &str) -> String {
    let diff = TextDiff::from_lines(expected, actual);
    let full = diff
        .unified_diff()
        .context_radius(DIFF_CONTEXT)
        .header("golden", "actual")
        .to_string();
    let total = full.lines().count();
    if total <= DIFF_LINE_LIMIT {
        return full;
    }
    let mut shortened: String = full.split_inclusive('\n').take(DIFF_LINE_LIMIT).collect();
    let _ = writeln!(
        shortened,
        "… {} more diff lines not shown",
        total - DIFF_LINE_LIMIT
    );
    shortened
}

/// Where two byte strings first differ, with a few bytes of each from there.
fn bytes_difference(expected: &[u8], actual: &[u8]) -> String {
    let offset = expected
        .iter()
        .zip(actual)
        .take_while(|(a, b)| a == b)
        .count();
    let window = |bytes: &[u8]| {
        let shown: Vec<String> = bytes
            .iter()
            .skip(offset)
            .take(16)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if shown.is_empty() {
            "(end)".to_owned()
        } else {
            shown.join(" ")
        }
    };
    format!(
        "golden is {} bytes, actual is {} bytes; first difference at offset {offset:#x}: \
         golden has {}, actual has {}",
        expected.len(),
        actual.len(),
        window(expected),
        window(actual)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(update: bool) -> (tempfile::TempDir, Golden) {
        let dir = tempfile::tempdir().unwrap();
        let golden = Golden::in_dir(dir.path().join("tests/golden"), update);
        (dir, golden)
    }

    #[test]
    fn matching_text_passes() {
        let (_dir, golden) = golden(false);
        let path = golden.path("a.txt").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "one\ntwo\n").unwrap();
        assert_eq!(
            golden.check_text("a.txt", "one\ntwo\n").unwrap(),
            GoldenOutcome::Matched
        );
        golden.assert_text("a.txt", "one\ntwo\n");
    }

    #[test]
    fn differing_text_fails_with_a_diff_and_leaves_the_file() {
        let (_dir, golden) = golden(false);
        let path = golden.path("a.txt").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();

        let error = golden.check_text("a.txt", "one\n2\nthree\n").unwrap_err();
        let GoldenError::TextMismatch { diff, .. } = &error else {
            panic!("{error:?}")
        };
        assert!(diff.contains("--- golden\n+++ actual\n"), "{diff}");
        assert!(diff.contains("-two\n+2\n"), "{diff}");
        assert!(
            diff.contains(" one\n") && diff.contains(" three\n"),
            "context: {diff}"
        );
        let message = error.to_string();
        assert!(
            message.contains("UPDATE_GOLDEN=1") && message.contains("a.txt"),
            "{message}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "one\ntwo\nthree\n",
            "not rewritten"
        );
    }

    #[test]
    fn a_missing_file_fails_and_says_how_to_create_it() {
        let (_dir, golden) = golden(false);
        let error = golden.check_text("new/sub/a.txt", "text").unwrap_err();
        assert!(matches!(error, GoldenError::Missing { .. }), "{error:?}");
        assert!(error.to_string().contains("UPDATE_GOLDEN=1"), "{error}");
        assert!(
            !golden.path("new/sub/a.txt").unwrap().exists(),
            "nothing is created"
        );
    }

    #[test]
    fn update_mode_creates_and_rewrites() {
        let (_dir, golden) = golden(true);
        assert_eq!(
            golden.check_text("new/sub/a.txt", "first\n").unwrap(),
            GoldenOutcome::Updated
        );
        let path = golden.path("new/sub/a.txt").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");

        assert_eq!(
            golden.check_text("new/sub/a.txt", "first\n").unwrap(),
            GoldenOutcome::Matched
        );
        assert_eq!(
            golden.check_text("new/sub/a.txt", "second\n").unwrap(),
            GoldenOutcome::Updated
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");

        // What update mode wrote is what a normal run then accepts.
        let strict = Golden::in_dir(path.parent().unwrap(), false);
        assert_eq!(
            strict.check_text("a.txt", "second\n").unwrap(),
            GoldenOutcome::Matched
        );
        assert!(strict.check_text("a.txt", "first\n").is_err());
    }

    #[test]
    fn bytes_are_compared_exactly() {
        let (_dir, golden) = golden(true);
        let data = [0u8, 1, 2, 0xff, 0x80, b'\r', b'\n'];
        assert_eq!(
            golden.check_bytes("blob.bin", &data).unwrap(),
            GoldenOutcome::Updated
        );
        let strict = Golden::in_dir(golden.path("blob.bin").unwrap().parent().unwrap(), false);
        assert_eq!(
            strict.check_bytes("blob.bin", &data).unwrap(),
            GoldenOutcome::Matched
        );
        strict.assert_bytes("blob.bin", &data);

        let mut changed = data.to_vec();
        changed[3] = 0xfe;
        changed.push(9);
        let error = strict
            .check_bytes("blob.bin", &changed)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("golden is 7 bytes, actual is 8 bytes"),
            "{error}"
        );
        assert!(error.contains("first difference at offset 0x3"), "{error}");
        assert!(
            error.contains("golden has ff 80 0d 0a, actual has fe 80 0d 0a 09"),
            "{error}"
        );

        let error = strict
            .check_bytes("blob.bin", &data[..4])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("offset 0x4: golden has 80 0d 0a, actual has (end)"),
            "{error}"
        );
    }

    #[test]
    fn non_utf8_golden_text_is_a_mismatch_not_a_crash() {
        let (_dir, golden) = golden(true);
        golden.check_bytes("a.txt", &[0xff, b'\n']).unwrap();
        let strict = Golden::in_dir(golden.path("a.txt").unwrap().parent().unwrap(), false);
        let error = strict.check_text("a.txt", "x\n").unwrap_err();
        assert!(
            matches!(error, GoldenError::TextMismatch { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn long_diffs_are_shortened() {
        let numbered = |word: &str| {
            (0..2000).fold(String::new(), |mut text, n| {
                let _ = writeln!(text, "{word} {n}");
                text
            })
        };
        let (expected, actual) = (numbered("line"), numbered("row"));
        let diff = text_diff(&expected, &actual);
        assert_eq!(diff.lines().count(), DIFF_LINE_LIMIT + 1);
        assert!(
            diff.ends_with("more diff lines not shown\n"),
            "{}",
            &diff[diff.len() - 60..]
        );
    }

    #[test]
    fn names_cannot_leave_the_directory() {
        let (_dir, golden) = golden(true);
        for name in ["", "../a.txt", "a/../../b.txt", "/etc/passwd", "./a.txt"] {
            let error = golden.check_text(name, "x").unwrap_err();
            assert!(
                matches!(error, GoldenError::InvalidName { .. }),
                "{name:?}: {error:?}"
            );
        }
        assert!(golden.path("dir/a.txt").is_ok());
    }

    #[test]
    #[should_panic(expected = "does not match")]
    fn assert_text_fails_the_test_on_a_mismatch() {
        let (_dir, golden) = golden(true);
        golden.check_text("a.txt", "one\n").unwrap();
        let strict = Golden::in_dir(golden.path("a.txt").unwrap().parent().unwrap(), false);
        strict.assert_text("a.txt", "two\n");
    }

    #[test]
    fn macro_points_at_this_crates_golden_directory() {
        let golden = crate::golden!();
        let path = golden.path("x.txt").unwrap();
        assert!(
            path.ends_with("crates/bk-testkit/tests/golden/x.txt"),
            "{}",
            path.display()
        );
    }
}
