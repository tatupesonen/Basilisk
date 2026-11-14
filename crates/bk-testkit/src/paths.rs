//! Where the Ghidra source tree and the reference directory are.
//!
//! Both roots are resolved the same way: an environment variable if it is
//! set, otherwise a directory beside the Basilisk checkout (`../ghidra`,
//! `../reference` relative to the workspace root). A root that is not there
//! is `None`, never an error: tests decide what to do about it (see
//! [`crate::skip`]).

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// Environment variable naming the Ghidra source tree (the spec root, ADR-002).
pub const GHIDRA_DIR_VAR: &str = "BASILISK_GHIDRA_DIR";

/// Environment variable naming the directory `scripts/build-reference.sh` builds into.
pub const REFERENCE_DIR_VAR: &str = "BASILISK_REFERENCE_DIR";

/// Path of the decompiler's native sources below a Ghidra root.
const DECOMPILE_DIR: &str = "Ghidra/Features/Decompiler/src/decompile";

/// Path of the processor modules below a Ghidra root or the reference overlay.
const PROCESSORS_DIR: &str = "Ghidra/Processors";

/// Source of environment variables, so resolution can be tested without
/// touching the process environment (which Rust 2024 only allows through
/// `unsafe`).
pub(crate) trait Environment {
    /// The value of `name`, if set.
    fn var(&self, name: &str) -> Option<OsString>;
}

/// The real process environment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

/// The root of the Basilisk workspace this crate was compiled in.
pub fn workspace_root() -> PathBuf {
    // crates/bk-testkit -> crates -> workspace root
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .unwrap_or(manifest)
        .to_path_buf()
}

/// The path a root is expected at: the variable's value when set and not
/// empty, otherwise `<workspace>/../<default_name>`.
pub(crate) fn expected_root(
    env: &dyn Environment,
    variable: &str,
    workspace: &Path,
    default_name: &str,
) -> PathBuf {
    match env.var(variable) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => workspace.parent().unwrap_or(workspace).join(default_name),
    }
}

/// Where the Ghidra source tree is expected, whether or not it exists.
pub fn expected_ghidra_dir() -> PathBuf {
    expected_root(
        &ProcessEnvironment,
        GHIDRA_DIR_VAR,
        &workspace_root(),
        "ghidra",
    )
}

/// Where the reference directory is expected, whether or not it exists.
pub fn expected_reference_dir() -> PathBuf {
    expected_root(
        &ProcessEnvironment,
        REFERENCE_DIR_VAR,
        &workspace_root(),
        "reference",
    )
}

/// The Ghidra source tree, or `None` when it is not present.
pub fn ghidra_dir() -> Option<GhidraDir> {
    GhidraDir::at(expected_ghidra_dir())
}

/// The reference directory, or `None` when `scripts/build-reference.sh` has
/// not completed there.
pub fn reference_dir() -> Option<ReferenceDir> {
    ReferenceDir::at(expected_reference_dir())
}

/// The canonical form of `path` when it can be had, for readable messages
/// and so the reference tools get a path without `..` in it.
fn tidy(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// A Ghidra source tree: the read-only reference and the home of the
/// processor specifications and the decompiler's tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraDir {
    root: PathBuf,
}

impl GhidraDir {
    /// Accepts `root` when it has Ghidra's `Ghidra/Processors` directory.
    pub fn at(root: impl Into<PathBuf>) -> Option<Self> {
        let root = root.into();
        root.join(PROCESSORS_DIR)
            .is_dir()
            .then(|| Self { root: tidy(root) })
    }

    /// The root of the tree.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `Ghidra/Processors`, one directory per processor module.
    pub fn processors_dir(&self) -> PathBuf {
        self.root.join(PROCESSORS_DIR)
    }

    /// A processor module's directory, for example `Ghidra/Processors/x86`.
    pub fn processor_dir(&self, module: &str) -> PathBuf {
        self.processors_dir().join(module)
    }

    /// A processor module's `data/languages` directory: its `.slaspec`,
    /// `.sinc`, `.ldefs`, `.pspec`, `.cspec` and `.opinion` files.
    pub fn language_dir(&self, module: &str) -> PathBuf {
        self.processor_dir(module).join("data").join("languages")
    }

    /// The decompiler's C++ sources (`decompile/cpp`).
    pub fn decompiler_cpp_dir(&self) -> PathBuf {
        self.root.join(DECOMPILE_DIR).join("cpp")
    }

    /// The decompiler's data tests (`decompile/datatests`), one
    /// `<decompilertest>` XML file per test.
    pub fn data_tests_dir(&self) -> PathBuf {
        self.root.join(DECOMPILE_DIR).join("datatests")
    }

    /// The decompiler's C++ unit tests (`decompile/unittests`).
    pub fn unit_tests_dir(&self) -> PathBuf {
        self.root.join(DECOMPILE_DIR).join("unittests")
    }
}

/// One of the programs in the reference directory's `bin`. Open for more
/// (a `GhidraHeadless` entry is expected, `docs/features/decomp-oracle.md`
/// 4.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tool {
    /// Ghidra's SLEIGH compiler (`sleigh_opt`).
    Sleigh,
    /// Ghidra's decompiler console (`decomp_opt`).
    Decomp,
    /// Ghidra's decompiler test runner (`decomp_test_dbg`).
    DecompTest,
    /// Basilisk's disassembly and p-code oracle (`tools/reference/pcodedump.cc`).
    Pcodedump,
    /// Basilisk's p-code snippet oracle (`tools/reference/snippetdump.cc`).
    Snippetdump,
    /// Ghidra's decompiler console built with `CPUI_DEBUG` (`decomp_dbg`).
    DecompDbg,
    /// The decompiler console with Basilisk's extension (`tools/reference/consoleext`).
    DecompBk,
    /// The `CPUI_DEBUG` console with Basilisk's extension.
    DecompBkDbg,
}

impl Tool {
    /// Every tool, in the order the build script lists them.
    pub const ALL: [Self; 8] = [
        Self::Sleigh,
        Self::Decomp,
        Self::DecompTest,
        Self::Pcodedump,
        Self::Snippetdump,
        Self::DecompDbg,
        Self::DecompBk,
        Self::DecompBkDbg,
    ];

    /// The tool's file name under `bin`.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Sleigh => "sleigh",
            Self::Decomp => "decomp",
            Self::DecompTest => "decomp_test",
            Self::Pcodedump => "pcodedump",
            Self::Snippetdump => "snippetdump",
            Self::DecompDbg => "decomp_dbg",
            Self::DecompBk => "decomp_bk",
            Self::DecompBkDbg => "decomp_bk_dbg",
        }
    }
}

impl fmt::Display for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.file_name())
    }
}

/// The directory `scripts/build-reference.sh` produced: the reference tools
/// and a copy of every language directory with a compiled `.sla` beside each
/// `.slaspec`. The overlay mirrors Ghidra's layout, so this root can be used
/// wherever a spec root that has `.sla` files is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceDir {
    root: PathBuf,
}

impl ReferenceDir {
    /// Accepts `root` when the build script has completed there, which is
    /// when it writes `STAMP`.
    pub fn at(root: impl Into<PathBuf>) -> Option<Self> {
        let root = root.into();
        root.join("STAMP")
            .is_file()
            .then(|| Self { root: tidy(root) })
    }

    /// The root of the reference directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The build record: Ghidra commit, tool versions, test baseline and the
    /// hash of every tool and `.sla` file.
    pub fn stamp_file(&self) -> PathBuf {
        self.root.join("STAMP")
    }

    /// Where a tool's binary is, whether or not it exists.
    pub fn tool_path(&self, tool: Tool) -> PathBuf {
        self.root.join("bin").join(tool.file_name())
    }

    /// A tool's binary, or `None` when it has not been built.
    pub fn tool(&self, tool: Tool) -> Option<PathBuf> {
        let path = self.tool_path(tool);
        path.is_file().then_some(path)
    }

    /// The overlay's `Ghidra/Processors`.
    pub fn processors_dir(&self) -> PathBuf {
        self.root.join(PROCESSORS_DIR)
    }

    /// The overlay copy of a processor module's `data/languages` directory.
    pub fn language_dir(&self, module: &str) -> PathBuf {
        self.processors_dir()
            .join(module)
            .join("data")
            .join("languages")
    }

    /// The compiled form of `<module>/data/languages/<name>.slaspec`.
    pub fn sla_file(&self, module: &str, name: &str) -> PathBuf {
        self.language_dir(module).join(format!("{name}.sla"))
    }

    /// The `sleigh` options the reference build compiled a processor
    /// module's specifications with — the module's `build.gradle` options
    /// that the C++ compiler accepts, such as `-l` or `-DNAME=VALUE`, in
    /// order. `scripts/build-reference.sh` keeps them one per line in
    /// `.state/lang/<Module>.opts`; a module without that file (or with an
    /// unreadable one) has none.
    pub fn module_options(&self, module: &str) -> Vec<String> {
        let path = self
            .root
            .join(".state")
            .join("lang")
            .join(format!("{module}.opts"));
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::Environment;
    use std::ffi::OsString;

    /// An environment made of the given pairs.
    pub(crate) struct FakeEnvironment(pub(crate) Vec<(&'static str, &'static str)>);

    impl Environment for FakeEnvironment {
        fn var(&self, name: &str) -> Option<OsString> {
            self.0
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeEnvironment;
    use super::*;

    #[test]
    fn workspace_root_holds_the_workspace_manifest() {
        let root = workspace_root();
        assert!(root.join("Cargo.toml").is_file(), "{}", root.display());
        assert!(root.join("crates").join("bk-testkit").is_dir());
    }

    #[test]
    fn default_root_is_beside_the_workspace() {
        let env = FakeEnvironment(vec![]);
        let path = expected_root(&env, GHIDRA_DIR_VAR, Path::new("/work/basilisk"), "ghidra");
        assert_eq!(path, Path::new("/work/ghidra"));
    }

    #[test]
    fn variable_overrides_the_default() {
        let env = FakeEnvironment(vec![(REFERENCE_DIR_VAR, "/elsewhere/ref")]);
        let path = expected_root(
            &env,
            REFERENCE_DIR_VAR,
            Path::new("/work/basilisk"),
            "reference",
        );
        assert_eq!(path, Path::new("/elsewhere/ref"));
    }

    #[test]
    fn empty_variable_counts_as_unset() {
        let env = FakeEnvironment(vec![(GHIDRA_DIR_VAR, "")]);
        let path = expected_root(&env, GHIDRA_DIR_VAR, Path::new("/work/basilisk"), "ghidra");
        assert_eq!(path, Path::new("/work/ghidra"));
    }

    #[test]
    fn other_variables_are_ignored() {
        let env = FakeEnvironment(vec![(REFERENCE_DIR_VAR, "/elsewhere/ref")]);
        let path = expected_root(&env, GHIDRA_DIR_VAR, Path::new("/work/basilisk"), "ghidra");
        assert_eq!(path, Path::new("/work/ghidra"));
    }

    #[test]
    fn absent_roots_are_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(GhidraDir::at(dir.path()), None);
        assert_eq!(ReferenceDir::at(dir.path()), None);
        assert_eq!(GhidraDir::at(dir.path().join("missing")), None);
    }

    #[test]
    fn ghidra_layout_is_recognised() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Ghidra/Processors/x86/data/languages")).unwrap();
        let ghidra = GhidraDir::at(dir.path()).unwrap();
        assert!(ghidra.language_dir("x86").is_dir());
        assert!(ghidra.processors_dir().ends_with("Ghidra/Processors"));
        assert!(
            ghidra
                .data_tests_dir()
                .ends_with("Ghidra/Features/Decompiler/src/decompile/datatests")
        );
        assert!(ghidra.decompiler_cpp_dir().ends_with("decompile/cpp"));
        assert!(ghidra.unit_tests_dir().ends_with("decompile/unittests"));
        assert!(
            ghidra
                .processor_dir("ARM")
                .ends_with("Ghidra/Processors/ARM")
        );
    }

    #[test]
    fn reference_needs_a_stamp_and_reports_tools() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        assert_eq!(ReferenceDir::at(dir.path()), None, "no STAMP yet");

        std::fs::write(dir.path().join("STAMP"), "generated: test\n").unwrap();
        std::fs::write(dir.path().join("bin/sleigh"), "").unwrap();
        let reference = ReferenceDir::at(dir.path()).unwrap();
        assert!(reference.tool(Tool::Sleigh).is_some());
        assert_eq!(reference.tool(Tool::Pcodedump), None);
        assert!(
            reference
                .tool_path(Tool::Pcodedump)
                .ends_with("bin/pcodedump")
        );
        assert!(reference.stamp_file().is_file());
        assert!(
            reference
                .sla_file("x86", "x86-64")
                .ends_with("Ghidra/Processors/x86/data/languages/x86-64.sla")
        );
    }

    #[test]
    fn tool_names_match_the_build_script() {
        let names: Vec<_> = Tool::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            [
                "sleigh",
                "decomp",
                "decomp_test",
                "pcodedump",
                "snippetdump",
                "decomp_dbg",
                "decomp_bk",
                "decomp_bk_dbg"
            ]
        );
    }

    #[test]
    fn module_options_are_read_one_per_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("STAMP"), "generated: test\n").unwrap();
        let state = dir.path().join(".state").join("lang");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("ARM.opts"),
            "-l\n\n-DBASE=/Ghidra/Processors/ARM\n",
        )
        .unwrap();
        let reference = ReferenceDir::at(dir.path()).unwrap();
        assert_eq!(
            reference.module_options("ARM"),
            ["-l", "-DBASE=/Ghidra/Processors/ARM"]
        );
        assert_eq!(reference.module_options("x86"), Vec::<String>::new());
    }
}
