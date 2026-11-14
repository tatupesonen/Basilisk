//! The corpus scripts and the console scripts the capture runs on them.

use std::path::{Path, PathBuf};

use crate::corpus::files_with_extension;
use crate::oracle::actions::ActionList;
use crate::paths::GhidraDir;

use super::CaptureError;

/// One script of a corpus: where it runs, how it loads its image, its commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusScript {
    /// `datatests` or `research`.
    pub corpus: &'static str,
    /// The script's name (the data test or fragment without extension).
    pub name: String,
    /// The directory the console runs in; paths in `load` are relative to it.
    pub dir: PathBuf,
    /// The command that loads the image (`load test file <name>.xml`, `load file frag/<name>.xml`).
    pub load: String,
    /// The commands after it, up to the first `quit`.
    pub commands: Vec<String>,
}

impl CorpusScript {
    /// How many decompilations the script runs.
    pub fn decompile_count(&self) -> usize {
        self.commands.iter().filter(|c| is_decompile(c)).count()
    }
}

/// Whether a command is `decompile` (or its abbreviation `dec`).
pub fn is_decompile(command: &str) -> bool {
    matches!(command.split_whitespace().next(), Some("decompile" | "dec"))
        && command.split_whitespace().nth(1).is_none()
}

fn until_quit(commands: impl IntoIterator<Item = String>) -> Vec<String> {
    commands
        .into_iter()
        .map(|c| c.trim().to_owned())
        .take_while(|c| c.split_whitespace().next() != Some("quit"))
        .filter(|c| !c.is_empty())
        .collect()
}

/// Every data test, in byte order of file names: run in the data-test
/// directory as `load test file <name>.xml` and the test's commands, as
/// `FunctionTestCollection` passes them (`testfunction.cc`).
pub fn data_tests(ghidra: &GhidraDir) -> Result<Vec<CorpusScript>, CaptureError> {
    let dir = ghidra.data_tests_dir();
    let files =
        files_with_extension(&dir, "xml").map_err(|e| CaptureError::Corpus(e.to_string()))?;
    files
        .iter()
        .map(|path| {
            let test =
                crate::read_data_test(path).map_err(|e| CaptureError::Corpus(e.to_string()))?;
            let file = file_name(path)?;
            Ok(CorpusScript {
                corpus: "datatests",
                name: file.trim_end_matches(".xml").to_owned(),
                dir: dir.clone(),
                load: format!("load test file {file}"),
                commands: until_quit(test.script),
            })
        })
        .collect()
}

/// Every fragment script of the research corpus
/// (`docs/research/decompiler-quality/frag/*.script`), run as it is in the
/// research directory.
pub fn research(workspace: &Path) -> Result<Vec<CorpusScript>, CaptureError> {
    let dir = workspace.join("docs/research/decompiler-quality");
    let files = files_with_extension(&dir.join("frag"), "script")
        .map_err(|e| CaptureError::Corpus(e.to_string()))?;
    files
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).map_err(|e| CaptureError::Io {
                path: path.clone(),
                source: e,
            })?;
            let mut lines = text.lines().map(str::to_owned);
            let load = lines.next().unwrap_or_default();
            if !load.starts_with("load file ") {
                return Err(CaptureError::Corpus(format!(
                    "{} does not start with `load file`",
                    path.display()
                )));
            }
            Ok(CorpusScript {
                corpus: "research",
                name: file_name(path)?.trim_end_matches(".script").to_owned(),
                dir: dir.clone(),
                load,
                commands: until_quit(lines),
            })
        })
        .collect()
}

fn file_name(path: &Path) -> Result<String, CaptureError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| CaptureError::Corpus(format!("{} has no UTF-8 file name", path.display())))
}

/// The four standard dump points of `decomp-oracle.md` 4.5, as positions
/// of the console's current root, found by path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Positions {
    /// The action after `start`: `universal:constbase`.
    pub after_start: u32,
    /// The first start of `oppool1`.
    pub oppool1: u32,
    /// The start of the `cleanup` pool.
    pub cleanup: u32,
    /// `universal:stop`.
    pub stop: u32,
}

impl Positions {
    /// Find the positions in an action list.
    pub fn find(actions: &ActionList) -> Result<Self, CaptureError> {
        let find = |path: &str| {
            actions.position_of(path).ok_or_else(|| {
                CaptureError::Corpus(format!("no action {path} in the current root"))
            })
        };
        let start = find("universal:start")?;
        let after_start = actions
            .next_after(start)
            .ok_or_else(|| CaptureError::Corpus("nothing after universal:start".into()))?;
        let oppool1 = actions
            .entries
            .iter()
            .position(|e| e.name() == "oppool1")
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| CaptureError::Corpus("no oppool1 in the current root".into()))?;
        Ok(Self {
            after_start,
            oppool1,
            cleanup: find("universal:cleanup")?,
            stop: find("universal:stop")?,
        })
    }
}

/// A path as a console argument (the console has no quoting).
pub(crate) fn arg(path: &Path) -> Result<String, CaptureError> {
    match path.to_str() {
        Some(text) if !text.contains(char::is_whitespace) => Ok(text.to_owned()),
        _ => Err(CaptureError::Corpus(format!(
            "the console cannot take a path with white space or that is not UTF-8: {}",
            path.display()
        ))),
    }
}

/// The marker echoed before a step whose output the capture reads.
pub(crate) fn mark(k: usize, what: &str) -> String {
    format!("echo bk-mark {k} {what}")
}

/// Run A: the four standard dumps, `print raw` at the first, and `print
/// raw`, `print tree varnode` and a dump at the end of every decompilation;
/// the whole run recorded with `bk pcode record`.
pub(crate) fn dumps_script(
    s: &CorpusScript,
    p: &Positions,
    out: &Path,
) -> Result<Vec<String>, CaptureError> {
    let file = |k: usize, kind: &str| arg(&out.join(format!("{}.{k}.{kind}", s.name)));
    let mut lines = vec![
        s.load.clone(),
        format!(
            "bk pcode record {}",
            arg(&out.join(format!("{}.pcoderec", s.name)))?
        ),
    ];
    let mut k = 0;
    for c in &s.commands {
        if !is_decompile(c) {
            lines.push(c.clone());
            continue;
        }
        lines.extend([
            format!("bk break start {}", p.after_start),
            format!("bk break start {}", p.oppool1),
            "decompile".into(),
            mark(k, "p1"),
            "print raw".into(),
            format!("bk dump state {}", file(k, "p1.state")?),
            "continue".into(),
            format!("bk dump state {}", file(k, "p2.state")?),
            "bk break clear".into(),
            format!("bk break start {}", p.cleanup),
            format!("bk break start {}", p.stop),
            "continue".into(),
            format!("bk dump state {}", file(k, "p3.state")?),
            "continue".into(),
            format!("bk dump state {}", file(k, "p4.state")?),
            "bk break clear".into(),
            "continue".into(),
            mark(k, "end"),
            "print raw".into(),
            "print tree varnode".into(),
            format!("bk dump state {}", file(k, "end.state")?),
        ]);
        k += 1;
    }
    lines.push("bk pcode stop".into());
    Ok(lines)
}

/// Run B: the recording of run A replayed, `print raw` at the action after
/// `start` of every decompilation.
pub(crate) fn replay_script(
    s: &CorpusScript,
    p: &Positions,
    recording: &Path,
) -> Result<Vec<String>, CaptureError> {
    let mut lines = vec![
        s.load.clone(),
        format!("bk pcode replay {}", arg(recording)?),
    ];
    let mut k = 0;
    for c in &s.commands {
        if !is_decompile(c) {
            lines.push(c.clone());
            continue;
        }
        lines.extend([
            format!("bk break start {}", p.after_start),
            "decompile".into(),
            mark(k, "p1"),
            "print raw".into(),
            "bk break clear".into(),
            "continue".into(),
        ]);
        k += 1;
    }
    lines.push("bk pcode stop".into());
    Ok(lines)
}

/// Run C (`decomp_bk_dbg`): the trace of every decompilation.
pub(crate) fn trace_script(s: &CorpusScript) -> Vec<String> {
    let mut lines = vec![s.load.clone(), "bk trace stream".into()];
    let mut k = 0;
    for c in &s.commands {
        if !is_decompile(c) {
            lines.push(c.clone());
            continue;
        }
        lines.extend([
            "trace clear".into(),
            "trace address".into(),
            "trace enable".into(),
            mark(k, "trace"),
            "decompile".into(),
            "trace disable".into(),
        ]);
        k += 1;
    }
    lines
}

/// Run D: every structuring run of every decompilation (`bk capture structure`).
pub(crate) fn structure_script(s: &CorpusScript, out: &Path) -> Result<Vec<String>, CaptureError> {
    let mut lines = vec![s.load.clone()];
    let mut k = 0;
    for c in &s.commands {
        if !is_decompile(c) {
            lines.push(c.clone());
            continue;
        }
        lines.push(format!(
            "bk capture structure {}",
            arg(&out.join(format!("{}.{k}", s.name)))?
        ));
        k += 1;
    }
    Ok(lines)
}

/// The plain script with `print raw`, `print tree varnode` and `print tree
/// block` after every decompilation (runs R5, R8), for `decomp` against
/// `decomp_dbg`.
pub(crate) fn plain_script(s: &CorpusScript) -> Vec<String> {
    let mut lines = vec![s.load.clone()];
    for c in &s.commands {
        lines.push(c.clone());
        if is_decompile(c) {
            lines.extend([
                "print raw".into(),
                "print tree varnode".into(),
                "print tree block".into(),
            ]);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script() -> CorpusScript {
        CorpusScript {
            corpus: "datatests",
            name: "t".into(),
            dir: PathBuf::from("/d"),
            load: "load test file t.xml".into(),
            commands: until_quit([
                "lo fu f".to_owned(),
                "decompile".into(),
                "print C".into(),
                "quit".into(),
                "x".into(),
            ]),
        }
    }

    #[test]
    fn commands_stop_at_quit_and_decompiles_are_counted() {
        let s = script();
        assert_eq!(s.commands, ["lo fu f", "decompile", "print C"]);
        assert_eq!(s.decompile_count(), 1);
        assert!(is_decompile("dec"));
        assert!(!is_decompile("decompile now"));
    }

    #[test]
    fn the_dump_script_stops_at_the_four_points() {
        let p = Positions {
            after_start: 2,
            oppool1: 27,
            cleanup: 192,
            stop: 242,
        };
        let lines = dumps_script(&script(), &p, Path::new("/out")).unwrap();
        let out = Path::new("/out");
        assert_eq!(
            lines[1],
            format!("bk pcode record {}", out.join("t.pcoderec").display())
        );
        assert_eq!(lines.iter().filter(|l| *l == "continue").count(), 4);
        assert!(lines.contains(&format!(
            "bk dump state {}",
            out.join("t.0.end.state").display()
        )));
        assert_eq!(lines.last().map(String::as_str), Some("bk pcode stop"));
        assert!(arg(Path::new("/a b")).is_err());
    }
}
