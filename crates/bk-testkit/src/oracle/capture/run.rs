//! Running one corpus through the consoles.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::oracle::actions::ActionList;
use crate::oracle::graph::GraphFile;
use crate::oracle::pcoderec::Recording;
use crate::oracle::state::StateDump;
use crate::oracle::structure::StructureDump;
use crate::oracle::trace::Trace;
use crate::oracle::{read_text, write_text};
use crate::paths::{GhidraDir, ReferenceDir};
use crate::tools::{Decomp, DecompTranscript};

use super::CaptureError;
use super::checks::{check_completeness, without_pointers};
use super::scripts::{
    CorpusScript, Positions, dumps_script, mark, plain_script, replay_script, structure_script,
    trace_script,
};

/// How long one console run may take.
const RUN_TIMEOUT: Duration = Duration::from_mins(10);

/// What was captured for one decompilation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionSummary {
    /// The function's name (from the end dump).
    pub function: String,
    /// Ops checked against `print raw`.
    pub ops: usize,
    /// Varnodes checked against `print tree varnode`.
    pub varnodes: usize,
    /// Of those, varnodes with a pointer-valued offset.
    pub pointer_valued: usize,
    /// Trace records.
    pub trace_records: usize,
    /// Structuring runs (`bk capture structure`).
    pub structuring_runs: usize,
    /// What went wrong, if anything.
    pub error: Option<String>,
}

/// What was captured for one script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptSummary {
    /// `datatests/<name>` or `research/<name>`.
    pub name: String,
    /// One entry per decompilation.
    pub functions: Vec<FunctionSummary>,
    /// Records in the p-code recording.
    pub recording_events: usize,
    /// Addresses whose recorded lifts differ (context dependence).
    pub context_dependent: usize,
    /// What went wrong for the script as a whole (a console failed, the
    /// replay differed, `decomp_dbg` differed from `decomp`), if anything.
    pub error: Option<String>,
}

/// One pass over a corpus.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureReport {
    /// One entry per script, in corpus order.
    pub scripts: Vec<ScriptSummary>,
}

impl CaptureReport {
    /// Every error, with the script it belongs to.
    pub fn errors(&self) -> Vec<String> {
        let mut out = Vec::new();
        for s in &self.scripts {
            if let Some(e) = &s.error {
                out.push(format!("{}: {e}", s.name));
            }
            for (k, f) in s.functions.iter().enumerate() {
                if let Some(e) = &f.error {
                    out.push(format!("{} #{k}: {e}", s.name));
                }
            }
        }
        out
    }

    /// The summary of `decomp-oracle.md` 4.15: one `S` line per script, one
    /// `F` line per decompilation, totals last.
    pub fn summary(&self) -> String {
        let mut s = String::from(
            "# bk-oracle capture (docs/features/decomp-oracle.md 4.15)\n\
             # S <script> decompiles recording-records context-dependent status\n\
             # F <script> <k> <function> ops varnodes pointer-valued trace-records structuring-runs status\n",
        );
        let (mut decompiles, mut ops, mut vns, mut trace, mut runs) = (0, 0, 0, 0, 0);
        for sc in &self.scripts {
            let _ = writeln!(
                s,
                "S\t{}\t{}\t{}\t{}\t{}",
                sc.name,
                sc.functions.len(),
                sc.recording_events,
                sc.context_dependent,
                sc.error
                    .as_deref()
                    .map_or("ok".to_owned(), |e| format!("error: {}", one_line(e)))
            );
            for (k, f) in sc.functions.iter().enumerate() {
                let _ = writeln!(
                    s,
                    "F\t{}\t{k}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    sc.name,
                    f.function,
                    f.ops,
                    f.varnodes,
                    f.pointer_valued,
                    f.trace_records,
                    f.structuring_runs,
                    f.error
                        .as_deref()
                        .map_or("ok".to_owned(), |e| format!("error: {}", one_line(e)))
                );
                decompiles += 1;
                ops += f.ops;
                vns += f.varnodes;
                trace += f.trace_records;
                runs += f.structuring_runs;
            }
        }
        let _ = writeln!(
            s,
            "T\tscripts={}\tdecompiles={decompiles}\tops={ops}\tvarnodes={vns}\ttrace-records={trace}\tstructuring-runs={runs}\terrors={}",
            self.scripts.len(),
            self.errors().len()
        );
        s
    }
}

fn one_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

/// The standard positions of the console's current root, from `bk list
/// actions` after loading a data test.
pub fn find_positions(
    reference: &ReferenceDir,
    ghidra: &GhidraDir,
) -> Result<Positions, CaptureError> {
    let transcript = reference
        .decomp_bk()
        .current_dir(ghidra.data_tests_dir())
        .run_script(["load test file elseif.xml", "bk list actions"])?;
    let listing = transcript
        .outputs_of("bk list actions")
        .next()
        .ok_or_else(|| CaptureError::Corpus("bk list actions printed nothing".into()))?;
    let actions = ActionList::parse(listing).map_err(|e| CaptureError::Corpus(e.to_string()))?;
    Positions::find(&actions)
}

/// The output of the step after the marker `echo bk-mark <k> <what>`, and of
/// the one after that.
fn after_mark<'a>(t: &'a DecompTranscript, k: usize, what: &str, nth: usize) -> Option<&'a str> {
    let wanted = mark(k, what);
    let at = t.steps.iter().position(|s| s.command == wanted)?;
    t.steps.get(at + 1 + nth).map(|s| s.output.as_str())
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> CaptureError + '_ {
    move |source| CaptureError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn console(reference: &ReferenceDir, which: fn(&ReferenceDir) -> Decomp, dir: &Path) -> Decomp {
    which(reference).timeout(RUN_TIMEOUT).current_dir(dir)
}

/// Capture one script into `out` (created if needed).
fn capture_script(
    reference: &ReferenceDir,
    script: &CorpusScript,
    p: &Positions,
    out: &Path,
) -> Result<ScriptSummary, CaptureError> {
    std::fs::create_dir_all(out).map_err(io(out))?;
    let n = script.decompile_count();
    let mut summary = ScriptSummary {
        name: format!("{}/{}", script.corpus, script.name),
        functions: vec![FunctionSummary::default(); n],
        ..ScriptSummary::default()
    };
    let file = |k: usize, kind: &str| out.join(format!("{}.{k}.{kind}", script.name));

    // Run A: dumps, print raw, print tree varnode, recording.
    let a = console(reference, ReferenceDir::decomp_bk, &script.dir)
        .run_script(dumps_script(script, p, out)?)?;
    for (k, f) in summary.functions.iter_mut().enumerate() {
        let p1 = after_mark(&a, k, "p1", 0).unwrap_or("");
        write_text(&file(k, "p1.raw"), p1).map_err(io(&file(k, "p1.raw")))?;
        for point in ["p1", "p2", "p3", "p4"] {
            let path = file(k, &format!("{point}.state"));
            let text = read_text(&path).map_err(io(&path))?;
            if let Err(e) = StateDump::parse(&text) {
                f.error
                    .get_or_insert(format!("{point} dump does not parse: {e}"));
            }
        }
        let path = file(k, "end.state");
        let dump = StateDump::parse(&read_text(&path).map_err(io(&path))?);
        let (raw, tree) = (after_mark(&a, k, "end", 0), after_mark(&a, k, "end", 1));
        match (dump, raw, tree) {
            (Ok(dump), Some(raw), Some(tree)) => {
                f.function.clone_from(&dump.function.function.name);
                match check_completeness(&dump, raw, tree) {
                    Ok(c) => {
                        f.ops = c.ops;
                        f.varnodes = c.varnodes;
                        f.pointer_valued = c.pointer_valued;
                    }
                    Err(e) => {
                        f.error.get_or_insert(format!("incomplete dump: {e}"));
                    }
                }
            }
            (Err(e), _, _) => {
                f.error
                    .get_or_insert(format!("end dump does not parse: {e}"));
            }
            _ => {
                f.error
                    .get_or_insert("no print raw / print tree varnode at the end".into());
            }
        }
    }
    let rec_path = out.join(format!("{}.pcoderec", script.name));
    let recording = Recording::parse(&read_text(&rec_path).map_err(io(&rec_path))?)
        .map_err(|e| CaptureError::Corpus(format!("{}: {e}", rec_path.display())))?;
    summary.recording_events = recording.events.len();
    summary.context_dependent = recording.context_dependent.len();

    // Run B: replay; print raw after start must be the same.
    if recording.context_dependent.is_empty() {
        let b = console(reference, ReferenceDir::decomp_bk, &script.dir)
            .run_script(replay_script(script, p, &rec_path)?)?;
        for k in 0..n {
            let replayed = after_mark(&b, k, "p1", 0).unwrap_or("");
            let recorded = after_mark(&a, k, "p1", 0).unwrap_or("");
            if replayed != recorded {
                summary
                    .error
                    .get_or_insert(format!("decompilation {k}: replayed print raw differs"));
            }
        }
    }

    // Run C: the trace.
    let c = console(reference, ReferenceDir::decomp_bk_dbg, &script.dir)
        .run_script(trace_script(script))?;
    for (k, f) in summary.functions.iter_mut().enumerate() {
        let output = after_mark(&c, k, "trace", 0).unwrap_or("");
        match Trace::extract(output) {
            Ok(t) => {
                f.trace_records = t.records.len();
                write_text(&file(k, "trace.gz"), &t.write()).map_err(io(&file(k, "trace.gz")))?;
            }
            Err(e) => {
                f.error.get_or_insert(format!("trace does not parse: {e}"));
            }
        }
    }

    // Run D: every structuring run.
    console(reference, ReferenceDir::decomp_bk, &script.dir)
        .run_script(structure_script(script, out)?)?;
    for (k, f) in summary.functions.iter_mut().enumerate() {
        let mut runs = 0;
        while file(k, &format!("{runs}.blocks.bkg")).is_file() {
            let g = file(k, &format!("{runs}.blocks.bkg"));
            let s = file(k, &format!("{runs}.structure.bks"));
            let ok = GraphFile::parse(&read_text(&g).map_err(io(&g))?).is_ok()
                && matches!(
                    StructureDump::parse(&read_text(&s).map_err(io(&s))?),
                    Ok(StructureDump::Ok(_))
                );
            if !ok {
                f.error
                    .get_or_insert(format!("structuring run {runs} does not parse"));
            }
            runs += 1;
        }
        f.structuring_runs = runs;
    }

    // decomp_dbg prints what decomp prints (R8), host pointers aside.
    let plain = plain_script(script);
    let opt = console(reference, ReferenceDir::decomp, &script.dir).run_script(plain.clone())?;
    let dbg = console(reference, ReferenceDir::decomp_dbg, &script.dir).run_script(plain)?;
    if without_pointers(&opt.output.stdout) != without_pointers(&dbg.output.stdout) {
        summary
            .error
            .get_or_insert("decomp_dbg output differs from decomp".into());
    }
    Ok(summary)
}

/// Capture every script of a corpus into `out/<corpus>/`; a script whose
/// consoles fail is reported, not fatal.
pub fn capture_corpus(
    reference: &ReferenceDir,
    scripts: &[CorpusScript],
    positions: &Positions,
    out: &Path,
) -> CaptureReport {
    let mut report = CaptureReport::default();
    for script in scripts {
        let dir: PathBuf = out.join(script.corpus);
        let summary =
            capture_script(reference, script, positions, &dir).unwrap_or_else(|e| ScriptSummary {
                name: format!("{}/{}", script.corpus, script.name),
                error: Some(e.to_string()),
                ..ScriptSummary::default()
            });
        report.scripts.push(summary);
    }
    report
}
