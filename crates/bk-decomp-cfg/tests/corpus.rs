#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]
//! Every structuring run of the corpora (`docs/features/decomp-cfg.md`
//! 6.3.2, 6.4): the data tests and the research fragments, each
//! `decompile` captured with D00's `bk capture structure` (the basic-block
//! graph with its real facts and the switch defaults installed, at every
//! `blockstructure` start whose structure is empty, and Ghidra's hierarchy
//! at the next action). For every run Ghidra's own structurer is also run on
//! the captured graph with `bk structure … asgiven trace`, which gives the
//! flips, goto marks, change count and rule sequence.
//!
//! The table (`tests/data/structure_corpus.<library>.txt.gz`) holds per
//! run the captured graph (the input, as text) and digests of Ghidra's two
//! dumps. `replay` (S) structures each graph `AsGiven` and requires
//! Basilisk's `bkstruct` dump to equal `bk structure`'s and its `S`/`P`
//! records to equal the captured hierarchy. `capture` (L, ignored)
//! regenerates it: `tests/oracle/regen_corpus.sh`.

mod support {
    pub(crate) mod graphgen;
    pub(crate) mod oracle;
    pub(crate) mod table;
}

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bk_decomp_cfg::{
    CaseLabels, GhidraGotoSelector, Limits, NodeId, Record, StructureOptions, finish, structure,
};
use bk_testkit::oracle::capture::{CorpusScript, data_tests, is_decompile, research};
use bk_testkit::oracle::host::{Library, digest};
use bk_testkit::oracle::{GraphFile, StateDump, StructureDump};
use support::oracle::{cfg_of, dump_structure, struct_dump};
use support::table::{data_dir, escape, read_gz, unescape, write_gz};

const HEADER: &str = "# bk-decomp-cfg corpus table v1: script decompilation run graph(bkgraph 1, escaped) fnv64(bk structure asgiven trace) fnv64(captured structure)";

fn table_path(lib: Library) -> PathBuf {
    data_dir().join(format!("structure_corpus.{}.txt.gz", lib.name()))
}

fn path_arg(p: &Path) -> String {
    let s = p.to_str().expect("UTF-8 path");
    assert!(
        !s.contains(char::is_whitespace),
        "the console cannot take {s}"
    );
    s.to_owned()
}

/// The script of `bk capture structure` for every decompilation of `s`.
fn capture_script(s: &CorpusScript, out: &Path) -> Vec<String> {
    let mut lines = vec![s.load.clone()];
    let mut d = 0;
    for c in &s.commands {
        if is_decompile(c) {
            lines.push(format!(
                "bk capture structure {}",
                path_arg(&out.join(format!("{}.{d}", s.name)))
            ));
            d += 1;
        } else {
            lines.push(c.clone());
        }
    }
    lines
}

/// Basilisk on one captured graph: the `bkstruct` dump as `bk structure …
/// asgiven trace` writes it, and the `S`/`P` records as `bk dump
/// structure` writes them.
fn basilisk(graph: &GraphFile) -> (String, String) {
    let (cfg, facts) = cfg_of(graph);
    let options = StructureOptions {
        record: Record::Trace,
        ..StructureOptions::default()
    };
    let r = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new());
    let full = struct_dump(&r).write();
    let hier = match &r {
        Ok(s) => dump_structure(&s.hierarchy).write(),
        Err(e) => StructureDump::Error(e.to_string()).write(),
    };
    (full, hier)
}

fn hex(d: u64) -> String {
    format!("{d:016x}")
}

/// One jump table as `finalizePrinting` reads it: the position of the
/// switch block, `block2addr` (out-edge position, address index), labels.
type JumpTable = (u32, Vec<(i32, i32)>, Vec<u64>);

fn tables_of(state: &StateDump) -> Vec<JumpTable> {
    state
        .jump_tables
        .iter()
        .filter_map(|j| {
            let op = j.table.op.as_ref()?;
            let block = state.blocks.iter().find(|b| b.block.ops.contains(op))?;
            Some((
                block.block.position,
                j.table
                    .block_to_address
                    .iter()
                    .map(|p| (p.0, p.1))
                    .collect(),
                j.table.labels.clone(),
            ))
        })
        .collect()
}

fn write_tables(t: &[JumpTable]) -> String {
    if t.is_empty() {
        return "-".to_owned();
    }
    t.iter()
        .map(|(pos, pairs, labels)| {
            let pairs: Vec<String> = pairs.iter().map(|(a, b)| format!("{a}:{b}")).collect();
            let labels: Vec<String> = labels.iter().map(|l| format!("{l:x}")).collect();
            format!("{pos}|{}|{}", pairs.join(","), labels.join(","))
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn read_tables(s: &str) -> Vec<JumpTable> {
    if s == "-" {
        return Vec::new();
    }
    s.split(';')
        .map(|t| {
            let f: Vec<&str> = t.split('|').collect();
            let list = |x: &str| {
                x.split(',')
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            (
                f[0].parse().unwrap(),
                list(f[1])
                    .iter()
                    .map(|p| {
                        let (a, b) = p.split_once(':').unwrap();
                        (a.parse().unwrap(), b.parse().unwrap())
                    })
                    .collect(),
                list(f[2])
                    .iter()
                    .map(|l| u64::from_str_radix(l, 16).unwrap())
                    .collect(),
            )
        })
        .collect()
}

/// `JumpTable::getIndexByBlock(bl, 0)` and `getLabelByIndex` over the
/// captured tables (jumptable.cc:2408, 2551).
struct Labels<'a> {
    graph: &'a GraphFile,
    tables: &'a [JumpTable],
}

impl CaseLabels for Labels<'_> {
    fn first_label(&self, switch_block: NodeId, case_block: NodeId) -> Option<u64> {
        let (_, pairs, labels) = self.tables.iter().find(|t| t.0 == switch_block.get())?;
        let node = self.graph.nodes.get(case_block.index())?;
        let position = node
            .in_edges
            .iter()
            .find(|e| e.src == switch_block.get())?
            .slot as i32;
        let (_, index) = pairs.iter().find(|p| p.0 == position)?;
        labels.get(usize::try_from(*index).ok()?).copied()
    }
}

/// `f_final_transform` (`FlowBlock::block_flags`), set by
/// `ActionStructureTransform` (D15) on every structured node.
const FINAL_TRANSFORM: u32 = 0x10_0000;

/// A hierarchy without names: kind, index, flags (masked), and children,
/// with the two bodies of `ifelse`/`ifnoexit` nodes in a fixed order when
/// `unswap` (what `ActionPreferComplement`'s `swapBlocks(1,2)` changes).
fn canonical(dump: &str, mask: u32, unswap: bool) -> Option<String> {
    use bk_testkit::oracle::NodeKind;
    let StructureDump::Ok(s) = StructureDump::parse(dump).ok()? else {
        return None;
    };
    fn front(s: &bk_testkit::oracle::Structured, mut name: bk_testkit::oracle::NodeName) -> String {
        loop {
            match name {
                bk_testkit::oracle::NodeName::Leaf(i) => return format!("L{i}"),
                bk_testkit::oracle::NodeName::Structured(_) => {
                    match s.node(name).and_then(|n| n.components.first()) {
                        Some(&c) => name = c,
                        None => return "?".to_owned(),
                    }
                }
            }
        }
    }
    fn walk(
        s: &bk_testkit::oracle::Structured,
        name: bk_testkit::oracle::NodeName,
        mask: u32,
        unswap: bool,
    ) -> String {
        use bk_testkit::oracle::KindData;
        let Some(n) = s.node(name) else {
            return "?".to_owned();
        };
        let mut kids: Vec<String> = n
            .components
            .iter()
            .map(|&c| walk(s, c, mask, unswap))
            .collect();
        if unswap && matches!(n.kind, NodeKind::IfElse | NodeKind::IfNoExit) && kids.len() == 3 {
            kids[1..].sort();
        }
        let leaf = match name {
            bk_testkit::oracle::NodeName::Leaf(i) => format!("L{i}"),
            bk_testkit::oracle::NodeName::Structured(_) => String::new(),
        };
        let data = match &n.data {
            KindData::None => String::new(),
            KindData::Goto { target, goto_type } => format!(
                "goto {} {goto_type:x}",
                target.map_or("-".to_owned(), |t| front(s, t))
            ),
            KindData::MultiGoto { targets, default } => format!(
                "multi {:?} {default}",
                targets.iter().map(|&t| front(s, t)).collect::<Vec<_>>()
            ),
            // A flip of the condition (preferComplement) toggles the opcode.
            KindData::Condition(op) => {
                if unswap {
                    String::new()
                } else {
                    op.clone()
                }
            }
            KindData::WhileDo { overflow } => format!("{overflow}"),
            KindData::Switch(cases) => cases
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}:{}:{:x}:{}:{}",
                        front(s, c.node),
                        c.out_index,
                        c.chain,
                        c.goto_type,
                        c.is_exit,
                        c.is_default
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        };
        format!(
            "{}{leaf}/{}/{:x}[{data}]({})",
            n.kind.name(),
            n.index,
            n.flags & !mask,
            kids.join(",")
        )
    }
    Some(
        s.top
            .iter()
            .map(|&t| walk(&s, t, mask, unswap))
            .collect::<Vec<_>>()
            .join(";"),
    )
}

/// Why Basilisk's finished hierarchy differs from Ghidra's final one, or
/// `None` if no known cause explains it. The causes are D15's actions that
/// run between `blockstructure` and `finalstructure`.
fn final_cause(ours: &str, theirs: &str) -> Option<&'static str> {
    if ours == theirs {
        return Some("equal");
    }
    if canonical(ours, FINAL_TRANSFORM, false)? == canonical(theirs, FINAL_TRANSFORM, false)? {
        return Some("finaltransform");
    }
    if canonical(ours, FINAL_TRANSFORM, true)? == canonical(theirs, FINAL_TRANSFORM, true)? {
        return Some("prefercomplement");
    }
    None
}

/// Basilisk's final hierarchy: the last structuring run, finished with the
/// case labels, as `bk dump structure` writes it.
fn basilisk_final(graph: &GraphFile, tables: &[JumpTable]) -> String {
    let (cfg, facts) = cfg_of(graph);
    match structure(
        &cfg,
        &facts,
        &StructureOptions::default(),
        &mut GhidraGotoSelector::new(),
    ) {
        Ok(mut s) => {
            finish(&mut s.hierarchy, &facts, Some(&Labels { graph, tables }));
            dump_structure(&s.hierarchy).write()
        }
        Err(e) => StructureDump::Error(e.to_string()).write(),
    }
}

#[test]
#[ignore = "runs decomp_bk over both corpora; tests/oracle/regen_corpus.sh"]
fn capture() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let lib = Library::of_reference(&reference).unwrap();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bk-cfg-corpus-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let mut scripts = data_tests(&ghidra).unwrap();
    scripts.extend(research(&bk_testkit::workspace_root()).unwrap());
    let mut skipped = Vec::new();
    for s in &scripts {
        let dir = out.join(s.corpus);
        std::fs::create_dir_all(&dir).unwrap();
        let r = reference
            .decomp_bk()
            .current_dir(&s.dir)
            .timeout(Duration::from_mins(5))
            .run_script(capture_script(s, &dir));
        if let Err(e) = r {
            skipped.push(format!(
                "{}/{}: {}",
                s.corpus,
                s.name,
                e.to_string().lines().next().unwrap_or("")
            ));
        }
    }
    // Every captured run, in name order.
    let mut runs: BTreeMap<String, (PathBuf, PathBuf)> = BTreeMap::new();
    for corpus in ["datatests", "research"] {
        let dir = out.join(corpus);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_str().unwrap().to_owned();
            if let Some(stem) = name.strip_suffix(".blocks.bkg") {
                let bks = dir.join(format!("{stem}.structure.bks"));
                runs.insert(format!("{corpus}/{stem}"), (p.clone(), bks));
            }
        }
    }
    // Ghidra's structurer on every captured graph.
    let elseif = ghidra.data_tests_dir().join("elseif.xml");
    let mut script = vec![format!("load test file {}", path_arg(&elseif))];
    for (bkg, _) in runs.values() {
        script.push(format!(
            "bk structure {} {}.ag asgiven trace",
            path_arg(bkg),
            path_arg(bkg)
        ));
    }
    reference
        .decomp_bk()
        .timeout(Duration::from_mins(30))
        .run_script(&script)
        .expect("bk structure session");
    let mut text = String::from(HEADER);
    text.push('\n');
    let mut mismatch = Vec::new();
    for (key, (bkg, bks)) in &runs {
        let graph = std::fs::read_to_string(bkg).unwrap();
        let ag = std::fs::read_to_string(format!("{}.ag", bkg.display())).unwrap();
        let captured = std::fs::read_to_string(bks).unwrap();
        let (script_name, run) = key.rsplit_once('.').unwrap();
        let _ = writeln!(
            text,
            "{script_name}\t{run}\t{}\t{}\t{}",
            escape(&graph),
            hex(digest(ag.as_bytes())),
            hex(digest(captured.as_bytes()))
        );
        let (full, hier) = basilisk(&GraphFile::parse(&graph).unwrap());
        if full != ag || hier != captured {
            mismatch.push(key.clone());
        }
    }
    // The final hierarchy of every decompilation, from its last run.
    let mut last: BTreeMap<String, (u32, PathBuf)> = BTreeMap::new();
    for (key, (bkg, _)) in &runs {
        let (prefix, run) = key.rsplit_once('.').unwrap();
        let run: u32 = run.parse().unwrap();
        if last.get(prefix).is_none_or(|(r, _)| run > *r) {
            last.insert(prefix.to_owned(), (run, bkg.clone()));
        }
    }
    let mut final_mismatch = Vec::new();
    for (prefix, (run, bkg)) in &last {
        let fin = out.join(format!("{prefix}.final.structure.bks"));
        let state = out.join(format!("{prefix}.final.state"));
        let (Ok(fin), Ok(state)) = (
            std::fs::read_to_string(&fin),
            std::fs::read_to_string(&state),
        ) else {
            continue;
        };
        let tables = tables_of(&StateDump::parse(&state).unwrap());
        let _ = writeln!(
            text,
            "final\t{prefix}\t{run}\t{}\t{}",
            write_tables(&tables),
            escape(&fin)
        );
        let graph = GraphFile::parse(&std::fs::read_to_string(bkg).unwrap()).unwrap();
        let ours = basilisk_final(&graph, &tables);
        if final_cause(&ours, &fin).is_none() {
            let _ = std::fs::write(out.join(format!("{prefix}.final.ours")), &ours);
            final_mismatch.push(prefix.clone());
        }
    }
    eprintln!(
        "final hierarchies: {} decompilations, {} unexplained {final_mismatch:?}",
        last.len(),
        final_mismatch.len()
    );
    let dest = std::env::var("BK_CFG_TABLE_OUT")
        .ok()
        .filter(|d| !d.is_empty())
        .map_or_else(
            || table_path(lib),
            |d| PathBuf::from(d).join(format!("structure_corpus.{}.txt.gz", lib.name())),
        );
    write_gz(&dest, &text);
    eprintln!(
        "corpus capture: {} scripts, {} skipped {skipped:?}, {} structuring runs, {} differ from Basilisk {mismatch:?}; wrote {}",
        scripts.len(),
        skipped.len(),
        runs.len(),
        mismatch.len(),
        dest.display()
    );
    if std::env::var_os("BK_CFG_KEEP").is_none() {
        let _ = std::fs::remove_dir_all(&out);
    } else {
        eprintln!("kept {}", out.display());
    }
}

struct CorpusTable {
    /// script.decompilation, run, graph, digest of `bk structure`, digest of the captured hierarchy.
    runs: Vec<(String, String, String, String, String)>,
    /// script.decompilation, last run, jump tables, Ghidra's final hierarchy.
    finals: Vec<(String, String, String, String)>,
}

fn read_table(lib: Library) -> Option<CorpusTable> {
    let text = read_gz(&table_path(lib))?;
    let mut t = CorpusTable {
        runs: Vec::new(),
        finals: Vec::new(),
    };
    for l in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = l.split('\t').collect();
        if f[0] == "final" {
            t.finals.push((
                f[1].to_owned(),
                f[2].to_owned(),
                f[3].to_owned(),
                unescape(f[4]),
            ));
        } else {
            t.runs.push((
                f[0].to_owned(),
                f[1].to_owned(),
                unescape(f[2]),
                f[3].to_owned(),
                f[4].to_owned(),
            ));
        }
    }
    Some(t)
}

/// Final hierarchies by cause (`final_cause`), measured: (equal, only
/// `f_final_transform`, `preferComplement` as well).
const FINAL_CAUSES: (usize, usize, usize) = (321, 173, 113);

#[test]
fn replay() {
    let tables: Vec<(Library, CorpusTable)> = [Library::Libcxx, Library::Libstdcxx]
        .into_iter()
        .filter_map(|l| read_table(l).map(|t| (l, t)))
        .collect();
    if tables.is_empty() {
        eprintln!("skipped: no structure_corpus table (tests/oracle/regen_corpus.sh)");
        return;
    }
    if let [(_, a), (_, b)] = &tables[..] {
        assert!(
            a.runs == b.runs,
            "the two reference builds captured different structuring runs"
        );
        assert!(
            a.finals == b.finals,
            "the two reference builds have different final hierarchies"
        );
    }
    let t = &tables[0].1;
    let mut differ = Vec::new();
    let (mut gotos, mut flips, mut rules) = (0usize, 0usize, 0usize);
    for (script, run, graph, ag, captured) in &t.runs {
        let g = GraphFile::parse(graph).unwrap();
        let (full, hier) = basilisk(&g);
        if hex(digest(full.as_bytes())) != *ag || hex(digest(hier.as_bytes())) != *captured {
            differ.push(format!("{script}.{run}"));
        }
        if let Ok(StructureDump::Ok(s)) = StructureDump::parse(&full) {
            gotos += s.gotos.len();
            flips += s.flips.len();
            rules += s.trace.len();
        }
    }
    let graphs: std::collections::HashMap<String, &String> = t
        .runs
        .iter()
        .map(|(s, r, g, _, _)| (format!("{s}.{r}"), g))
        .collect();
    let mut causes = (0usize, 0usize, 0usize);
    for (prefix, run, tables_text, fin) in &t.finals {
        let g = GraphFile::parse(graphs[&format!("{prefix}.{run}")]).unwrap();
        let ours = basilisk_final(&g, &read_tables(tables_text));
        match final_cause(&ours, fin) {
            Some("equal") => causes.0 += 1,
            Some("finaltransform") => causes.1 += 1,
            Some(_) => causes.2 += 1,
            None => differ.push(format!("{prefix} final")),
        }
    }
    eprintln!(
        "corpus replay ({} table(s)): {} structuring runs, {} final hierarchies, {} differ; {gotos} goto marks, {flips} flips, {rules} rule applications compared; finals: {} equal, {} differ only by f_final_transform, {} also by preferComplement",
        tables.len(),
        t.runs.len(),
        t.finals.len(),
        differ.len(),
        causes.0,
        causes.1,
        causes.2
    );
    assert!(differ.is_empty(), "{differ:?}");
    assert_eq!(causes, FINAL_CAUSES, "final causes moved");
}

/// The largest corpus graph, structured as the pipeline does (6.7).
#[test]
#[ignore = "benchmark"]
fn largest_corpus_graph() {
    let Some(rows) = read_table(Library::Libcxx).or_else(|| read_table(Library::Libstdcxx)) else {
        eprintln!("skipped: no corpus table");
        return;
    };
    let mut steps_ratio: f64 = 0.0;
    let mut largest: Option<(usize, String, GraphFile)> = None;
    for (script, run, graph, _, _) in rows.runs {
        let g = GraphFile::parse(&graph).unwrap();
        let (cfg, facts) = cfg_of(&g);
        let size = cfg.len() + cfg.edge_count();
        let options = StructureOptions {
            limits: Limits {
                max_steps: Some(u64::MAX / 2),
                ..Limits::default()
            },
            ..StructureOptions::default()
        };
        if let Ok(s) = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new()) {
            steps_ratio = steps_ratio.max(s.measure.steps as f64 / (size * size) as f64);
        }
        if largest.as_ref().is_none_or(|(n, _, _)| cfg.len() > *n) {
            largest = Some((cfg.len(), format!("{script}.{run}"), g));
        }
    }
    let (n, name, g) = largest.unwrap();
    let (cfg, facts) = cfg_of(&g);
    let mut best = Duration::MAX;
    let mut steps = 0;
    for _ in 0..20 {
        let t = Instant::now();
        let s = structure(
            &cfg,
            &facts,
            &StructureOptions::default(),
            &mut GhidraGotoSelector::new(),
        )
        .unwrap();
        best = best.min(t.elapsed());
        steps = s.measure.steps;
    }
    eprintln!(
        "bench corpus: largest graph {name}: {n} nodes {} edges, structure (as given) {:.3} ms, {steps} steps; worst steps/(n+e)^2 over the corpus {steps_ratio:.3}",
        cfg.edge_count(),
        best.as_secs_f64() * 1e3
    );
}
