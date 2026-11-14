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
//! The full oracle on generated graphs (`docs/features/decomp-cfg.md` 6.3.1,
//! 6.3.3, 6.4): every graph through D00's `bk cfg analyze` and `bk
//! structure` (modes `bare trace`, `bare finish`, and `asgiven` for the
//! function-like ones), compared with Basilisk's dumps in the same formats.
//!
//! The table stores per graph and mode the dump's header line and a 128-bit
//! hash of the whole dump (about 12,000 graphs times four dumps would not
//! fit the repository as text). `replay` (S) needs the table; `regen` (L,
//! ignored) needs the reference build's extended console `decomp_bk`. Both
//! skip with a printed reason until D00 has delivered them.

mod support {
    pub(crate) mod dump;
    pub(crate) mod graphgen;
    pub(crate) mod table;
}

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bk_decomp_cfg::{
    Analyse, BlockFacts, Cfg, GhidraGotoSelector, Record, StructureOptions, finish, structure,
};
use support::dump::{asgiven, cfg_dump, graph_file, struct_dump};
use support::graphgen::{Class, GenGraph, generate};
use support::table::{data_dir, escape, read_gz, unescape, write_gz};
use wait_timeout::ChildExt as _;

const TABLE: &str = "cfg_oracle.txt.gz";
const MAX_NODES: usize = 64;
const HEADER: &str = "# bk-decomp-cfg oracle table v1: class seed mode header-line fnv128-of-dump";

fn per_class(c: Class) -> u64 {
    match c {
        Class::Func | Class::Arb => 4000,
        Class::Red | Class::Irr => 2000,
    }
}

fn cases() -> impl Iterator<Item = (Class, u64)> {
    Class::ALL
        .into_iter()
        .flat_map(|c| (0..per_class(c)).map(move |s| (c, s)))
}

/// Two FNV-1a hashes with different offsets: a 128-bit fingerprint.
fn fnv128(text: &str) -> String {
    let mut a: u64 = 0xcbf2_9ce4_8422_2325;
    let mut b: u64 = 0x6c62_272e_07bb_0142;
    for &byte in text.as_bytes() {
        a = (a ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        b = (b ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{a:016x}{b:016x}")
}

/// Basilisk's four dumps of one graph: `cfg`, `bare-trace`, `bare-finish`
/// and (function-like graphs) `asgiven`.
fn basilisk_dumps(class: Class, g: &GenGraph) -> Vec<(&'static str, String)> {
    let cfg = g.to_cfg();
    let facts = g.block_facts();
    let mut out = vec![("cfg", cfg_dump(&cfg, &facts))];
    let bare = |record| StructureOptions {
        analyse: Analyse::Recompute,
        record,
        ..StructureOptions::default()
    };
    out.push((
        "bare-trace",
        struct_dump(&structure(
            &cfg,
            &facts,
            &bare(Record::Trace),
            &mut GhidraGotoSelector::new(),
        )),
    ));
    let mut fin = structure(
        &cfg,
        &facts,
        &bare(Record::None),
        &mut GhidraGotoSelector::new(),
    );
    if let Ok(s) = &mut fin {
        finish(&mut s.hierarchy, &facts, None);
    }
    out.push(("bare-finish", struct_dump(&fin)));
    if class == Class::Func {
        let mut analysed = cfg.clone();
        let ok = analysed
            .structure_loops()
            .and_then(|roots| analysed.forward_dominators(&roots));
        if ok.is_ok() {
            let (given, gfacts, _) = asgiven(&analysed, &facts);
            out.push((
                "asgiven",
                struct_dump(&structure(
                    &given,
                    &gfacts,
                    &StructureOptions::default(),
                    &mut GhidraGotoSelector::new(),
                )),
            ));
        }
    }
    out
}

fn row_of(dump: &str) -> String {
    let header = dump.lines().next().unwrap_or("");
    format!("{}\t{}", escape(header), fnv128(dump))
}

#[test]
fn replay() {
    let path = data_dir().join(TABLE);
    let Some(text) = read_gz(&path) else {
        eprintln!(
            "skipped: {} not generated yet (needs D00's decomp_bk; tests/oracle/regen.sh)",
            path.display()
        );
        return;
    };
    let mut expected = std::collections::HashMap::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.splitn(5, '\t').collect();
        expected.insert(
            (
                f[0].to_owned(),
                f[1].parse::<u64>().unwrap(),
                f[2].to_owned(),
            ),
            (unescape(f[3]), f[4].to_owned()),
        );
    }
    let (mut same, mut differ) = (0, Vec::new());
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, true);
        for (mode, dump) in basilisk_dumps(class, &g) {
            let Some((header, hash)) =
                expected.get(&(class.name().to_owned(), seed, mode.to_owned()))
            else {
                continue;
            };
            let ours_header = dump.lines().next().unwrap_or("");
            if fnv128(&dump) == *hash
                || (header == "hang" && ours_header.contains("does not terminate"))
            {
                same += 1;
            } else {
                differ.push(format!(
                    "{} {seed} {mode}: ours {ours_header:?}, Ghidra {header:?}",
                    class.name()
                ));
            }
        }
    }
    eprintln!("oracle replay: {same} dumps equal, {} differ", differ.len());
    assert!(differ.is_empty(), "{:#?}", &differ[..differ.len().min(20)]);
}

/// Runs `decomp_bk` on a script with a time limit; `None` on timeout.
fn run_console(
    console: &Path,
    sleighhome: &Path,
    script: &Path,
    limit: Duration,
) -> Option<String> {
    let out_path = script.with_extension("stdout");
    let mut child = std::process::Command::new(console)
        .arg("-i")
        .arg(script)
        .env("SLEIGHHOME", sleighhome)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(&out_path).unwrap())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    if child.wait_timeout(limit).unwrap().is_some() {
        return Some(std::fs::read_to_string(&out_path).unwrap_or_default());
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
#[ignore = "runs the reference console decomp_bk (D00); tests/oracle/regen.sh"]
fn regen() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let console = reference.root().join("bin").join("decomp_bk");
    if !console.is_file() {
        eprintln!("skipped: {} not built (D00)", console.display());
        return;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bk-cfg-oracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let load = format!(
        "load test file {}",
        ghidra.data_tests_dir().join("elseif.xml").display()
    );
    let mut script = vec![load.clone()];
    let mut jobs = Vec::new();
    let mut rows = std::collections::BTreeMap::new();
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, true);
        let ours = basilisk_dumps(class, &g);
        let base = dir.join(format!("{}{seed}", class.name()));
        let gf = base.with_extension("graph");
        std::fs::write(&gf, graph_file(&g)).unwrap();
        let mut cmds = vec![(
            "cfg",
            format!("bk cfg analyze {} {}.cfg", gf.display(), base.display()),
        )];
        cmds.push((
            "bare-trace",
            format!(
                "bk structure {} {}.bt bare trace",
                gf.display(),
                base.display()
            ),
        ));
        cmds.push((
            "bare-finish",
            format!(
                "bk structure {} {}.bf bare finish",
                gf.display(),
                base.display()
            ),
        ));
        if class == Class::Func {
            let cfg = g.to_cfg();
            let mut analysed = cfg.clone();
            if let Ok(roots) = analysed.structure_loops()
                && analysed.forward_dominators(&roots).is_ok()
            {
                let (_, _, text) = asgiven(&analysed, &g.block_facts());
                let ag = base.with_extension("asgiven.graph");
                std::fs::write(&ag, text).unwrap();
                cmds.push((
                    "asgiven",
                    format!(
                        "bk structure {} {}.ag asgiven",
                        ag.display(),
                        base.display()
                    ),
                ));
            }
        }
        for (mode, cmd) in cmds {
            let out_file = PathBuf::from(
                cmd.split(' ')
                    .nth(if mode == "cfg" { 4 } else { 3 })
                    .unwrap(),
            );
            let hang = ours.iter().any(|(m, d)| {
                *m == mode
                    && d.lines()
                        .next()
                        .unwrap_or("")
                        .contains("does not terminate")
            });
            if hang {
                let s = base.with_extension(format!("{mode}.script"));
                std::fs::write(&s, format!("{load}\n{cmd}\nquit\n")).unwrap();
                let r = run_console(&console, reference.root(), &s, Duration::from_secs(10));
                let row = match r {
                    None => "hang\t-".to_owned(),
                    Some(_) => row_of(&std::fs::read_to_string(&out_file).unwrap_or_default()),
                };
                rows.insert((class.name(), seed, mode), row);
            } else {
                script.push(cmd);
                jobs.push((class.name(), seed, mode, out_file));
            }
        }
    }
    script.push("quit".to_owned());
    let s = dir.join("all.script");
    std::fs::write(&s, script.join("\n") + "\n").unwrap();
    run_console(&console, reference.root(), &s, Duration::from_mins(30))
        .expect("decomp_bk timed out");
    for (class, seed, mode, out_file) in jobs {
        let dump = std::fs::read_to_string(&out_file)
            .unwrap_or_else(|_| panic!("no output {}", out_file.display()));
        rows.insert((class, seed, mode), row_of(&dump));
    }
    let mut text = String::from(HEADER);
    text.push('\n');
    for ((class, seed, mode), row) in &rows {
        let _ = writeln!(text, "{class}\t{seed}\t{mode}\t{row}");
    }
    let out =
        std::env::var_os("BK_CFG_TABLE_OUT").map_or_else(|| data_dir().join(TABLE), PathBuf::from);
    write_gz(&out, &text);
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("wrote {} ({} rows)", out.display(), rows.len());
}

#[test]
fn basilisk_dumps_are_deterministic() {
    for (class, seed) in [
        (Class::Func, 3),
        (Class::Arb, 7),
        (Class::Red, 11),
        (Class::Irr, 13),
    ] {
        let g = generate(class, seed, MAX_NODES, true);
        assert_eq!(basilisk_dumps(class, &g), basilisk_dumps(class, &g));
    }
    let _ = Cfg::new();
    let _ = BlockFacts::neutral(0);
}

/// `orderBlocks` ties (`docs/features/decomp-cfg.md` 4.9, 10 item 1): how
/// many finished runs of the oracle's graphs have two or more top-level
/// nodes ending in `RETURN`, by top-level list length — the rows where the
/// C++ libraries may order differently (libc++ for four or more elements,
/// libstdc++ for 17 or more). The counts are printed for the report and
/// pinned so that a generator change shows.
#[test]
fn return_ties() {
    let (mut runs, mut tied, mut tied4, mut tied17) = (0, 0, 0, 0);
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, true);
        let cfg = g.to_cfg();
        let facts = g.block_facts();
        let options = StructureOptions {
            analyse: Analyse::Recompute,
            ..StructureOptions::default()
        };
        let Ok(s) = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new()) else {
            continue;
        };
        runs += 1;
        let h = &s.hierarchy;
        let top = h.top_level();
        let returns = top
            .iter()
            .filter(|&&n| h.front_leaf(n).is_some() && ends_in_return(h, n, &facts))
            .count();
        if top.len() > 1 && returns >= 2 {
            tied += 1;
            if top.len() >= 4 {
                tied4 += 1;
            }
            if top.len() >= 17 {
                tied17 += 1;
            }
        }
    }
    eprintln!(
        "orderBlocks ties: {runs} finished runs, {tied} with two or more RETURN nodes on a top level of 2+ nodes, {tied4} of 4+, {tied17} of 17+"
    );
    assert_eq!(
        (tied, tied4, tied17),
        (TIES.0, TIES.1, TIES.2),
        "counts moved; update TIES after checking"
    );
}

/// (ties, ties on 4+ nodes, ties on 17+ nodes), measured.
const TIES: (usize, usize, usize) = (120, 119, 25);

/// `lastOp()` is a `RETURN`: the leaf the hierarchy delegates to.
fn ends_in_return(
    h: &bk_decomp_cfg::Hierarchy,
    n: bk_decomp_cfg::NodeId,
    facts: &BlockFacts,
) -> bool {
    use bk_decomp_cfg::Kind;
    let mut x = n;
    loop {
        let c = h.components(x);
        x = match h.kind(x) {
            Some(Kind::Copy) => return facts.get(x.index()).ends_in_return,
            Some(Kind::Goto | Kind::MultiGoto | Kind::IfGoto) => c[0],
            Some(Kind::List) => *c.last().unwrap(),
            Some(Kind::Condition) => c[1],
            Some(Kind::IfNoExit) => c[2],
            _ => return false,
        };
    }
}
