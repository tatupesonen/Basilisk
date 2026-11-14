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
//! structure` (modes `bare trace`, `bare finish`, and `asgiven trace` for
//! the function-like ones, on a graph file written from the analysis),
//! compared with Basilisk's dumps written by `bk-testkit`'s writers.
//!
//! One table per reference build (`cfg_oracle.libcxx.txt.gz`,
//! `cfg_oracle.libstdcxx.txt.gz`) stores per graph and mode the dump's
//! header line and a 64-bit FNV-1a digest of the whole dump (about 12,000
//! graphs times four dumps would not fit the repository as text). `replay`
//! (S) requires every row to equal Basilisk's dump and the two builds'
//! tables to agree, or each disagreement to be recognised by cause
//! (ADR-040). `regen` (L, ignored) runs `decomp_bk`; `tests/oracle/regen.sh`
//! drives it twice per build.

mod support {
    pub(crate) mod graphgen;
    pub(crate) mod oracle;
    pub(crate) mod table;
}

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use bk_decomp_cfg::{
    Analyse, BlockFacts, GhidraGotoSelector, Kind, Record, StructureOptions, finish, structure,
};
use bk_testkit::oracle::host::{Library, digest};
use support::graphgen::{Class, GenGraph, generate};
use support::oracle::{asgiven_of, cfg_dump, cfg_of, graph_of, struct_dump};
use support::table::{data_dir, escape, read_gz, unescape, write_gz};

const MAX_NODES: usize = 64;
const HEADER: &str = "# bk-decomp-cfg oracle table v2: class seed mode header-line fnv64-of-dump (bkcfg 1, bkstruct 1)";
/// The header Basilisk's dump has where Ghidra's console never finishes.
const HANG: &str = "hang";

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

fn table_path(lib: Library) -> PathBuf {
    data_dir().join(format!("cfg_oracle.{}.txt.gz", lib.name()))
}

/// The analysed graph of a function-like case in `asgiven` form, if the
/// analyses succeed.
fn asgiven_file(g: &GenGraph) -> Option<bk_testkit::oracle::GraphFile> {
    let file = graph_of(g);
    let (cfg, facts) = cfg_of(&file);
    let mut analysed = cfg;
    let roots = analysed.structure_loops().ok()?;
    analysed.forward_dominators(&roots).ok()?;
    Some(asgiven_of(&analysed, &facts))
}

/// Basilisk's dumps of one case, by mode.
fn basilisk_dumps(class: Class, g: &GenGraph) -> Vec<(&'static str, String)> {
    let file = graph_of(g);
    let (cfg, facts) = cfg_of(&file);
    let mut out = vec![("cfg", cfg_dump(&file).write())];
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
        ))
        .write(),
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
    out.push(("bare-finish", struct_dump(&fin).write()));
    if class == Class::Func
        && let Some(given) = asgiven_file(g)
    {
        let (gcfg, gfacts) = cfg_of(&given);
        let options = StructureOptions {
            record: Record::Trace,
            ..StructureOptions::default()
        };
        out.push((
            "asgiven-trace",
            struct_dump(&structure(
                &gcfg,
                &gfacts,
                &options,
                &mut GhidraGotoSelector::new(),
            ))
            .write(),
        ));
    }
    out
}

fn header_of(dump: &str) -> &str {
    dump.lines().next().unwrap_or("")
}

fn row_of(dump: &str) -> String {
    format!(
        "{}\t{:016x}",
        escape(header_of(dump)),
        digest(dump.as_bytes())
    )
}

type Table = BTreeMap<(String, u64, String), (String, String)>;

fn read_table(lib: Library) -> Option<Table> {
    let text = read_gz(&table_path(lib))?;
    let mut t = Table::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.splitn(5, '\t').collect();
        t.insert(
            (f[0].to_owned(), f[1].parse().unwrap(), f[2].to_owned()),
            (unescape(f[3]), f[4].to_owned()),
        );
    }
    Some(t)
}

/// Whether Basilisk's dump matches a table row.
fn matches(dump: &str, row: &(String, String)) -> bool {
    if row.0 == HANG {
        return header_of(dump).contains("does not terminate");
    }
    row.1 == format!("{:016x}", digest(dump.as_bytes()))
}

/// Why the two builds' rows differ, if a known cause explains it: the
/// top level of the finished hierarchy has two or more nodes ending in
/// `RETURN`, which `compareFinalOrder` calls equal, so `std::sort` leaves
/// their order to the library (`decomp-cfg.md` 4.9, ADR-040).
fn return_tie(class: Class, seed: u64, mode: &str) -> bool {
    if mode != "bare-finish" {
        return false;
    }
    let g = generate(class, seed, MAX_NODES, true);
    let file = graph_of(&g);
    let (cfg, facts) = cfg_of(&file);
    let options = StructureOptions {
        analyse: Analyse::Recompute,
        ..StructureOptions::default()
    };
    let Ok(s) = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new()) else {
        return false;
    };
    let h = &s.hierarchy;
    h.top_level().len() >= 4
        && h.top_level()
            .iter()
            .filter(|&&n| ends_in_return(h, n, &facts))
            .count()
            >= 2
}

/// Rows where a build's `orderBlocks` breaks a RETURN tie differently from
/// Basilisk's stable sort (ADR-040), per library: pinned, measured.
const RETURN_TIE_ROWS: [(Library, usize); 2] = [
    (Library::Libcxx, LIBCXX_TIES),
    (Library::Libstdcxx, LIBSTDCXX_TIES),
];
const LIBCXX_TIES: usize = 1;
const LIBSTDCXX_TIES: usize = 15;

#[test]
fn replay() {
    let tables: Vec<(Library, Table)> = [Library::Libcxx, Library::Libstdcxx]
        .into_iter()
        .filter_map(|lib| read_table(lib).map(|t| (lib, t)))
        .collect();
    if tables.is_empty() {
        eprintln!("skipped: no cfg_oracle table (tests/oracle/regen.sh)");
        return;
    }
    let mut equal = vec![0usize; tables.len()];
    let mut ties = vec![0usize; tables.len()];
    let mut builds_differ = 0usize;
    let mut differ = Vec::new();
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, true);
        for (mode, dump) in basilisk_dumps(class, &g) {
            let key = (class.name().to_owned(), seed, mode.to_owned());
            let rows: Vec<&(String, String)> = tables.iter().map(|(_, t)| &t[&key]).collect();
            if rows.windows(2).any(|w| w[0] != w[1]) {
                builds_differ += 1;
            }
            for (i, row) in rows.iter().enumerate() {
                if matches(&dump, row) {
                    equal[i] += 1;
                } else if return_tie(class, seed, mode) {
                    ties[i] += 1;
                } else {
                    differ.push(format!(
                        "{} {} {seed} {mode}: ours {:?}, Ghidra {:?}",
                        tables[i].0.name(),
                        class.name(),
                        header_of(&dump),
                        row.0
                    ));
                }
            }
        }
    }
    for (i, (lib, _)) in tables.iter().enumerate() {
        eprintln!(
            "oracle replay {}: {} dumps equal, {} recognised as orderBlocks RETURN ties",
            lib.name(),
            equal[i],
            ties[i]
        );
        let pinned = RETURN_TIE_ROWS
            .iter()
            .find(|(l, _)| l == lib)
            .map_or(0, |(_, n)| *n);
        assert_eq!(ties[i], pinned, "{}: tie count moved", lib.name());
    }
    eprintln!(
        "rows where the two builds differ: {builds_differ}; unexplained: {}",
        differ.len()
    );
    assert!(differ.is_empty(), "{:#?}", &differ[..differ.len().min(20)]);
}

#[test]
#[ignore = "runs the reference console decomp_bk (D00); tests/oracle/regen.sh"]
fn regen() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let lib = Library::of_reference(&reference).expect("reference STAMP names its host");
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
    let mut rows = BTreeMap::new();
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, true);
        let ours = basilisk_dumps(class, &g);
        let base = format!("{}{seed}", class.name());
        std::fs::write(dir.join(format!("{base}.bkg")), graph_of(&g).write()).unwrap();
        let mut cmds = vec![
            (
                "cfg",
                format!("bk cfg analyze {base}.bkg {base}.cfg"),
                format!("{base}.cfg"),
            ),
            (
                "bare-trace",
                format!("bk structure {base}.bkg {base}.bt bare trace"),
                format!("{base}.bt"),
            ),
            (
                "bare-finish",
                format!("bk structure {base}.bkg {base}.bf bare finish"),
                format!("{base}.bf"),
            ),
        ];
        if class == Class::Func
            && let Some(given) = asgiven_file(&g)
        {
            std::fs::write(dir.join(format!("{base}.ag.bkg")), given.write()).unwrap();
            cmds.push((
                "asgiven-trace",
                format!("bk structure {base}.ag.bkg {base}.ag asgiven trace"),
                format!("{base}.ag"),
            ));
        }
        for (mode, cmd, out) in cmds {
            let hang = ours
                .iter()
                .any(|(m, d)| *m == mode && header_of(d).contains("does not terminate"));
            if hang {
                let alone = reference
                    .decomp_bk()
                    .current_dir(&dir)
                    .timeout(Duration::from_secs(10))
                    .run_script([load.as_str(), cmd.as_str()]);
                let row = match alone {
                    Err(bk_testkit::ToolError::Timeout { .. }) => format!("{HANG}\t-"),
                    _ => row_of(&std::fs::read_to_string(dir.join(&out)).unwrap_or_default()),
                };
                rows.insert((class.name(), seed, mode), row);
            } else {
                script.push(cmd);
                jobs.push((class.name(), seed, mode, out));
            }
        }
    }
    reference
        .decomp_bk()
        .current_dir(&dir)
        .timeout(Duration::from_mins(30))
        .run_script(&script)
        .expect("decomp_bk session");
    let mut cfg_mismatch = Vec::new();
    for (class, seed, mode, out) in jobs {
        let dump =
            std::fs::read_to_string(dir.join(&out)).unwrap_or_else(|_| panic!("no output {out}"));
        // The asgiven input was written from Basilisk's analysis: it is
        // Ghidra's only if the two analyses agree.
        if mode == "cfg" && class == "func" {
            let g = generate(Class::Func, seed, MAX_NODES, true);
            if cfg_dump(&graph_of(&g)).write() != dump {
                cfg_mismatch.push(seed);
            }
        }
        rows.insert((class, seed, mode), row_of(&dump));
    }
    assert!(
        cfg_mismatch.is_empty(),
        "analysis differs (asgiven input not Ghidra's) for func {cfg_mismatch:?}"
    );
    let mut text = String::from(HEADER);
    text.push('\n');
    for ((class, seed, mode), row) in &rows {
        let _ = writeln!(text, "{class}\t{seed}\t{mode}\t{row}");
    }
    let out = match std::env::var("BK_CFG_TABLE_OUT") {
        Ok(dir) if !dir.is_empty() => {
            PathBuf::from(dir).join(format!("cfg_oracle.{}.txt.gz", lib.name()))
        }
        _ => table_path(lib),
    };
    write_gz(&out, &text);
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "wrote {} ({} rows, {})",
        out.display(),
        rows.len(),
        lib.name()
    );
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
        let a = basilisk_dumps(class, &g);
        assert_eq!(a, basilisk_dumps(class, &g));
        // Every dump is accepted by bk-testkit's readers, and written back
        // byte for byte.
        for (mode, d) in &a {
            if *mode == "cfg" {
                assert_eq!(bk_testkit::oracle::CfgDump::parse(d).unwrap().write(), *d);
            } else {
                assert_eq!(
                    bk_testkit::oracle::StructureDump::parse(d).unwrap().write(),
                    *d
                );
            }
        }
    }
}

/// `orderBlocks` ties (`docs/features/decomp-cfg.md` 4.9, 10 item 1): how
/// many finished runs of the oracle's graphs have two or more top-level
/// nodes ending in `RETURN`, by top-level list length — the rows where the
/// C++ libraries may order differently (libc++ for four or more elements,
/// libstdc++ for 17 or more). Pinned so that a generator change shows.
#[test]
fn return_ties() {
    let (mut runs, mut tied, mut tied4, mut tied17) = (0, 0, 0, 0);
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, true);
        let (cfg, facts) = cfg_of(&graph_of(&g));
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
            .filter(|&&n| ends_in_return(h, n, &facts))
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
        TIES,
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
