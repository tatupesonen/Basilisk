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
//! The `structure blocks` cross-check (`docs/features/decomp-cfg.md` 6.2):
//! generated graphs in Ghidra's block XML, structured by the reference
//! console's own command, compared byte for byte with Basilisk's encoder.
//!
//! `replay` (S) regenerates each graph from its class and seed and compares
//! with the checked-in table. `regen` (L, ignored) runs the reference twice
//! and writes the table; `tests/oracle/regen_xml.sh` drives it on either
//! reference build.

mod support {
    pub(crate) mod blocks;
    pub(crate) mod graphgen;
    pub(crate) mod table;
}

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use support::graphgen::{Class, generate};
use support::table::{data_dir, escape, read_gz, unescape, write_gz};

const PER_CLASS: u64 = 1000;
const MAX_NODES: usize = 40;
const TABLE: &str = "structure_blocks.txt.gz";
/// Basilisk's message for Ghidra's endless `TraceDAG` (a `hang` row).
const TRACE_CYCLE: &str = "goto trace does not terminate (cycle in the loop DAG)";
/// How long the reference gets on such a graph before it counts as hanging.
const HANG_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER: &str = "# bk-decomp-cfg structure-blocks table v1: class seed ok|err output (generated graphs, max 40 nodes)";

fn cases() -> impl Iterator<Item = (Class, u64)> {
    Class::ALL
        .into_iter()
        .flat_map(|c| (0..PER_CLASS).map(move |s| (c, s)))
}

/// Runs the reference console once over every case and returns the table.
fn regen_rows(reference: &bk_testkit::ReferenceDir, ghidra: &bk_testkit::GhidraDir) -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bk-cfg-xml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let elseif = ghidra.data_tests_dir().join("elseif.xml");
    let load = format!("load test file {}", elseif.display());
    let mut commands = vec![load.clone()];
    let mut files = Vec::new();
    let mut hangs = std::collections::BTreeMap::new();
    for (class, seed) in cases() {
        let g = generate(class, seed, MAX_NODES, false);
        let input = dir.join(format!("{}{seed}.xml", class.name()));
        let output = dir.join(format!("{}{seed}.out", class.name()));
        std::fs::write(&input, g.to_xml()).unwrap();
        let cmd = format!("structure blocks {} {}", input.display(), output.display());
        // A graph on which Basilisk finds Ghidra's endless trace would stop
        // the whole session: it runs alone, and must time out.
        if support::blocks::structure_blocks(&g.to_xml()) == Err(TRACE_CYCLE.to_owned()) {
            let alone = reference
                .decomp()
                .timeout(HANG_TIMEOUT)
                .run_script([load.as_str(), cmd.as_str()]);
            let row = match alone {
                Err(bk_testkit::ToolError::Timeout { .. }) => "hang\t".to_owned(),
                Ok(_) if output.is_file() => {
                    format!("ok\t{}", escape(&std::fs::read_to_string(&output).unwrap()))
                }
                other => panic!(
                    "{} {seed}: expected the reference to hang: {other:?}",
                    class.name()
                ),
            };
            hangs.insert((class.name(), seed), row);
            continue;
        }
        commands.push(cmd.clone());
        files.push((class, seed, cmd, output));
    }
    let transcript = reference
        .decomp()
        .timeout(Duration::from_mins(10))
        .run_script(&commands)
        .unwrap();
    let mut rows = String::from(HEADER);
    rows.push('\n');
    let mut body = std::collections::BTreeMap::new();
    for (class, seed, cmd, output) in files {
        let printed: String = transcript.outputs_of(&cmd).collect();
        let printed = printed.trim();
        let field = if printed.is_empty() {
            format!("ok\t{}", escape(&std::fs::read_to_string(&output).unwrap()))
        } else {
            format!("err\t{}", escape(printed))
        };
        body.insert((class.name(), seed), field);
    }
    body.extend(hangs);
    for (class, seed) in cases() {
        let field = &body[&(class.name(), seed)];
        let _ = writeln!(rows, "{}\t{seed}\t{field}", class.name());
    }
    let _ = std::fs::remove_dir_all(&dir);
    rows
}

#[test]
#[ignore = "runs the reference console; tests/oracle/regen_xml.sh"]
fn regen() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Decomp) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let first = regen_rows(&reference, &ghidra);
    let second = regen_rows(&reference, &ghidra);
    assert!(
        first == second,
        "the reference console gave different outputs in two runs"
    );
    let out =
        std::env::var_os("BK_CFG_TABLE_OUT").map_or_else(|| data_dir().join(TABLE), PathBuf::from);
    write_gz(&out, &first);
    eprintln!(
        "wrote {} ({} rows)",
        out.display(),
        first.lines().count() - 1
    );
}

#[test]
fn replay() {
    let path = data_dir().join(TABLE);
    let text = read_gz(&path).unwrap_or_else(|| panic!("missing table {}", path.display()));
    let mut rows = 0;
    let mut errors = 0;
    let mut hangs = 0;
    let mut mismatches = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let mut f = line.splitn(4, '\t');
        let class = Class::from_name(f.next().unwrap()).unwrap();
        let seed: u64 = f.next().unwrap().parse().unwrap();
        let status = f.next().unwrap();
        let expected = unescape(f.next().unwrap_or(""));
        let g = generate(class, seed, MAX_NODES, false);
        let ours = support::blocks::structure_blocks(&g.to_xml());
        let theirs = match status {
            "ok" => Ok(expected),
            "hang" => {
                hangs += 1;
                Err(TRACE_CYCLE.to_owned())
            }
            _ => {
                errors += 1;
                Err(expected)
            }
        };
        if ours != theirs {
            mismatches.push(format!("{} {seed}", class.name()));
        }
        rows += 1;
    }
    eprintln!(
        "structure blocks replay: {rows} graphs, {errors} reference errors, {hangs} reference hangs, {} differ",
        mismatches.len()
    );
    assert_eq!(rows, cases().count(), "table does not cover every case");
    assert!(mismatches.is_empty(), "differing graphs: {mismatches:?}");
}
