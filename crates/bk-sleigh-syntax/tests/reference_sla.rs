//! Differential check of the syntax tree against Ghidra's own compiler.
//!
//! Ghidra does not dump its syntax tree, but its compiled `.sla` records
//! much of what the tree determines. For every shipped `.slaspec`, this test
//! runs the reference C++ `sleigh` compiler (`BASILISK_REFERENCE_DIR`,
//! default `../reference`, see `docs/features/reference-tools.md`) with
//! `-y`, which writes the `.sla` as XML, and compares it with a model built
//! from this crate's tree (`tests/reference/`):
//!
//! * constructors per table, in order, each at the same file and line
//!   (constructor boundaries, `with` table inheritance, source locations
//!   through includes and expansions);
//! * each constructor's print pieces and operands (display sections);
//! * the shape of every compound operand definition and context change
//!   (pattern-expression trees from real specifications), `globalset`
//!   counts, `unimpl`, `export`, named sections and labels;
//! * varnodes with their offsets, token and context fields, attached
//!   variables, names and values, user operations and address spaces.
//!
//! It skips, with a printed reason, when the Ghidra tree or the reference
//! compiler is absent. `BK_SLA_FILTER=<substring>` limits it to matching
//! spec paths.

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

mod common;
mod reference;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bk_sleigh_syntax::{FsLoader, parse_file};

/// The reference compiler, or `None` (with a printed reason) if absent.
fn reference_sleigh() -> Option<PathBuf> {
    let dir = std::env::var_os("BASILISK_REFERENCE_DIR").map_or_else(
        || common::workspace_root().join("../reference"),
        PathBuf::from,
    );
    let sleigh = dir.join("bin/sleigh");
    if sleigh.is_file() {
        Some(sleigh)
    } else {
        eprintln!(
            "SKIPPED: reference sleigh compiler not found at {} (set BASILISK_REFERENCE_DIR)",
            sleigh.display()
        );
        None
    }
}

#[derive(Default)]
struct Totals {
    specs: usize,
    constructors: usize,
    print_pieces: usize,
    context_ops: usize,
    operand_defs: usize,
    varnodes: usize,
    fields: usize,
    attached: usize,
}

/// Compiles `spec` with Ghidra's compiler into `out_dir` and returns the
/// XML text.
fn compile(sleigh: &Path, spec: &Path, out_dir: &Path) -> String {
    let stem = spec.file_stem().unwrap().to_string_lossy();
    let written = out_dir.join(format!("{stem}.sla"));
    let status = Command::new(sleigh)
        .arg("-y")
        .arg(spec)
        .arg(&written)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "sleigh failed on {}: {}",
        spec.display(),
        String::from_utf8_lossy(&status.stderr)
    );
    let text = std::fs::read_to_string(&written).unwrap();
    std::fs::remove_file(&written).unwrap();
    text
}

#[test]
fn trees_agree_with_ghidras_compiled_sla() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let Some(sleigh) = reference_sleigh() else {
        return;
    };
    let filter = std::env::var("BK_SLA_FILTER").ok();
    let specs: Vec<PathBuf> = common::slaspec_files(&ghidra)
        .into_iter()
        .filter(|p| {
            filter
                .as_ref()
                .is_none_or(|f| p.to_string_lossy().contains(f))
        })
        .collect();
    let defines = common::build_defines();
    let out_dir = tempfile::tempdir().unwrap();

    let started = Instant::now();
    let next = AtomicUsize::new(0);
    let totals = Mutex::new(Totals::default());
    let failures = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(spec) = specs.get(index) else { break };
                    let xml = compile(&sleigh, spec, out_dir.path());
                    let ghidra_model = reference::xml_side::model(&xml);
                    drop(xml);
                    let parsed = parse_file(spec, &defines, &mut FsLoader);
                    assert!(parsed.diagnostics.is_empty(), "{}", spec.display());
                    let ours = reference::ast_side::model(&parsed);
                    let differences = reference::differences(&ours, &ghidra_model);

                    let mut t = totals.lock().unwrap();
                    t.specs += 1;
                    for ctors in ghidra_model.tables.values() {
                        t.constructors += ctors.len();
                        for c in ctors {
                            t.print_pieces += c.display.len();
                            t.context_ops += c.context_ops.len();
                            t.operand_defs += c.operand_defs.len();
                        }
                    }
                    t.varnodes += ghidra_model.varnodes.len();
                    t.fields += ghidra_model.token_fields.len() + ghidra_model.context_fields.len();
                    t.attached += ghidra_model.attached.len();
                    drop(t);
                    if !differences.is_empty() {
                        let shown: Vec<&String> = differences.iter().take(8).collect();
                        failures.lock().unwrap().push(format!(
                            "{}: {} differences\n  {}",
                            spec.display(),
                            differences.len(),
                            shown
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join("\n  ")
                        ));
                    }
                }
            });
        }
    });
    let t = totals.into_inner().unwrap();
    let failures = failures.into_inner().unwrap();
    eprintln!(
        "reference: {} specs compared with Ghidra's compiler in {:.1} s: {} constructors \
         (table, file, line), {} print pieces, {} context changes, {} compound operand \
         definitions, {} varnodes, {} fields, {} attached fields",
        t.specs,
        started.elapsed().as_secs_f64(),
        t.constructors,
        t.print_pieces,
        t.context_ops,
        t.operand_defs,
        t.varnodes,
        t.fields,
        t.attached
    );
    assert!(
        failures.is_empty(),
        "{} of {} specs differ from Ghidra:\n{}",
        failures.len(),
        t.specs,
        failures.join("\n")
    );
    if filter.is_none() {
        assert_eq!(t.specs, 150);
    }
}
