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

use bk_sleigh_syntax::{Defines, FsLoader, parse_file};

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

/// Small hand-written specifications on which the two Ghidra front ends,
/// or this crate and Ghidra's C++ front end, could disagree. Each case
/// records whether this crate accepts it and whether Ghidra's C++
/// compiler does; the test runs both and checks the record. Where they
/// differ, this crate follows Ghidra's Java front end (the authority,
/// which cannot be run here), as the comment on each case says.
#[test]
fn edge_cases_against_ghidras_cpp_compiler() {
    let Some(sleigh) = reference_sleigh() else {
        return;
    };
    let base = "define endian=little;\n\
                define space ram type=ram_space size=4 default;\n\
                define space register type=register_space size=4;\n\
                define register offset=0 size=4 [ r0 r1 r2 ];\n\
                define token instr(8) opc=(4,7) reg=(0,3);\n\
                :Z reg is opc=15 & reg { r0 = 1; }\n";
    // (name, text, accepted here, accepted by the C++ compiler)
    let cases: [(&str, &str, bool, bool); 15] = [
        ("plain", ":A reg is opc=0 & reg { r0 = 1; }", true, true),
        // A prefix without digits is `0` then a name in both front ends'
        // longest-match lexers, a syntax error here.
        (
            "hex-without-digits",
            ":A reg is opc=0 & reg { r0 = 0xg; }",
            false,
            false,
        ),
        // Display: a lone `_` and `0n12` are not print pieces in Java's
        // DisplayParser.g; C++ makes them operands, which are undefined.
        (
            "display-underscore",
            ":A _ reg is opc=0 & reg { r0 = 1; }",
            false,
            false,
        ),
        (
            "display-0n",
            ":A 0n12 reg is opc=0 & reg { r0 = 1; }",
            false,
            false,
        ),
        (
            "display-with",
            ":A with reg is opc=0 & reg { r0 = 1; }",
            false,
            false,
        ),
        // Java prints `0x10` literally; C++ splits it into `0` and the
        // operand `x10`.
        (
            "display-hex",
            ":A 0x10 reg is opc=0 & reg { r0 = 1; }",
            true,
            false,
        ),
        (
            "display-leading-space",
            ":  A reg is opc=0 & reg { r0 = 1; }",
            true,
            true,
        ),
        // `0n` decimal operands exist only in Java's SemanticLexer.g.
        (
            "semantic-0n",
            ":A reg is opc=0 & reg { r0 = 0n12; }",
            true,
            false,
        ),
        // Nested unary operators: C++ accepts them, Java does not; accepted.
        (
            "nested-unary",
            ":A reg is opc=0 & reg { r0 = - - r1; }",
            true,
            true,
        ),
        // Comparisons are left-associative in Java, non-associative in C++.
        (
            "comparison-chain",
            ":A reg is opc=0 & reg { r0 = zext(r1 < r2 < r0); }",
            true,
            false,
        ),
        // Java strings accept backslash escapes; C++ strings do not.
        (
            "string-escape",
            ":\"a\\\"b\" reg is opc=1 & reg { r0 = 1; }",
            true,
            false,
        ),
        // `!` in `@if` exists only in Java's BooleanExpression.g, and only
        // before a parenthesised expression.
        (
            "if-not-paren",
            "@if !(defined(X))\n:A reg is opc=0 & reg { r0 = 1; }\n@endif",
            true,
            false,
        ),
        (
            "if-not-bare",
            "@if !defined(X)\n:A reg is opc=0 & reg { r0 = 1; }\n@endif",
            false,
            false,
        ),
        // An `@if` left open at the end of a file is closed silently.
        (
            "open-conditional",
            "@ifdef X\n:A reg is opc=0 & reg { r0 = 1; }",
            true,
            true,
        ),
        // Directives start in column one.
        (
            "indented-directive",
            " @define Y 1\n:A reg is opc=0 & reg { r0 = 1; }",
            false,
            false,
        ),
    ];
    let dir = tempfile::tempdir().unwrap();
    let mut wrong = Vec::new();
    for (name, text, ours_expected, cpp_expected) in cases {
        let source = format!("{base}{text}\n");
        let path = dir.path().join(format!("{name}.slaspec"));
        std::fs::write(&path, &source).unwrap();
        let ours = parse_file(&path, &Defines::new(), &mut FsLoader)
            .diagnostics
            .is_empty();
        let out = Command::new(&sleigh)
            .arg(&path)
            .arg(dir.path().join(format!("{name}.sla")))
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&out.stderr).into_owned()
            + &String::from_utf8_lossy(&out.stdout);
        let cpp = !log.contains("ERROR");
        if (ours, cpp) != (ours_expected, cpp_expected) {
            wrong.push(format!(
                "{name}: here {ours} (expected {ours_expected}), C++ {cpp} (expected {cpp_expected}): {log}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
