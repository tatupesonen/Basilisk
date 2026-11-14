//! Spec 6.2: for every shipped specification, the elaboration equals
//! Ghidra's compiled `.sla` in the canonical form (`bk_sleigh_compiler::canon`).

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

use std::collections::BTreeMap;
use std::sync::Mutex;

use bk_sla::{Limits, Sla};
use bk_sleigh_compiler::canon::{self, category};
use bk_sleigh_compiler::{Options, elaborate};

/// The result of comparing one specification.
struct Report {
    name: String,
    differences: Vec<String>,
    total: usize,
    /// Entries compared and differing, per category.
    categories: BTreeMap<&'static str, (usize, usize)>,
}

fn compare(reference: &bk_testkit::ReferenceDir, spec: &common::Spec) -> Report {
    let name = format!("{}/{}", spec.module, spec.name);
    let options = Options::from_switches(
        common::module_options(reference, &spec.module)
            .iter()
            .map(String::as_str),
    );
    let parsed = common::parse(&spec.slaspec);
    let outcome = elaborate(&parsed, options);
    let mut report = Report {
        name,
        differences: Vec::new(),
        total: 0,
        categories: BTreeMap::new(),
    };
    if parsed.has_errors() {
        report.differences.push(format!(
            "parse errors: {:?}",
            parsed.rendered_diagnostics().first()
        ));
        report.total = 1;
        return report;
    }
    let Some(ours) = outcome.spec else {
        let errors: Vec<String> = outcome
            .diagnostics
            .iter()
            .filter(|d| d.is_error())
            .take(5)
            .map(|d| d.message.clone())
            .collect();
        report
            .differences
            .push(format!("elaboration failed: {errors:?}"));
        report.total = 1;
        return report;
    };
    let sla = Sla::read_file(&spec.sla, &Limits::default()).unwrap();
    let ours = canon::of_elaborated(&ours);
    let theirs = canon::of_sla(&sla);
    for (path, _) in theirs.iter() {
        report.categories.entry(category(path)).or_default().0 += 1;
    }
    let (diffs, total) = canon::diff(&ours, &theirs, usize::MAX);
    for d in &diffs {
        report.categories.entry(category(&d.path)).or_default().1 += 1;
    }
    report.total = total;
    report.differences = diffs.iter().take(12).map(ToString::to_string).collect();
    report
}

#[test]
fn every_shipped_spec_matches_the_reference_elaboration() {
    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    let specs = common::reference_specs(&reference);
    assert!(!specs.is_empty());
    let filter = std::env::var("BK_SPEC_FILTER").ok();
    let specs: Vec<_> = specs
        .into_iter()
        .filter(|s| {
            filter
                .as_deref()
                .is_none_or(|f| s.name.contains(f) || s.module.contains(f))
        })
        .collect();
    let reports = Mutex::new(Vec::new());
    let next = Mutex::new(0_usize);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                loop {
                    let i = {
                        let mut n = next.lock().unwrap();
                        let i = *n;
                        *n += 1;
                        i
                    };
                    let Some(spec) = specs.get(i) else { break };
                    let report = compare(&reference, spec);
                    reports.lock().unwrap().push(report);
                }
            });
        }
    });
    let mut reports = reports.into_inner().unwrap();
    reports.sort_by(|a, b| a.name.cmp(&b.name));
    let mut per_category: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    let mut failing = 0;
    for r in &reports {
        let mut bad = Vec::new();
        for (cat, (n, d)) in &r.categories {
            let e = per_category.entry(cat).or_default();
            e.0 += 1;
            if *d > 0 {
                e.1 += 1;
                bad.push(format!("{cat}: {d}/{n}"));
            }
        }
        if r.total > 0 {
            failing += 1;
            eprintln!(
                "MISMATCH {} ({} differences; {})",
                r.name,
                r.total,
                bad.join(", ")
            );
            for d in &r.differences {
                eprintln!("    {d}");
            }
        }
    }
    eprintln!(
        "specifications: {} compared, {} match, {} differ",
        reports.len(),
        reports.len() - failing,
        failing
    );
    for (cat, (n, d)) in &per_category {
        eprintln!("  {cat}: {} of {n} specifications agree", n - d);
    }
    assert_eq!(
        failing, 0,
        "{failing} specifications differ from the reference"
    );
}
