//! Snapshots of the parsed models of a few shipped files: all of x86's
//! (`x86.ldefs`, `x86.pspec`, `x86.opinion`) and the small 6502's. They
//! pin the readers' output on real input; a change shows up as a diff to
//! review. Regenerate with `INSTA_UPDATE=always`. Skipped without a Ghidra
//! tree.

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

use std::fmt::{Debug, Write as _};

use bk_lang::{Mode, ldefs, opinion, pspec};

/// One item per line: compact enough to review, complete because it is
/// the `Debug` form of the whole item.
fn section<T: Debug>(out: &mut String, title: &str, items: impl IntoIterator<Item = T>) {
    writeln!(out, "[{title}]").unwrap();
    for item in items {
        writeln!(out, "{item:?}").unwrap();
    }
}

fn ldefs_snapshot(module: &str, file: &str) -> Option<String> {
    let path = common::ghidra_dir()?
        .join("Ghidra/Processors")
        .join(module)
        .join("data/languages")
        .join(file);
    let model = ldefs::read_file(&path, Mode::Strict).unwrap().value;
    let mut out = String::new();
    section(&mut out, "languages", &model.languages);
    Some(out)
}

fn pspec_snapshot(module: &str, file: &str) -> Option<String> {
    let path = common::ghidra_dir()?
        .join("Ghidra/Processors")
        .join(module)
        .join("data/languages")
        .join(file);
    let spec = pspec::read_file(&path, Mode::Strict).unwrap().value;
    let mut out = String::new();
    section(&mut out, "sections", &spec.sections);
    section(&mut out, "properties", &spec.properties);
    section(&mut out, "programcounter", &spec.program_counter);
    section(&mut out, "data_space", &spec.data_space);
    section(&mut out, "inferptrbounds", &spec.infer_ptr_bounds);
    section(&mut out, "segmented_address", &spec.segmented_address);
    section(&mut out, "segmentop", &spec.segment_ops);
    section(&mut out, "context_data", &spec.context_data);
    section(&mut out, "volatile", &spec.volatile);
    section(&mut out, "incidentalcopy", &spec.incidental_copy);
    section(&mut out, "jumpassist", &spec.jump_assists);
    section(&mut out, "register_data", &spec.registers);
    section(&mut out, "default_symbols", &spec.default_symbols);
    section(
        &mut out,
        "default_memory_blocks",
        &spec.default_memory_blocks,
    );
    Some(out)
}

#[test]
fn x86_ldefs() {
    let Some(snapshot) = ldefs_snapshot("x86", "x86.ldefs") else {
        return;
    };
    insta::assert_snapshot!(snapshot);
}

#[test]
fn x86_pspec() {
    let Some(snapshot) = pspec_snapshot("x86", "x86.pspec") else {
        return;
    };
    insta::assert_snapshot!(snapshot);
}

#[test]
fn x86_16_pspec() {
    // The 16-bit spec has what x86.pspec lacks: a segmented address space
    // and a <segmentop> with p-code.
    let Some(snapshot) = pspec_snapshot("x86", "x86-16.pspec") else {
        return;
    };
    insta::assert_snapshot!(snapshot);
}

#[test]
fn x86_opinion() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let path = ghidra.join("Ghidra/Processors/x86/data/languages/x86.opinion");
    let model = opinion::read_file(&path, Mode::Strict).unwrap().value;
    let mut out = String::new();
    section(&mut out, "constraints as written", model.constraints());
    section(&mut out, "constraints resolved", model.resolved());
    insta::assert_snapshot!(out);
}

#[test]
fn mos6502_ldefs() {
    let Some(snapshot) = ldefs_snapshot("6502", "6502.ldefs") else {
        return;
    };
    insta::assert_snapshot!(snapshot);
}

#[test]
fn mos6502_pspec() {
    let Some(snapshot) = pspec_snapshot("6502", "6502.pspec") else {
        return;
    };
    insta::assert_snapshot!(snapshot);
}
