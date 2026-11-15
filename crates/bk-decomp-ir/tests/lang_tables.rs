#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]
//! The checked-in register and user-op tables (`tests/data/lang`) equal
//! what the reference build's languages give (L). `BK_UPDATE_TABLES=1`
//! regenerates them.

mod support;

use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::Language;
use support::lang::LangTables;

/// The languages the checked-in dumps use.
pub const LANGUAGES: &[&str] = &["x86:LE:64:default", "AARCH64:LE:64:v8A", "x86:LE:32:default"];

fn generate(registry: &LanguageRegistry, id: &str) -> LangTables {
    let lang = Language::load(registry, &LanguageId::new(id).unwrap()).unwrap();
    let mut t = LangTables::default();
    for (vd, name) in lang.registers().all() {
        let space = vd.space().and_then(|s| lang.spaces().space(s)).unwrap();
        t.registers.push((name.to_owned(), space.name().to_owned(), vd.offset, vd.size));
    }
    t.userops = (0..lang.num_user_ops())
        .map(|i| lang.user_op_name(i).map(str::to_owned))
        .collect();
    t
}

#[test]
fn language_tables_are_current() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let mut builder = LanguageRegistry::builder();
    for e in std::fs::read_dir(reference.root().join("Ghidra/Processors")).unwrap() {
        builder = builder.module(e.unwrap().path());
    }
    let registry = builder.build().unwrap();
    for id in LANGUAGES {
        let text = generate(&registry, id).write();
        let path = LangTables::path(id);
        if std::env::var_os("BK_UPDATE_TABLES").is_some() {
            bk_testkit::oracle::write_text(&path, &text).unwrap();
            eprintln!("updated {}", path.display());
            continue;
        }
        let have = bk_testkit::oracle::read_text(&path).unwrap_or_default();
        assert!(have == text, "{id}: table stale (BK_UPDATE_TABLES=1 regenerates)");
    }
}
