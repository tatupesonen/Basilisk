#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

mod common;

#[test]
fn smoke() {
    let Some(reference) = common::reference() else { return };
    let ids: Vec<String> = std::env::var("BK_LANGS").unwrap_or_else(|_| "Toy:BE:32:default".into()).split(',').map(str::to_owned).collect();
    for id in ids {
        let lang = common::load(&reference, &id);
        let t = std::time::Instant::now();
        let r = common::coverage::run_language(&reference, &lang, &id, common::coverage::Budget { samples_per_pair: 8, random_bytes: 65536, max_streams: 200, coverage_attempts: 300_000 }, &[]);
        eprintln!("{} ({:.1}s, {} invocations)", r.row(), t.elapsed().as_secs_f64(), r.invocations);
        for f in &r.failures { eprintln!("  {f}"); }
    }
}
