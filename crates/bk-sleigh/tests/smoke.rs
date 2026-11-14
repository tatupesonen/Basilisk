#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

mod common;

#[test]
fn smoke() {
    let Some(reference) = common::reference() else { return };
    for (id, data) in [
        ("x86:LE:64:default", vec![0x55u8, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x08, 0xe8, 0, 0, 0, 0, 0xc3, 0x06, 0x0f, 0x05, 0xf3, 0xa4]),
        ("Toy:BE:32:default", (0u8..=255).collect()),
    ] {
        let lang = common::load(&reference, id);
        let ours = common::sweep(&lang, 0x1000, &data, &[]);
        let theirs = common::oracle(&reference, id, 0x1000, &data, &[]);
        let cmp = common::compare(&theirs, &ours);
        for f in &cmp.failures { eprintln!("{id}: {f}"); }
        assert!(cmp.failures.is_empty(), "{id}");
    }
}
