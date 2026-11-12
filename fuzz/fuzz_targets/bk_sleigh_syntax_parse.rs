//! Fuzz target for `bk-sleigh-syntax`: preprocessor, lexer and parser.
//!
//! The input is split at NUL bytes into up to four files, `f0.slaspec`
//! (the root) and `f1.sinc` .. `f3.sinc`, so `@include` between them is
//! exercised. The root text is also parsed as a standalone p-code body.
//! Nothing may panic, hang or allocate without bound (ADR-009).

#![no_main]

use std::path::Path;

use bk_sleigh_syntax::{Defines, MemoryLoader, parse_file, parse_semantic_body};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut loader = MemoryLoader::new();
    let mut root = "";
    for (i, part) in text.splitn(4, '\0').enumerate() {
        let name = if i == 0 {
            root = part;
            "f0.slaspec".to_owned()
        } else {
            format!("f{i}.sinc")
        };
        loader.add(name, part);
    }
    let defines = Defines::new().with("D", "x");
    let parsed = parse_file(Path::new("f0.slaspec"), &defines, &mut loader);
    for diagnostic in &parsed.diagnostics {
        let _ = parsed.sources.render(diagnostic);
    }
    let _ = bk_sleigh_syntax::ast::dump::spec(&parsed.spec, &parsed.names, Some(&parsed.sources));
    let _ = parse_semantic_body(root);
});
