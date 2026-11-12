//! Helpers shared by the integration tests.
//!
//! `bk-testkit` will own the spec-root lookup; until this crate may depend
//! on it, this is a local copy of the rule in `docs/LOOP.md`.

#![allow(dead_code, reason = "each test crate uses a different subset")]

use std::path::{Path, PathBuf};

/// The workspace root (two levels above this crate).
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The Ghidra source tree: `BASILISK_GHIDRA_DIR`, or `../ghidra` beside the
/// workspace. Prints why and returns `None` when it is absent, so the
/// calling test can skip.
pub(crate) fn ghidra_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("BASILISK_GHIDRA_DIR")
        .map_or_else(|| workspace_root().join("../ghidra"), PathBuf::from);
    if dir.join("Ghidra/Processors").is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "SKIPPED: Ghidra source tree not found at {} (set BASILISK_GHIDRA_DIR)",
            dir.display()
        );
        None
    }
}

/// Every `.slaspec` under `Ghidra/Processors/*/data/languages`, sorted.
pub(crate) fn slaspec_files(ghidra: &Path) -> Vec<PathBuf> {
    let mut specs = Vec::new();
    let processors = ghidra.join("Ghidra/Processors");
    for entry in std::fs::read_dir(&processors).unwrap().flatten() {
        let languages = entry.path().join("data/languages");
        let Ok(files) = std::fs::read_dir(&languages) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().is_some_and(|e| e == "slaspec") {
                specs.push(path);
            }
        }
    }
    specs.sort();
    specs
}

/// The preprocessor definitions Ghidra's build compiles the shipped
/// specifications with: none. `gradle/processorProject.gradle` passes each
/// module's `sleighCompileOptions`, and no shipped module sets a `-D` or
/// `-d` option (they set only `-l` and `-t`). Passing module definitions
/// anyway would be wrong: the module names `HCS08` and `HCS12` are also
/// conditional symbols inside the HCS08 specifications.
pub(crate) fn build_defines() -> bk_sleigh_syntax::Defines {
    bk_sleigh_syntax::Defines::new()
}

/// Parses `source` (a whole specification without its endian line) and
/// fails the test if anything is reported.
pub(crate) fn parse_ok(source: &str) -> bk_sleigh_syntax::Parsed {
    let text = format!("define endian=big;\n{source}");
    let parsed =
        bk_sleigh_syntax::parse_str("test.slaspec", &text, &bk_sleigh_syntax::Defines::new());
    assert!(
        parsed.diagnostics.is_empty(),
        "unexpected diagnostics for {source:?}:\n{}",
        parsed.rendered_diagnostics().join("\n")
    );
    parsed
}

/// The rendering of a whole specification (without its endian line).
pub(crate) fn dump_spec(source: &str) -> String {
    let parsed = parse_ok(source);
    bk_sleigh_syntax::ast::dump::spec(&parsed.spec, &parsed.names, None)
}

/// The renderings of the items of a specification, one string per item,
/// with the indentation of nested lines removed.
pub(crate) fn dump_items(source: &str) -> Vec<String> {
    let dump = dump_spec(source);
    let mut items: Vec<String> = Vec::new();
    for line in dump.lines().skip(2) {
        if line == ")" {
            break;
        }
        if line.starts_with("  (") && !line.starts_with("   ") {
            items.push(line.trim().to_owned());
        } else if let Some(last) = items.last_mut() {
            last.push(' ');
            last.push_str(line.trim());
        }
    }
    items
}

/// Parses semantic statements and fails the test if anything is reported.
pub(crate) fn body_ok(source: &str) -> bk_sleigh_syntax::ParsedBody {
    let parsed = bk_sleigh_syntax::parse_semantic_body(source);
    assert!(
        parsed.diagnostics.is_empty(),
        "unexpected diagnostics for {source:?}:\n{}",
        parsed
            .diagnostics
            .iter()
            .map(|d| parsed.sources.render(d))
            .collect::<Vec<_>>()
            .join("\n")
    );
    parsed
}

/// The renderings of semantic statements, one string per statement.
pub(crate) fn statements(source: &str) -> Vec<String> {
    let parsed = body_ok(source);
    bk_sleigh_syntax::ast::dump::body(&parsed.body, &parsed.nodes, &parsed.names)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The rendering of one semantic expression.
pub(crate) fn expr(source: &str) -> String {
    let rendered = statements(&format!("x = {source};"));
    assert_eq!(rendered.len(), 1, "{source:?} is one expression");
    rendered[0]
        .strip_prefix("(= x ")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unexpected statement {:?}", rendered[0]))
        .to_owned()
}

/// The rendering of a constructor's pattern equation.
pub(crate) fn equation(source: &str) -> String {
    use bk_sleigh_syntax::ast::{Item, dump::Dumper};
    let parsed = parse_ok(&format!(":X is {source} unimpl"));
    let Some(Item::Constructor(ctor)) = parsed.spec.items.first() else {
        panic!("{source:?} did not give a constructor");
    };
    Dumper::new(&parsed.spec.nodes, &parsed.names).equation_string(ctor.pattern)
}

/// The rendering of a constructor's context block.
pub(crate) fn context(source: &str) -> String {
    use bk_sleigh_syntax::ast::{Item, dump::Dumper};
    let parsed = parse_ok(&format!(":X is a [ {source} ] unimpl"));
    let Some(Item::Constructor(ctor)) = parsed.spec.items.first() else {
        panic!("{source:?} did not give a constructor");
    };
    Dumper::new(&parsed.spec.nodes, &parsed.names).context_string(ctor.context.as_ref().unwrap())
}

/// The messages and 1-based (line, column) of the diagnostics for `source`,
/// a whole specification including its endian line.
pub(crate) fn errors(source: &str) -> Vec<(u32, u32, String)> {
    let parsed =
        bk_sleigh_syntax::parse_str("test.slaspec", source, &bk_sleigh_syntax::Defines::new());
    parsed
        .diagnostics
        .iter()
        .map(|d| {
            let loc = parsed.sources.locate(d.span.start).unwrap();
            (loc.line, loc.column, d.message.clone())
        })
        .collect()
}
