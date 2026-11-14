//! The state dump, recording and trace samples against what the extended
//! consoles write now (`docs/features/decomp-oracle.md` 6.1), and the
//! checked-in capture fixtures against each other (4.11, 4.15) and, when
//! the reference has the extension, against a fresh capture.
//!
//! The samples are regenerated in place with `BK_UPDATE_SAMPLES=1` (review
//! the diff before committing).

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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bk_testkit::oracle::capture::{self, Positions};
use bk_testkit::oracle::host::{self, KNOWN_CAUSES, Library};
use bk_testkit::oracle::{Recording, StateDump, Trace, read_text, sample_dir, write_text};
use bk_testkit::{Tool, require_ghidra, require_tool, workspace_root};

fn fixtures() -> std::path::PathBuf {
    workspace_root().join("fixtures/decomp-oracle")
}

fn path_text(path: &Path) -> String {
    let text = path.to_str().unwrap().to_owned();
    assert!(!text.contains(char::is_whitespace), "{text}");
    text
}

/// Compare a regenerated sample with the checked-in one, or replace it.
fn check_sample(name: &str, regenerated: &str) {
    let path = sample_dir().join(name);
    if std::env::var_os("BK_UPDATE_SAMPLES").is_some() {
        write_text(&path, regenerated).unwrap();
        eprintln!("updated {}", path.display());
        return;
    }
    assert_eq!(
        read_text(&path).unwrap(),
        regenerated,
        "{name} (BK_UPDATE_SAMPLES=1 regenerates)"
    );
}

#[test]
fn the_state_recording_and_trace_samples_are_current() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let Some(_) = require_tool(Tool::DecompBkDbg) else {
        return;
    };
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let out = |name: &str| path_text(&dir.path().join(name));
    let positions: Positions = capture::find_positions(&reference, &ghidra).unwrap();
    let scripts = capture::data_tests(&ghidra).unwrap();
    let switchind = scripts.iter().find(|s| s.name == "switchind").unwrap();
    let elseif = scripts.iter().find(|s| s.name == "elseif").unwrap();

    // switchind at the four standard points and at the end.
    let mut script = vec![switchind.load.clone()];
    for c in &switchind.commands {
        if !capture::is_decompile(c) {
            script.push(c.clone());
            continue;
        }
        script.extend([
            format!("bk break start {}", positions.after_start),
            format!("bk break start {}", positions.oppool1),
            "decompile".into(),
            format!("bk dump state {}", out("p1")),
            "continue".into(),
            format!("bk dump state {}", out("p2")),
            "bk break clear".into(),
            format!("bk break start {}", positions.cleanup),
            format!("bk break start {}", positions.stop),
            "continue".into(),
            format!("bk dump state {}", out("p3")),
            "continue".into(),
            format!("bk dump state {}", out("p4")),
            "bk break clear".into(),
            "continue".into(),
            format!("bk dump state {}", out("end")),
        ]);
    }
    reference
        .decomp_bk()
        .current_dir(&switchind.dir)
        .run_script(script)
        .unwrap();
    for point in ["p1", "p2", "p3", "p4", "end"] {
        let text = std::fs::read_to_string(dir.path().join(point)).unwrap();
        StateDump::parse(&text).unwrap();
        check_sample(&format!("switchind.{point}.state.gz"), &text);
    }

    // elseif: the recording of a whole run, and the trace of its decompile.
    let mut script = vec![
        elseif.load.clone(),
        format!("bk pcode record {}", out("rec")),
    ];
    script.extend(elseif.commands.iter().cloned());
    script.push("bk pcode stop".into());
    reference
        .decomp_bk()
        .current_dir(&elseif.dir)
        .run_script(script)
        .unwrap();
    let rec = std::fs::read_to_string(dir.path().join("rec")).unwrap();
    Recording::parse(&rec).unwrap();
    check_sample("elseif.pcoderec.gz", &rec);

    let mut script = vec![elseif.load.clone(), "bk trace stream".into()];
    for c in &elseif.commands {
        if capture::is_decompile(c) {
            script.extend(["trace address".into(), "trace enable".into()]);
        }
        script.push(c.clone());
    }
    let transcript = reference
        .decomp_bk_dbg()
        .current_dir(&elseif.dir)
        .run_script(script)
        .unwrap();
    let output = transcript.outputs_of("decompile").next().unwrap();
    let trace = Trace::extract(output).unwrap();
    assert_eq!(trace.records.len(), 1347, "R9's count");
    check_sample("elseif.trace.gz", output);
}

#[test]
fn the_fixtures_agree_with_each_other() {
    let read = |name: &str| std::fs::read_to_string(fixtures().join(name)).unwrap();
    let libcxx = host::read_digests(&read("captures.libcxx.txt")).unwrap();
    let libstdcxx = host::read_digests(&read("captures.libstdcxx.txt")).unwrap();
    let diff = host::diff_tables(&libcxx, &libstdcxx);
    assert!(
        diff.only_first.is_empty() && diff.only_second.is_empty(),
        "{diff:?}"
    );
    // Every capture group where the builds differ is explained, file by
    // file and cause by cause, in hostdiff.txt — and nothing else is.
    let mut explained = BTreeSet::new();
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    for line in read("hostdiff.txt").lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split('\t').collect();
        let [path, cause, count] = f.as_slice() else {
            panic!("bad hostdiff line {line}");
        };
        assert!(
            KNOWN_CAUSES.iter().any(|c| c.name == *cause),
            "unknown cause {cause}"
        );
        let count: usize = count.parse().unwrap();
        if *path == "total" {
            totals.insert((*cause).to_owned(), count);
        } else {
            explained.insert(host::capture_group(path));
            *per_file.entry((*cause).to_owned()).or_insert(0) += count;
        }
    }
    let differing: BTreeSet<String> = diff.changed.into_iter().collect();
    assert_eq!(differing, explained);
    assert_eq!(per_file, totals);
    // ADR-040's form: the counts are pinned; a new cause or a moved count fails.
    let pinned: BTreeMap<String, usize> =
        [("nan-order".to_owned(), 8), ("nan-sign".to_owned(), 48)].into();
    assert_eq!(totals, pinned);

    let summary = read("summary.txt");
    let total = summary.lines().last().unwrap();
    assert_eq!(
        total,
        "T\tscripts=167\tdecompiles=607\tops=11005\tvarnodes=18134\ttrace-records=74836\tstructuring-runs=767\terrors=0"
    );
    for line in summary
        .lines()
        .filter(|l| l.starts_with("S\t") || l.starts_with("F\t"))
    {
        let status = line.rsplit('\t').next().unwrap();
        assert!(
            status == "ok" || status.starts_with("skipped: fails in decomp too"),
            "{line}"
        );
    }
    let skipped = summary
        .lines()
        .filter(|l| l.contains("\tskipped: "))
        .count();
    assert_eq!(
        skipped, 2,
        "the two research fragments Ghidra's console cannot parse"
    );
}

#[test]
fn a_fresh_capture_matches_the_fixture_of_this_build() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let (Some(_), Some(_), Some(ghidra)) = (
        require_tool(Tool::DecompBkDbg),
        require_tool(Tool::DecompDbg),
        require_ghidra(),
    ) else {
        return;
    };
    let Some(library) = Library::of_reference(&reference) else {
        eprintln!("skipped: the reference STAMP names no host");
        return;
    };
    let fixture = fixtures().join(format!("captures.{}.txt", library.name()));
    let expected = host::read_digests(&std::fs::read_to_string(fixture).unwrap()).unwrap();
    let positions = capture::find_positions(&reference, &ghidra).unwrap();
    let mut scripts = capture::data_tests(&ghidra).unwrap();
    scripts.retain(|s| ["elseif", "switchind", "inline", "floatprint"].contains(&s.name.as_str()));
    let dir = tempfile::tempdir().unwrap();
    let report = capture::capture_corpus(&reference, &scripts, &positions, dir.path(), 4);
    assert_eq!(report.errors(), Vec::<String>::new());
    let groups = host::group_digests(&host::digest_tree(dir.path()).unwrap());
    assert_eq!(groups.len(), 4 * 5);
    for (group, digest) in &groups {
        assert_eq!(
            expected.get(group),
            Some(digest),
            "{group} drifted from the {library} fixture"
        );
    }
}
