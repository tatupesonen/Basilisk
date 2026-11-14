//! The structurer commands of the console extension against the checked-in
//! samples and against Ghidra's own `structure blocks`
//! (`docs/features/decomp-oracle.md` 4.6, 4.7, 6.1, 6.4). Needs
//! `decomp_bk` and the Ghidra tree (for the data test that gives the
//! console an architecture); skips with a printed reason without them.

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

use std::path::Path;

use bk_testkit::oracle::generate::random_graphs;
use bk_testkit::oracle::{ActionList, CfgDump, GraphFile, StructureDump, sample_dir};
use bk_testkit::{Tool, require_ghidra, require_tool};

/// How many generated graphs the cross-check runs (R3 ran 3,000).
const COUNT: usize = 3000;

/// The console command that gives the console an architecture.
fn load_elseif(ghidra: &bk_testkit::GhidraDir) -> String {
    format!(
        "load test file {}",
        ghidra.data_tests_dir().join("elseif.xml").display()
    )
}

fn path_text(path: &Path) -> String {
    let text = path.to_str().unwrap().to_owned();
    assert!(!text.contains(char::is_whitespace), "{text}");
    text
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn the_samples_are_what_the_extension_writes() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let samples = sample_dir();
    let dir = tempfile::tempdir().unwrap();
    let out = |name: &str| path_text(&dir.path().join(name));
    let input = |name: &str| path_text(&samples.join(name));

    // Positions by path, from the console itself (decomp-oracle.md 4.5).
    let listing = reference
        .decomp_bk()
        .run_script([load_elseif(&ghidra), "bk list actions".into()])
        .unwrap();
    let actions = ActionList::parse(listing.outputs_of("bk list actions").next().unwrap()).unwrap();
    assert_eq!(
        actions.write(),
        read(&samples.join("decompile.actions")),
        "decompile.actions"
    );
    let structure_at = actions
        .position_of("universal:fullloop:mainloop:blockstructure")
        .unwrap();
    let after = actions.next_after(structure_at).unwrap();

    let script = [
        load_elseif(&ghidra),
        "execute test command 1-7".into(),
        format!("bk break start {structure_at}"),
        format!("bk break start {after}"),
        "decompile".into(),
        format!("bk dump blocks {}", out("elseif.blocks.bkg")),
        "continue".into(),
        format!("bk dump structure {}", out("elseif.structure.bks")),
        format!(
            "bk structure {} {} asgiven finish trace",
            input("elseif.blocks.bkg"),
            out("elseif.finish.trace.bks")
        ),
        format!(
            "bk structure {} {} asgiven",
            input("elseif.blocks.bkg"),
            out("elseif.asgiven.bks")
        ),
        format!(
            "bk cfg analyze {} {}",
            input("elseif.blocks.bkg"),
            out("elseif.cfg")
        ),
        format!(
            "bk structure {} {} bare trace",
            input("random.bkg"),
            out("random.trace.bks")
        ),
        format!(
            "bk cfg analyze {} {}",
            input("random.bkg"),
            out("random.cfg")
        ),
        format!(
            "bk structure {} {} bare",
            input("clipped.bkg"),
            out("clipped.bks")
        ),
    ];
    reference.decomp_bk().run_script(script).unwrap();
    for name in [
        "elseif.blocks.bkg",
        "elseif.structure.bks",
        "elseif.finish.trace.bks",
        "elseif.asgiven.bks",
        "elseif.cfg",
        "random.trace.bks",
        "random.cfg",
        "clipped.bks",
    ] {
        let written = read(&dir.path().join(name));
        assert_eq!(written, read(&samples.join(name)), "{name}");
    }
}

#[test]
fn asgiven_structuring_of_the_dumped_blocks_is_ghidras_structure() {
    // Both checked in from one run of elseif.xml: the blocks at the
    // mainloop's blockstructure start (`bk dump blocks`), the structure at
    // the next action's start (`bk dump structure`), and `bk structure
    // asgiven` of those blocks. Structuring the dumped blocks with their
    // real facts and Ghidra's own analyses reproduces the pipeline's
    // hierarchy exactly — the property D04's corpus replay rests on.
    let samples = sample_dir();
    let StructureDump::Ok(replayed) =
        StructureDump::parse(&read(&samples.join("elseif.asgiven.bks"))).unwrap()
    else {
        panic!()
    };
    let StructureDump::Ok(actual) =
        StructureDump::parse(&read(&samples.join("elseif.structure.bks"))).unwrap()
    else {
        panic!()
    };
    assert_eq!(replayed.nodes, actual.nodes);
    assert_eq!(replayed.top, actual.top);
    assert_eq!(replayed.change_count, Some(6));
    assert_eq!(replayed.flips.len(), 7);
    let graph = GraphFile::parse(&read(&samples.join("elseif.blocks.bkg"))).unwrap();
    let leaves = actual
        .nodes
        .iter()
        .filter(|n| n.parent.is_some() && n.components.is_empty());
    assert_eq!(leaves.count(), graph.nodes.len());
}

#[test]
fn structure_blocks_and_bk_structure_agree_on_generated_graphs() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let graphs = random_graphs(1, COUNT, 40);
    let dir = tempfile::tempdir().unwrap();
    let mut script = vec![load_elseif(&ghidra)];
    for (i, graph) in graphs.iter().enumerate() {
        let xml = dir.path().join(format!("g{i}.xml"));
        let bkg = dir.path().join(format!("g{i}.bkg"));
        std::fs::write(&xml, graph.to_ghidra_xml()).unwrap();
        std::fs::write(&bkg, graph.write()).unwrap();
        let p = |suffix: &str| path_text(&dir.path().join(format!("g{i}.{suffix}")));
        script.push(format!("structure blocks {} {}", p("xml"), p("sb.xml")));
        script.push(format!(
            "bk structure {} {} bare trace xml {}",
            p("bkg"),
            p("bks"),
            p("bk.xml")
        ));
        script.push(format!("bk cfg analyze {} {}", p("bkg"), p("cfg")));
    }
    let transcript = reference
        .decomp_bk()
        .timeout(std::time::Duration::from_secs(600))
        .run_script(script)
        .unwrap();
    let mut errors = 0;
    for i in 0..COUNT {
        let p = |suffix: &str| dir.path().join(format!("g{i}.{suffix}"));
        let dump = StructureDump::parse(&read(&p("bks"))).unwrap();
        CfgDump::parse(&read(&p("cfg"))).unwrap();
        match dump {
            StructureDump::Ok(_) => {
                // Neutral facts behave as Ghidra's plain blocks.
                assert_eq!(read(&p("bk.xml")), read(&p("sb.xml")), "graph {i}");
            }
            StructureDump::Error(message) => {
                assert_eq!(
                    message, "Could not finish collapsing block structure",
                    "graph {i}"
                );
                assert!(!p("sb.xml").exists(), "graph {i}");
                errors += 1;
            }
        }
    }
    // structure blocks prints Ghidra's error for exactly the failing graphs.
    let printed = transcript
        .steps
        .iter()
        .filter(|s| s.command.starts_with("structure blocks"))
        .filter(|s| {
            s.output
                .contains("Could not finish collapsing block structure")
        })
        .count();
    assert_eq!(printed, errors);
    eprintln!("structure blocks = bk structure on {COUNT} graphs; {errors} end in Ghidra's error");
}
