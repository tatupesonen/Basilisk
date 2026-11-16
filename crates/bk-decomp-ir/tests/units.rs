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
//! Spec 6, test 10: the unit table. The Ghidra-origin names and groups
//! (`unit/ghidra.rs`) equal those of `docs/inventory/02-decompiler.md`
//! sections 5.2 (the universal action, 86 placements of 71 actions) and 6
//! (161 rules); a table built from them passes `check_ghidra`; a duplicate,
//! an unknown name or wrong groups are refused.

use bk_decomp_ir::unit::{
    GHIDRA_ACTIONS, GHIDRA_RULES, Origin, Soundness, UnitError, UnitInfo, UnitKind, UnitTable,
};
use bk_testkit::workspace_root;

/// The rows of the first table after `heading`: cells without backticks.
fn rows(text: &str, heading: &str) -> Vec<Vec<String>> {
    let (_, after) = text.split_once(heading).unwrap();
    after
        .lines()
        .skip_while(|l| !l.starts_with("| 1 |"))
        .take_while(|l| l.starts_with('|'))
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(|c| c.trim().trim_matches('`').to_owned())
                .collect()
        })
        .collect()
}

#[test]
fn ghidra_lists_equal_the_inventory() {
    let text =
        std::fs::read_to_string(workspace_root().join("docs/inventory/02-decompiler.md")).unwrap();
    // 5.2: | # | Container | Action | Name | Group | … ; groups in order of
    // placement, each once.
    let mut actions: Vec<(String, Vec<String>)> = Vec::new();
    let placements = rows(&text, "### 5.2 The universal action");
    for r in &placements {
        let (name, group) = (r[3].clone(), r[4].clone());
        if name.is_empty() {
            continue; // a group or pool heading row
        }
        match actions.iter_mut().find(|(n, _)| *n == name) {
            Some((_, groups)) if !groups.contains(&group) => groups.push(group),
            Some(_) => {}
            None => actions.push((name, vec![group])),
        }
    }
    assert_eq!(placements.len(), 86);
    let ours: Vec<(String, Vec<String>)> = GHIDRA_ACTIONS
        .iter()
        .map(|(n, g)| ((*n).to_owned(), g.iter().map(|s| (*s).to_owned()).collect()))
        .collect();
    assert_eq!(ours, actions);
    // 6: | # | Class | Name | Pool | Group | …
    let rules: Vec<(String, String)> = rows(&text, "## 6. Rules")
        .iter()
        .map(|r| (r[2].clone(), r[4].clone()))
        // Rules the universal action does not place (group "—").
        .filter(|(_, g)| g != "—")
        .collect();
    let ours: Vec<(String, String)> = GHIDRA_RULES
        .iter()
        .map(|(n, g)| ((*n).to_owned(), (*g).to_owned()))
        .collect();
    assert_eq!(ours, rules);
    assert_eq!((GHIDRA_ACTIONS.len(), GHIDRA_RULES.len()), (71, 161));
}

fn unit(name: &'static str, kind: UnitKind, groups: &'static [&'static str]) -> UnitInfo {
    UnitInfo {
        name,
        origin: Origin::Ghidra,
        groups,
        kind,
        opcodes: &[],
        soundness: Soundness::Exact,
    }
}

fn ghidra_units() -> Vec<UnitInfo> {
    let mut v: Vec<UnitInfo> = GHIDRA_ACTIONS
        .iter()
        .map(|(n, g)| unit(n, UnitKind::Action, g))
        .collect();
    v.extend(
        GHIDRA_RULES
            .iter()
            .map(|(n, g)| unit(n, UnitKind::Rule, std::slice::from_ref(g))),
    );
    v
}

#[test]
fn a_table_of_ghidras_units_checks_complete() {
    let units = ghidra_units();
    let table = UnitTable::build(&[&units]).unwrap();
    assert_eq!(table.len(), 71 + 161);
    table.check_ghidra(true).unwrap();
    let id = table
        .find("heritage", UnitKind::Action, Origin::Ghidra)
        .unwrap();
    assert_eq!(table.get(id).unwrap().name, "heritage");
    // Missing one: incomplete.
    let partial = UnitTable::build(&[&units[1..]]).unwrap();
    partial.check_ghidra(false).unwrap();
    assert!(matches!(
        partial.check_ghidra(true),
        Err(UnitError::Unknown(_))
    ));
}

#[test]
fn duplicates_unknown_names_and_wrong_groups_are_refused() {
    let units = ghidra_units();
    let dup = [units[0]];
    assert!(matches!(
        UnitTable::build(&[&units, &dup]),
        Err(UnitError::Duplicate { .. })
    ));
    // The same name of another origin is a different unit.
    let mut ours = units[0];
    ours.origin = Origin::Basilisk;
    UnitTable::build(&[&units, &[ours]]).unwrap();
    let unknown = [unit("nosuchrule", UnitKind::Rule, &["analysis"])];
    let t = UnitTable::build(&[&unknown]).unwrap();
    assert!(matches!(t.check_ghidra(false), Err(UnitError::Unknown(_))));
    let wrong = [unit("heritage", UnitKind::Action, &["analysis"])];
    let t = UnitTable::build(&[&wrong]).unwrap();
    assert!(matches!(
        t.check_ghidra(false),
        Err(UnitError::Groups { .. })
    ));
}
