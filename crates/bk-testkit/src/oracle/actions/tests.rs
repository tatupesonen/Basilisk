use super::*;
use crate::oracle::sample_dir;
use crate::oracle::strategies::mutated;
use proptest::prelude::*;

fn sample() -> String {
    std::fs::read_to_string(sample_dir().join("decompile.actions")).unwrap()
}

#[test]
fn the_decompile_root_is_read() {
    let text = sample();
    let list = ActionList::parse(&text).unwrap();
    assert_eq!(list.write(), text);
    assert_eq!(list.root, "decompile");
    assert_eq!(list.entries.len(), 243);
    assert_eq!(list.entries[0].path, "universal");
    // The name that occurs twice (decomp-oracle.md 4.1).
    assert_eq!(list.positions_named("blockstructure"), [168, 231]);
    assert_eq!(list.position_of("universal:blockstructure"), Some(231));
    assert_eq!(list.position_of("universal:constbase"), Some(2));
    assert_eq!(list.position_of("universal:stop"), Some(242));
    assert_eq!(list.entries[168].depth(), 3);
    // After a group comes the first action outside it.
    let fullloop = list.position_of("universal:fullloop").unwrap();
    let after = list.next_after(fullloop).unwrap();
    assert!(
        !list.entries[after as usize]
            .path
            .starts_with("universal:fullloop")
    );
    assert_eq!(list.next_after(242), None);
}

#[test]
fn inconsistent_lines_are_rejected() {
    let good = "H\tbkactions\t1\tr\t2\n   0        !    universal\tuniversal\n   \
                1                  start\tuniversal:start\nT\n";
    assert!(ActionList::parse(good).is_ok());
    for bad in [
        good.replace("   1   ", "   7   "),
        good.replace("universal:start", "universal:stop"),
        good.replace("\t2\n", "\t3\n"),
        good.replace("\tuniversal\n", "\n"),
    ] {
        assert!(ActionList::parse(&bad).is_err(), "{bad}");
    }
}

proptest! {
    #[test]
    fn no_input_panics(text in "\\PC{0,200}") {
        let _ = ActionList::parse(&text);
    }

    #[test]
    fn damaged_samples_never_panic(text in mutated(Just(sample()))) {
        if let Ok(list) = ActionList::parse(&text) {
            prop_assert_eq!(list.write(), text);
        }
    }
}
