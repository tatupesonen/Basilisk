#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]
//! Development check: compares with a directory of `structure blocks`
//! outputs named by `BK_CFG_XC_DIR` (skipped when unset).

mod support {
    pub(crate) mod blocks;
}

#[test]
fn compare_dir() {
    let Ok(dir) = std::env::var("BK_CFG_XC_DIR") else {
        eprintln!("skipped: BK_CFG_XC_DIR not set");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let log = std::fs::read_to_string(dir.join("log.txt")).unwrap();
    let mut errors = std::collections::HashMap::new();
    let mut last = String::new();
    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("init> structure blocks ") {
            last = rest.split(' ').next().unwrap().to_string();
        } else if !line.starts_with("init>") && !line.starts_with('[') && !last.is_empty() {
            errors.insert(last.clone(), line.to_string());
        }
    }
    let mut paths: Vec<_> = std::fs::read_dir(dir.join("g")).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "xml")).collect();
    paths.sort();
    let (mut same, mut diff) = (0, 0);
    for p in &paths {
        let xml = std::fs::read_to_string(p).unwrap();
        let ours = support::blocks::structure_blocks(&xml);
        let key = format!("g/{}", p.file_name().unwrap().to_str().unwrap());
        let theirs = match errors.get(&key) {
            Some(e) => Err(e.clone()),
            None => Ok(std::fs::read_to_string(p.with_extension("out")).unwrap()),
        };
        if ours == theirs {
            same += 1;
        } else {
            diff += 1;
            if diff <= 3 {
                eprintln!("DIFF {}:\n--- ours\n{:?}\n--- theirs\n{:?}", p.display(), ours, theirs);
            }
        }
    }
    eprintln!("same {same} diff {diff}");
    assert_eq!(diff, 0);
}
