//! Kind G checks against Ghidra's own files (skipped without the spec
//! root): the data organisation decoded from every `.cspec` equals what
//! Ghidra's `setupSizes` left (table `types_orgs.txt.gz`), and every
//! `parse line` declaration of the decompiler's data tests parses.
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

mod oracle_common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bk_decomp_types::cdecl::{self, Declaration};
use bk_decomp_types::{DataOrganization, TypeEnv, TypeFactory};
use bk_marshal::Document;
use oracle_common::{env_from, org_fields, table};

/// Every file under the processors' `data/languages` directories, by name.
fn language_files(processors: &Path) -> BTreeMap<String, Vec<PathBuf>> {
    let mut out: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for module in std::fs::read_dir(processors).unwrap().flatten() {
        let dir = module.path().join("data").join("languages");
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    out.entry(n.to_owned()).or_default().push(p);
                }
            }
        }
    }
    out
}

/// The `.cspec` named `cspec` for the language whose `.sla` is `sla`.
fn find_cspec(files: &BTreeMap<String, Vec<PathBuf>>, cspec: &str, sla: &str) -> PathBuf {
    let cands = files.get(cspec).unwrap_or_else(|| panic!("no {cspec}"));
    if cands.len() == 1 {
        return cands[0].clone();
    }
    let slaspec = sla.replace(".sla", ".slaspec");
    let dirs: Vec<&Path> = files
        .get(&slaspec)
        .map(|v| v.iter().filter_map(|p| p.parent()).collect())
        .unwrap_or_default();
    cands
        .iter()
        .find(|c| c.parent().is_some_and(|d| dirs.contains(&d)))
        .unwrap_or(&cands[0])
        .clone()
}

/// Ghidra `LanguageDescription::getCompiler`: the pair for `arch`, else
/// the language's `default` compiler, else its first.
fn lookup<'p>(pairs: &'p [(String, Pair)], arch: &str) -> Option<&'p Pair> {
    if let Some((_, p)) = pairs.iter().find(|(id, _)| id == arch) {
        return Some(p);
    }
    let lang = arch.rsplit_once(':')?.0;
    let same: Vec<&(String, Pair)> = pairs
        .iter()
        .filter(|(id, _)| id.rsplit_once(':').is_some_and(|(l, _)| l == lang))
        .collect();
    same.iter()
        .find(|(id, _)| id.ends_with(":default"))
        .or_else(|| same.first())
        .map(|(_, p)| p)
}

struct Pair {
    env: TypeEnv,
    org_text: String,
    cspec: PathBuf,
}

fn pairs(files: &BTreeMap<String, Vec<PathBuf>>) -> Vec<(String, Pair)> {
    let mut out = Vec::new();
    for l in table("types_orgs.txt.gz") {
        let f: Vec<&str> = l.split('\t').collect();
        if f[2] == "ERR" {
            continue;
        }
        let cspec = find_cspec(files, f[2], f[3]);
        out.push((
            f[1].to_owned(),
            Pair {
                env: env_from(&f[4..14]),
                org_text: f[14..].join("\t"),
                cspec,
            },
        ));
    }
    out
}

#[test]
fn data_organisation_of_every_cspec() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let files = language_files(&ghidra.processors_dir());
    let pairs = pairs(&files);
    assert!(pairs.len() > 250, "{}", pairs.len());
    let mut bad = Vec::new();
    let mut cspecs = std::collections::BTreeSet::new();
    for (id, p) in &pairs {
        let text = std::fs::read_to_string(&p.cspec).unwrap();
        let org = DataOrganization::from_cspec(&text, &p.env).unwrap();
        cspecs.insert(p.cspec.clone());
        if org_fields(&org) != p.org_text {
            bad.push(format!(
                "{id} ({}): ghidra {} Basilisk {}",
                p.cspec.display(),
                p.org_text,
                org_fields(&org)
            ));
        }
    }
    eprintln!(
        "{} pairs, {} distinct .cspec files",
        pairs.len(),
        cspecs.len()
    );
    assert!(bad.is_empty(), "{bad:#?}");
}

/// Prototype model names a `.cspec` declares, plus `__thiscall`, which
/// Ghidra always provides.
fn model_names(cspec_text: &str) -> Vec<String> {
    let mut names = vec!["__thiscall".to_owned()];
    let Ok(doc) = Document::parse(cspec_text) else {
        return names;
    };
    let mut stack = vec![doc.root()];
    while let Some(e) = stack.pop() {
        if matches!(e.name(), "prototype" | "resolveprototype" | "modelalias")
            && let Some(n) = e.attribute("name")
        {
            names.push(n.to_owned());
        }
        stack.extend(e.children());
    }
    names
}

#[test]
fn data_test_parse_lines() {
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let files = language_files(&ghidra.processors_dir());
    let pairs = pairs(&files);
    let mut entries: Vec<PathBuf> = std::fs::read_dir(ghidra.data_tests_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "xml"))
        .collect();
    entries.sort();
    let (mut count, mut failures) = (0, Vec::new());
    for path in entries {
        let text = std::fs::read_to_string(&path).unwrap();
        let doc = Document::parse(&text).unwrap();
        let mut arch = None;
        let mut coms = Vec::new();
        let mut stack = vec![doc.root()];
        while let Some(e) = stack.pop() {
            if e.name() == "binaryimage" {
                arch = e.attribute("arch").map(str::to_owned);
            }
            if e.name() == "com" {
                coms.push((e.source_offset(), e.content().to_owned()));
            }
            stack.extend(e.children());
        }
        coms.sort();
        let lines: Vec<String> = coms
            .into_iter()
            .map(|(_, c)| c.trim().to_owned())
            .filter(|c| c.starts_with("parse line") || c.starts_with("pointer setting"))
            .collect();
        if lines.is_empty() {
            continue;
        }
        let arch = arch.unwrap();
        let pair =
            lookup(&pairs, &arch).unwrap_or_else(|| panic!("no data organisation for {arch}"));
        let cspec_text = std::fs::read_to_string(&pair.cspec).unwrap();
        let org = DataOrganization::from_cspec(&cspec_text, &pair.env).unwrap();
        let models = model_names(&cspec_text);
        let has_model = |n: &str| models.iter().any(|m| m == n);
        let mut f = TypeFactory::with_core_types(pair.env.clone(), org).unwrap();
        for com in lines {
            if let Some(rest) = com.strip_prefix("pointer setting") {
                // The console's `pointer setting <name> <struct> offset <n>`
                // (Ghidra `IfcPointerSetting`), which data tests use to
                // define relative pointers that later declarations name.
                let w: Vec<&str> = rest.split_whitespace().collect();
                assert_eq!(w.get(2), Some(&"offset"), "{com}");
                let off: i32 = w[3].parse().unwrap();
                let base = f.find_by_name(w[1]).unwrap();
                let to = f.ptr_to_from_parent(base, off).unwrap();
                let (size, ws) = (f.env().data_space.addr_size, f.env().data_space.word_size);
                f.pointer_rel_named(size, base, to, ws, off, w[0]).unwrap();
                continue;
            }
            let line = com.trim_start_matches("parse line").trim().to_owned();
            count += 1;
            match cdecl::parse_declaration(&mut f, &line, &has_model) {
                Ok(
                    Declaration::Prototype(_) | Declaration::Typedef(_) | Declaration::Defined(_),
                ) => {}
                Ok(other) => failures.push(format!("{}: {line}: {other:?}", path.display())),
                Err(e) => failures.push(format!("{}: {line}: {e}", path.display())),
            }
        }
    }
    eprintln!("{count} parse line declarations");
    assert_eq!(count, 232);
    assert!(failures.is_empty(), "{failures:#?}");
}
