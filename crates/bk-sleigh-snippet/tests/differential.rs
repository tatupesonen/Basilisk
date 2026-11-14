//! Spec 6.2: every p-code snippet of the shipped `.pspec`/`.cspec` files,
//! for every language that uses the file, compiled by Ghidra's
//! `PcodeSnippet` (the `snippetdump` oracle) and by Basilisk, in the
//! injection library's order and with its unique bases; the template XML,
//! or the failure, must be equal. Tolerated differences: none.

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

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use bk_sleigh_snippet::{Options, SnippetCompiler, TempAllocator};
use common::corpus::{Snippet, snippets_of};
use common::oracle::{Base, Outcome, Record, run_basilisk, run_oracle};

struct Job {
    id: String,
    truncations: Vec<(String, u32)>,
    /// Records and, per record, the snippet it came from.
    records: Vec<Record>,
    origins: Vec<Snippet>,
}

#[derive(Default)]
struct Tally {
    languages: usize,
    records: usize,
    ok: usize,
    rejected: usize,
    exceptions: usize,
    dynamic: usize,
    distinct: BTreeSet<(PathBuf, usize)>,
    ghidra_rejects: BTreeSet<(PathBuf, usize)>,
    mismatches: Vec<String>,
}

#[test]
fn every_shipped_snippet_matches_ghidra() {
    let Some((ghidra, reference)) = common::roots() else {
        return;
    };
    let Some(tool) = common::snippetdump(&reference) else {
        return;
    };
    let registry = common::registry(ghidra.root(), reference.root());
    let mut cache: HashMap<PathBuf, Vec<Snippet>> = HashMap::new();
    let mut snippets = |path: &PathBuf| -> Vec<Snippet> {
        cache
            .entry(path.clone())
            .or_insert_with(|| snippets_of(path))
            .clone()
    };

    // Every element in the tree, for the count the spec quotes.
    let mut elements = BTreeSet::new();
    let mut without_body = BTreeSet::new();
    let mut jobs = Vec::new();
    for language in registry.languages() {
        let pspec = snippets(&language.files().pspec);
        let mut sequences: Vec<Vec<Snippet>> = Vec::new();
        if language.compiler_specs().is_empty() {
            sequences.push(pspec.clone());
        }
        for cspec in language.compiler_specs() {
            let mut seq = pspec.clone();
            seq.extend(snippets(&cspec.file));
            sequences.push(seq);
        }
        let mut records = Vec::new();
        let mut origins = Vec::new();
        for seq in sequences {
            let mut started = false;
            for s in seq {
                elements.insert((s.file.clone(), s.offset));
                let Some(body) = s.body.clone() else {
                    without_body.insert((s.file.clone(), s.offset));
                    continue;
                };
                let base = if s.executable {
                    Base::Fixed(TempAllocator::EXECUTABLE_BASE)
                } else if started {
                    Base::Continue
                } else {
                    started = true;
                    // Replaced by the language's real start below.
                    Base::Start(0)
                };
                records.push(Record {
                    source: s.label(),
                    base,
                    body,
                    params: s.params.clone(),
                });
                origins.push(s);
            }
        }
        if records.is_empty() {
            continue;
        }
        jobs.push(Job {
            id: language.id().to_string(),
            truncations: language
                .truncated_spaces()
                .iter()
                .map(|t| (t.space.clone(), t.size))
                .collect(),
            records,
            origins,
        });
    }

    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(16));
    let chunks: Vec<&[Job]> = jobs.chunks(jobs.len().div_ceil(threads).max(1)).collect();
    let tallies: Vec<Tally> = std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                let registry = &registry;
                let tool = &tool;
                let root = reference.root();
                scope.spawn(move || {
                    let mut t = Tally::default();
                    for job in chunk {
                        run_job(registry, tool, root, job, &mut t);
                    }
                    t
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut total = Tally::default();
    for t in tallies {
        total.languages += t.languages;
        total.records += t.records;
        total.ok += t.ok;
        total.rejected += t.rejected;
        total.exceptions += t.exceptions;
        total.dynamic += t.dynamic;
        total.distinct.extend(t.distinct);
        total.ghidra_rejects.extend(t.ghidra_rejects);
        total.mismatches.extend(t.mismatches);
    }
    let mut by_file: BTreeMap<String, usize> = BTreeMap::new();
    for (file, _) in &elements {
        *by_file
            .entry(file.file_name().unwrap().to_string_lossy().into_owned())
            .or_default() += 1;
    }
    eprintln!(
        "snippets: {} elements in {} files, {} of them dynamic without a body; {} languages, {} compilations \
         ({} of dynamic payloads Ghidra does not compile itself); Ghidra compiled {}, \
         rejected {}, threw {}; distinct elements compiled {}, rejected by Ghidra in some \
         language {}; differences {}",
        elements.len(),
        by_file.len(),
        without_body.len(),
        total.languages,
        total.records,
        total.dynamic,
        total.ok,
        total.rejected,
        total.exceptions,
        total.distinct.len(),
        total.ghidra_rejects.len(),
        total.mismatches.len()
    );
    for m in total.mismatches.iter().take(20) {
        eprintln!("{m}");
    }
    assert!(total.records > 0, "no snippet was compiled");
    assert_eq!(
        elements.len(),
        137,
        "the shipped trees hold 137 snippet elements outside XML comments"
    );
    assert_eq!(total.distinct.len() + without_body.len(), elements.len());
    assert_eq!(total.mismatches, Vec::<String>::new());
}

fn run_job(
    registry: &bk_lang::LanguageRegistry,
    tool: &std::path::Path,
    root: &std::path::Path,
    job: &Job,
    t: &mut Tally,
) {
    let Some(sla) = common::load_sla(registry, &job.id) else {
        return;
    };
    let mut options = Options::default();
    for (space, size) in &job.truncations {
        options = options.truncate_space(space.clone(), *size);
    }
    let start = TempAllocator::for_injection(sla.header().unique_base).next;
    let records: Vec<Record> = job
        .records
        .iter()
        .map(|r| Record {
            base: match r.base {
                Base::Start(_) => Base::Start(start),
                other => other,
            },
            ..r.clone()
        })
        .collect();
    let compiler = SnippetCompiler::new(&sla, &options);
    let expected = run_oracle(tool, root, &job.id, &records);
    let actual = run_basilisk(&compiler, start, &records);
    t.languages += 1;
    for ((exp, act), origin) in expected.iter().zip(&actual).zip(&job.origins) {
        t.records += 1;
        if origin.dynamic {
            t.dynamic += 1;
        }
        let key = (origin.file.clone(), origin.offset);
        t.distinct.insert(key.clone());
        match exp {
            Outcome::Ok { .. } => t.ok += 1,
            Outcome::Rejected { .. } => {
                t.rejected += 1;
                t.ghidra_rejects.insert(key);
            }
            Outcome::Exception { .. } => {
                t.exceptions += 1;
                t.ghidra_rejects.insert(key);
            }
        }
        if exp != act {
            t.mismatches.push(format!(
                "{} {}:\n  ghidra:   {exp:?}\n  basilisk: {act:?}",
                job.id,
                origin.label()
            ));
        }
    }
}
