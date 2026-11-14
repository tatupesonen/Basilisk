//! Replays the oracle table (`tests/data/cspec_oracle.txt.gz`, from
//! Ghidra's compiled reader and models): every `.cspec` of the spec root is
//! read against the spaces and registers Ghidra had, and every record of
//! the table is produced again and compared. Needs the spec root (kind G);
//! skipped with a printed reason without it.

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
mod oracle_common;

use std::collections::BTreeMap;

use bk_core::{Address, SpaceManager, SpaceType};
use bk_cspec::list::ParamList;
use bk_cspec::proto::PrototypePieces;
use bk_cspec::types::ParamTypes;
use bk_cspec::{CompilerSpec, ParamActive, ProtoModel, ReadOptions};
use common::cparse;
use common::testtypes::TestTypes;
use oracle_common::describe::{model_records, spec_records};
use oracle_common::{Pair, addr, b, desc, parse_vn, vn};

const SIGNATURES: &str = include_str!("oracle/signatures.txt");

#[derive(Default)]
struct Diffs {
    by_kind: BTreeMap<String, Vec<String>>,
    rows: usize,
}

impl Diffs {
    fn check(&mut self, kind: &str, pair: &str, want: &str, got: &str) {
        self.rows += 1;
        if want != got {
            self.by_kind
                .entry(kind.to_owned())
                .or_default()
                .push(format!("{pair}\n  ghidra:   {want}\n  basilisk: {got}"));
        }
    }

    /// As [`Diffs::check`], but rows equal after `norm` count as the
    /// known difference `known` instead.
    fn check_norm(
        &mut self,
        kind: &str,
        pair: &str,
        (want, got): (&str, &str),
        norm: fn(&str) -> String,
        known: &str,
    ) {
        if want != got && norm(want) == norm(got) {
            self.rows += 1;
            self.by_kind
                .entry(known.to_owned())
                .or_default()
                .push(format!("{pair}\n  ghidra:   {want}\n  basilisk: {got}"));
            return;
        }
        self.check(kind, pair, want, got);
    }

    fn report(&self) -> usize {
        let mut total = 0;
        for (k, v) in &self.by_kind {
            eprintln!("{k}: {} differing rows", v.len());
            for e in v.iter().take(6) {
                eprintln!("  {e}");
            }
            total += v.len();
        }
        eprintln!("{} rows compared, {total} differ", self.rows);
        total
    }
}

fn sigs() -> Vec<(char, i32, String)> {
    SIGNATURES
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let kind = l.chars().next().unwrap();
            if kind == 'V' {
                let (n, rest) = l.get(2..).unwrap().split_once(' ').unwrap();
                (kind, n.parse().unwrap(), rest.to_owned())
            } else {
                (kind, -1, l.get(2..).unwrap().to_owned())
            }
        })
        .collect()
}

fn read_pair(
    pair: &Pair,
    files: &BTreeMap<String, std::path::PathBuf>,
) -> Result<(CompilerSpec, SpaceManager), String> {
    let mut m = oracle_common::manager(pair);
    let path = files.get(&pair.cspec).ok_or("no such .cspec")?;
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let opts = ReadOptions {
        arch_id: pair.id.clone(),
        ..ReadOptions::default()
    };
    let spec = CompilerSpec::read(&text, &mut m, opts).map_err(|e| e.to_string())?;
    Ok((spec, m))
}

fn compare_rows(d: &mut Diffs, pair: &Pair, kind: &str, mine: &[String]) {
    let theirs: Vec<String> = pair.get(kind).iter().map(|r| r.join("\t")).collect();
    let n = theirs.len().max(mine.len());
    for i in 0..n {
        let w = theirs.get(i).map_or("<none>", String::as_str);
        let g = mine.get(i).map_or("<none>", String::as_str);
        d.check(kind, &pair.id, w, g);
    }
}

fn decode_dump(d: &mut Diffs, pair: &Pair, spec: &CompilerSpec, m: &SpaceManager) {
    for s in pair.get("SPACE").iter().filter(|s| s[2] == "2") {
        let index: u32 = s[0].parse().unwrap();
        let got = m.space_at(index).map_or_else(
            || "<none>".to_owned(),
            |sp| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    sp.name(),
                    sp.addr_size(),
                    sp.word_size(),
                    b(sp.is_big_endian()),
                    sp.delay(),
                    sp.deadcode_delay(),
                    b(sp.is_reverse_justified())
                )
            },
        );
        let want = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s[1], s[3], s[4], s[5], s[6], s[7], s[9]
        );
        d.check("SPACE", &pair.id, &want, &got);
    }
    let theirs_inj = pair.get("INJ");
    let mine_inj = spec.injects().payloads();
    let base = theirs_inj.len() as i64 - mine_inj.len() as i64;
    let mut recs = Vec::new();
    for name in spec.model_names() {
        model_records(spec, spec.model_by_name(name).unwrap(), base, &mut recs);
    }
    spec_records(spec, m, &mut recs);
    let mut by: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in recs {
        by.entry(k).or_default().push(v);
    }
    for kind in [
        "MODEL", "LIST", "ENTRY", "RULE", "SHARED", "EFFECT", "TRASH", "INTERNAL", "LRANGE",
        "PRANGE", "SPEC", "SPLIT", "GLOBAL",
    ] {
        compare_rows(d, pair, kind, by.get(kind).map_or(&[], Vec::as_slice));
    }
    let mine: Vec<String> = mine_inj
        .iter()
        .enumerate()
        .map(|(i, p)| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                i as i64 + base,
                p.kind as u8,
                p.name,
                p.inputs.len(),
                p.outputs.len(),
                p.paramshift
            )
        })
        .collect();
    let theirs: Vec<String> = theirs_inj
        .iter()
        .skip(base.max(0) as usize)
        .map(|r| r.join("\t"))
        .collect();
    for (w, g) in theirs.iter().zip(mine.iter()) {
        d.check("INJ", &pair.id, w, g);
    }
}

fn assign_row(
    model: &ProtoModel,
    m: &SpaceManager,
    types: &mut TestTypes,
    proto: &PrototypePieces,
) -> String {
    let mut res = Vec::new();
    match model.assign_parameter_storage(m, types, proto, &mut res, false) {
        Err(e) => format!("ERR {}", e.message()),
        Ok(()) => res
            .iter()
            .map(|p| {
                let a = if p.addr.is_invalid() {
                    "-".to_owned()
                } else {
                    addr(p.addr, types.size(p.ty))
                };
                format!("{a}/{}/{}", p.flags.bits(), desc(types, p.ty))
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn list_of<'a>(model: &'a ProtoModel, io: &str) -> &'a ParamList {
    if io == "in" {
        model.input()
    } else {
        model.output()
    }
}

fn trial_row(model: &ProtoModel, m: &SpaceManager, io: &str, set: &str) -> String {
    let mut active = ParamActive::new(false);
    for t in set.split(' ').filter(|s| !s.is_empty()) {
        let v = parse_vn(t).unwrap();
        let i = active.register_trial(m, v.addr(), v.size as i32);
        active.trial_mut(i).unwrap().mark_active();
    }
    let r = if io == "in" {
        model.derive_input_map(m, &mut active)
    } else {
        model.derive_output_map(m, &mut active)
    };
    if let Err(e) = r {
        return format!("ERR {}", e.message());
    }
    active
        .trials()
        .iter()
        .map(|t| {
            format!(
                "{}/{}/{}/{}/{}",
                addr(t.addr, t.size),
                t.flags.bits() & 0x7ff,
                t.slot,
                t.entry.map_or(-1, |e| e as i64),
                t.offset
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn query_row(list: &ParamList, m: &SpaceManager, probe: &str) -> String {
    let v = parse_vn(probe).unwrap();
    let (a, sz) = (v.addr(), v.size as i32);
    let ws = list
        .possible_param_with_slot(m, a, sz)
        .map_or_else(|| "-".to_owned(), |(s, n)| format!("{s},{n}"));
    let opt = |o: Option<bk_core::VarnodeData>| o.map_or_else(|| "-".to_owned(), |v| vn(&v));
    let (ext, res) = list.assumed_extension(m, a, sz);
    let mut e = ext.opcode_name().to_owned();
    if let Some(r) = res {
        e.push(' ');
        e.push_str(&vn(&r));
    }
    format!(
        "{probe}\t{}\t{ws}\t{}\t{}\t{}\t{e}",
        b(list.possible_param(m, a, sz)),
        list.characterize(m, a, sz) as u8,
        opt(list.biggest_contained_param(m, a, sz)),
        opt(list.unjustified_container(m, a, sz)),
    )
}

fn heavy(d: &mut Diffs, pair: &Pair, spec: &CompilerSpec, m: &SpaceManager) {
    let mut types = oracle_common::types(pair);
    let sigs = sigs();
    for (k, _, text) in &sigs {
        if *k == 'S' {
            cparse::structure(&mut types, text);
        }
    }
    for row in pair.get("ASSIGN") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let (kind, var, text) = &sigs[row[1].parse::<usize>().unwrap()];
        let mut proto = cparse::proto(&mut types, model.name(), text);
        if *kind == 'V' {
            proto.first_vararg = *var;
        }
        let got = format!(
            "{}\t{}\t{}",
            row[0],
            row[1],
            assign_row(model, m, &mut types, &proto)
        );
        d.check("ASSIGN", &pair.id, &row.join("\t"), &got);
    }
    let sets = pair.get("TSET");
    for (set, res) in sets.iter().zip(pair.get("TRES")) {
        let model = spec.model_by_name(&set[0]).unwrap();
        let got = format!(
            "{}\t{}\t{}\t{}",
            set[0],
            set[1],
            set[2],
            trial_row(model, m, &set[1], &set[3])
        );
        d.check_norm(
            "TRES",
            &pair.id,
            (&res.join("\t"), &got),
            unordered_tail,
            "known: trials without an entry, in library order",
        );
    }
    for row in pair.get("Q") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let got = format!(
            "{}\t{}\t{}",
            row[0],
            row[1],
            query_row(list_of(model, &row[1]), m, &row[2])
        );
        d.check("Q", &pair.id, &row.join("\t"), &got);
    }
    for row in pair.get("JOIN") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let list = list_of(model, &row[1]);
        let hi = &list.entries()[row[2].parse::<usize>().unwrap()];
        let lo = &list.entries()[row[3].parse::<usize>().unwrap()];
        let hs = if hi.align() != 0 {
            hi.align()
        } else {
            hi.size()
        };
        let ls = if lo.align() != 0 {
            lo.align()
        } else {
            lo.size()
        };
        let r = list.check_join(m, (hi.address(), hs), (lo.address(), ls));
        let got = format!("{}\t{}\t{}\t{}\t{}", row[0], row[1], row[2], row[3], b(r));
        d.check("JOIN", &pair.id, &row.join("\t"), &got);
    }
    for row in pair.get("SPLITQ") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let list = list_of(model, &row[1]);
        let e = &list.entries()[row[2].parse::<usize>().unwrap()];
        let r = list.check_split(m, e.address(), e.size(), e.size() / 2);
        let got = format!("{}\t{}\t{}\t{}", row[0], row[1], row[2], b(r));
        d.check("SPLITQ", &pair.id, &row.join("\t"), &got);
    }
    for row in pair.get("EFF") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let v = parse_vn(&row[1]).unwrap();
        let e = model.has_effect(m, v.addr(), v.size);
        let got = format!("{}\t{}\t{}", row[0], row[1], e as u8);
        d.check("EFF", &pair.id, &row.join("\t"), &got);
    }
}

/// The trials that matched no entry sort last in an order Ghidra leaves
/// to `std::sort` (libc++ here, libstdc++ on Linux); basilisk keeps them in
/// registration order. Sorts them so the rest can be compared.
fn unordered_tail(row: &str) -> String {
    let (head, tail): (Vec<&str>, Vec<&str>) = row
        .split(' ')
        .partition(|t| t.split('/').nth(3) != Some("-1"));
    let mut tail = tail;
    tail.sort_unstable();
    format!("{} | {}", head.join(" "), tail.join(" "))
}

/// Rows whose difference is explained (spec section 8 and the host
/// dependence of Ghidra's own sorts).
fn known(kind: &str) -> bool {
    kind.starts_with("known:")
}

#[test]
fn oracle_replays_for_every_cspec() {
    let Some(ghidra) = bk_testkit::skip::require_ghidra() else {
        return;
    };
    let files = oracle_common::cspec_files(&ghidra.processors_dir());
    let text = oracle_common::table();
    let (pairs, errs) = oracle_common::pairs(&text);
    eprintln!(
        "{} pairs, {} failing in Ghidra itself",
        pairs.len(),
        errs.len()
    );
    let mut d = Diffs::default();
    let mut read_errors = Vec::new();
    let mut cspecs = std::collections::BTreeSet::new();
    for pair in &pairs {
        match read_pair(pair, &files) {
            Err(e) => read_errors.push(format!("{}: {e}", pair.id)),
            Ok((spec, m)) => {
                cspecs.insert(pair.cspec.clone());
                decode_dump(&mut d, pair, &spec, &m);
                if pair.heavy {
                    heavy(&mut d, pair, &spec, &m);
                }
            }
        }
    }
    for e in &read_errors {
        eprintln!("read error: {e}");
    }
    let total = d.report();
    eprintln!("{} distinct .cspec files read", cspecs.len());
    assert!(
        read_errors.is_empty(),
        "{} pairs failed to read",
        read_errors.len()
    );
    let unexplained: usize = d
        .by_kind
        .iter()
        .filter(|(k, _)| !known(k))
        .map(|(_, v)| v.len())
        .sum();
    assert_eq!(unexplained, 0, "{total} rows differ from Ghidra");
    let _ = (Address::INVALID, SpaceType::Join);
}
