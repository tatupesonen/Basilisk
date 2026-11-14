//! Replays the oracle tables (`tests/data/cspec_oracle.{libcxx,libstdcxx}.txt.gz`,
//! from Ghidra's compiled reader and models built against libc++ and
//! libstdc++): every `.cspec` of the spec root is read against the spaces
//! and registers Ghidra had, and every record is produced again and
//! compared with both tables. A row where the tables agree passes only if
//! Basilisk agrees; a row where they disagree passes only if it is one of
//! the counted causes of ADR-040 and Basilisk gives the result the ADR
//! defines (`oracle_common::host`). Needs the spec root (kind G); skipped
//! with a printed reason without it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    clippy::many_single_char_names,
    reason = "test code"
)]

mod common;
mod oracle_common;

use std::collections::BTreeMap;

use bk_core::SpaceManager;
use bk_cspec::list::ParamList;
use bk_cspec::proto::PrototypePieces;
use bk_cspec::types::ParamTypes;
use bk_cspec::{CompilerSpec, ParamActive, ProtoModel, ReadOptions};
use common::cparse;
use common::testtypes::TestTypes;
use oracle_common::describe::{model_records, spec_records};
use oracle_common::host::{self, Cause};
use oracle_common::{Lib, Pair, addr, b, desc, parse_vn, vn};

const SIGNATURES: &str = include_str!("oracle/signatures.txt");

/// Rows per cause where the two tables differ (README, ADR-040). A
/// regenerated table that changes these fails here until they are updated.
const EXPECTED: [(Cause, usize); 4] = [
    (Cause::EffectOrder, 56),
    (Cause::EffectLookup, 24),
    (Cause::IdenticalTrials, 38),
    (Cause::EntrylessTrials, 1),
];

/// Addresses with several effect records in a non-merged model, over all
/// pairs: each must be in document order in Basilisk's list. With the 6 in
/// merged models (intersections of these lists; both tables agree there)
/// they are the 89 ties of the README.
const TIE_GROUPS: usize = 83;

#[derive(Default)]
struct Check {
    rows: usize,
    differ: BTreeMap<String, Vec<String>>,
    causes: BTreeMap<Cause, usize>,
    tie_groups: usize,
}

impl Check {
    /// One row: `a` from libc++, `b` from libstdc++, `got` from Basilisk.
    /// `cause` recognises a row where the tables disagree.
    fn row(
        &mut self,
        kind: &str,
        pair: &str,
        (a, b, got): (&str, &str, &str),
        cause: impl FnOnce() -> Result<Cause, String>,
    ) {
        self.rows += 1;
        if a == b {
            if got != a {
                self.fail(kind, format!("{pair}\n  ghidra:   {a}\n  basilisk: {got}"));
            }
            return;
        }
        match cause() {
            Ok(c) => *self.causes.entry(c).or_default() += 1,
            Err(why) => self.fail(
                &format!("{kind} (tables disagree)"),
                format!("{pair}: {why}\n  libc++:    {a}\n  libstdc++: {b}\n  basilisk:  {got}"),
            ),
        }
    }

    /// A row both tables agree on (inputs such as trial sets).
    fn same(&mut self, kind: &str, pair: &str, want: &str, got: &str) {
        self.row(kind, pair, (want, want, got), || unreachable!());
    }

    fn fail(&mut self, kind: &str, msg: String) {
        self.differ.entry(kind.to_owned()).or_default().push(msg);
    }

    fn report(&self) -> usize {
        let mut total = 0;
        for (k, v) in &self.differ {
            eprintln!("{k}: {} rows", v.len());
            for e in v.iter().take(6) {
                eprintln!("  {e}");
            }
            total += v.len();
        }
        for c in Cause::ALL {
            eprintln!(
                "tables disagree, {}: {} rows",
                c.name(),
                self.causes.get(&c).copied().unwrap_or(0)
            );
        }
        eprintln!(
            "{} rows compared, {total} unexplained; {} effect tie groups in document order",
            self.rows, self.tie_groups
        );
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
) -> Result<(CompilerSpec, SpaceManager, String), String> {
    let mut m = oracle_common::manager(pair);
    let path = files.get(&pair.cspec).ok_or("no such .cspec")?;
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let opts = ReadOptions {
        arch_id: pair.id.clone(),
        ..ReadOptions::default()
    };
    let spec = CompilerSpec::read(&text, &mut m, opts).map_err(|e| e.to_string())?;
    Ok((spec, m, text))
}

/// The two tables' records of one pair.
struct Both<'a> {
    a: &'a Pair,
    b: &'a Pair,
}

impl Both<'_> {
    fn id(&self) -> &str {
        &self.a.id
    }
}

fn compare_rows(c: &mut Check, p: &Both<'_>, kind: &str, mine: &[String]) {
    let (ta, tb) = (p.a.get(kind), p.b.get(kind));
    let n = ta.len().max(mine.len());
    for i in 0..n {
        let w = ta
            .get(i)
            .map_or_else(|| "<none>".to_owned(), |r| r.join("\t"));
        let wb = tb
            .get(i)
            .map_or_else(|| "<none>".to_owned(), |r| r.join("\t"));
        let g = mine.get(i).map_or("<none>", String::as_str);
        c.row(kind, p.id(), (&w, &wb, g), || {
            Err("no cause is known for this kind".into())
        });
    }
}

/// Inputs of [`host::doc_effects`] from the pair's records.
struct DocInputs {
    regs: BTreeMap<String, String>,
    spaces: BTreeMap<String, String>,
    retaddr: Option<String>,
    default_model: String,
}

impl DocInputs {
    fn of(p: &Pair) -> Self {
        let spec = p.get("SPEC").first();
        Self {
            regs: p
                .get("REG")
                .iter()
                .map(|r| (r[0].clone(), r[1].clone()))
                .collect(),
            spaces: p
                .get("SPACE")
                .iter()
                .map(|s| (s[1].clone(), s[0].clone()))
                .collect(),
            retaddr: spec.map(|s| s[5].clone()),
            default_model: spec.map(|s| s[0].clone()).unwrap_or_default(),
        }
    }

    fn effects(&self, cspec: &str, model: &str) -> Result<Vec<(String, String)>, String> {
        let names = host::DocNames {
            regs: &self.regs,
            spaces: &self.spaces,
            default_ret: self.retaddr.as_deref(),
            default_model: &self.default_model,
        };
        host::doc_effects(cspec, model, &names)
    }
}

fn split_rows(rows: &[String]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|r| r.split('\t').map(str::to_owned).collect())
        .collect()
}

/// `EFFECT` rows: compared as the other kinds, a disagreement recognised
/// as cause A; and every address with several records in a non-merged
/// model of Basilisk's must be in document order.
fn compare_effects(c: &mut Check, p: &Both<'_>, spec: &CompilerSpec, cspec: &str, mine: &[String]) {
    let (ta, tb) = (p.a.get("EFFECT"), p.b.get("EFFECT"));
    let got = split_rows(mine);
    let doc = DocInputs::of(p.a);
    if ta.len() != got.len() || tb.len() != got.len() {
        compare_rows(c, p, "EFFECT", mine);
        return;
    }
    let of_model = |rows: &[Vec<String>], model: &str| -> (usize, Vec<Vec<String>>) {
        let first = rows.iter().position(|r| r[0] == model).unwrap_or(0);
        (
            first,
            rows.iter().filter(|r| r[0] == model).cloned().collect(),
        )
    };
    for i in 0..got.len() {
        let (w, wb, g) = (ta[i].join("\t"), tb[i].join("\t"), &mine[i]);
        c.row("EFFECT", p.id(), (&w, &wb, g), || {
            let model = &ta[i][0];
            let (first, la) = of_model(ta, model);
            let (_, lb) = of_model(tb, model);
            let (_, lg) = of_model(&got, model);
            let d = doc.effects(cspec, model)?;
            host::effect_order(&la, &lb, &lg, i - first, &d)
        });
    }
    for name in spec.model_names() {
        let model = spec.model_by_name(name).unwrap();
        if model.is_merged() {
            continue;
        }
        let (_, lg) = of_model(&got, name);
        let mut keys: Vec<&str> = lg
            .iter()
            .map(|r| r[2].rsplit_once(':').unwrap().0)
            .collect();
        keys.dedup();
        let tied: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|k| {
                lg.iter()
                    .filter(|r| r[2].rsplit_once(':').unwrap().0 == *k)
                    .count()
                    > 1
            })
            .collect();
        if tied.is_empty() {
            continue;
        }
        let checked = doc.effects(cspec, name).and_then(|d| {
            tied.iter()
                .try_for_each(|k| host::tie_group_in_doc_order(&lg, k, &d))
        });
        match checked {
            Ok(()) => c.tie_groups += tied.len(),
            Err(e) => c.fail("EFFECT document order", format!("{} {name}: {e}", p.id())),
        }
    }
}

fn decode_dump(c: &mut Check, p: &Both<'_>, spec: &CompilerSpec, m: &SpaceManager, cspec: &str) {
    let pair = p.a;
    for (s, sb) in pair
        .get("SPACE")
        .iter()
        .zip(p.b.get("SPACE"))
        .filter(|(s, _)| s[2] == "2")
    {
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
        let f = |s: &[String]| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                s[1], s[3], s[4], s[5], s[6], s[7], s[9]
            )
        };
        c.row("SPACE", p.id(), (&f(s), &f(sb), &got), || {
            Err("no cause for SPACE".into())
        });
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
        "MODEL", "LIST", "ENTRY", "RULE", "SHARED", "TRASH", "INTERNAL", "LRANGE", "PRANGE",
        "SPEC", "SPLIT", "GLOBAL",
    ] {
        compare_rows(c, p, kind, by.get(kind).map_or(&[], Vec::as_slice));
    }
    compare_effects(
        c,
        p,
        spec,
        cspec,
        by.get("EFFECT").map_or(&[], Vec::as_slice),
    );
    let mine: Vec<String> = mine_inj
        .iter()
        .enumerate()
        .map(|(i, x)| {
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                i as i64 + base,
                x.kind as u8,
                x.name,
                x.inputs.len(),
                x.outputs.len(),
                x.paramshift
            )
        })
        .collect();
    let skip = base.max(0) as usize;
    let theirs = theirs_inj
        .iter()
        .skip(skip)
        .zip(p.b.get("INJ").iter().skip(skip));
    for ((w, wb), g) in theirs.zip(mine.iter()) {
        c.row("INJ", p.id(), (&w.join("\t"), &wb.join("\t"), g), || {
            Err("no cause for INJ".into())
        });
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

/// Rows of one kind from both tables, joined.
fn rows2<'p>(
    p: &'p Both<'_>,
    kind: &str,
) -> impl Iterator<Item = (&'p Vec<String>, String, String)> {
    let tb = p.b.get(kind);
    p.a.get(kind).iter().enumerate().map(move |(i, r)| {
        (
            r,
            r.join("\t"),
            tb.get(i)
                .map_or_else(|| "<none>".to_owned(), |x| x.join("\t")),
        )
    })
}

fn heavy(c: &mut Check, p: &Both<'_>, spec: &CompilerSpec, m: &SpaceManager) {
    let mut types = oracle_common::types(p.a);
    let sigs = sigs();
    for (k, _, text) in &sigs {
        if *k == 'S' {
            cparse::structure(&mut types, text);
        }
    }
    let none = || Err::<Cause, String>("no cause is known for this kind".into());
    for (row, w, wb) in rows2(p, "ASSIGN") {
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
        c.row("ASSIGN", p.id(), (&w, &wb, &got), none);
    }
    for (i, ((set, w, wb), res)) in rows2(p, "TSET").zip(p.a.get("TRES")).enumerate() {
        // The trial sets are the generator's input: the same in both tables.
        c.same("TSET", p.id(), &w, &wb);
        let model = spec.model_by_name(&set[0]).unwrap();
        let got = format!(
            "{}\t{}\t{}\t{}",
            set[0],
            set[1],
            set[2],
            trial_row(model, m, &set[1], &set[3])
        );
        let rb =
            p.b.get("TRES")
                .get(i)
                .map_or_else(|| "<none>".to_owned(), |x| x.join("\t"));
        let ra = res.join("\t");
        let tail = |r: &str| r.splitn(4, '\t').nth(3).unwrap_or("").to_owned();
        let (ta, tb, tg) = (tail(&ra), tail(&rb), tail(&got));
        c.row("TRES", p.id(), (&ra, &rb, &got), || {
            host::trial_row(&ta, &tb, &tg)
        });
    }
    for (row, w, wb) in rows2(p, "Q") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let got = format!(
            "{}\t{}\t{}",
            row[0],
            row[1],
            query_row(list_of(model, &row[1]), m, &row[2])
        );
        c.row("Q", p.id(), (&w, &wb, &got), none);
    }
    for (row, w, wb) in rows2(p, "JOIN") {
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
        c.row("JOIN", p.id(), (&w, &wb, &got), none);
    }
    for (row, w, wb) in rows2(p, "SPLITQ") {
        let model = spec.model_by_name(&row[0]).unwrap();
        let list = list_of(model, &row[1]);
        let e = &list.entries()[row[2].parse::<usize>().unwrap()];
        let r = list.check_split(m, e.address(), e.size(), e.size() / 2);
        let got = format!("{}\t{}\t{}\t{}", row[0], row[1], row[2], b(r));
        c.row("SPLITQ", p.id(), (&w, &wb, &got), none);
    }
    for (i, (row, w, wb)) in rows2(p, "EFF").enumerate() {
        let model = spec.model_by_name(&row[0]).unwrap();
        let v = parse_vn(&row[1]).unwrap();
        let e = (model.has_effect(m, v.addr(), v.size) as u8).to_string();
        let got = format!("{}\t{}\t{e}", row[0], row[1]);
        let vb = p.b.get("EFF").get(i).map_or("", |x| x[2].as_str());
        c.row("EFF", p.id(), (&w, &wb, &got), || {
            host::effect_lookup(model, &row[1], (&row[2], vb, &e))
        });
    }
}

/// The two tables must describe the same pairs with the same records, in
/// the same order and number; only values may differ.
fn aligned(a: &[Pair], b: &[Pair]) {
    assert_eq!(
        a.len(),
        b.len(),
        "the tables hold different numbers of pairs"
    );
    for (x, y) in a.iter().zip(b) {
        assert_eq!(
            (&x.id, &x.cspec, x.heavy),
            (&y.id, &y.cspec, y.heavy),
            "pair order or heavy choice differs"
        );
        let shape = |p: &Pair| {
            p.records
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(x), shape(y), "{}: record counts differ", x.id);
    }
}

#[test]
fn oracle_replays_for_every_cspec() {
    let Some(ghidra) = bk_testkit::skip::require_ghidra() else {
        return;
    };
    let files = oracle_common::cspec_files(&ghidra.processors_dir());
    let [ta, tb] = Lib::ALL.map(oracle_common::table_of);
    let (pairs, errs) = oracle_common::pairs(&ta);
    let (pairs_b, errs_b) = oracle_common::pairs(&tb);
    aligned(&pairs, &pairs_b);
    assert_eq!(errs, errs_b, "the tables fail on different pairs");
    eprintln!(
        "{} pairs, {} failing in Ghidra itself",
        pairs.len(),
        errs.len()
    );
    let mut c = Check::default();
    let mut read_errors = Vec::new();
    let mut cspecs = std::collections::BTreeSet::new();
    for (a, b) in pairs.iter().zip(&pairs_b) {
        let p = Both { a, b };
        match read_pair(a, &files) {
            Err(e) => read_errors.push(format!("{}: {e}", a.id)),
            Ok((spec, m, text)) => {
                cspecs.insert(a.cspec.clone());
                decode_dump(&mut c, &p, &spec, &m, &text);
                if a.heavy {
                    heavy(&mut c, &p, &spec, &m);
                }
            }
        }
    }
    for e in &read_errors {
        eprintln!("read error: {e}");
    }
    let total = c.report();
    eprintln!("{} distinct .cspec files read", cspecs.len());
    assert_eq!(read_errors, Vec::<String>::new(), "pairs failed to read");
    assert_eq!(
        total, 0,
        "{total} rows differ from Ghidra without a known cause"
    );
    let got: Vec<(Cause, usize)> = Cause::ALL
        .iter()
        .map(|c0| (*c0, c.causes.get(c0).copied().unwrap_or(0)))
        .collect();
    assert_eq!(
        got, EXPECTED,
        "rows per cause where libc++ and libstdc++ disagree"
    );
    assert_eq!(
        c.tie_groups, TIE_GROUPS,
        "effect tie groups checked against document order"
    );
}
