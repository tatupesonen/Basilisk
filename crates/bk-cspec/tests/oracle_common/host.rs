//! The rows where Ghidra's answer depends on the C++ standard library it
//! was built with (ADR-038). The oracle exists twice, from libc++ (macOS)
//! and libstdc++ (x86-64 Linux); a row where the two disagree passes only
//! when it is one of the counted causes below and Basilisk gives the
//! result the ADR defines. Each recogniser checks both: that the two
//! tables differ in the way the cause explains, and Basilisk's row.

#![expect(
    clippy::string_slice,
    clippy::indexing_slicing,
    reason = "test code: table rows have the generator's field counts, and the small XML scanner \
              slices at offsets found for ASCII patterns, always char boundaries"
)]

use std::cmp::Ordering;
use std::collections::BTreeMap;

use bk_cspec::{EffectKind, EffectRecord, ProtoModel};

use super::parse_vn;

/// Why the two tables disagree on a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cause {
    /// A. Effects at one address after Ghidra's unstable sort
    /// (`ProtoModel::decode`, fspec.cc:2680): Basilisk keeps document
    /// order, the default return address last.
    EffectOrder,
    /// B. `hasEffect` at an address with several effects
    /// (`ProtoModel::lookupEffect`, fspec.cc:2463, takes the last of the
    /// tied records): Basilisk answers with the last in document order.
    EffectLookup,
    /// C. Two trials with the same address, size and entry
    /// (`ParamActive::sortTrials`, fspec.hh:322, from
    /// `ParamListStandard::buildTrialMap`, fspec.cc:921): the earlier
    /// registered (lower slot) comes first and is the one kept.
    IdenticalTrials,
    /// D. Trials without an entry (operator< fspec.cc:1881 calls them all
    /// equal): Basilisk keeps the order they had before the sort.
    EntrylessTrials,
}

impl Cause {
    pub(crate) const ALL: [Self; 4] = [
        Self::EffectOrder,
        Self::EffectLookup,
        Self::IdenticalTrials,
        Self::EntrylessTrials,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::EffectOrder => "A effect tie order",
            Self::EffectLookup => "B effect lookup in a tie group",
            Self::IdenticalTrials => "C identical trials",
            Self::EntrylessTrials => "D trials without an entry",
        }
    }
}

/// `space:offset` of an `index:hexoffset:size` field: the sort key of
/// Ghidra's `EffectRecord::compareByAddress`.
fn addr_key(vn: &str) -> &str {
    vn.rsplit_once(':').map_or(vn, |(k, _)| k)
}

/// An `EFFECT` row where the tables differ (fields after the pair: model,
/// kind, address). `a`, `b` and `got` are the model's whole effect list
/// from libc++, libstdc++ and Basilisk, `i` the row within it; `doc` the
/// model's records in document order (kind, address), from
/// [`doc_effects`].
pub(crate) fn effect_order(
    a: &[Vec<String>],
    b: &[Vec<String>],
    got: &[Vec<String>],
    i: usize,
    doc: &[(String, String)],
) -> Result<Cause, String> {
    let (ra, rb) = (&a[i], &b[i]);
    if addr_key(&ra[2]) != addr_key(&rb[2]) {
        return Err("the two tables differ at different addresses".into());
    }
    let sorted = |l: &[Vec<String>]| {
        let mut v = l.to_vec();
        v.sort();
        v
    };
    if sorted(a) != sorted(b) || sorted(a) != sorted(got) {
        return Err("the lists are not permutations of each other".into());
    }
    if got
        .get(i)
        .is_none_or(|g| addr_key(&g[2]) != addr_key(&ra[2]))
    {
        return Err("basilisk has another address in this row".into());
    }
    tie_group_in_doc_order(got, addr_key(&ra[2]), doc)?;
    Ok(Cause::EffectOrder)
}

/// Checks that the records of one address in Basilisk's list (`model`,
/// `kind`, `address` fields) are in document order.
pub(crate) fn tie_group_in_doc_order(
    got: &[Vec<String>],
    key: &str,
    doc: &[(String, String)],
) -> Result<(), String> {
    let mut used = vec![false; doc.len()];
    let mut last = None;
    for g in got.iter().filter(|g| addr_key(&g[2]) == key) {
        let pos = doc
            .iter()
            .enumerate()
            .position(|(j, (k, v))| !used[j] && *k == g[1] && *v == g[2])
            .ok_or_else(|| format!("record {} {} not found in the document", g[1], g[2]))?;
        used[pos] = true;
        if last.is_some_and(|l| l > pos) {
            return Err(format!("records at {key} are not in document order"));
        }
        last = Some(pos);
    }
    Ok(())
}

/// An `EFF` row (`hasEffect`) where the tables differ: the probe must hit
/// an address with several effect records in Basilisk's list, both tables'
/// answers must be kinds of those records, and Basilisk's answer must be
/// the last of them (Ghidra's own `upper_bound` rule over document order).
pub(crate) fn effect_lookup(
    model: &ProtoModel,
    probe: &str,
    (a, b, got): (&str, &str, &str),
) -> Result<Cause, String> {
    let v = parse_vn(probe).ok_or("bad probe")?;
    let list = model.effects();
    let key = EffectRecord::new(v, EffectKind::Unknown);
    // upper_bound, as lookupEffect: the first record after the probe.
    let upper = list.partition_point(|r| r.cmp_by_address(&key) != Ordering::Greater);
    let hit = upper
        .checked_sub(1)
        .and_then(|j| list.get(j))
        .ok_or("the probe precedes every record")?;
    let group: Vec<EffectKind> = list
        .iter()
        .filter(|r| r.range.space() == hit.range.space() && r.range.offset == hit.range.offset)
        .map(|r| r.kind)
        .collect();
    if group.len() < 2 {
        return Err("the probe hits an address with one record".into());
    }
    let kinds: Vec<String> = group.iter().map(|k| (*k as u8).to_string()).collect();
    if !kinds.iter().any(|k| k == a) || !kinds.iter().any(|k| k == b) {
        return Err(format!(
            "answers {a}/{b} are not kinds {kinds:?} of the tie group"
        ));
    }
    let want = kinds.last().ok_or("empty group")?;
    if got != want {
        return Err(format!("basilisk {got}, the rule gives {want}"));
    }
    Ok(Cause::EffectLookup)
}

/// One trial of a `TRES` row: address (with size), flags, slot, entry,
/// offset.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Trial<'a> {
    addr: &'a str,
    flags: &'a str,
    slot: i64,
    entry: &'a str,
    offset: &'a str,
}

fn trials(row: &str) -> Option<Vec<Trial<'_>>> {
    row.split(' ')
        .filter(|t| !t.is_empty())
        .map(|t| {
            let f: Vec<&str> = t.split('/').collect();
            Some(Trial {
                addr: f.first()?,
                flags: f.get(1)?,
                slot: f.get(2)?.parse().ok()?,
                entry: f.get(3)?,
                offset: f.get(4)?,
            })
        })
        .collect()
}

fn show(v: &[Trial<'_>]) -> String {
    v.iter()
        .map(|t| format!("{}/{}/{}/{}/{}", t.addr, t.flags, t.slot, t.entry, t.offset))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Cause C's rule applied to a row: in every set of trials with the same
/// address, size and entry, slots ascend in list order (the earlier
/// registered first; flags stay with the position, so the first is the
/// one kept).
fn identical_rule<'a>(v: &[Trial<'a>]) -> Vec<Trial<'a>> {
    let mut out = v.to_vec();
    let mut groups: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    for (j, t) in v.iter().enumerate() {
        if t.entry != "-1" {
            groups.entry((t.addr, t.entry)).or_default().push(j);
        }
    }
    for idx in groups.values().filter(|g| g.len() > 1) {
        let mut slots: Vec<i64> = idx.iter().map(|&j| v[j].slot).collect();
        slots.sort_unstable();
        for (&j, s) in idx.iter().zip(slots) {
            out[j].slot = s;
        }
    }
    out
}

/// A `TRES` row (the trial list after classification) where the tables
/// differ. Recognised as cause C when the rows differ only in the slots of
/// trials sharing address, size and entry, and as D when they differ only
/// in the order of the trials without an entry; in either case both rows
/// must give the same row under the cause's rule, and Basilisk must give
/// that row.
pub(crate) fn trial_row(a: &str, b: &str, got: &str) -> Result<Cause, String> {
    let (Some(ta), Some(tb)) = (trials(a), trials(b)) else {
        return Err("unparsable trial row (an error row?)".into());
    };
    if ta.len() != tb.len() {
        return Err("the rows hold different numbers of trials".into());
    }
    let diff: Vec<usize> = (0..ta.len()).filter(|&j| ta[j] != tb[j]).collect();
    let only_slots = diff.iter().all(|&j| {
        let (x, y) = (&ta[j], &tb[j]);
        x.addr == y.addr
            && x.flags == y.flags
            && x.entry == y.entry
            && x.entry != "-1"
            && x.offset == y.offset
    });
    let only_entryless = diff
        .iter()
        .all(|&j| ta[j].entry == "-1" && tb[j].entry == "-1");
    if only_slots {
        let (want, want_b) = (show(&identical_rule(&ta)), show(&identical_rule(&tb)));
        if want != want_b {
            return Err("the two rows are not the same row under the rule".into());
        }
        if got != want {
            return Err(format!(
                "basilisk differs from the rule\n  rule:     {want}"
            ));
        }
        return Ok(Cause::IdenticalTrials);
    }
    if !only_entryless {
        return Err("the rows differ in more than one way".into());
    }
    // D: the order of the entry-less tail is what the earlier sorts of the
    // same derivation left (several sorts with changing entries in
    // ParamListStandardOut::fillinMapFallback, fspec.cc:1659 and 1708), so
    // it cannot be computed from the row; Basilisk's sort is stable (unit
    // tests in trial.rs). Checked here: the same head and the same tail as
    // a set, the tail all entry-less and last.
    let (sa, sb) = (sorted_tail(&ta), sorted_tail(&tb));
    let tg = trials(got).ok_or("unparsable basilisk row")?;
    let head = |v: &[Trial<'_>]| {
        show(
            &v.iter()
                .filter(|t| t.entry != "-1")
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    let tail_last = |v: &[Trial<'_>]| {
        v.iter()
            .skip_while(|t| t.entry != "-1")
            .all(|t| t.entry == "-1")
    };
    if sa != sb || head(&ta) != head(&tb) {
        return Err("the rows differ in more than the order of entry-less trials".into());
    }
    if head(&tg) != head(&ta) || sorted_tail(&tg) != sa || !tail_last(&tg) {
        return Err("basilisk's row is not the same trials with the same head".into());
    }
    Ok(Cause::EntrylessTrials)
}

fn sorted_tail(v: &[Trial<'_>]) -> Vec<String> {
    let mut t: Vec<String> = v
        .iter()
        .filter(|t| t.entry == "-1")
        .map(|t| show(std::slice::from_ref(t)))
        .collect();
    t.sort();
    t
}

/// Names a model's records are looked up with: the pair's registers and
/// spaces (name → `index:hexoffset:size`, name → index), its default
/// return address and default model.
pub(crate) struct DocNames<'a> {
    pub(crate) regs: &'a BTreeMap<String, String>,
    pub(crate) spaces: &'a BTreeMap<String, String>,
    pub(crate) default_ret: Option<&'a str>,
    pub(crate) default_model: &'a str,
}

/// The effect records of a model in document order (kind number,
/// `index:hexoffset:size`), as `ProtoModel::decode` pushes them before its
/// sort: `<unaffected>`, `<killedbycall>`, `<returnaddress>` children and
/// the register entries of an `<input>` or `<output>` with
/// `killedbycall="true"` (fspec.cc:1229), then the default return address
/// when the model names none (fspec.cc:2676). A `<modelalias>` gives its
/// parent's list, a missing `__thiscall` the default model's (Ghidra makes
/// it an alias of that). Forms this reader does not know (joins, stack
/// entries) are left out; a tie member missing from the result fails the
/// check that uses it.
pub(crate) fn doc_effects(
    cspec: &str,
    model: &str,
    names: &DocNames<'_>,
) -> Result<Vec<(String, String)>, String> {
    let text = strip_comments(cspec);
    let Some(body) = element_body(&text, "prototype", model) else {
        let parent = tags(&text)
            .find(|(n, a)| *n == "modelalias" && attr(a, "name") == Some(model))
            .and_then(|(_, a)| attr(a, "parent"))
            .or_else(|| (model == "__thiscall").then_some(names.default_model))
            .ok_or_else(|| format!("no prototype or alias {model}"))?;
        if parent == model {
            return Err("alias of itself".into());
        }
        return doc_effects(cspec, parent, names);
    };
    let (regs, spaces, default_ret) = (names.regs, names.spaces, names.default_ret);
    let mut out = Vec::new();
    let mut section: Option<&str> = None;
    let mut in_kill_output = false;
    let mut pentry_size: Option<String> = None;
    let mut saw_ret = false;
    for (name, attrs) in tags(body) {
        match name {
            "unaffected" => section = Some("1"),
            "killedbycall" => section = Some("2"),
            "returnaddress" => {
                section = Some("3");
                saw_ret = true;
            }
            "/unaffected" | "/killedbycall" | "/returnaddress" => section = None,
            "input" | "output" => in_kill_output = attr(attrs, "killedbycall") == Some("true"),
            "/input" | "/output" => in_kill_output = false,
            "pentry" => pentry_size = attr(attrs, "maxsize").map(str::to_owned),
            "/pentry" => pentry_size = None,
            "register" | "varnode" => {
                let vn = if name == "register" {
                    attr(attrs, "name").and_then(|r| regs.get(r)).cloned()
                } else {
                    varnode(attrs, spaces)
                };
                if let (Some(kind), Some(vn)) = (section, &vn) {
                    out.push((kind.to_owned(), vn.clone()));
                } else if in_kill_output
                    && name == "register"
                    && let (Some(vn), Some(sz)) = (vn, &pentry_size)
                {
                    let k = addr_key(&vn).to_owned();
                    out.push(("2".to_owned(), format!("{k}:{sz}")));
                }
            }
            _ => {}
        }
    }
    if !saw_ret && let Some(r) = default_ret.filter(|r| *r != "-") {
        out.push(("3".to_owned(), r.to_owned()));
    }
    Ok(out)
}

fn strip_comments(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(s) = rest.find("<!--") {
        out.push_str(&rest[..s]);
        rest = rest[s..].find("-->").map_or("", |e| &rest[s + e + 3..]);
    }
    out.push_str(rest);
    out
}

/// Tags in order: (name, attribute text); closing tags as `/name`.
fn tags(t: &str) -> impl Iterator<Item = (&str, &str)> {
    t.split('<').skip(1).filter_map(|s| {
        let s = s.split('>').next()?;
        let s = s.strip_suffix('/').unwrap_or(s);
        let (name, attrs) = s.split_once(char::is_whitespace).unwrap_or((s, ""));
        (!name.starts_with('?') && !name.starts_with('!')).then_some((name, attrs))
    })
}

fn attr<'a>(attrs: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("{name}=\"");
    let mut search = attrs;
    loop {
        let p = search.find(&pat)?;
        let before = search[..p].chars().last();
        let rest = &search[p + pat.len()..];
        if before.is_none_or(char::is_whitespace) {
            return rest.split('"').next();
        }
        search = rest;
    }
}

/// The text inside `<tag name="NAME" …>…</tag>`.
fn element_body<'a>(t: &'a str, tag: &str, name: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0;
    while let Some(p) = t[from..].find(&open) {
        let start = from + p;
        let head_end = start + t[start..].find('>')?;
        let head = &t[start + open.len()..head_end];
        from = head_end;
        if attr(head, "name") == Some(name) {
            let end = head_end + t[head_end..].find(&close)?;
            return Some(&t[head_end + 1..end]);
        }
    }
    None
}

fn varnode(attrs: &str, spaces: &BTreeMap<String, String>) -> Option<String> {
    let space = spaces.get(attr(attrs, "space")?)?;
    let off = attr(attrs, "offset")?;
    let off = match off.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok()?,
        None => off.parse().ok()?,
    };
    let size: u32 = attr(attrs, "size")?.parse().ok()?;
    Some(format!("{space}:{off:x}:{size}"))
}
