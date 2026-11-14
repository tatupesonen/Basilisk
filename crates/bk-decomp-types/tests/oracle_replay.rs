//! Replays the oracle table `tests/data/types_oracle.txt.gz` (Ghidra's
//! compiled `TypeFactory` and C parser on `tests/oracle/decls.txt` for six
//! languages; see `tests/oracle/types_oracle.cc`): every record is rebuilt
//! with basilisk and compared line for line. Kind S: needs nothing outside
//! the repository.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    clippy::string_slice,
    clippy::many_single_char_names,
    clippy::format_push_string,
    reason = "test code"
)]

mod oracle_common;

use std::collections::BTreeMap;
use std::path::Path;

use bk_decomp_types::cdecl::{self, Declaration};
use bk_decomp_types::{Metatype, TypeFactory, TypeId, TypeKind};
use oracle_common::{env_from, esc, org_fields, org_from, table};

fn raw(f: &TypeFactory, t: Option<TypeId>) -> String {
    t.map_or_else(|| "null".to_owned(), |t| esc(&f.print_raw(t)))
}

fn desc(f: &TypeFactory, t: TypeId) -> String {
    let e = f.get(t).unwrap();
    format!(
        "{:x}\t{}\t{}\t{}\t{}\t{}\t{:x}\t{}\t{}",
        e.id(),
        e.size(),
        e.alignment(),
        e.align_size(),
        e.metatype() as u8,
        e.submeta() as u8,
        e.flags().bits(),
        raw(f, Some(t)),
        esc(e.name())
    )
}

fn xml(f: &TypeFactory, t: TypeId) -> String {
    esc(&f.encode_type_text(t).unwrap())
}

/// Builds every record the oracle prints for one language.
/// Returns the indices of declarations whose type involves a function type
/// with a signature.
fn records(
    lang: &str,
    env_line: &[&str],
    org_line: &[&str],
    decls: &[String],
    out: &mut Vec<String>,
) -> Vec<usize> {
    let env = env_from(env_line);
    let org = org_from(org_line);
    let mut f = TypeFactory::with_core_types(env, org).unwrap();
    out.push(format!(
        "ORG\t{lang}\t{}",
        org_fields(f.data_organization())
    ));
    let mut enc = bk_marshal::XmlEncoder::new(false);
    f.encode_core_types(&mut enc).unwrap();
    out.push(format!("CORE\t{lang}\t{}", esc(enc.as_str())));
    let mut res: Vec<Option<TypeId>> = vec![None; decls.len()];
    for (i, d) in decls.iter().enumerate() {
        let (kind, text) = d.split_at(2);
        if kind.starts_with('T') {
            match cdecl::parse_type(&mut f, text, &cdecl::no_models) {
                Ok((t, name)) => {
                    res[i] = Some(t);
                    out.push(format!(
                        "D\t{lang}\t{i}\tOK\t{}\t{}",
                        desc(&f, t),
                        esc(&name)
                    ));
                    composite(&f, lang, i, t, out);
                }
                Err(e) => out.push(format!("D\t{lang}\t{i}\tERR\t{}", esc(&e.to_string()))),
            }
        } else {
            match cdecl::parse_declaration(&mut f, text, &cdecl::no_models) {
                // Ghidra's parse_C hands a prototype to
                // Architecture::setPrototype, which fails without a
                // function of that name; here it is returned to the caller.
                Ok(Declaration::Prototype(p)) => {
                    out.push(format!(
                        "D\t{lang}\t{i}\tERR\tUnknown function name: {}",
                        p.name
                    ));
                }
                Ok(_) => out.push(format!("D\t{lang}\t{i}\tDONE")),
                Err(e) => out.push(format!("D\t{lang}\t{i}\tERR\t{}", esc(&e.to_string()))),
            }
        }
    }
    for (i, a) in res.iter().enumerate() {
        let Some(a) = *a else { continue };
        let (mut cmp, mut dep) = (String::new(), String::new());
        for b in &res {
            match b {
                None => {
                    cmp.push('.');
                    dep.push('.');
                }
                Some(b) => {
                    cmp.push(match f.compare_raw(a, *b, 10) {
                        c if c < 0 => '<',
                        0 => '=',
                        _ => '>',
                    });
                    dep.push(if f.compare_dependency(a, *b) == 0 {
                        '0'
                    } else {
                        '1'
                    });
                }
            }
        }
        out.push(format!("CMP\t{lang}\t{i}\t{cmp}"));
        out.push(format!("DEP\t{lang}\t{i}\t{dep}"));
    }
    for (i, t) in res.iter().enumerate() {
        let Some(t) = *t else { continue };
        out.push(format!("E\t{lang}\t{i}\t{}", xml(&f, t)));
        let e = f.get(t).unwrap();
        if e.is_enum() && e.metatype() != Metatype::Ptr {
            let mut vals: Vec<u64> = (0..1024).collect();
            let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
            for k in 0..64u64 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                vals.push(x);
                vals.push(!k);
            }
            for v in vals {
                let rep = f.enum_matches(t, v);
                let names: Vec<String> = rep.names.iter().map(|n| esc(n)).collect();
                out.push(format!(
                    "M\t{lang}\t{i}\t{v:x}\t{}\t{}\t{}",
                    i32::from(rep.complement),
                    rep.shift,
                    names.join(",")
                ));
            }
        }
    }
    let mut enc = bk_marshal::XmlEncoder::new(false);
    f.encode(&mut enc).unwrap();
    out.push(format!("G\t{lang}\t{}", esc(enc.as_str())));
    for (i, t) in res.iter().enumerate() {
        let Some(t) = *t else { continue };
        if let Err(e) = queries(&mut f, lang, i, t, out) {
            out.push(format!("Q\t{lang}\t{i}\terror\t-\t{}", esc(&e.to_string())));
        }
    }
    res.iter()
        .enumerate()
        .filter_map(|(i, t)| t.filter(|&t| involves_signature(&f, t)).map(|_| i))
        .collect()
}

fn involves_signature(f: &TypeFactory, t: TypeId) -> bool {
    let mut cur = t;
    for _ in 0..8 {
        let e = f.get(cur).unwrap();
        if e.signature().is_some() {
            return true;
        }
        match f.depend(cur, 0) {
            Some(d) if matches!(e.metatype(), Metatype::Ptr | Metatype::Array) => cur = d,
            _ => return false,
        }
    }
    false
}

fn composite(f: &TypeFactory, lang: &str, i: usize, t: TypeId, out: &mut Vec<String>) {
    let e = f.get(t).unwrap();
    for (k, fl) in e.fields().iter().enumerate() {
        out.push(format!(
            "F\t{lang}\t{i}\t{k}\t{}\t{}\t{}\t{}",
            fl.offset,
            fl.ident,
            esc(&fl.name),
            raw(f, Some(fl.ty))
        ));
    }
    for (k, b) in e.bitfields().iter().enumerate() {
        let r = &b.bits;
        out.push(format!(
            "B\t{lang}\t{i}\t{k}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.byte_offset,
            r.byte_size,
            r.least_sig_bit,
            r.num_bits,
            b.ident,
            esc(&b.name),
            raw(f, Some(b.ty))
        ));
    }
}

fn queries(
    f: &mut TypeFactory,
    lang: &str,
    i: usize,
    t: TypeId,
    out: &mut Vec<String>,
) -> bk_decomp_types::Result<()> {
    let e = f.get(t).unwrap().clone();
    let m = e.metatype();
    let top = (e.size() + 2).min(40);
    if matches!(m, Metatype::Struct | Metatype::Union | Metatype::Array) {
        for off in 0..top {
            let (sub, newoff) = f.sub_type(t, i64::from(off));
            out.push(format!(
                "Q\t{lang}\t{i}\tsub\t{off}\t{},{newoff}",
                raw(f, sub)
            ));
            out.push(format!(
                "Q\t{lang}\t{i}\thole\t{off}\t{}",
                f.hole_size(t, off)
            ));
            for hint in [1u32, 4] {
                let r = f.nearest_arrayed_component(t, i64::from(off), hint);
                out.push(format!(
                    "Q\t{lang}\t{i}\tnearest\t{off},{hint}\t{},{}",
                    i32::from(r.is_some()),
                    r.unwrap_or(0)
                ));
            }
            for sz in [1, 2, 4, 8] {
                let (small, noff) = f.find_smallest_container(t, i64::from(off), i64::from(sz));
                out.push(format!(
                    "Q\t{lang}\t{i}\tsmallest\t{off},{sz}\t{},{noff}",
                    raw(f, Some(small))
                ));
                let piece = f.exact_piece(t, off, sz)?;
                let mut line = format!("Q\t{lang}\t{i}\tpiece\t{off},{sz}\t{}", raw(f, piece));
                if let Some(p) = piece {
                    let pe = f.get(p).unwrap();
                    line.push_str(&format!(
                        ",{},{},{:x}",
                        pe.metatype() as u8,
                        pe.submeta() as u8,
                        pe.flags().bits()
                    ));
                }
                out.push(line);
            }
        }
    }
    if matches!(
        m,
        Metatype::Int | Metatype::Uint | Metatype::Unknown | Metatype::Bool
    ) {
        for sz in [1, 2, 4, 8] {
            let r = f.resize_integer(t, sz)?;
            out.push(format!("Q\t{lang}\t{i}\tresize\t{sz}\t{}", raw(f, Some(r))));
        }
    }
    let c = f.concretize(t)?;
    out.push(format!(
        "Q\t{lang}\t{i}\tconcretize\t-\t{}",
        raw(f, Some(c))
    ));
    let psize = f.data_organization().size_of_pointer;
    let ps = f.pointer_strip_array(psize, t, 1)?;
    let pe = f.get(ps).unwrap();
    out.push(format!(
        "Q\t{lang}\t{i}\tstrip\t-\t{},{},{:x}",
        raw(f, Some(ps)),
        pe.submeta() as u8,
        pe.flags().bits()
    ));
    if m == Metatype::Struct && e.size() > 0 {
        let p = f.pointer(psize, t, 1)?;
        for off in 1..top {
            let to = f.ptr_to_from_parent(t, off)?;
            let rel = f.pointer_rel(p, to, off)?;
            let re = f.get(rel).unwrap();
            let stripped = match re.kind() {
                TypeKind::PointerRel { stripped, .. } => *stripped,
                _ => None,
            };
            out.push(format!(
                "Q\t{lang}\t{i}\trel\t{off}\t{},{},{:x},{}",
                raw(f, Some(rel)),
                re.submeta() as u8,
                re.flags().bits(),
                raw(f, stripped)
            ));
        }
    }
    Ok(())
}

/// Records whose difference from Ghidra is deliberate (spec section 8).
fn known_difference(
    e: &str,
    g: &str,
    functions: &BTreeMap<String, Vec<usize>>,
) -> Option<&'static str> {
    // Function types: storage of the prototype belongs to bk-cspec; the
    // signature codec writes a reduced <prototype> (spec 4.7).
    if e.contains("<prototype") || g.contains("<prototype") {
        return Some("prototype encoding");
    }
    let (fe, fg): (Vec<&str>, Vec<&str>) = (e.split('\t').collect(), g.split('\t').collect());
    if fe.len() != fg.len() || fe.len() < 3 || fe[..2] != fg[..2] {
        return None;
    }
    match fe[0] {
        // The factory's order follows creation where Ghidra's follows heap
        // addresses (spec 4.3): the same types, listed in another order.
        "G" => (top_level(fe[2]) == top_level(fg[2])).then_some("dependency order"),
        // Comparing function types needs the parameter storage the model
        // assigns (Ghidra drops all parameters when assignment fails, as on
        // 8051): differences only in columns of function types.
        "CMP" | "DEP" => {
            let idx: Vec<usize> = functions.get(fe[1]).cloned().unwrap_or_default();
            let row: usize = fe[2].parse().ok()?;
            let all = fe[3]
                .chars()
                .zip(fg[3].chars())
                .enumerate()
                .all(|(j, (a, b))| a == b || idx.contains(&j) || idx.contains(&row));
            all.then_some("function signature storage")
        }
        _ => None,
    }
}

/// The top-level elements of an XML text, sorted.
fn top_level(text: &str) -> Vec<String> {
    let inner = text
        .trim_start_matches("<typegrp>")
        .trim_end_matches("</typegrp>");
    let bytes = inner.as_bytes();
    let (mut depth, mut start, mut out) = (0i32, 0usize, Vec::new());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let close = bytes.get(i + 1) == Some(&b'/');
            let end = inner[i..].find('>').map_or(bytes.len(), |e| i + e);
            let selfclose = end > 0 && bytes.get(end - 1) == Some(&b'/');
            if close {
                depth -= 1;
            } else if !selfclose {
                depth += 1;
            }
            i = end + 1;
            if depth == 0 {
                out.push(inner[start..i].to_owned());
                start = i;
            }
        } else {
            i += 1;
        }
    }
    out.sort();
    out
}

#[test]
fn oracle_table_replays() {
    let lines = table("types_oracle.txt.gz");
    let decl_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("oracle")
        .join("decls.txt");
    let decls: Vec<String> = std::fs::read_to_string(&decl_path)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    let mut expected: Vec<String> = Vec::new();
    let mut envs: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    for l in &lines {
        let fields: Vec<&str> = l.split('\t').collect();
        match fields[0] {
            "ENV" => envs.push((
                fields[1].to_owned(),
                fields[2..].iter().map(|s| (*s).to_owned()).collect(),
                Vec::new(),
            )),
            "ORG" => {
                envs.last_mut().unwrap().2 = fields[2..].iter().map(|s| (*s).to_owned()).collect();
                expected.push(l.clone());
            }
            "H" => {}
            _ => expected.push(l.clone()),
        }
    }
    let mut got = Vec::new();
    let mut functions = BTreeMap::new();
    for (lang, env, org) in &envs {
        let env: Vec<&str> = env.iter().map(String::as_str).collect();
        let org: Vec<&str> = org.iter().map(String::as_str).collect();
        functions.insert(lang.clone(), records(lang, &env, &org, &decls, &mut got));
    }
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut shown = 0;
    let mut known: BTreeMap<&str, usize> = BTreeMap::new();
    let n = expected.len().max(got.len());
    for k in 0..n {
        let (e, g) = (expected.get(k), got.get(k));
        if e == g {
            continue;
        }
        let e = e.map_or("", String::as_str);
        let g = g.map_or("", String::as_str);
        if let Some(why) = known_difference(e, g, &functions) {
            *known.entry(why).or_default() += 1;
            continue;
        }
        let kind = e.split('\t').next().unwrap_or("?").to_owned();
        *by_kind.entry(kind).or_default() += 1;
        if shown < 12 {
            let at = e
                .bytes()
                .zip(g.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            let from = at.saturating_sub(150);
            eprintln!(
                "line {k} at {at}\n  ghidra:   {}\n  basilisk: {}",
                truncate(e.get(from..).unwrap_or(e)),
                truncate(g.get(from..).unwrap_or(g))
            );
            shown += 1;
        }
    }
    eprintln!("{n} records; known differences: {known:?}");
    assert!(by_kind.is_empty(), "differing records by kind: {by_kind:?}");
    assert_eq!(expected.len(), got.len());
}

fn truncate(s: &str) -> String {
    if s.len() > 400 {
        let mut end = 400;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    } else {
        s.to_owned()
    }
}

#[test]
fn hash_name_table() {
    let mut count = 0;
    for l in table("types_oracle.txt.gz") {
        let fields: Vec<&str> = l.split('\t').collect();
        if fields[0] != "H" {
            continue;
        }
        let bytes: Vec<u8> = (0..fields[1].len() / 2)
            .map(|i| u8::from_str_radix(&fields[1][2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let expected = u64::from_str_radix(fields[2], 16).unwrap();
        // Names with bytes >= 0x80 that are not UTF-8 cannot be a Rust
        // `str`; hash the bytes through the same routine.
        let got = bk_decomp_types::entry::hash_name_bytes(&bytes);
        assert_eq!(got, expected, "{}", fields[1]);
        count += 1;
    }
    assert_eq!(count, 1000);
}
