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
//! Replays the image oracle (spec 6.2, 6.3): for each of the 93 data tests,
//! Basilisk reads the `<binaryimage>`, the language's `.sla`, `.pspec` and
//! `.cspec`, runs spec 4.18's steps and the loader symbols, and prints the
//! same `K Y R D P B M V c C t T L` rows as `tests/oracle/image.cc`. The
//! `B`/`M` rows are `print map` of the global scope.
//!
//! Needs the reference directory (its compiled `.sla` files and language
//! files) and the Ghidra tree (the data tests); skips with a printed reason
//! when either is missing.

mod common;

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use bk_core::{Address, SpaceManager};
use bk_decomp_symbols::image::{LoadImage, XmlImage};
use bk_decomp_symbols::{ArchEnv, ContextNames, Database, arch, ids};
use bk_decomp_types::{DataOrganization, SpaceInfo, TypeEnv, TypeFactory};
use bk_lang::{LanguageId, LanguageRegistry};
use bk_marshal::{Document, ElementRef, IdTable, XmlDecoder};
use common::oracle::{fnv64, read_table};

fn space_name(m: &SpaceManager, a: Address) -> String {
    m.space_of(a)
        .map_or_else(|| "?".into(), |s| s.name().to_owned())
}

fn child<'a>(root: ElementRef<'a>, name: &str) -> Option<ElementRef<'a>> {
    root.children().find(|c| c.name() == name)
}

/// Runs one data test and appends its rows.
fn one(out: &mut String, path: &Path, registry: &LanguageRegistry, table: &IdTable) {
    let base = path.file_name().unwrap().to_string_lossy();
    let _ = writeln!(out, "F\t{base}");
    let text = std::fs::read_to_string(path).unwrap();
    let doc = Document::parse(&text).unwrap();
    let image_el = child(doc.root(), "binaryimage").expect("binaryimage");
    let archid = image_el.attribute("arch").unwrap();
    let parts: Vec<&str> = archid.split(':').collect();
    let lang_id = LanguageId::new(parts[..4].join(":")).unwrap();
    let desc = registry.language(&lang_id).unwrap();
    let cspec_desc = desc
        .compiler_specs()
        .iter()
        .find(|c| c.id.as_str() == parts[4])
        .or_else(|| desc.default_compiler_spec())
        .unwrap();
    let lang = bk_sleigh::Language::load(registry, &lang_id).unwrap();
    let mut m = SpaceManager::new();
    m.copy_spaces(lang.spaces()).unwrap();
    m.set_registers(Arc::clone(lang.registers()) as Arc<dyn bk_core::RegisterLookup>);
    // The decompiler's own spaces, as Architecture::restoreFromSpec adds them.
    let n = m.num_spaces();
    m.insert_space(bk_core::Space::fspec(n).unwrap()).unwrap();
    m.insert_space(bk_core::Space::iop(n + 1).unwrap()).unwrap();
    m.insert_space(bk_core::Space::join(n + 2, lang.is_big_endian()).unwrap())
        .unwrap();
    let cspec_text = std::fs::read_to_string(&cspec_desc.file).unwrap();
    let _spec = bk_cspec::CompilerSpec::read(&cspec_text, &mut m, bk_cspec::ReadOptions::default())
        .unwrap();
    let spaces = Arc::new(m);
    let mut env = ArchEnv::new(Arc::clone(&spaces));
    let align = lang.alignment() as i32;
    env.min_funcsymbol_size = if align <= 8 { align } else { 1 };
    let data_space = spaces.default_data_space().unwrap();
    let info = |s: &bk_core::Space| SpaceInfo {
        id: s.id(),
        name: s.name().to_owned(),
        addr_size: s.addr_size() as i32,
        word_size: s.word_size(),
        big_endian: s.is_big_endian(),
    };
    let mut tenv = TypeEnv::simple(data_space.addr_size() as i32, data_space.is_big_endian());
    tenv.data_space = info(data_space);
    tenv.other_spaces = spaces
        .spaces()
        .filter(|s| s.id() != data_space.id())
        .map(info)
        .collect();
    let org = DataOrganization::from_cspec(&cspec_text, &tenv).unwrap_or_default();
    let mut types = TypeFactory::with_core_types(tenv, org).unwrap();
    let mut db = Database::new(env, true);
    let mut ctx = ContextNames::new();
    ctx.set_space_limits(&spaces);
    for var in lang.context_variables() {
        ctx.register_variable(var.name(), var.start_bit(), var.end_bit())
            .unwrap();
    }
    // The .pspec, element by element in file order.
    let pspec_text = std::fs::read_to_string(&desc.files().pspec).unwrap();
    let pdoc = Document::parse(&pspec_text).unwrap();
    let mut default_symbols = None;
    for el in pdoc.root().children() {
        let mut dec = XmlDecoder::at(el, table, &*spaces);
        match el.name() {
            "volatile" => arch::decode_volatile(&mut db, &mut dec).unwrap(),
            "incidentalcopy" => arch::decode_incidental_copy(&mut db, &mut dec).unwrap(),
            "register_data" => arch::decode_register_data(&mut db, &mut dec).unwrap(),
            "context_data" => ctx.decode_from_spec(&mut dec, &spaces).unwrap(),
            "default_symbols" => default_symbols = Some(el),
            _ => {}
        }
    }
    // The .cspec.
    let cdoc = Document::parse(&cspec_text).unwrap();
    let mut globals = Vec::new();
    for el in cdoc.root().children() {
        let mut dec = XmlDecoder::at(el, table, &*spaces);
        match el.name() {
            "readonly" => arch::decode_readonly(&mut db, &mut dec).unwrap(),
            "context_data" => ctx.decode_from_spec(&mut dec, &spaces).unwrap(),
            "global" => globals.extend(arch::decode_global(&mut dec).unwrap()),
            _ => {}
        }
    }
    for g in &globals {
        arch::add_to_global_scope(&mut db, g).unwrap();
    }
    arch::add_other_space(&mut db).unwrap();
    db.adjust_caches();
    if let Some(el) = default_symbols {
        let mut dec = XmlDecoder::at(el, table, &*spaces);
        arch::build_default_symbols(&mut db, &mut dec, &mut types).unwrap();
    }
    let mut dec = XmlDecoder::at(image_el, table, &*spaces);
    let image = XmlImage::decode(&mut dec, Arc::clone(&spaces), &path.to_string_lossy()).unwrap();
    arch::fill_readonly_from_image(&mut db, &image);
    arch::read_loader_symbols(&mut db, &image, &mut types).unwrap();

    for (a, v) in image.chunks() {
        let ro = u8::from(image.is_readonly_chunk(*a));
        let _ = writeln!(
            out,
            "K\t{}\t0x{:x}\t{}\t{ro}\t{:x}",
            space_name(&spaces, *a),
            a.offset(),
            v.len(),
            fnv64(v)
        );
    }
    for f in image.symbols() {
        let _ = writeln!(
            out,
            "Y\t{}\t0x{:x}\t{}",
            space_name(&spaces, f.address),
            f.address.offset(),
            f.name
        );
    }
    for r in image.readonly().iter() {
        let _ = writeln!(
            out,
            "R\t{}\t0x{:x}\t0x{:x}",
            space_name(&spaces, r.first_addr()),
            r.first(),
            r.last()
        );
    }
    let _ = writeln!(out, "D\t0x{:x}", db.property_default());
    for (a, v) in db.property_points() {
        let _ = writeln!(
            out,
            "P\t{}\t0x{:x}\t0x{v:x}",
            space_name(&spaces, a),
            a.offset()
        );
    }
    let glob = db.global().unwrap();
    for line in db.print_bounds(glob).unwrap().lines() {
        let _ = writeln!(out, "B\t{line}");
    }
    for line in db.print_entries(glob, &types).unwrap().lines() {
        let _ = writeln!(out, "M\t{line}");
    }
    for (name, var) in ctx.variables() {
        let _ = writeln!(
            out,
            "V\t{name}\t{}\t{}\t{}\t{}\t0x{:x}",
            var.word(),
            var.start_bit() % 32,
            var.end_bit() % 32,
            var.shift(),
            var.value_mask()
        );
    }
    out.push('c');
    for w in ctx.db().default_words() {
        let _ = write!(out, "\t0x{w:x}");
    }
    out.push('\n');
    for (a, words, _) in ctx.db().split_points() {
        let _ = write!(out, "C\t{}\t0x{:x}", space_name(&spaces, a), a.offset());
        for w in words {
            let _ = write!(out, "\t0x{w:x}");
        }
        out.push('\n');
    }
    let tracked = |out: &mut String, set: &[bk_context::TrackedValue]| {
        let _ = write!(out, "{}", set.len());
        for t in set {
            let name = spaces.space(t.space).map_or("?", |s| s.name());
            let _ = write!(
                out,
                "\t({name},0x{:x},{},0x{:x})",
                t.offset, t.size, t.value
            );
        }
        out.push('\n');
    };
    out.push_str("t\t");
    tracked(out, ctx.db().tracked_default());
    for (a, set) in ctx.db().tracked_points() {
        let _ = write!(out, "T\t{}\t0x{:x}\t", space_name(&spaces, a), a.offset());
        tracked(out, set);
    }
    let keys: Vec<(Address, i64)> = image.chunks().map(|(a, v)| (*a, v.len() as i64)).collect();
    let probe = |out: &mut String, a: Address, size: i64| {
        let mut buf = vec![0u8; size.max(1) as usize];
        let _ = write!(
            out,
            "L\t{}\t0x{:x}\t{size}\t",
            space_name(&spaces, a),
            a.offset()
        );
        match image.load_fill(&mut buf[..size as usize], a) {
            Ok(()) => {
                let _ = writeln!(out, "ok\t{:x}", fnv64(&buf[..size as usize]));
            }
            Err(e) => {
                let _ = writeln!(out, "err\t{}", e.message);
            }
        }
    };
    for (a, sz) in keys {
        if a.offset() != 0 {
            probe(out, a.sub(&spaces, 1), 1);
        }
        probe(out, a, sz.min(16));
        if sz >= 2 {
            probe(out, a.add(&spaces, sz - 2), 4);
        }
        probe(out, a.add(&spaces, sz), 1);
        probe(out, a, sz + 1);
    }
}

#[test]
fn image_table_replays() {
    let Some(reference) = bk_testkit::paths::reference_dir() else {
        eprintln!("skipping: no reference directory (the compiled .sla files)");
        return;
    };
    let Some(ghidra) = bk_testkit::paths::ghidra_dir() else {
        eprintln!("skipping: no Ghidra tree (the data tests)");
        return;
    };
    let registry = LanguageRegistry::builder()
        .ghidra_root(ghidra.root())
        .sla_overlay(reference.root())
        .build()
        .unwrap();
    let dt = ghidra
        .root()
        .join("Ghidra/Features/Decompiler/src/decompile/datatests");
    let mut files: Vec<_> = std::fs::read_dir(&dt)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "xml"))
        .collect();
    files.sort_by(|a, b| {
        a.file_name()
            .unwrap()
            .as_encoded_bytes()
            .cmp(b.file_name().unwrap().as_encoded_bytes())
    });
    // The table covers the 93 data tests; a different count means the
    // tree is not the one the table was made from, never a silent pass.
    assert_eq!(files.len(), 93, "data tests in {}", dt.display());
    let table = ids::id_table();
    let want = read_table("image.txt.gz");
    let mut got = String::new();
    for f in &files {
        one(&mut got, f, &registry, &table);
    }
    let w: Vec<&str> = want.lines().collect();
    let g: Vec<&str> = got.lines().collect();
    let mut bad = Vec::new();
    let mut file = "";
    for (i, (a, b)) in w.iter().zip(&g).enumerate() {
        if a.starts_with("F\t") {
            file = a;
        }
        if a != b {
            bad.push(format!("{file} row {i}:\n  want: {a}\n  got:  {b}"));
            if bad.len() >= 10 {
                break;
            }
        }
    }
    assert!(
        bad.is_empty() && w.len() == g.len(),
        "{} rows vs {}; first differences:\n{}",
        w.len(),
        g.len(),
        bad.join("\n")
    );
    eprintln!(
        "image table: {} data tests replayed, {} rows equal",
        files.len(),
        g.len()
    );
}
