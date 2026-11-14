//! Tests of the demo source through the data interface.

use super::*;
use crate::model::{RefKind, Referent, RowContent, TokenKind};

fn licd() -> DemoProgram {
    DemoProgram::licd().unwrap()
}

fn addr_of(p: &DemoProgram, name: &str) -> Address {
    p.lookup(name, 5)
        .unwrap()
        .into_iter()
        .find(|s| &*s.name == name)
        .unwrap()
        .address
}

#[test]
fn opens_at_main_with_a_full_listing() {
    let p = licd();
    assert_eq!(p.info().name, "licd");
    assert_eq!(p.info().entry, addr_of(&p, "main"));
    let n = p.listing_len().unwrap();
    assert!(n > 2000, "{n} rows");
    // The whole listing pages through without gaps.
    let mut seen = 0;
    while seen < n {
        let rows = p.listing_rows(RowIndex(seen), 500).unwrap();
        assert_ne!(rows, []);
        seen += rows.len() as u64;
    }
    assert_eq!(seen, n);
}

#[test]
fn function_header_has_ghidra_shape() {
    let p = licd();
    let main = addr_of(&p, "main");
    let span = p.rows_for_address(main).unwrap();
    let rows = p
        .listing_rows(span.first, (span.unit.0 - span.first.0 + 1) as u32)
        .unwrap();
    assert!(matches!(rows[0].content, RowContent::Blank));
    assert!(matches!(rows[1].content, RowContent::PlateBorder));
    assert!(
        rows.iter()
            .any(|r| matches!(&r.content, RowContent::Plate(t) if t.contains("Entry point")))
    );
    assert!(
        rows.iter()
            .any(|r| matches!(&r.content, RowContent::Signature(_)))
    );
    assert!(rows.iter().any(
        |r| matches!(&r.content, RowContent::Variable { storage, .. } if &**storage == "EDI:4")
    ));
    assert!(matches!(
        &rows.iter().rev().find(|r| matches!(r.content, RowContent::Label { .. })).unwrap().content,
        RowContent::Label { name, .. } if &*name.text == "main"
    ));
    assert!(rows.last().unwrap().is_unit());
}

#[test]
fn calls_resolve_to_names_with_references_back() {
    let p = licd();
    let parse_config_line = addr_of(&p, "parse_config_line");
    let refs = p.references_to(parse_config_line, 100).unwrap();
    assert_eq!(refs.total, 1);
    let r = &refs.rows[0];
    assert_eq!(r.kind, RefKind::Call);
    assert_eq!(r.from_function.as_deref(), Some("load_config"));
    assert!(
        r.code.contains("CALL") && r.code.contains("parse_config_line"),
        "{}",
        r.code
    );
    // Calls to imports show the thunk's name.
    let span = p.rows_for_address(r.from).unwrap();
    let row = &p.listing_rows(span.unit, 1).unwrap()[0];
    let RowContent::Instruction { operands, .. } = &row.content else {
        panic!("not an instruction")
    };
    assert_eq!(operands[0].kind, TokenKind::Function);
    assert_eq!(
        operands[0].referent.as_ref().and_then(Referent::address),
        Some(parse_config_line)
    );
}

#[test]
fn decompiled_lines_map_to_instructions_both_ways() {
    let p = licd();
    let main = addr_of(&p, "main");
    let d = p.decompile(main).unwrap();
    assert_eq!(&*d.name, "main");
    let call = d
        .lines
        .iter()
        .find(|l| l.tokens.iter().any(|t| &*t.text == "load_config"))
        .unwrap();
    assert_ne!(call.ranges, []);
    let target = call
        .tokens
        .iter()
        .find(|t| &*t.text == "load_config")
        .unwrap();
    assert_eq!(target.kind, TokenKind::Function);
    // Every instruction in the range is inside main.
    let f = p
        .function_containing(call.ranges[0].start)
        .unwrap()
        .unwrap();
    assert_eq!(f.entry, main);
    // Variables are tokens with referents shared by all their uses.
    let uses: Vec<_> = d
        .lines
        .iter()
        .flat_map(|l| l.tokens.iter())
        .filter(|t| &*t.text == "iVar1")
        .collect();
    assert!(uses.len() > 3);
    assert!(
        uses.iter()
            .all(|t| t.referent == uses[0].referent && t.kind == TokenKind::Variable)
    );
}

#[test]
fn renames_and_comments_show_everywhere() {
    let p = licd();
    let target = addr_of(&p, "validate_key");
    p.apply(&Command::RenameSymbol {
        address: target,
        name: "check_licence".into(),
    })
    .unwrap();
    let main = p.decompile(addr_of(&p, "main")).unwrap();
    assert!(
        main.lines
            .iter()
            .flat_map(|l| &l.tokens)
            .any(|t| &*t.text == "check_licence")
    );
    assert!(
        p.lookup("validate_key", 10)
            .unwrap()
            .iter()
            .all(|s| &*s.name != "validate_key")
    );

    let before = p.listing_len().unwrap();
    p.apply(&Command::SetComment {
        address: target,
        kind: CommentKind::Pre,
        text: "two\nlines".into(),
    })
    .unwrap();
    assert_eq!(p.listing_len().unwrap(), before + 2);

    p.apply(&Command::RenameVariable {
        function: target,
        index: 0,
        name: "key".into(),
    })
    .unwrap();
    let d = p.decompile(target).unwrap();
    let signature = d
        .lines
        .iter()
        .find(|l| l.tokens.iter().any(|t| t.kind == TokenKind::Function))
        .unwrap();
    assert!(
        signature
            .tokens
            .iter()
            .any(|t| &*t.text == "key" && t.kind == TokenKind::Parameter)
    );
    assert!(
        p.apply(&Command::RenameSymbol {
            address: target,
            name: "has space".into()
        })
        .is_err()
    );
}

#[test]
fn tables_filter_sort_and_page() {
    let p = licd();
    let q = TableQuery {
        filter: "rc4".into(),
        sort: FunctionColumn::Name,
        order: SortOrder::Ascending,
        offset: 0,
        limit: 10,
    };
    let page = p.functions(&q).unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(&*page.rows[0].name, "rc4_crypt");
    let strings = p
        .strings(&TableQuery {
            filter: "usage".into(),
            sort: StringColumn::Location,
            order: SortOrder::Ascending,
            offset: 0,
            limit: 10,
        })
        .unwrap();
    assert_eq!(strings.total, 1);
    let imports = p.symbols(SymbolCategory::Imports, "", 100).unwrap();
    assert!(imports.rows.iter().any(|s| &*s.name == "getaddrinfo"));
}

#[test]
fn search_finds_text_and_bytes() {
    let p = licd();
    let hits = p
        .search(&SearchQuery::Text("getaddrinfo".into()), 100)
        .unwrap();
    assert!(hits.total >= 2, "{hits:?}");
    let push_rbp = p
        .search(&SearchQuery::Bytes(vec![0x55, 0x48, 0x89, 0xe5]), 1000)
        .unwrap();
    let push_only = p.search(&SearchQuery::Bytes(vec![0x55]), 1000).unwrap();
    assert!(push_only.total >= 30);
    assert!(push_rbp.total <= push_only.total);
}

#[test]
fn every_unit_produces_the_rows_it_counts() {
    // The row numbering (and so paging) depends on this.
    let p = licd();
    let db = p.db.read();
    for (i, u) in db.units.iter().enumerate() {
        assert_eq!(
            rows::unit_rows(&db, i).len(),
            rows::unit_row_count(&db, u),
            "unit at {:#x}",
            u.address
        );
    }
    drop(db);
    // And paging returns each row once: no row appears on two pages.
    let n = p.listing_len().unwrap();
    let mut seen = Vec::new();
    for start in (0..n).step_by(64) {
        seen.extend(p.listing_rows(RowIndex(start), 64).unwrap());
    }
    assert_eq!(seen.len() as u64, n);
    let units: Vec<_> = seen
        .iter()
        .filter(|r| r.is_unit())
        .map(|r| r.address)
        .collect();
    let mut dedup = units.clone();
    dedup.dedup();
    assert_eq!(units, dedup);
}
