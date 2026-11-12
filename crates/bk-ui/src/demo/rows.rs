//! Listing rows for the demo program, laid out as Ghidra lays out a code
//! unit: section header, plate comment, function signature, variables,
//! label with XREFs, pre-comments, the unit, post-comments.

use super::db::{Db, Unit, UnitKind};
use super::lex::OpPiece;
use crate::model::{
    Address, CommentKind, ListingRow, Referent, RowContent, SymbolKind, Token, TokenKind,
    XrefEntry,
};

/// XREFs shown below a label before "[more]" (Ghidra's default is 4).
pub(crate) const MAX_XREFS: usize = 4;

fn comment_lines(db: &Db, a: u64, kind: CommentKind) -> Vec<&str> {
    db.comments
        .get(&(a, kind))
        .map(|c| c.lines().collect())
        .unwrap_or_default()
}

fn label_rows(db: &Db, a: u64) -> usize {
    let n = db.xrefs.get(&a).map_or(0, Vec::len);
    // The label row, further XREF rows, and "[more]" past MAX_XREFS
    // (see push_label).
    if n <= MAX_XREFS { n.max(1) } else { MAX_XREFS }
}

/// Number of rows `unit` occupies (must agree with [`unit_rows`]).
pub(crate) fn unit_row_count(db: &Db, u: &Unit) -> usize {
    let a = u.address;
    let mut n = 0;
    if u.section_start.is_some() {
        n += 2;
    }
    let plate = comment_lines(db, a, CommentKind::Plate).len();
    match db.func_containing(a).filter(|f| f.entry == a) {
        Some(f) => {
            let vars = f.vars.iter().filter(|v| v.storage.is_some()).count();
            n += 1 + 2 + plate.max(1) + 1 + 1 + vars + label_rows(db, a);
        }
        None => {
            if plate > 0 {
                n += plate + 2;
            }
            if db.names.contains_key(&a) {
                n += label_rows(db, a);
            }
        }
    }
    n += comment_lines(db, a, CommentKind::Pre).len();
    n += 1;
    n += comment_lines(db, a, CommentKind::Post).len();
    n
}

fn xref_entry(db: &Db, x: super::db::Xref) -> XrefEntry {
    XrefEntry {
        from: Address(x.from),
        from_function: db.func_containing(x.from).map(|f| db.func_name(f).into()),
        kind: x.kind,
    }
}

fn name_token(db: &Db, a: u64) -> Token {
    let (name, kind) = db.label_for(a);
    Token::with_referent(name, symbol_token_kind(kind), Referent::Address(Address(a)))
}

/// Token kind used for a symbol of `kind`.
pub(crate) fn symbol_token_kind(kind: SymbolKind) -> TokenKind {
    kind.token_kind()
}

fn push_label(db: &Db, a: u64, rows: &mut Vec<ListingRow>) {
    let address = Address(a);
    let refs = db.xrefs.get(&a).map(Vec::as_slice).unwrap_or_default();
    rows.push(ListingRow {
        address,
        content: RowContent::Label {
            name: name_token(db, a),
            xref_count: refs.len() as u32,
            first_xref: refs.first().map(|x| xref_entry(db, *x)),
        },
    });
    let shown = if refs.len() > MAX_XREFS {
        MAX_XREFS - 1
    } else {
        refs.len()
    };
    for x in refs.iter().take(shown).skip(1) {
        rows.push(ListingRow {
            address,
            content: RowContent::Xref(xref_entry(db, *x)),
        });
    }
    if refs.len() > MAX_XREFS {
        rows.push(ListingRow {
            address,
            content: RowContent::XrefMore((refs.len() - shown) as u32),
        });
    }
}

/// Tokens of a line of C (the signature row uses this too).
pub(crate) fn signature_tokens(db: &Db, f: &super::db::Func) -> Vec<Token> {
    super::decompile::c_tokens(db, Some(f), f.signature.as_ref())
}

/// Operand tokens with addresses replaced by names, as Ghidra shows them.
fn operand_tokens(db: &Db, pieces: &[OpPiece]) -> Vec<Token> {
    pieces
        .iter()
        .map(|p| match p {
            OpPiece::Register(r) => Token::with_referent(
                r.clone(),
                TokenKind::Register,
                Referent::Register(r.clone()),
            ),
            OpPiece::Scalar(s) => Token::new(s.clone(), TokenKind::Immediate),
            OpPiece::Number { value, .. } if db.in_memory(*value) => {
                let (name, kind) = db.label_for(*value);
                let shown = match name.strip_prefix("PTR_") {
                    Some(rest) if kind == SymbolKind::Data => format!("->{rest}"),
                    _ => name,
                };
                Token::with_referent(
                    shown,
                    symbol_token_kind(kind),
                    Referent::Address(Address(*value)),
                )
            }
            OpPiece::Number { text, .. } => Token::new(text.clone(), TokenKind::Immediate),
            OpPiece::Word(w) => Token::new(w.clone(), TokenKind::Plain),
            OpPiece::Punct(s) => Token::new(s.clone(), TokenKind::Punctuation),
        })
        .collect()
}

fn ret_storage(ty: &str) -> &'static str {
    match ty {
        "void" => "<VOID>",
        "char" | "byte" | "undefined" => "AL:1",
        "int" | "uint" | "undefined4" => "EAX:4",
        _ => "RAX:8",
    }
}

/// All rows of the unit at index `i`.
pub(crate) fn unit_rows(db: &Db, i: usize) -> Vec<ListingRow> {
    let Some(u) = db.units.get(i) else {
        return Vec::new();
    };
    let a = u.address;
    let address = Address(a);
    let mut rows = Vec::new();
    let row = |content| ListingRow { address, content };
    if let Some(s) = u.section_start.and_then(|s| db.sections.get(s)) {
        rows.push(row(RowContent::Blank));
        rows.push(row(RowContent::Section {
            name: format!("{},{}", s.segment, s.name).into(),
            range: format!("ram:{:08x}-{:08x}", s.start, s.start + s.size.max(1) - 1).into(),
        }));
    }
    let plate = comment_lines(db, a, CommentKind::Plate);
    if let Some(f) = db.func_containing(a).filter(|f| f.entry == a) {
        rows.push(row(RowContent::Blank));
        rows.push(row(RowContent::PlateBorder));
        if plate.is_empty() {
            let title = if f.is_thunk {
                "THUNK FUNCTION"
            } else {
                "FUNCTION"
            };
            rows.push(row(RowContent::Plate(title.into())));
        } else {
            rows.extend(plate.iter().map(|l| row(RowContent::Plate((*l).into()))));
        }
        rows.push(row(RowContent::PlateBorder));
        rows.push(row(RowContent::Signature(signature_tokens(db, f))));
        let ret = f
            .signature
            .split('(')
            .next()
            .and_then(|s| s.trim().rsplit_once(' '))
            .map_or("undefined", |(t, _)| t.trim_start_matches("thunk ").trim());
        rows.push(row(RowContent::Variable {
            datatype: ret.into(),
            storage: ret_storage(ret).into(),
            name: Token::new("<RETURN>", TokenKind::Plain),
        }));
        for (vi, v) in f.vars.iter().enumerate() {
            if let Some(storage) = &v.storage {
                let name = db.var_name(f, vi as u32).unwrap_or(&v.name);
                rows.push(row(RowContent::Variable {
                    datatype: v.datatype.clone(),
                    storage: storage.clone(),
                    name: Token::with_referent(
                        name,
                        if v.is_param {
                            TokenKind::Parameter
                        } else {
                            TokenKind::Variable
                        },
                        Referent::Variable {
                            function: Address(f.entry),
                            index: vi as u32,
                        },
                    ),
                }));
            }
        }
        push_label(db, a, &mut rows);
    } else {
        if !plate.is_empty() {
            rows.push(row(RowContent::PlateBorder));
            rows.extend(plate.iter().map(|l| row(RowContent::Plate((*l).into()))));
            rows.push(row(RowContent::PlateBorder));
        }
        if db.names.contains_key(&a) {
            push_label(db, a, &mut rows);
        }
    }
    for l in comment_lines(db, a, CommentKind::Pre) {
        rows.push(row(RowContent::PreComment(l.into())));
    }
    let eol = db
        .comments
        .get(&(a, CommentKind::Eol))
        .map(|c| c.replace('\n', " ").into());
    rows.push(row(match &u.kind {
        UnitKind::Insn {
            bytes,
            mnemonic,
            operands,
            ..
        } => RowContent::Instruction {
            bytes: bytes.clone(),
            mnemonic: Token::new(mnemonic.clone(), TokenKind::Mnemonic),
            operands: operand_tokens(db, operands),
            comment: eol,
        },
        UnitKind::Data {
            bytes,
            datatype,
            value,
            target,
        } => RowContent::Data {
            bytes: bytes.clone(),
            datatype: Token::with_referent(
                datatype.clone(),
                TokenKind::Type,
                Referent::Type(datatype.clone()),
            ),
            value: vec![match target {
                Some(t) => {
                    let (name, kind) = db.label_for(*t);
                    Token::with_referent(
                        if value.starts_with("->") {
                            value.to_string()
                        } else {
                            name
                        },
                        symbol_token_kind(kind),
                        Referent::Address(Address(*t)),
                    )
                }
                None if &**datatype == "ds" => Token::new(value.clone(), TokenKind::String),
                None => Token::new(value.clone(), TokenKind::Constant),
            }],
            comment: eol,
        },
    }));
    for l in comment_lines(db, a, CommentKind::Post) {
        rows.push(row(RowContent::PostComment(l.into())));
    }
    rows
}

/// The listing text of a unit, for search previews and the References
/// table (`CALL parse_config`).
pub(crate) fn unit_text(db: &Db, i: usize) -> String {
    let rows = unit_rows(db, i);
    let mut s = String::new();
    for r in rows.iter().filter(|r| r.is_unit()) {
        for t in r.tokens() {
            s.push_str(&t.text);
            if t.kind == TokenKind::Mnemonic || t.kind == TokenKind::Type {
                s.push(' ');
            }
        }
    }
    s
}
