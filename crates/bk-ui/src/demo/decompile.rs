//! "Decompiling" a demo function: its C text, tokenised and resolved
//! against the program's symbols and the function's variables, with each
//! line's instruction ranges from the DWARF line table.

use super::db::{Db, Func, UnitKind};
use super::lex::{self, CClass};
use super::rows::symbol_token_kind;
use crate::model::{
    Address, AddressRange, CommentKind, DecompLine, DecompVariable, DecompiledFunction, Referent,
    Token, TokenKind,
};

/// Undoes C escapes in a string literal's body.
fn c_unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Tokens of one line of C in the context of function `f`.
pub(crate) fn c_tokens(db: &Db, f: Option<&Func>, line: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut after_member = false;
    for (class, text) in lex::c_line(line) {
        let tok = match class {
            CClass::Space => Token::new(text, TokenKind::Plain),
            CClass::Number | CClass::Char => Token::new(text, TokenKind::Constant),
            CClass::Comment => Token::new(text, TokenKind::Comment),
            CClass::String => {
                let body = text.get(1..text.len().saturating_sub(1)).unwrap_or_default();
                match db.string_index.get(c_unescape(body).as_str()) {
                    Some(a) => {
                        Token::with_referent(text, TokenKind::String, Referent::Address(Address(*a)))
                    }
                    None => Token::new(text, TokenKind::String),
                }
            }
            CClass::Punct => Token::new(text, TokenKind::Punctuation),
            CClass::Ident => ident(db, f, text, after_member),
        };
        if class != CClass::Space {
            after_member = class == CClass::Punct && (text == "->" || text == ".");
        }
        out.push(tok);
    }
    out
}

fn ident(db: &Db, f: Option<&Func>, text: &str, after_member: bool) -> Token {
    if after_member {
        return Token::new(text, TokenKind::Field);
    }
    if lex::is_keyword(text) {
        return Token::new(text, TokenKind::Keyword);
    }
    if lex::is_type(text) {
        return Token::with_referent(text, TokenKind::Type, Referent::Type(text.into()));
    }
    if let Some(f) = f {
        if let Some(i) = f.vars.iter().position(|v| &*v.name == text) {
            let v = f.vars.get(i);
            let name = db.var_name(f, i as u32).unwrap_or(text);
            let kind = if v.is_some_and(|v| v.is_param) {
                TokenKind::Parameter
            } else {
                TokenKind::Variable
            };
            return Token::with_referent(
                name,
                kind,
                Referent::Variable {
                    function: Address(f.entry),
                    index: i as u32,
                },
            );
        }
    }
    if let Some((a, kind)) = db.ident_index.get(text) {
        let (name, _) = db.label_for(*a);
        return Token::with_referent(name, symbol_token_kind(*kind), Referent::Address(Address(*a)));
    }
    Token::new(text, TokenKind::Plain)
}

/// Instruction ranges of function `f` produced from licd.c line `line`.
fn line_ranges(db: &Db, f: &Func, line: u32) -> Vec<AddressRange> {
    let mut ranges: Vec<AddressRange> = Vec::new();
    let start = db.units.partition_point(|u| u.address < f.entry);
    for u in db.units.iter().skip(start).take_while(|u| u.address < f.end) {
        if let UnitKind::Insn { line: l, .. } = u.kind {
            if l == line {
                let end = Address(u.address + u.size);
                match ranges.last_mut() {
                    Some(r) if r.end == Address(u.address) => r.end = end,
                    _ => ranges.push(AddressRange {
                        start: Address(u.address),
                        end,
                    }),
                }
            }
        }
    }
    ranges
}

/// The decompiled form of function `f`.
pub(crate) fn decompile(db: &Db, f: &Func) -> DecompiledFunction {
    let mut lines = Vec::new();
    let mut commented = std::collections::HashSet::new();
    if f.source.is_empty() {
        // Thunks and functions without source: Ghidra's thunk output.
        let name = db.func_name(f);
        for text in [
            format!("void {name}(void)"),
            "{".to_owned(),
            format!("  /* WARNING: Could not recover jumptable. Thunk to external {name} */"),
            format!("  {name}();"),
            "  return;".to_owned(),
            "}".to_owned(),
        ] {
            lines.push(DecompLine {
                indent: 0,
                tokens: c_tokens(db, Some(f), &text),
                ranges: Vec::new(),
            });
        }
    }
    for (n, text) in &f.source {
        let ranges = line_ranges(db, f, *n);
        let spaces = text.len() - text.trim_start().len();
        let indent = (spaces / 2) as u16;
        if let Some(first) = ranges.first() {
            let a = first.start.0;
            for kind in [CommentKind::Plate, CommentKind::Pre] {
                if kind == CommentKind::Plate && a != f.entry {
                    continue;
                }
                if let Some(c) = db.comments.get(&(a, kind)) {
                    if commented.insert((a, kind)) && *n != f.source.first().map_or(0, |s| s.0) {
                        for l in c.lines() {
                            lines.push(DecompLine {
                                indent,
                                tokens: vec![Token::new(format!("/* {l} */"), TokenKind::Comment)],
                                ranges: vec![*first],
                            });
                        }
                    }
                }
            }
        }
        lines.push(DecompLine {
            indent,
            tokens: c_tokens(db, Some(f), text.trim_start()),
            ranges,
        });
    }
    // A plate comment on the function goes above the signature, as Ghidra
    // prints it.
    if let Some(c) = db.comments.get(&(f.entry, CommentKind::Plate)) {
        let mut plate: Vec<DecompLine> = c
            .lines()
            .map(|l| DecompLine {
                indent: 0,
                tokens: vec![Token::new(format!("/* {l} */"), TokenKind::Comment)],
                ranges: Vec::new(),
            })
            .collect();
        plate.push(DecompLine {
            indent: 0,
            tokens: Vec::new(),
            ranges: Vec::new(),
        });
        plate.append(&mut lines);
        lines = plate;
    }
    let variables = f
        .vars
        .iter()
        .enumerate()
        .map(|(i, v)| DecompVariable {
            name: db.var_name(f, i as u32).unwrap_or(&v.name).into(),
            datatype: v.datatype.clone(),
            is_parameter: v.is_param,
        })
        .collect();
    let name: Box<str> = db.func_name(f).into();
    let signature = f
        .signature
        .replacen(&*f.original_name, &name, 1)
        .into_boxed_str();
    DecompiledFunction {
        entry: Address(f.entry),
        name,
        signature,
        lines,
        variables,
    }
}
