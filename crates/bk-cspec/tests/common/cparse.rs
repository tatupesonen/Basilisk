//! A tiny C declaration parser for the tests: prototypes such as
//! `int4 func(char a,int8 b[3]);` or Java-style `double[5] func(int[10] b)`,
//! and structure definitions `struct s { int4 a; float8 b; };` (the subset
//! Ghidra's `parse_protopieces`, `parse_C` and Java's signature parser are
//! given in the ported tests).

use bk_cspec::proto::PrototypePieces;
use bk_cspec::types::{ParamTypes, TypeHandle};

use super::testtypes::TestTypes;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Num(i32),
    Punct(char),
}

fn lex(text: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '\\' {
            chars.next();
        } else if c.is_ascii_alphabetic() || c == '_' {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    s.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Tok::Ident(s));
        } else if c.is_ascii_digit() {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    s.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Tok::Num(s.parse().unwrap()));
        } else {
            out.push(Tok::Punct(c));
            chars.next();
        }
    }
    out
}

struct P<'a> {
    toks: Vec<Tok>,
    pos: usize,
    types: &'a mut TestTypes,
}

impl P<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn ident(&mut self) -> Option<String> {
        if let Some(Tok::Ident(s)) = self.peek() {
            let s = s.clone();
            self.pos += 1;
            Some(s)
        } else {
            None
        }
    }

    /// A base type name, possibly several words, then pointers and array
    /// suffixes.
    fn ty(&mut self) -> TypeHandle {
        let first = self.ident().expect("type name");
        let mut name = first;
        if name == "struct" {
            name = self.ident().expect("struct name");
        }
        while let Some(Tok::Ident(next)) = self.peek() {
            let joined = format!("{name} {next}");
            if self.types.named(&joined).is_some() {
                name = joined;
                self.pos += 1;
            } else {
                break;
            }
        }
        let mut t = self.types.get(&name);
        let psize = self.types.c_sizes.pointer;
        while self.eat('*') {
            t = self.types.pointer_to(t, psize, 1);
        }
        self.suffix(t)
    }

    fn suffix(&mut self, mut t: TypeHandle) -> TypeHandle {
        while self.eat('[') {
            let Some(Tok::Num(n)) = self.peek().cloned() else {
                panic!("array size")
            };
            self.pos += 1;
            assert!(self.eat(']'));
            t = self.types.array(t, n);
        }
        t
    }
}

/// Parses a prototype into pieces with the given model name.
pub(crate) fn proto(types: &mut TestTypes, model: &str, text: &str) -> PrototypePieces {
    let mut p = P {
        toks: lex(text),
        pos: 0,
        types,
    };
    let out = p.ty();
    let name = p.ident().unwrap_or_default();
    assert!(p.eat('('), "expected ( in {text}");
    let mut intypes = Vec::new();
    let mut innames = Vec::new();
    let mut vararg = -1;
    if p.peek() == Some(&Tok::Ident("void".into()))
        && p.toks.get(p.pos + 1) == Some(&Tok::Punct(')'))
    {
        p.pos += 1;
    }
    while !p.eat(')') {
        if p.eat('.') {
            p.eat('.');
            p.eat('.');
            vararg = intypes.len() as i32;
            continue;
        }
        let t = p.ty();
        let n = p.ident().unwrap_or_default();
        let t = p.suffix(t);
        intypes.push(t);
        innames.push(n);
        p.eat(',');
    }
    let out = p.suffix(out);
    let mut pieces = PrototypePieces::new(out);
    pieces.model = Some(model.to_owned());
    pieces.name = name;
    pieces.intypes = intypes;
    pieces.innames = innames;
    pieces.first_vararg = vararg;
    pieces
}

/// Parses `struct name { type a; type b; };` and defines it.
pub(crate) fn structure(types: &mut TestTypes, text: &str) -> TypeHandle {
    let mut p = P {
        toks: lex(text),
        pos: 0,
        types,
    };
    assert_eq!(p.ident().as_deref(), Some("struct"));
    let name = p.ident().unwrap();
    assert!(p.eat('{'));
    let mut members = Vec::new();
    while !p.eat('}') {
        let t = p.ty();
        let _ = p.ident();
        let t = p.suffix(t);
        members.push(t);
        assert!(p.eat(';'));
    }
    p.types.structure(&name, &members)
}

/// Defines a packed structure from a Java-style list of member types
/// (`AbstractProtoModelTest.parseStructure`).
pub(crate) fn java_structure(types: &mut TestTypes, name: &str, body: &str) -> TypeHandle {
    let members: Vec<TypeHandle> = body
        .split(',')
        .map(|m| {
            let mut p = P {
                toks: lex(m),
                pos: 0,
                types: &mut *types,
            };
            p.ty()
        })
        .collect();
    types.structure(name, &members)
}
