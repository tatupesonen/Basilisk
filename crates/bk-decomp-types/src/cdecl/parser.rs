//! The C declaration parser (Ghidra `CParse` and the grammar of
//! `grammar.y`), as recursive descent.
//!
//! Bison's behaviour is kept where it shows: a semantic action that fails
//! records an error, and the parse fails at the *next* token it asks for
//! (Ghidra's `lex` returns `BADTOKEN` once an error is set); tokens are
//! read only when a decision needs them, as an LALR(1) parser with default
//! reductions reads them, so an action error after the last token is not
//! reported by the grammar but by the checks that follow (as in Ghidra).

use std::fmt::Write as _;

use crate::cdecl::ast::{Declarator, Modifier, Specifiers, flag, keyword};
use crate::cdecl::lexer::{Lexer, Raw, Token};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::enumeration::Enumerator;
use crate::ids::TypeId;

/// The deepest nesting of declarators and type bodies accepted.
pub const MAX_NESTING: usize = 128;

/// A parser token (Ghidra's bison tokens).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Number(u64),
    Ident(String),
    TypeName(TypeId),
    Storage(String),
    Qualifier(String),
    FuncSpec(String),
    Struct,
    Union,
    Enum,
    DotDotDot,
    ScopeRes,
    Punct(u8),
    Bad,
    Eof,
}

/// Whether a declarator may or must be abstract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Concrete,
    Abstract,
    Either,
}

/// One item of a specifier list, applied right to left as bison's
/// right-recursive rule does.
enum SpecItem {
    Spec(String),
    Type(Option<TypeId>),
    Func(String),
}

/// A syntax failure: the message is already in `lasterror`.
pub(super) struct Fail;

pub(super) type PResult<T> = std::result::Result<T, PErr>;

/// Why parsing stopped.
pub(super) enum PErr {
    /// A syntax error (or a pending action error): report `lasterror`.
    Syntax(Fail),
    /// A hard error that Ghidra throws out of the parser.
    Hard(TypeError),
}

impl From<TypeError> for PErr {
    fn from(e: TypeError) -> Self {
        Self::Hard(e)
    }
}

/// The parser state (Ghidra `CParse`).
pub(crate) struct Parser<'f, 'a> {
    pub(super) f: &'f mut TypeFactory,
    pub(super) has_model: &'a dyn Fn(&str) -> bool,
    lexer: Lexer<'a>,
    peeked: Option<Tok>,
    lineno: i32,
    colno: i32,
    filenum: i32,
    lasterror: String,
}

impl<'f, 'a> Parser<'f, 'a> {
    pub(crate) fn new(
        f: &'f mut TypeFactory,
        text: &'a str,
        has_model: &'a dyn Fn(&str) -> bool,
    ) -> Self {
        Self {
            f,
            has_model,
            lexer: Lexer::new(text),
            peeked: None,
            lineno: -1,
            colno: -1,
            filenum: -1,
            lasterror: String::new(),
        }
    }

    /// Ghidra `setError`: the message with the location of the last token.
    pub(super) fn set_error(&mut self, msg: &str) {
        let mut s = String::from(msg);
        let file = if self.filenum == 0 { "stream" } else { "" };
        let _ = writeln!(s, " at line {} in {file}", self.lineno);
        if self.lineno == self.lexer.line() {
            s.push_str(&String::from_utf8_lossy(self.lexer.buffer()));
            s.push('\n');
            for _ in 0..self.colno.max(0) {
                s.push(' ');
            }
            s.push_str("^--\n");
        }
        self.lasterror = s;
    }

    /// Ghidra `lookupIdentifier`.
    fn lookup(&self, name: String) -> Tok {
        if let Some(k) = keyword(&name) {
            return match k {
                flag::TYPEDEF | flag::EXTERN | flag::STATIC | flag::AUTO | flag::REGISTER => {
                    Tok::Storage(name)
                }
                flag::CONST | flag::RESTRICT | flag::VOLATILE => Tok::Qualifier(name),
                flag::INLINE => Tok::FuncSpec(name),
                flag::STRUCT => Tok::Struct,
                flag::UNION => Tok::Union,
                _ => Tok::Enum,
            };
        }
        if let Some(t) = self.f.find_by_name(&name) {
            return Tok::TypeName(t);
        }
        if (self.has_model)(&name) {
            return Tok::FuncSpec(name);
        }
        Tok::Ident(name)
    }

    /// Ghidra `CParse::lex`.
    fn lex(&mut self) -> Tok {
        if !self.lasterror.is_empty() {
            return Tok::Bad;
        }
        let Token {
            raw,
            line,
            col,
            file,
        } = self.lexer.next_token();
        self.lineno = line;
        self.colno = col;
        self.filenum = file;
        match raw {
            Raw::Number(v) => Tok::Number(v),
            Raw::Ident(s) => self.lookup(s),
            Raw::Str => {
                self.set_error("Illegal string constant");
                Tok::Bad
            }
            Raw::DotDotDot => Tok::DotDotDot,
            Raw::ScopeRes => Tok::ScopeRes,
            Raw::Bad => {
                let msg = self.lexer.error.clone();
                self.set_error(&msg);
                Tok::Bad
            }
            Raw::Eof => Tok::Eof,
            Raw::Punct(p) => Tok::Punct(p),
        }
    }

    fn peek(&mut self) -> &Tok {
        if self.peeked.is_none() {
            let t = self.lex();
            self.peeked = Some(t);
        }
        self.peeked.as_ref().unwrap_or(&Tok::Eof)
    }

    fn next(&mut self) -> Tok {
        self.peek();
        self.peeked.take().unwrap_or(Tok::Eof)
    }

    fn syntax<T>(&mut self) -> PResult<T> {
        if self.lasterror.is_empty() {
            self.set_error("Syntax error");
        }
        Err(PErr::Syntax(Fail))
    }

    fn expect_punct(&mut self, p: u8) -> PResult<()> {
        if *self.peek() == Tok::Punct(p) {
            self.next();
            Ok(())
        } else {
            self.syntax()
        }
    }

    fn is_punct(&mut self, p: u8) -> bool {
        *self.peek() == Tok::Punct(p)
    }

    /// Runs a parse; returns the declarations, or the error Ghidra reports.
    pub(crate) fn run(&mut self, param: bool) -> Result<Vec<Declarator>> {
        let res = if param {
            self.parameter_declaration(0).map(|d| vec![d])
        } else {
            self.declaration()
        };
        let res = res.and_then(|d| {
            if *self.peek() == Tok::Eof {
                Ok(d)
            } else {
                self.syntax()
            }
        });
        match res {
            Ok(d) => Ok(d),
            Err(PErr::Hard(e)) => Err(e),
            Err(PErr::Syntax(Fail)) => Err(TypeError::parse(self.lasterror.clone())),
        }
    }

    // ---- grammar ------------------------------------------------------

    fn declaration(&mut self) -> PResult<Vec<Declarator>> {
        let spec = self.declaration_specifiers(0)?;
        if self.is_punct(b';') {
            self.next();
            let mut d = Declarator::default();
            d.merge(&spec);
            return Ok(vec![d]);
        }
        let mut list = vec![self.declarator(Mode::Concrete, 0)?.0];
        while self.is_punct(b',') {
            self.next();
            list.push(self.declarator(Mode::Concrete, 0)?.0);
        }
        self.expect_punct(b';')?;
        for d in &mut list {
            d.merge(&spec);
        }
        Ok(list)
    }

    fn starts_decl_spec(t: &Tok) -> bool {
        matches!(
            t,
            Tok::Storage(_)
                | Tok::Qualifier(_)
                | Tok::FuncSpec(_)
                | Tok::TypeName(_)
                | Tok::Struct
                | Tok::Union
                | Tok::Enum
        )
    }

    fn declaration_specifiers(&mut self, depth: usize) -> PResult<Specifiers> {
        let mut items = Vec::new();
        loop {
            let t = self.peek().clone();
            match t {
                Tok::Storage(s) | Tok::Qualifier(s) => {
                    self.next();
                    items.push(SpecItem::Spec(s));
                }
                Tok::FuncSpec(s) => {
                    self.next();
                    items.push(SpecItem::Func(s));
                }
                Tok::TypeName(_) | Tok::Struct | Tok::Union | Tok::Enum => {
                    let ty = self.type_specifier(depth)?;
                    items.push(SpecItem::Type(ty));
                }
                _ => break,
            }
            if !Self::starts_decl_spec(self.peek()) {
                break;
            }
        }
        if items.is_empty() {
            return self.syntax();
        }
        Ok(self.apply_specs(items))
    }

    fn specifier_qualifier_list(&mut self, depth: usize) -> PResult<Specifiers> {
        let mut items = Vec::new();
        loop {
            let t = self.peek().clone();
            match t {
                Tok::Qualifier(s) => {
                    self.next();
                    items.push(SpecItem::Spec(s));
                }
                Tok::TypeName(_) | Tok::Struct | Tok::Union | Tok::Enum => {
                    let ty = self.type_specifier(depth)?;
                    items.push(SpecItem::Type(ty));
                }
                _ => break,
            }
        }
        if items.is_empty() {
            return self.syntax();
        }
        Ok(self.apply_specs(items))
    }

    /// The specifier actions, right to left.
    fn apply_specs(&mut self, items: Vec<SpecItem>) -> Specifiers {
        let mut spec = Specifiers::default();
        for item in items.into_iter().rev() {
            match item {
                SpecItem::Spec(s) => match keyword(&s) {
                    Some(k) => spec.flags |= k,
                    None => self.set_error("Unknown qualifier"),
                },
                SpecItem::Type(t) => {
                    if spec.ty.is_some() {
                        self.set_error("Multiple type specifiers");
                    }
                    spec.ty = t;
                }
                SpecItem::Func(s) => {
                    if let Some(k) = keyword(&s) {
                        spec.flags |= k;
                    } else {
                        if !spec.function.is_empty() {
                            self.set_error("Multiple parameter models");
                        }
                        spec.function = s;
                    }
                }
            }
        }
        spec
    }

    fn type_specifier(&mut self, depth: usize) -> PResult<Option<TypeId>> {
        if depth > MAX_NESTING {
            return Err(PErr::Hard(TypeError::TooDeep(MAX_NESTING)));
        }
        match self.next() {
            Tok::TypeName(t) => Ok(Some(t)),
            Tok::Struct => self.struct_or_union(true, depth),
            Tok::Union => self.struct_or_union(false, depth),
            Tok::Enum => self.enum_specifier(),
            _ => self.syntax(),
        }
    }

    fn struct_or_union(&mut self, is_struct: bool, depth: usize) -> PResult<Option<TypeId>> {
        let name = match self.peek().clone() {
            Tok::Punct(b'{') => String::new(),
            Tok::Ident(n) => {
                self.next();
                if !self.is_punct(b'{') {
                    return Ok(self.old_composite(&n, is_struct));
                }
                n
            }
            _ => return self.syntax(),
        };
        self.next(); // '{'
        let mut decls = Vec::new();
        loop {
            let spec = self.specifier_qualifier_list(depth + 1)?;
            let mut list = vec![self.struct_declarator(depth + 1)?];
            while self.is_punct(b',') {
                self.next();
                list.push(self.struct_declarator(depth + 1)?);
            }
            self.expect_punct(b';')?;
            for d in &mut list {
                d.merge(&spec);
            }
            decls.extend(list);
            if self.is_punct(b'}') {
                break;
            }
        }
        self.next(); // '}'
        if is_struct {
            self.new_struct(&name, &decls)
        } else {
            self.new_union(&name, &decls)
        }
    }

    fn struct_declarator(&mut self, depth: usize) -> PResult<Declarator> {
        let (mut d, _) = self.declarator(Mode::Concrete, depth)?;
        if self.is_punct(b':') {
            self.next();
            match self.next() {
                Tok::Number(n) => d.num_bits = n as i32,
                _ => return self.syntax(),
            }
        }
        Ok(d)
    }

    fn enum_specifier(&mut self) -> PResult<Option<TypeId>> {
        let name = match self.peek().clone() {
            Tok::Punct(b'{') => String::new(),
            Tok::Ident(n) => {
                self.next();
                if !self.is_punct(b'{') {
                    return Ok(self.old_enum(&n));
                }
                n
            }
            _ => return self.syntax(),
        };
        self.next(); // '{'
        let mut list = Vec::new();
        loop {
            let Tok::Ident(n) = self.next() else {
                return self.syntax();
            };
            let value = if self.is_punct(b'=') {
                self.next();
                match self.next() {
                    Tok::Number(v) => Some(v),
                    _ => return self.syntax(),
                }
            } else {
                None
            };
            list.push(Enumerator { name: n, value });
            if self.is_punct(b',') {
                self.next();
                if self.is_punct(b'}') {
                    break;
                }
                continue;
            }
            if self.is_punct(b'}') {
                break;
            }
            return self.syntax();
        }
        self.next(); // '}'
        self.new_enum(&name, &list)
    }

    /// A declarator, abstract or not as `mode` allows; returns it and
    /// whether it turned out abstract.
    fn declarator(&mut self, mode: Mode, depth: usize) -> PResult<(Declarator, bool)> {
        if depth > MAX_NESTING {
            return Err(PErr::Hard(TypeError::TooDeep(MAX_NESTING)));
        }
        let mut ptrs = 0usize;
        while self.is_punct(b'*') {
            self.next();
            ptrs += 1;
            while let Tok::Qualifier(q) = self.peek().clone() {
                self.next();
                if keyword(&q).is_none() {
                    self.set_error("Unknown qualifier");
                }
            }
        }
        let t = self.peek().clone();
        let (mut d, is_abstract) = match t {
            Tok::Ident(_) if mode != Mode::Abstract => {
                let ident = self.var_identifier()?;
                (
                    Declarator {
                        ident,
                        ..Declarator::default()
                    },
                    false,
                )
            }
            Tok::Punct(b'(') => {
                self.next();
                let inner = self.declarator(mode, depth + 1)?;
                self.expect_punct(b')')?;
                inner
            }
            _ if ptrs > 0 && mode != Mode::Concrete => {
                let mut d = Declarator::default();
                d.mods.extend(std::iter::repeat_n(Modifier::Pointer, ptrs));
                return Ok((d, true));
            }
            _ => return self.syntax(),
        };
        loop {
            if self.is_punct(b'[') {
                self.next();
                if !is_abstract {
                    while let Tok::Qualifier(q) = self.peek().clone() {
                        self.next();
                        if keyword(&q).is_none() {
                            self.set_error("Unknown qualifier");
                        }
                    }
                }
                let Tok::Number(n) = self.next() else {
                    return self.syntax();
                };
                self.expect_punct(b']')?;
                d.mods.push(Modifier::Array(n as i32));
            } else if self.is_punct(b'(') {
                self.next();
                let (params, dots) = self.parameter_type_list(depth + 1)?;
                self.expect_punct(b')')?;
                let m = Modifier::function(params, dots, self.f);
                d.mods.push(m);
            } else {
                break;
            }
        }
        d.mods.extend(std::iter::repeat_n(Modifier::Pointer, ptrs));
        Ok((d, is_abstract))
    }

    fn var_identifier(&mut self) -> PResult<String> {
        let Tok::Ident(mut s) = self.next() else {
            return self.syntax();
        };
        while *self.peek() == Tok::ScopeRes {
            self.next();
            let Tok::Ident(t) = self.next() else {
                return self.syntax();
            };
            s.push_str("::");
            s.push_str(&t);
        }
        Ok(s)
    }

    fn parameter_type_list(&mut self, depth: usize) -> PResult<(Vec<Declarator>, bool)> {
        let mut params = vec![self.parameter_declaration(depth)?];
        while self.is_punct(b',') {
            self.next();
            if *self.peek() == Tok::DotDotDot {
                self.next();
                return Ok((params, true));
            }
            params.push(self.parameter_declaration(depth)?);
        }
        Ok((params, false))
    }

    fn parameter_declaration(&mut self, depth: usize) -> PResult<Declarator> {
        let spec = self.declaration_specifiers(depth)?;
        let mut d = match self.peek() {
            Tok::Punct(b'*' | b'(') | Tok::Ident(_) => self.declarator(Mode::Either, depth)?.0,
            _ => Declarator::default(),
        };
        d.merge(&spec);
        Ok(d)
    }
}
