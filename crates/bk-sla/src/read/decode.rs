//! Decoding the `<sleigh>` document into the model: the header, source
//! files, spaces and the symbol table (Ghidra `SleighBase::decode`,
//! `SymbolTable::decode` and the symbols' `decode`).

use std::fmt::Write as _;
use std::marker::PhantomData;

use bk_pcode::OpCode;

use super::source::{OpcodeAttr, Source, SpaceAttr, element_text};
use crate::error::{Fail, Location, StreamError};
use crate::ids::{self, a, e};
use crate::limits::Limits;
use crate::model::Arenas;
use crate::model::constructor::DecisionNode;
use crate::model::constructor::MaskWord;
use crate::model::handles::{ExprId, ScopeId, Span, StrId, SymbolId};
use crate::model::symbol::{Header, Operand, Scope, SpaceKind, SpaceRecord, Symbol, SymbolKind};

/// What a file says before validation: the header, the default space and
/// the arenas.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub(crate) header: Header,
    pub(crate) default_space: u32,
    pub(crate) arenas: Arenas,
}

/// The kinds a symbol head can announce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadKind {
    UserOp,
    Epsilon,
    Value,
    ValueMap,
    Name,
    Varnode,
    Context,
    VarnodeList,
    Operand,
    Start,
    End,
    Next2,
    Subtable,
}

impl HeadKind {
    fn from_head(id: u32) -> Option<Self> {
        Some(match id {
            e::USEROP_HEAD => Self::UserOp,
            e::EPSILON_SYM_HEAD => Self::Epsilon,
            e::VALUE_SYM_HEAD => Self::Value,
            e::VALUEMAP_SYM_HEAD => Self::ValueMap,
            e::NAME_SYM_HEAD => Self::Name,
            e::VARNODE_SYM_HEAD => Self::Varnode,
            e::CONTEXT_SYM_HEAD => Self::Context,
            e::VARLIST_SYM_HEAD => Self::VarnodeList,
            e::OPERAND_SYM_HEAD => Self::Operand,
            e::START_SYM_HEAD => Self::Start,
            e::END_SYM_HEAD => Self::End,
            e::NEXT2_SYM_HEAD => Self::Next2,
            e::SUBTABLE_SYM_HEAD => Self::Subtable,
            _ => return None,
        })
    }

    fn from_body(id: u32) -> Option<Self> {
        Some(match id {
            e::USEROP => Self::UserOp,
            e::EPSILON_SYM => Self::Epsilon,
            e::VALUE_SYM => Self::Value,
            e::VALUEMAP_SYM => Self::ValueMap,
            e::NAME_SYM => Self::Name,
            e::VARNODE_SYM => Self::Varnode,
            e::CONTEXT_SYM => Self::Context,
            e::VARLIST_SYM => Self::VarnodeList,
            e::OPERAND_SYM => Self::Operand,
            e::START_SYM => Self::Start,
            e::END_SYM => Self::End,
            e::NEXT2_SYM => Self::Next2,
            e::SUBTABLE_SYM => Self::Subtable,
            _ => return None,
        })
    }

    /// The content of a symbol of this kind that has no body, for the kinds
    /// that have no content.
    fn empty(self) -> Option<SymbolKind> {
        match self {
            Self::Start => Some(SymbolKind::Start),
            Self::End => Some(SymbolKind::End),
            Self::Next2 => Some(SymbolKind::Next2),
            Self::Epsilon => Some(SymbolKind::Epsilon),
            _ => None,
        }
    }
}

/// What the reader is inside of, for error paths.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Context {
    pub(crate) symbol: Option<SymbolId>,
    pub(crate) constructor: Option<u32>,
}

/// The model decoder, generic over the element source.
pub(crate) struct Reader<'a, 'l, S> {
    pub(crate) src: S,
    pub(crate) limits: &'l Limits,
    pub(crate) a: Arenas,
    pub(crate) ctx: Context,
    pub(crate) decision_scratch: Vec<DecisionNode>,
    pub(crate) word_scratch: Vec<MaskWord>,
    pub(crate) names: Vec<StrId>,
    marker: PhantomData<&'a ()>,
}

/// Converts a read value to `i32`, as Ghidra stores it.
pub(crate) fn to_i32(value: i64, attribute: &'static str) -> Result<i32, Fail> {
    i32::try_from(value).map_err(|_overflow| {
        StreamError::OutOfRange {
            attribute,
            value: i128::from(value),
        }
        .into()
    })
}

/// Converts a read value to `u32`, as Ghidra stores it.
pub(crate) fn to_u32(value: u64, attribute: &'static str) -> Result<u32, Fail> {
    u32::try_from(value).map_err(|_overflow| {
        StreamError::OutOfRange {
            attribute,
            value: i128::from(value),
        }
        .into()
    })
}

/// Converts a signed value that must not be negative to `u32`.
pub(crate) fn to_index(value: i64, attribute: &'static str) -> Result<u32, Fail> {
    u32::try_from(value).map_err(|_overflow| {
        StreamError::OutOfRange {
            attribute,
            value: i128::from(value),
        }
        .into()
    })
}

fn missing(attribute: &'static str) -> Fail {
    Fail::Stream(StreamError::MissingAttribute(attribute))
}

/// A required attribute.
pub(crate) fn need<T>(value: Option<T>, attribute: &'static str) -> Result<T, Fail> {
    value.ok_or_else(|| missing(attribute))
}

impl<'a, 'l, S: Source<'a>> Reader<'a, 'l, S> {
    pub(crate) fn new(src: S, limits: &'l Limits) -> Self {
        Self {
            src,
            limits,
            a: Arenas::default(),
            ctx: Context::default(),
            decision_scratch: Vec::new(),
            word_scratch: Vec::new(),
            names: Vec::new(),
            marker: PhantomData,
        }
    }

    /// Where the reader is, for an error.
    pub(crate) fn location(&self) -> Location {
        let mut path = String::new();
        for &id in self.src.stack() {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(ids::element_name(id).unwrap_or("?"));
            if id == e::SYMBOL_TABLE
                && let Some(symbol) = self.ctx.symbol
            {
                let name = self
                    .names
                    .get(symbol.slot())
                    .map_or("", |&name| self.a.strings.get(name));
                let _ = write!(path, "/symbol {symbol} \"{name}\"");
            }
            if id == e::CONSTRUCTOR
                && let Some(index) = self.ctx.constructor
            {
                let _ = write!(path, " {index}");
            }
        }
        Location {
            path,
            offset: self.src.offset(),
        }
    }

    /// Opens the next child, which must be `expected`.
    pub(crate) fn open_expect(&mut self, expected: bk_marshal::ElementId) -> Result<(), Fail> {
        match self.src.peek()? {
            Some(id) if id == expected.id() => {
                self.src.open()?;
                Ok(())
            }
            found => Err(StreamError::UnexpectedElement {
                expected: expected.name(),
                found: found.map_or_else(|| "the end of the element".to_owned(), element_text),
            }
            .into()),
        }
    }

    #[expect(
        clippy::unused_self,
        reason = "called like the reader's other error helpers"
    )]
    pub(crate) fn unexpected(&self, found: u32, expected: &'static str) -> Fail {
        StreamError::UnexpectedElement {
            expected,
            found: element_text(found),
        }
        .into()
    }

    /// The index of a space reference.
    pub(crate) fn space_ref(&self, attr: SpaceAttr<'_>) -> Result<u32, Fail> {
        match attr {
            SpaceAttr::Index(index) => to_u32(index, "space"),
            SpaceAttr::Name(name) => {
                if name == crate::spaces::CONSTANT_SPACE_NAME {
                    return Ok(0);
                }
                self.a
                    .spaces
                    .iter()
                    .find(|space| self.a.strings.get(space.name) == name)
                    .map(|space| space.index)
                    .ok_or_else(|| StreamError::UnknownSpace(name.to_owned()).into())
            }
        }
    }

    pub(crate) fn opcode(&mut self) -> Result<OpCode, Fail> {
        match self.src.opcode()? {
            OpcodeAttr::Number(value) => u8::try_from(value)
                .ok()
                .and_then(OpCode::from_u8)
                .ok_or_else(|| StreamError::UnknownOpcode(value.to_string()).into()),
            OpcodeAttr::Name(name) => OpCode::from_name(name)
                .ok_or_else(|| StreamError::UnknownOpcode(name.to_owned()).into()),
        }
    }

    /// Decodes the whole `<sleigh>` element.
    /// Also returns the offset of any data after the root element.
    pub(crate) fn sleigh(mut self) -> Result<(Decoded, Option<usize>), (Fail, Location)> {
        match self.sleigh_inner() {
            Ok((header, default_space)) => {
                let trailing = self.src.trailing();
                Ok((
                    Decoded {
                        header,
                        default_space,
                        arenas: self.a,
                    },
                    trailing,
                ))
            }
            Err(fail) => {
                let location = self.location();
                Err((fail, location))
            }
        }
    }

    fn sleigh_inner(&mut self) -> Result<(Header, u32), Fail> {
        self.open_expect(ids::ELEM_SLEIGH)?;
        let mut header = Header::default();
        let mut version = 0;
        while let Some(attr) = self.src.next_attr()? {
            match attr {
                a::VERSION => version = self.src.signed()?,
                a::BIGENDIAN => header.big_endian = self.src.bool()?,
                a::ALIGN => header.align = to_i32(self.src.signed()?, "align")?,
                a::UNIQBASE => header.unique_base = to_u32(self.src.unsigned()?, "uniqbase")?,
                a::MAXDELAY => header.max_delay = to_u32(self.src.unsigned()?, "maxdelay")?,
                a::UNIQMASK => header.unique_mask = to_u32(self.src.unsigned()?, "uniqmask")?,
                a::NUMSECTIONS => {
                    header.num_sections = to_u32(self.src.unsigned()?, "numsections")?;
                }
                _ => {}
            }
        }
        if version != i64::from(ids::FORMAT_VERSION) {
            return Err(Fail::invalid(format!(
                ".sla file has wrong format: version {version}, expected {}",
                ids::FORMAT_VERSION
            )));
        }
        self.source_files()?;
        let default_space = self.spaces()?;
        self.symbol_table()?;
        self.src.close()?;
        Ok((header, default_space))
    }

    fn source_files(&mut self) -> Result<(), Fail> {
        self.open_expect(ids::ELEM_SOURCEFILES)?;
        let mut files: Vec<(i64, StrId)> = Vec::new();
        while self.src.peek()? == Some(e::SOURCEFILE) {
            self.src.open()?;
            let (mut name, mut index) = (None, None);
            while let Some(attr) = self.src.next_attr()? {
                match attr {
                    a::NAME => name = Some(self.src.string()?),
                    a::INDEX => index = Some(self.src.signed()?),
                    _ => {}
                }
            }
            let name = self.a.strings.add(need(name, "name")?);
            files.push((need(index, "index")?, name));
            self.src.close()?;
        }
        self.src.close()?;
        files.sort_by_key(|&(index, _)| index);
        for (position, &(index, name)) in files.iter().enumerate() {
            if index != position as i64 {
                return Err(Fail::invalid(format!(
                    "source file indices are not 0..{}: found {index}",
                    files.len()
                )));
            }
            self.a.source_files.push(name);
        }
        Ok(())
    }

    fn spaces(&mut self) -> Result<u32, Fail> {
        self.open_expect(ids::ELEM_SPACES)?;
        let mut default_name = None;
        while let Some(attr) = self.src.next_attr()? {
            if attr == a::DEFAULTSPACE {
                default_name = Some(self.src.string()?);
            }
        }
        let default_name = need(default_name, "defaultspace")?;
        while let Some(id) = self.src.peek()? {
            let kind = match id {
                e::SPACE => SpaceKind::Processor,
                e::SPACE_UNIQUE => SpaceKind::Unique,
                e::SPACE_OTHER => SpaceKind::Other,
                _ => return Err(self.unexpected(id, "a space element")),
            };
            self.src.open()?;
            self.space(kind)?;
            self.src.close()?;
        }
        self.src.close()?;
        self.a
            .spaces
            .iter()
            .find(|space| self.a.strings.get(space.name) == default_name)
            .map(|space| space.index)
            .ok_or_else(|| Fail::invalid(format!("Bad 'defaultspace' attribute: {default_name}")))
    }

    fn space(&mut self, kind: SpaceKind) -> Result<(), Fail> {
        let (mut name, mut index, mut size, mut word_size) = (None, 0, None, 1);
        let (mut big_endian, mut delay, mut physical) = (false, None, None);
        while let Some(attr) = self.src.next_attr()? {
            match attr {
                a::NAME => name = Some(self.src.string()?),
                a::INDEX => index = to_index(self.src.signed()?, "index")?,
                a::SIZE => size = Some(to_i32(self.src.signed()?, "size")?),
                a::WORDSIZE => word_size = to_i32(self.src.signed()?, "wordsize")?,
                a::BIGENDIAN => big_endian = self.src.bool()?,
                a::DELAY => delay = Some(to_i32(self.src.signed()?, "delay")?),
                a::PHYSICAL => physical = Some(self.src.bool()?),
                _ => {}
            }
        }
        if index == 0 {
            return Err(Fail::invalid("Expecting index attribute"));
        }
        // What Ghidra's loader builds where the file leaves a value out.
        let (default_name, default_size, default_physical) = match kind {
            SpaceKind::Unique => ("unique", 4, true),
            SpaceKind::Other => ("OTHER", 8, false),
            SpaceKind::Processor => {
                if size.unwrap_or(0) == 0 || delay.is_none() || name.unwrap_or("").is_empty() {
                    return Err(Fail::invalid("Expecting size/delay/name attributes"));
                }
                ("", 0, false)
            }
        };
        let name = self.a.strings.add(name.unwrap_or(default_name));
        self.a.spaces.push(SpaceRecord {
            kind,
            name,
            index,
            big_endian,
            delay: delay.unwrap_or(0),
            size: size.unwrap_or(default_size),
            word_size,
            physical: physical.unwrap_or(default_physical),
        });
        Ok(())
    }

    fn symbol_table(&mut self) -> Result<(), Fail> {
        self.open_expect(ids::ELEM_SYMBOL_TABLE)?;
        let (mut scope_size, mut symbol_size) = (None, None);
        while let Some(attr) = self.src.next_attr()? {
            match attr {
                a::SCOPESIZE => scope_size = Some(self.src.signed()?),
                a::SYMBOLSIZE => symbol_size = Some(self.src.signed()?),
                _ => {}
            }
        }
        let scope_size = need(scope_size, "scopesize")?;
        let symbol_size = need(symbol_size, "symbolsize")?;
        let (Ok(scope_size), Ok(symbol_size)) =
            (u64::try_from(scope_size), u64::try_from(symbol_size))
        else {
            return Err(Fail::invalid("Bad symbol table size"));
        };
        if scope_size > self.limits.scopes {
            return Err(Fail::limit("scopes", self.limits.scopes, scope_size));
        }
        if symbol_size > self.limits.symbols {
            return Err(Fail::limit("symbols", self.limits.symbols, symbol_size));
        }
        // Counts are not trusted for allocation: each entry is pushed only
        // once its element has been read.
        let mut scopes: Vec<(u32, u32)> = Vec::new();
        for _ in 0..scope_size {
            self.open_expect(ids::ELEM_SCOPE)?;
            let (mut id, mut parent) = (None, None);
            while let Some(attr) = self.src.next_attr()? {
                match attr {
                    a::ID => id = Some(self.src.unsigned()?),
                    a::PARENT => parent = Some(self.src.unsigned()?),
                    _ => {}
                }
            }
            let id = need(id, "id")?;
            let parent = need(parent, "parent")?;
            if id >= scope_size {
                return Err(Fail::invalid(
                    "Bad symbol scope id: exceeds symbol scope table size",
                ));
            }
            if parent >= scope_size {
                return Err(Fail::invalid(
                    "Bad symbol scope parent id: exceeds symbol scope table size",
                ));
            }
            scopes.push((id as u32, parent as u32));
            self.src.close()?;
        }
        let mut table: Vec<Option<Scope>> = vec![None; scopes.len()];
        for &(id, parent) in &scopes {
            let slot = table
                .get_mut(id as usize)
                .ok_or_else(|| Fail::invalid("Bad symbol scope id"))?;
            if slot.is_some() {
                return Err(Fail::invalid("Bad symbol scope parent id: not unique"));
            }
            *slot = Some(Scope {
                parent: (parent != id).then_some(ScopeId::new(parent)),
            });
        }
        self.a.scopes = table.into_iter().flatten().collect();

        let mut heads: Vec<(u32, HeadKind, StrId, u32)> = Vec::new();
        for _ in 0..symbol_size {
            let Some(id) = self.src.peek()? else {
                return Err(StreamError::UnexpectedElement {
                    expected: "a symbol head",
                    found: "the end of the element".to_owned(),
                }
                .into());
            };
            let kind = HeadKind::from_head(id).ok_or_else(|| Fail::invalid("Bad symbol xml"))?;
            self.src.open()?;
            let (mut name, mut sym_id, mut scope) = (None, None, None);
            while let Some(attr) = self.src.next_attr()? {
                match attr {
                    a::NAME => name = Some(self.src.string()?),
                    a::ID => sym_id = Some(self.src.unsigned()?),
                    a::SCOPE => scope = Some(self.src.unsigned()?),
                    _ => {}
                }
            }
            let name = self.a.strings.add(need(name, "name")?);
            let sym_id = need(sym_id, "id")?;
            let scope = need(scope, "scope")?;
            if sym_id >= symbol_size {
                return Err(Fail::invalid("Bad symbol id: exceeds symbollist size"));
            }
            if scope >= scope_size {
                return Err(Fail::invalid("Bad symbol scope id: too large"));
            }
            heads.push((sym_id as u32, kind, name, scope as u32));
            self.src.close()?;
        }
        let mut slots: Vec<Option<(HeadKind, StrId, u32)>> = vec![None; heads.len()];
        for &(id, kind, name, scope) in &heads {
            let slot = slots
                .get_mut(id as usize)
                .ok_or_else(|| Fail::invalid("Bad symbol id"))?;
            if slot.is_some() {
                return Err(Fail::invalid("Bad symbol id: not unique"));
            }
            *slot = Some((kind, name, scope));
        }
        let slots: Vec<(HeadKind, StrId, u32)> = slots.into_iter().flatten().collect();
        self.names = slots.iter().map(|&(_, name, _)| name).collect();
        let mut kinds: Vec<Option<SymbolKind>> = vec![None; slots.len()];
        while let Some(element) = self.src.peek()? {
            let body = HeadKind::from_body(element)
                .ok_or_else(|| self.unexpected(element, "a symbol body"))?;
            self.src.open()?;
            let (id, kind) = self.symbol_body(body)?;
            let head = slots.get(id as usize).map(|&(kind, _, _)| kind);
            if head != Some(body) {
                return Err(Fail::invalid(format!(
                    "the body of symbol {id} does not match its head"
                )));
            }
            let slot = kinds
                .get_mut(id as usize)
                .ok_or_else(|| Fail::invalid("Bad symbol id"))?;
            if slot.is_some() {
                return Err(Fail::invalid("Already decoded symbol"));
            }
            *slot = Some(kind);
            self.src.close()?;
            self.ctx = Context::default();
        }
        self.src.close()?;
        for (id, (&(head, name, scope), kind)) in slots.iter().zip(kinds).enumerate() {
            let kind = kind.or_else(|| head.empty()).ok_or_else(|| {
                Fail::invalid(format!(
                    "symbol {id} \"{}\" has a head and no body",
                    self.a.strings.get(name)
                ))
            })?;
            self.a.symbols.push(Symbol {
                name,
                scope: ScopeId::new(scope),
                kind,
            });
        }
        Ok(())
    }

    /// Reads the attributes and children of a symbol body; returns its id.
    fn symbol_body(&mut self, body: HeadKind) -> Result<(u32, SymbolKind), Fail> {
        let mut id = None;
        let mut index = None;
        let (mut space, mut offset, mut size) = (None, None, None);
        let (mut varnode, mut low, mut high, mut flow) = (None, None, None, false);
        let (mut subsym, mut base, mut minlen, mut code) = (None, None, None, false);
        let mut numct = None;
        while let Some(attr) = self.src.next_attr()? {
            match (attr, body) {
                (a::ID, _) => {
                    let value = to_u32(self.src.unsigned()?, "id")?;
                    id = Some(value);
                    self.ctx.symbol = Some(SymbolId::new(value));
                }
                (a::INDEX, HeadKind::UserOp | HeadKind::Operand) => {
                    index = Some(to_i32(self.src.signed()?, "index")?);
                }
                (a::SPACE, HeadKind::Varnode) => {
                    let attr = self.src.space()?;
                    space = Some(self.space_ref(attr)?);
                }
                (a::OFF, HeadKind::Varnode) => offset = Some(self.src.unsigned()?),
                (a::SIZE, HeadKind::Varnode) => size = Some(to_i32(self.src.signed()?, "size")?),
                (a::VARNODE, HeadKind::Context) => {
                    varnode = Some(to_u32(self.src.unsigned()?, "varnode")?);
                }
                (a::LOW, HeadKind::Context) => low = Some(to_i32(self.src.signed()?, "low")?),
                (a::HIGH, HeadKind::Context) => high = Some(to_i32(self.src.signed()?, "high")?),
                (a::FLOW, HeadKind::Context) => flow = self.src.bool()?,
                (a::SUBSYM, HeadKind::Operand) => {
                    subsym = Some(to_u32(self.src.unsigned()?, "subsym")?);
                }
                (a::OFF, HeadKind::Operand) => offset = Some(self.src.signed()?.cast_unsigned()),
                (a::BASE, HeadKind::Operand) => base = Some(to_i32(self.src.signed()?, "base")?),
                (a::MINLEN, HeadKind::Operand) => {
                    minlen = Some(to_i32(self.src.signed()?, "minlen")?);
                }
                (a::CODE, HeadKind::Operand) => code = self.src.bool()?,
                (a::NUMCT, HeadKind::Subtable) => numct = Some(self.src.signed()?),
                _ => {}
            }
        }
        let id = need(id, "id")?;
        let kind = match body {
            HeadKind::UserOp => SymbolKind::UserOp {
                index: need(index, "index")?,
            },
            HeadKind::Epsilon => SymbolKind::Epsilon,
            HeadKind::Start => SymbolKind::Start,
            HeadKind::End => SymbolKind::End,
            HeadKind::Next2 => SymbolKind::Next2,
            HeadKind::Value => SymbolKind::Value {
                expr: self.expr(0)?,
            },
            HeadKind::ValueMap => {
                let expr = self.expr(0)?;
                let start = self.a.value_table.len();
                while let Some(element) = self.src.peek()? {
                    if element != e::VALUETAB {
                        return Err(self.unexpected(element, "<valuetab>"));
                    }
                    self.src.open()?;
                    let mut value = None;
                    while let Some(attr) = self.src.next_attr()? {
                        if attr == a::VAL {
                            value = Some(self.src.signed()?);
                        }
                    }
                    self.a.value_table.push(need(value, "val")?);
                    self.src.close()?;
                }
                SymbolKind::ValueMap {
                    expr,
                    table: Span::since(start, &self.a.value_table),
                }
            }
            HeadKind::Name => {
                let expr = self.expr(0)?;
                let start = self.a.name_table.len();
                while let Some(element) = self.src.peek()? {
                    if element != e::NAMETAB {
                        return Err(self.unexpected(element, "<nametab>"));
                    }
                    self.src.open()?;
                    // Ghidra looks only at the first attribute.
                    let name = if self.src.next_attr()? == Some(a::NAME) {
                        Some(self.src.string()?)
                    } else {
                        None
                    };
                    let entry = name
                        .filter(|&name| name != "_" && name != "\t")
                        .map(|name| self.a.strings.add(name));
                    self.a.name_table.push(entry);
                    self.src.close()?;
                }
                SymbolKind::Name {
                    expr,
                    table: Span::since(start, &self.a.name_table),
                }
            }
            HeadKind::Varnode => SymbolKind::Varnode {
                space: need(space, "space")?,
                offset: need(offset, "off")?,
                size: need(size, "size")?,
            },
            HeadKind::Context => {
                let (Some(low), Some(high)) = (low, high) else {
                    return Err(Fail::invalid("Missing high/low attributes"));
                };
                SymbolKind::Context {
                    varnode: SymbolId::new(need(varnode, "varnode")?),
                    low,
                    high,
                    flow,
                    expr: self.expr(0)?,
                }
            }
            HeadKind::VarnodeList => {
                let expr = self.expr(0)?;
                let start = self.a.varnode_table.len();
                while let Some(element) = self.src.peek()? {
                    self.src.open()?;
                    let entry = match element {
                        e::VAR => {
                            let mut var = None;
                            while let Some(attr) = self.src.next_attr()? {
                                if attr == a::ID {
                                    var = Some(to_u32(self.src.unsigned()?, "id")?);
                                }
                            }
                            Some(SymbolId::new(need(var, "id")?))
                        }
                        e::NULL => None,
                        _ => return Err(self.unexpected(element, "<var> or <null>")),
                    };
                    self.a.varnode_table.push(entry);
                    self.src.close()?;
                }
                SymbolKind::VarnodeList {
                    expr,
                    table: Span::since(start, &self.a.varnode_table),
                }
            }
            HeadKind::Operand => {
                let offset = need(offset, "off")?.cast_signed();
                let local_expr = self.expr(0)?;
                let defining_expr = if self.src.peek()?.is_some() {
                    Some(self.expr(0)?)
                } else {
                    None
                };
                SymbolKind::Operand(Operand {
                    index: need(index, "index")?,
                    offset: to_i32(offset, "off")?,
                    base: need(base, "base")?,
                    min_length: need(minlen, "minlen")?,
                    code,
                    defining_symbol: subsym.map(SymbolId::new),
                    local_expr,
                    defining_expr,
                })
            }
            HeadKind::Subtable => {
                let numct = need(numct, "numct")?;
                SymbolKind::Subtable(self.subtable(numct)?)
            }
        };
        Ok((id, kind))
    }

    /// Reads one pattern expression (Ghidra `decodeExpression`).
    pub(crate) fn expr(&mut self, depth: u32) -> Result<ExprId, Fail> {
        super::expr::read_expr(self, depth)
    }
}
