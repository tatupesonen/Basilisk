//! Items: `define`, `attach`, and the dispatch between item kinds.

use super::{PResult, Parser, Reported};
use crate::ast::{
    AlignmentDef, AttachNames, AttachValues, AttachVariables, BitrangeDef, BitrangeEntry,
    ContextDef, Definition, Endian, EndianDef, FieldDef, FieldDisplay, IdentOrWild, IntOrWild,
    Item, NameOrWild, PcodeOpDef, SpaceDef, SpaceMod, StrLit, TokenDef, VarnodeDef,
};
use crate::intern::kw;
use crate::lex::{Mode, TokenKind, string_content};
use crate::span::Span;

impl Parser<'_> {
    /// Parses items until the end of input, or, inside a `with` block,
    /// until its closing `}` (which is left for the caller).
    pub(super) fn items(&mut self, in_with: bool) -> Vec<Item> {
        let mut items = Vec::new();
        loop {
            if self.at_eof() || (in_with && self.at(TokenKind::RBrace)) {
                return items;
            }
            let before = self.tok.span.start;
            match self.item() {
                Ok(Some(item)) => items.push(item),
                Ok(None) => {}
                Err(Reported) => self.recover_item(in_with),
            }
            if self.tok.span.start == before && !self.at_eof() {
                // Nothing was consumed: skip the offending token.
                self.bump();
            }
        }
    }

    /// One definition, macro, `with` block or constructor. `Ok(None)` is a
    /// `define endian`, which is stored on the parser rather than returned.
    fn item(&mut self) -> PResult<Option<Item>> {
        if self.at(TokenKind::Colon) {
            return self.constructor(None).map(|c| Some(Item::Constructor(c)));
        }
        if self.at_word(kw::WITH) {
            return self.with_block().map(|w| Some(Item::With(w)));
        }
        if self.at_identifier() {
            if self.peek(1).kind == TokenKind::Colon {
                let table = self.identifier()?;
                return self
                    .constructor(Some(table))
                    .map(|c| Some(Item::Constructor(c)));
            }
            if self.at_word(kw::DEFINE) {
                return self.define().map(|d| d.map(Item::Definition));
            }
            if self.at_word(kw::ATTACH) {
                return self.attach().map(|d| Some(Item::Definition(d)));
            }
            if self.at_word(kw::MACRO) {
                return self.macro_def().map(|m| Some(Item::Macro(m)));
            }
        }
        if self.at(TokenKind::RBrace) {
            return Err(self.error("unexpected `}`"));
        }
        let found = self.found();
        Err(self.error(format!(
            "expected a definition, a macro, a `with` block or a constructor, found {found}"
        )))
    }

    /// Skips to the end of a broken item: past its `;`, or past the `}`
    /// that closes its body. Inside a `with` block the block's own `}` is
    /// left in place.
    fn recover_item(&mut self, in_with: bool) {
        self.set_mode(Mode::Base);
        let mut depth = 0u32;
        loop {
            match self.tok.kind {
                TokenKind::Eof => return,
                TokenKind::Semi if depth == 0 => {
                    self.bump();
                    return;
                }
                TokenKind::LBrace => depth += 1,
                TokenKind::RBrace => {
                    if depth == 0 && in_with {
                        return;
                    }
                    if depth <= 1 {
                        self.bump();
                        return;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            self.bump();
        }
    }

    /// A `define` statement, through its `;`.
    fn define(&mut self) -> PResult<Option<Definition>> {
        let start = self.bump().span; // `define`
        // `define SPACE offset = N ...` defines varnodes even when the
        // space's name is a keyword.
        let varnodes = self.peek(1).is_word(kw::OFFSET)
            && self.peek(2).kind == TokenKind::Assign
            && self.peek(3).kind.is_int();
        let definition = if varnodes {
            Definition::Varnode(self.varnode_def(start)?)
        } else if self.at_word(kw::ENDIAN) {
            self.endian_def(start)?;
            self.expect(TokenKind::Semi)?;
            return Ok(None);
        } else if self.eat_word(kw::ALIGNMENT).is_some() {
            self.expect(TokenKind::Assign)?;
            let value = self.integer()?;
            Definition::Alignment(AlignmentDef {
                value,
                span: self.span_from(start),
            })
        } else if self.eat_word(kw::TOKEN).is_some() {
            Definition::Token(self.token_def(start)?)
        } else if self.eat_word(kw::CONTEXT).is_some() {
            let varnode = self.identifier()?;
            let mut fields = Vec::new();
            while self.at_identifier() {
                fields.push(self.field_def(true)?);
            }
            Definition::Context(ContextDef {
                varnode,
                fields,
                span: self.span_from(start),
            })
        } else if self.eat_word(kw::SPACE).is_some() {
            Definition::Space(self.space_def(start)?)
        } else if self.eat_word(kw::BITRANGE).is_some() {
            let mut entries = vec![self.bitrange_entry()?];
            while self.at_identifier() {
                entries.push(self.bitrange_entry()?);
            }
            Definition::Bitrange(BitrangeDef {
                entries,
                span: self.span_from(start),
            })
        } else if self.eat_word(kw::PCODEOP).is_some() {
            let names = self.identifier_list()?;
            Definition::PcodeOp(PcodeOpDef {
                names,
                span: self.span_from(start),
            })
        } else if self.at_identifier() {
            Definition::Varnode(self.varnode_def(start)?)
        } else {
            let found = self.found();
            return Err(self.error(format!(
                "expected `endian`, `alignment`, `space`, `token`, `context`, `bitrange`, \
                 `pcodeop` or a space name after `define`, found {found}"
            )));
        };
        self.expect(TokenKind::Semi)?;
        Ok(Some(definition))
    }

    /// `endian = big|little` after `define`.
    fn endian_def(&mut self, start: Span) -> PResult<()> {
        let first_statement = self.tokens == 1;
        self.bump(); // `endian`
        self.expect(TokenKind::Assign)?;
        let endian = self.endian_value()?;
        let span = self.span_from(start);
        if self.endian.is_some() {
            self.error_at(span, "the endianness is already defined");
        } else {
            self.endian = Some(EndianDef { endian, span });
            if !first_statement {
                self.error_at(span, "`define endian` must be the first statement");
            }
        }
        Ok(())
    }

    fn endian_value(&mut self) -> PResult<Endian> {
        if self.eat_word(kw::BIG).is_some() {
            Ok(Endian::Big)
        } else if self.eat_word(kw::LITTLE).is_some() {
            Ok(Endian::Little)
        } else {
            Err(self.error_expected("`big` or `little`"))
        }
    }

    /// `name ( size ) [endian = e] fields...` after `define token`.
    fn token_def(&mut self, start: Span) -> PResult<TokenDef> {
        let name = self.identifier()?;
        self.expect(TokenKind::LParen)?;
        let size = self.integer()?;
        self.expect(TokenKind::RParen)?;
        let endian = if self.eat_word(kw::ENDIAN).is_some() {
            self.expect(TokenKind::Assign)?;
            Some(self.endian_value()?)
        } else {
            None
        };
        let mut fields = Vec::new();
        while self.at(TokenKind::Ident) {
            fields.push(self.field_def(false)?);
        }
        Ok(TokenDef {
            name,
            size,
            endian,
            fields,
            span: self.span_from(start),
        })
    }

    /// `name = ( low , high ) modifiers...`. A token field's name must not
    /// be a keyword (`strict_id`); a context field's may be.
    fn field_def(&mut self, context: bool) -> PResult<FieldDef> {
        if !context
            && self
                .tok
                .ident()
                .is_some_and(|name| name.is_keyword() || name.is_reserved())
        {
            let found = self.found();
            return Err(self.error(format!(
                "{found} is a keyword and cannot name a token field"
            )));
        }
        let name = self.identifier()?;
        self.expect(TokenKind::Assign)?;
        self.expect(TokenKind::LParen)?;
        let low = self.integer()?;
        self.expect(TokenKind::Comma)?;
        let high = self.integer()?;
        self.expect(TokenKind::RParen)?;
        let (mut signed, mut noflow, mut display) = (false, false, None);
        loop {
            // In a context definition a modifier word followed by `=`
            // starts the next field instead.
            if context && self.peek(1).kind == TokenKind::Assign {
                break;
            }
            if self.eat_word(kw::SIGNED).is_some() {
                signed = true;
            } else if self.eat_word(kw::HEX).is_some() {
                display = Some(FieldDisplay::Hex);
            } else if self.eat_word(kw::DEC).is_some() {
                display = Some(FieldDisplay::Dec);
            } else if context && self.eat_word(kw::NOFLOW).is_some() {
                noflow = true;
            } else {
                break;
            }
        }
        Ok(FieldDef {
            name,
            low,
            high,
            signed,
            noflow,
            display,
            span: self.span_from(name.span),
        })
    }

    /// `name modifiers...` after `define space`.
    fn space_def(&mut self, start: Span) -> PResult<SpaceDef> {
        let name = self.identifier()?;
        let mut mods = Vec::new();
        loop {
            if self.eat_word(kw::TYPE).is_some() {
                self.expect(TokenKind::Assign)?;
                mods.push(SpaceMod::Type(self.identifier()?));
            } else if self.eat_word(kw::SIZE).is_some() {
                self.expect(TokenKind::Assign)?;
                mods.push(SpaceMod::Size(self.integer()?));
            } else if self.eat_word(kw::WORDSIZE).is_some() {
                self.expect(TokenKind::Assign)?;
                mods.push(SpaceMod::WordSize(self.integer()?));
            } else if let Some(token) = self.eat_word(kw::DEFAULT) {
                mods.push(SpaceMod::Default(token.span));
            } else {
                break;
            }
        }
        Ok(SpaceDef {
            name,
            mods,
            span: self.span_from(start),
        })
    }

    /// `space offset = o size = s names` after `define`.
    fn varnode_def(&mut self, start: Span) -> PResult<VarnodeDef> {
        let space = self.identifier()?;
        self.expect_word(kw::OFFSET)?;
        self.expect(TokenKind::Assign)?;
        let offset = self.integer()?;
        self.expect_word(kw::SIZE)?;
        self.expect(TokenKind::Assign)?;
        let size = self.integer()?;
        let names = self.identifier_list()?;
        Ok(VarnodeDef {
            space,
            offset,
            size,
            names,
            span: self.span_from(start),
        })
    }

    /// `name = varnode [ low , width ]`.
    fn bitrange_entry(&mut self) -> PResult<BitrangeEntry> {
        let name = self.identifier()?;
        self.expect(TokenKind::Assign)?;
        let varnode = self.identifier()?;
        self.expect(TokenKind::LBracket)?;
        let low = self.integer()?;
        self.expect(TokenKind::Comma)?;
        let width = self.integer()?;
        self.expect(TokenKind::RBracket)?;
        Ok(BitrangeEntry {
            name,
            varnode,
            low,
            width,
            span: self.span_from(name.span),
        })
    }

    /// An `attach` statement, through its `;`.
    fn attach(&mut self) -> PResult<Definition> {
        let start = self.bump().span; // `attach`
        let definition = if self.eat_word(kw::VALUES).is_some() {
            let fields = self.identifier_list()?;
            let values = self.int_list()?;
            Definition::AttachValues(AttachValues {
                fields,
                values,
                span: self.span_from(start),
            })
        } else if self.eat_word(kw::NAMES).is_some() {
            let fields = self.identifier_list()?;
            let names = self.name_list()?;
            Definition::AttachNames(AttachNames {
                fields,
                names,
                span: self.span_from(start),
            })
        } else if self.eat_word(kw::VARIABLES).is_some() {
            let fields = self.identifier_list()?;
            let varnodes = self.identifier_list()?;
            Definition::AttachVariables(AttachVariables {
                fields,
                varnodes,
                span: self.span_from(start),
            })
        } else {
            return Err(self.error_expected("`values`, `names` or `variables` after `attach`"));
        };
        self.expect(TokenKind::Semi)?;
        Ok(definition)
    }

    /// Parses `[ item+ ]` or a single item.
    fn list<T>(
        &mut self,
        what: &str,
        mut item: impl FnMut(&mut Self) -> PResult<Option<T>>,
    ) -> PResult<Vec<T>> {
        let mut items = Vec::new();
        if self.eat(TokenKind::LBracket).is_none() {
            return match item(self)? {
                Some(single) => {
                    items.push(single);
                    Ok(items)
                }
                None => Err(self.error_expected(what)),
            };
        }
        while let Some(next) = item(self)? {
            items.push(next);
        }
        if self.eat(TokenKind::RBracket).is_none() {
            let found = self.found();
            return Err(self.error(format!(
                "expected {what} or `]`, found {found} (forget to close a list above?)"
            )));
        }
        if items.is_empty() {
            let span = Span::at(self.prev_end.saturating_sub(1));
            return Err(self.error_at(span, format!("expected {what} in list")));
        }
        Ok(items)
    }

    fn ident_or_wild(&mut self) -> PResult<Option<IdentOrWild>> {
        if let Some(token) = self.eat(TokenKind::Underscore) {
            Ok(Some(IdentOrWild::Wildcard(token.span)))
        } else if self.at_identifier() {
            self.identifier().map(|i| Some(IdentOrWild::Ident(i)))
        } else {
            Ok(None)
        }
    }

    /// `identifierlist`: names and `_` placeholders.
    fn identifier_list(&mut self) -> PResult<Vec<IdentOrWild>> {
        self.list("identifier", Self::ident_or_wild)
    }

    /// `stringoridentlist`: names, quoted names and `_` placeholders.
    fn name_list(&mut self) -> PResult<Vec<NameOrWild>> {
        self.list("name or string", |p| {
            if let Some(token) = p.eat(TokenKind::QString) {
                let value = p.names.intern(&string_content(p.text(token.span)));
                return Ok(Some(NameOrWild::Str(StrLit {
                    value,
                    span: token.span,
                })));
            }
            Ok(p.ident_or_wild()?.map(|entry| match entry {
                IdentOrWild::Ident(ident) => NameOrWild::Ident(ident),
                IdentOrWild::Wildcard(span) => NameOrWild::Wildcard(span),
            }))
        })
    }

    /// `intblist`: integers, negated integers and, in brackets, `_`.
    fn int_list(&mut self) -> PResult<Vec<IntOrWild>> {
        let bracketed = self.at(TokenKind::LBracket);
        self.list("integer", |p| {
            if bracketed && let Some(token) = p.eat(TokenKind::Underscore) {
                return Ok(Some(IntOrWild::Wildcard(token.span)));
            }
            let negative = p.at(TokenKind::Minus);
            if negative {
                p.bump();
                return p
                    .integer()
                    .map(|value| Some(IntOrWild::Int { negative, value }));
            }
            if p.tok.kind.is_int() {
                return p
                    .integer()
                    .map(|value| Some(IntOrWild::Int { negative, value }));
            }
            Ok(None)
        })
    }
}
