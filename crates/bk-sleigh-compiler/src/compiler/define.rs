//! Definitions (inventory 9.3; grammar actions `slghparse.y` 166-270;
//! `SleighCompile::defineToken`, `addTokenField`, `addContextField`,
//! `newSpace`, `defineVarnodes`, `defineBitrange`, `addUserOp`,
//! `attachValues`, `attachNames`, `attachVarnodes`).

use bk_sla::Field;
use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{
    AttachNames, AttachValues, AttachVariables, BitrangeDef, ContextDef, Definition, Endian,
    FieldDef, IdentOrWild, IntLit, IntOrWild, NameOrWild, PcodeOpDef, SpaceDef, SpaceMod, TokenDef,
    VarnodeDef,
};

use super::{Compiler, PendingField};
use crate::pattern::PatValue;
use crate::spaces::{SpaceInfo, SpaceKind};
use crate::symbols::{SymbolKind, VarnodeData};

impl Compiler<'_> {
    /// One `define` or `attach` statement.
    pub(crate) fn definition(&mut self, def: &Definition) {
        match def {
            Definition::Alignment(d) => {
                if let Some(value) = self.literal(&d.value) {
                    self.align = value as i32;
                }
            }
            Definition::Token(d) => self.define_token(d),
            Definition::Context(d) => self.define_context(d),
            Definition::Space(d) => self.define_space(d),
            Definition::Varnode(d) => self.define_varnodes(d),
            Definition::Bitrange(d) => self.define_bitranges(d),
            Definition::PcodeOp(d) => self.define_userops(d),
            Definition::AttachValues(d) => {
                self.lock_context();
                self.attach_values(d);
            }
            Definition::AttachNames(d) => {
                self.lock_context();
                self.attach_names(d);
            }
            Definition::AttachVariables(d) => {
                self.lock_context();
                self.attach_variables(d);
            }
        }
    }

    /// An integer of a definition; an overflow is a syntax error there.
    fn literal(&mut self, lit: &IntLit) -> Option<u64> {
        let value = lit.to_u64();
        if value.is_none() {
            self.syntax_error(lit.span);
        }
        value
    }

    /// Whether the name already names a symbol (`anysymbol`); reports
    /// "`N`: `what`" if so.
    fn redefined(&mut self, name: bk_sleigh_syntax::ast::Ident, what: &str) -> bool {
        if self.lookup(name.name).is_none() {
            return false;
        }
        let message = format!("{}{what}", self.text(name.name));
        self.diags.error(Some(name.span), message);
        true
    }

    /// Whether a `[` appears in the source between two offsets: tells a
    /// bracketed list from a single entry.
    fn bracket_between(&self, from: u32, to: u32) -> bool {
        self.parsed
            .sources
            .snippet(Span::new(from, to))
            .contains('[')
    }

    fn define_token(&mut self, d: &TokenDef) {
        if self.redefined(d.name, ": redefined as a token") {
            return;
        }
        let Some(bits) = self.literal(&d.size) else {
            return;
        };
        let bits = bits as u32;
        let size = if bits & 7 != 0 {
            let message = format!(
                "'{}': token size must be multiple of 8",
                self.text(d.name.name)
            );
            self.diags.error_at(d.size.span, message);
            bits / 8 + 1
        } else {
            bits / 8
        };
        let big_endian = match d.endian {
            None => self.big_endian,
            Some(e) => e == Endian::Big,
        };
        let token = self.tokens;
        self.tokens = self.tokens.wrapping_add(1);
        self.add_symbol(d.name.name, SymbolKind::Token(token), d.span);
        for field in &d.fields {
            if !self.token_field(field, size, big_endian) {
                return;
            }
        }
    }

    fn field_bounds(&mut self, field: &FieldDef) -> Option<(u32, u32)> {
        let low = self.literal(&field.low)? as u32;
        let high = self.literal(&field.high)? as u32;
        Some((low, high))
    }

    /// `addTokenField`; false stops the statement (`YYERROR`).
    fn token_field(&mut self, field: &FieldDef, token_size: u32, big_endian: bool) -> bool {
        if self.redefined(field.name, ": redefined as field") {
            return false;
        }
        let Some((low, high)) = self.field_bounds(field) else {
            return false;
        };
        let name = self.text(field.name.name).to_owned();
        if high < low {
            self.diags.error_at(
                field.span,
                format!("Field '{name}' starts at {low} and ends at {high}"),
            );
        }
        if token_size.wrapping_mul(8) <= high {
            self.diags.error_at(
                field.span,
                format!("Field '{name}' high must be less than token size"),
            );
        }
        let (start, end) = (low as i32, high as i32);
        let total = (token_size as i32).wrapping_mul(8);
        let (start_byte, end_byte) = if big_endian {
            (
                total.wrapping_sub(end).wrapping_sub(1) / 8,
                total.wrapping_sub(start).wrapping_sub(1) / 8,
            )
        } else {
            (start / 8, end / 8)
        };
        let value = PatValue::Token(Field {
            big_endian,
            sign_bit: field.signed,
            start_bit: start,
            end_bit: end,
            start_byte,
            end_byte,
            shift: start % 8,
        });
        self.add_symbol(field.name.name, SymbolKind::Value(value), field.span);
        true
    }

    fn define_context(&mut self, d: &ContextDef) {
        let Some(id) = self.lookup(d.varnode.name) else {
            self.syntax_error(d.varnode.span);
            return;
        };
        let Some(SymbolKind::Varnode(vn)) = self.kind(id).cloned() else {
            self.syntax_error(d.varnode.span);
            return;
        };
        for field in &d.fields {
            if self.redefined(field.name, ": redefined as field") {
                return;
            }
            let Some((low, high)) = self.field_bounds(field) else {
                return;
            };
            let name = self.text(field.name.name).to_owned();
            if high < low {
                self.diags.error_at(
                    field.span,
                    format!("Context field '{name}' starts at {low} and ends at {high}"),
                );
            }
            if (vn.size as u32).wrapping_mul(8) <= high {
                self.diags.error_at(
                    field.span,
                    format!("Context field '{name}' high must be less than context size"),
                );
            }
            if self.context_locked {
                self.diags.error(
                    Some(field.span),
                    "All context definitions must come before constructors",
                );
                return;
            }
            self.pending_context.push(PendingField {
                varnode: id,
                name: field.name.name,
                low: u64::from(low),
                high: u64::from(high),
                signed: field.signed,
                flow: !field.noflow,
            });
        }
    }

    fn define_space(&mut self, d: &SpaceDef) {
        if self.redefined(d.name, ": redefined as space") {
            return;
        }
        let mut register = false;
        let mut size = 0_u32;
        let mut word_size = 1_u32;
        let mut is_default = false;
        for m in &d.mods {
            match m {
                SpaceMod::Type(t) => match self.text(t.name) {
                    "ram_space" => register = false,
                    "register_space" => register = true,
                    _ => {
                        self.syntax_error(t.span);
                        return;
                    }
                },
                SpaceMod::Size(lit) => match self.literal(lit) {
                    Some(v) => size = v as u32,
                    None => return,
                },
                SpaceMod::WordSize(lit) => match self.literal(lit) {
                    Some(v) => word_size = v as u32,
                    None => return,
                },
                SpaceMod::Default(_) => is_default = true,
            }
        }
        let name = self.text(d.name.name).to_owned();
        if size == 0 {
            self.diags.error_at(
                d.span,
                format!("Space definition '{name}' missing size attribute"),
            );
            return;
        }
        let index = self.spaces.len() as u32;
        let delay = i32::from(!register);
        self.spaces.push(SpaceInfo {
            name: name.clone(),
            index,
            kind: SpaceKind::Processor,
            is_other: false,
            big_endian: self.big_endian,
            addr_size: size,
            word_size,
            delay,
            physical: true,
        });
        if is_default {
            if let Some(old) = self.default_space.and_then(|i| self.spaces.get(i as usize)) {
                let message = format!("Multiple default spaces -- '{}', '{name}'", old.name);
                self.diags.error_at(d.span, message);
            } else {
                self.default_space = Some(index);
            }
        }
        self.add_symbol(d.name.name, SymbolKind::Space(index), d.span);
    }

    /// The names of a `stringlist`; `None` stops the statement.
    fn string_list(
        &mut self,
        names: &[IdentOrWild],
        bracketed: bool,
    ) -> Option<Vec<(bk_sleigh_syntax::Symbol, Span)>> {
        let underscore = self.intern("_");
        let mut list = Vec::with_capacity(names.len());
        for entry in names {
            let (name, span) = match entry {
                IdentOrWild::Ident(ident) => (ident.name, ident.span),
                IdentOrWild::Wildcard(span) => (underscore, *span),
            };
            if self.lookup(name).is_some() {
                if bracketed {
                    let message = format!("{}: redefined", self.text(name));
                    self.diags.error(Some(span), message);
                } else {
                    self.syntax_error(span);
                }
                return None;
            }
            list.push((name, span));
        }
        Some(list)
    }

    fn define_varnodes(&mut self, d: &VarnodeDef) {
        let Some(&SymbolKind::Space(space)) = self.lookup_kind(d.space.name) else {
            self.syntax_error(d.space.span);
            return;
        };
        let Some(offset) = d.offset.to_u64() else {
            self.diags
                .error(Some(d.offset.span), "Parsed integer is too big (overflow)");
            return;
        };
        let Some(size) = self.literal(&d.size) else {
            return;
        };
        let bracketed = d
            .names
            .first()
            .is_some_and(|first| self.bracket_between(d.size.span.end, first.span().start));
        let Some(names) = self.string_list(&d.names, bracketed) else {
            return;
        };
        let underscore = self.intern("_");
        let mut at = offset;
        for (name, span) in names {
            if name != underscore {
                let vn = VarnodeData {
                    space,
                    offset: at,
                    size: size as i32,
                };
                self.add_symbol(name, SymbolKind::Varnode(vn), span);
            }
            at = at.wrapping_add(size);
        }
    }

    fn define_bitranges(&mut self, d: &BitrangeDef) {
        for entry in &d.entries {
            if self.lookup(entry.name.name).is_some() {
                self.syntax_error(entry.name.span);
                return;
            }
            let parent = match self.lookup(entry.varnode.name) {
                Some(id) if matches!(self.kind(id), Some(SymbolKind::Varnode(_))) => id,
                _ => {
                    self.syntax_error(entry.varnode.span);
                    return;
                }
            };
            let (Some(low), Some(width)) = (self.literal(&entry.low), self.literal(&entry.width))
            else {
                return;
            };
            let (bit_offset, bits) = (low as u32, width as u32);
            let Some(SymbolKind::Varnode(vn)) = self.kind(parent).cloned() else {
                return;
            };
            let name = self.text(entry.name.name).to_owned();
            let size = (vn.size as u32).wrapping_mul(8);
            if bits == 0 {
                self.diags
                    .error_at(entry.span, format!("'{name}': size of bitrange is zero"));
                continue;
            }
            if bit_offset >= size || bit_offset.wrapping_add(bits) > size {
                self.diags
                    .error_at(entry.span, format!("'{name}': bad bitrange"));
                continue;
            }
            let kind = if bit_offset.is_multiple_of(8) && bits.is_multiple_of(8) {
                let delta = if self.big_endian {
                    (size - bit_offset - bits) / 8
                } else {
                    bit_offset / 8
                };
                SymbolKind::Varnode(VarnodeData {
                    space: vn.space,
                    offset: vn.offset.wrapping_add(u64::from(delta)),
                    size: (bits / 8) as i32,
                })
            } else {
                SymbolKind::Bitrange {
                    varnode: parent,
                    offset: bit_offset,
                    bits,
                }
            };
            self.add_symbol(entry.name.name, kind, entry.span);
        }
    }

    fn define_userops(&mut self, d: &PcodeOpDef) {
        let bracketed = d
            .names
            .first()
            .is_some_and(|first| self.bracket_between(d.span.start, first.span().start));
        let Some(names) = self.string_list(&d.names, bracketed) else {
            return;
        };
        for (name, span) in names {
            let index = self.userop_count;
            self.userop_count = self.userop_count.wrapping_add(1);
            self.add_symbol(name, SymbolKind::UserOp(index), span);
        }
    }

    /// The symbols of an attach statement's field list (`valuelist`) with
    /// duplicates dropped (`dedupSymbolList`); `None` stops the statement.
    fn value_list(
        &mut self,
        fields: &[IdentOrWild],
        keyword: &str,
        start: u32,
    ) -> Option<Vec<crate::ids::SymbolId>> {
        let bracketed = fields
            .first()
            .is_some_and(|first| self.bracket_between(start, first.span().start));
        let underscore = self.intern("_");
        let mut list: Vec<Option<crate::ids::SymbolId>> = Vec::new();
        for (i, entry) in fields.iter().enumerate() {
            let (name, span) = match entry {
                IdentOrWild::Ident(ident) => (ident.name, ident.span),
                IdentOrWild::Wildcard(span) => (underscore, *span),
            };
            match self.lookup(name) {
                Some(id)
                    if matches!(
                        self.kind(id),
                        Some(SymbolKind::Value(_) | SymbolKind::Context { .. })
                    ) =>
                {
                    list.push(Some(id))
                }
                None if bracketed && i > 0 => {
                    let message = format!("{}: is not a value pattern", self.text(name));
                    self.diags.error(Some(span), message);
                    return None;
                }
                _ => {
                    self.syntax_error(span);
                    return None;
                }
            }
        }
        let mut duplicate = None;
        for i in 0..list.len() {
            let Some(Some(sym)) = list.get(i).copied() else {
                continue;
            };
            for later in list.iter_mut().skip(i + 1) {
                if *later == Some(sym) {
                    duplicate = Some(sym);
                    *later = None;
                }
            }
        }
        if let Some(sym) = duplicate {
            let name = self.symbols.get(sym).map(|s| s.name);
            let text = name.map_or("", |n| self.text(n)).to_owned();
            self.diags.warning_at(
                Span::at(start),
                format!("'attach {keyword}' list contains duplicate entries: {text}"),
            );
        }
        Some(list.into_iter().flatten().collect())
    }

    /// The field of a symbol being attached to, and its size check.
    fn attach_field(
        &mut self,
        sym: crate::ids::SymbolId,
        what: &str,
        entries: usize,
        at: Span,
    ) -> Option<PatValue> {
        let symbol = self.symbols.get(sym)?;
        let value = symbol.kind.pattern_value()?;
        let max = value.max_value();
        if max.wrapping_add(1) != entries as i64 {
            let name = self.text(symbol.name).to_owned();
            let message = format!(
                "Attach {what} '{name}' (range 0..{max}) is wrong size for list (of {entries} entries)"
            );
            self.diags.error_at(at, message);
        }
        Some(value)
    }

    fn attach_values(&mut self, d: &AttachValues) {
        let Some(fields) = self.value_list(&d.fields, "values", d.span.start) else {
            return;
        };
        let mut values = Vec::with_capacity(d.values.len());
        for v in &d.values {
            match v {
                IntOrWild::Int { negative, value } => {
                    let Some(n) = self.literal(value) else { return };
                    let n = n as i64;
                    values.push(if *negative { n.wrapping_neg() } else { n });
                }
                IntOrWild::Wildcard(_) => values.push(0x0BAD_BEEF),
            }
        }
        for sym in fields {
            if let Some(field) = self.attach_field(sym, "value", values.len(), d.span) {
                self.symbols
                    .replace(sym, SymbolKind::ValueMap(field, values.clone()));
            }
        }
    }

    fn attach_names(&mut self, d: &AttachNames) {
        let Some(fields) = self.value_list(&d.fields, "names", d.span.start) else {
            return;
        };
        let names: Vec<Option<String>> = d
            .names
            .iter()
            .map(|n| match n {
                NameOrWild::Ident(i) => Some(self.text(i.name).to_owned()),
                NameOrWild::Str(s) => Some(self.text(s.value).to_owned()),
                NameOrWild::Wildcard(_) => None,
            })
            .map(|n| n.filter(|n| n != "_" && n != "\t"))
            .collect();
        for sym in fields {
            if let Some(field) = self.attach_field(sym, "name", names.len(), d.span) {
                self.symbols
                    .replace(sym, SymbolKind::Name(field, names.clone()));
            }
        }
    }

    fn attach_variables(&mut self, d: &AttachVariables) {
        let Some(fields) = self.value_list(&d.fields, "variables", d.span.start) else {
            return;
        };
        let mut list = Vec::with_capacity(d.varnodes.len());
        for entry in &d.varnodes {
            match entry {
                IdentOrWild::Wildcard(_) => list.push(None),
                IdentOrWild::Ident(ident) => match self.lookup(ident.name) {
                    Some(id) if matches!(self.kind(id), Some(SymbolKind::Varnode(_))) => {
                        list.push(Some(id))
                    }
                    None => {
                        let message = format!("{}: is not a varnode symbol", self.text(ident.name));
                        self.diags.error(Some(ident.span), message);
                        return;
                    }
                    Some(_) => {
                        self.syntax_error(ident.span);
                        return;
                    }
                },
            }
        }
        for sym in fields {
            let Some(field) = self.attach_field(sym, "varnode", list.len(), d.span) else {
                continue;
            };
            let mut size = 0;
            for vsym in list.iter().flatten() {
                let Some(SymbolKind::Varnode(vn)) = self.kind(*vsym) else {
                    continue;
                };
                if size == 0 {
                    size = vn.size;
                } else if size != vn.size {
                    let message = format!(
                        "Attach statement contains varnodes of different sizes -- {size} != {}",
                        vn.size
                    );
                    self.diags.error_at(d.span, message);
                    break;
                }
            }
            self.symbols
                .replace(sym, SymbolKind::VarnodeList(field, list.clone()));
        }
    }
}
