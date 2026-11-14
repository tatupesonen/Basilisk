//! Validation of a decoded or built model (`features/sla.md` 4.3): every id
//! refers to an object of the right kind, shapes and value ranges hold, no
//! operand expression depends on itself. A model that passes can be used
//! with unchecked-by-construction indices.

mod tables;

pub(crate) use tables::check_template;

use std::collections::HashSet;

use crate::error::SlaError;
use crate::limits::Limits;
use crate::model::expr::Expr;
use crate::model::handles::{ExprId, ScopeId, SymbolId};
use crate::model::symbol::SymbolKind;
use crate::model::{Arenas, Sla};
use crate::read::Decoded;

/// The number of context words the context fields address.
pub(crate) fn context_words(a: &Arenas) -> u32 {
    a.exprs
        .iter()
        .filter_map(|expr| match expr {
            Expr::ContextField(field) => a.fields.get(field.slot()),
            _ => None,
        })
        .map(|field| u32::try_from(field.end_bit / 32 + 1).unwrap_or(0))
        .max()
        .unwrap_or(0)
}

/// Turns what was decoded into a validated model.
pub(crate) fn finish(decoded: Decoded, limits: &Limits) -> Result<Sla, SlaError> {
    let mut sla = Sla {
        header: decoded.header,
        default_space: decoded.default_space,
        root: SymbolId::new(0),
        a: decoded.arenas,
    };
    sla.root = validate(&sla, limits)?;
    Ok(sla)
}

/// Checks every rule; returns the root subtable.
pub(crate) fn validate(sla: &Sla, limits: &Limits) -> Result<SymbolId, SlaError> {
    let mut v = Validator::new(sla, limits);
    v.spaces()?;
    v.exprs()?;
    let root = v.symbols()?;
    v.tables()?;
    v.operand_cycles()?;
    Ok(root)
}

pub(crate) struct Validator<'s> {
    pub(crate) sla: &'s Sla,
    pub(crate) limits: &'s Limits,
    /// Which space indices exist (index 0, the constant space, always).
    known_spaces: Vec<bool>,
    pub(crate) context_words: u32,
    /// How many constructors own each operand symbol.
    pub(crate) owners: Vec<u8>,
}

/// A byte quantity: not negative and within the limit.
pub(crate) fn byte_quantity(
    limits: &Limits,
    path: &str,
    what: &str,
    value: i32,
) -> Result<(), SlaError> {
    if value < 0 {
        return fail(path, format!("{what} {value} is negative"));
    }
    if value as u32 > limits.byte_quantity {
        return Err(SlaError::Limit {
            location: crate::error::Location {
                path: format!("{path} ({what})"),
                offset: None,
            },
            what: "byte quantity",
            limit: u64::from(limits.byte_quantity),
            found: value as u64,
        });
    }
    Ok(())
}

pub(crate) fn fail<T>(path: impl Into<String>, message: impl Into<String>) -> Result<T, SlaError> {
    Err(SlaError::structure(path, message))
}

impl<'s> Validator<'s> {
    fn new(sla: &'s Sla, limits: &'s Limits) -> Self {
        Self {
            sla,
            limits,
            known_spaces: vec![true],
            context_words: context_words(&sla.a),
            owners: vec![0; sla.a.symbols.len()],
        }
    }

    pub(crate) fn symbol_path(&self, id: SymbolId) -> String {
        format!(
            "sleigh/symbol_table/symbol {id} \"{}\"",
            self.sla.symbol_name(id)
        )
    }

    pub(crate) fn space_known(&self, index: u32) -> bool {
        self.known_spaces
            .get(index as usize)
            .copied()
            .unwrap_or(false)
    }

    pub(crate) fn byte_quantity(&self, path: &str, what: &str, value: i32) -> Result<(), SlaError> {
        byte_quantity(self.limits, path, what, value)
    }

    fn spaces(&mut self) -> Result<(), SlaError> {
        let path = "sleigh/spaces";
        let (mut unique, mut other) = (0, 0);
        for space in &self.sla.a.spaces {
            let name = self.sla.text(space.name);
            if space.index == 0 || space.index > bk_core::space::MAX_SPACE_INDEX {
                return fail(path, format!("space \"{name}\" has index {}", space.index));
            }
            let slot = space.index as usize;
            if self.known_spaces.len() <= slot {
                self.known_spaces.resize(slot + 1, false);
            }
            if self.known_spaces.get(slot).copied().unwrap_or(false) {
                return fail(path, format!("two spaces have index {}", space.index));
            }
            if let Some(known) = self.known_spaces.get_mut(slot) {
                *known = true;
            }
            match space.kind {
                crate::model::symbol::SpaceKind::Unique => unique += 1,
                crate::model::symbol::SpaceKind::Other => other += 1,
                crate::model::symbol::SpaceKind::Processor => {
                    if space.size <= 0 || space.delay < 0 || name.is_empty() {
                        return fail(path, "Expecting size/delay/name attributes");
                    }
                }
            }
            if space.word_size < 1 {
                return fail(
                    path,
                    format!("space \"{name}\" has word size {}", space.word_size),
                );
            }
        }
        if unique > 1 || other > 1 {
            return fail(path, "more than one space_unique or space_other");
        }
        if !self
            .sla
            .a
            .spaces
            .iter()
            .any(|space| space.index == self.sla.default_space)
        {
            return fail(path, "the default space is not declared");
        }
        let max_delay = i32::try_from(self.sla.header.max_delay).unwrap_or(i32::MAX);
        self.byte_quantity("sleigh", "maxdelay", max_delay)?;
        if self.context_words > self.limits.context_words {
            return Err(SlaError::Limit {
                location: crate::error::Location::default(),
                what: "context words",
                limit: u64::from(self.limits.context_words),
                found: u64::from(self.context_words),
            });
        }
        Ok(())
    }

    /// Every expression node: children are earlier nodes, nesting is
    /// bounded, fields are well formed, operand references resolve.
    fn exprs(&self) -> Result<(), SlaError> {
        let a = &self.sla.a;
        let mut depth: Vec<u32> = Vec::with_capacity(a.exprs.len());
        for (index, expr) in a.exprs.iter().enumerate() {
            let path = || format!("expression {index}");
            let child_depth = |child: ExprId| -> Result<u32, SlaError> {
                if child.slot() >= index {
                    return fail(path(), "an expression refers to a later node");
                }
                Ok(depth.get(child.slot()).copied().unwrap_or(0))
            };
            let mine = match *expr {
                Expr::Binary { left, right, .. } => 1 + child_depth(left)?.max(child_depth(right)?),
                Expr::Unary { operand, .. } => 1 + child_depth(operand)?,
                Expr::TokenField(field) | Expr::ContextField(field) => {
                    let token = matches!(expr, Expr::TokenField(_));
                    let Some(f) = a.fields.get(field.slot()) else {
                        return fail(path(), "dangling field");
                    };
                    let bytes = i64::from(f.end_byte) - i64::from(f.start_byte) + 1;
                    let bits = i64::from(f.end_bit) - i64::from(f.start_bit) + 1;
                    let ok = f.start_bit >= 0
                        && f.start_bit <= f.end_bit
                        && f.start_byte >= 0
                        && f.start_byte <= f.end_byte
                        && bytes <= 8
                        && (0..=7).contains(&f.shift)
                        && i64::from(f.shift) + bits <= 8 * bytes
                        && (token || bits <= 32)
                        && (token
                            || u64::try_from(f.end_bit).unwrap_or(u64::MAX)
                                < u64::from(self.limits.context_words) * 32)
                        && f.end_byte as u32 <= self.limits.byte_quantity;
                    if !ok {
                        return fail(path(), format!("malformed field {f:?}"));
                    }
                    1
                }
                Expr::Operand {
                    index: op,
                    table,
                    ct,
                } => {
                    let Some(subtable) = self.sla.subtable(table) else {
                        return fail(
                            path(),
                            format!("operand_exp table {table} is not a subtable"),
                        );
                    };
                    let Some(ctor) = subtable
                        .constructor(ct)
                        .and_then(|id| self.sla.constructor(id))
                    else {
                        return fail(path(), format!("operand_exp ct {ct} is out of range"));
                    };
                    if op < 0 || op as u32 >= ctor.num_operands() {
                        return fail(path(), format!("operand_exp index {op} is out of range"));
                    }
                    1
                }
                _ => 1,
            };
            if mine > self.limits.expr_depth {
                return Err(SlaError::Limit {
                    location: crate::error::Location {
                        path: path(),
                        offset: None,
                    },
                    what: "expression nesting",
                    limit: u64::from(self.limits.expr_depth),
                    found: u64::from(mine),
                });
            }
            depth.push(mine);
        }
        Ok(())
    }

    pub(crate) fn expr_ok(&self, path: &str, expr: ExprId) -> Result<&'s Expr, SlaError> {
        self.sla
            .expr(expr)
            .map_or_else(|| fail(path, format!("dangling expression {expr}")), Ok)
    }

    fn value_expr(&self, path: &str, expr: ExprId) -> Result<(), SlaError> {
        if !self.expr_ok(path, expr)?.is_value() {
            return fail(
                path,
                "the field of a value symbol is not a value expression",
            );
        }
        Ok(())
    }

    fn symbols(&self) -> Result<SymbolId, SlaError> {
        let sla = self.sla;
        for (index, scope) in sla.a.scopes.iter().enumerate() {
            if let Some(parent) = scope.parent
                && parent.slot() >= sla.a.scopes.len()
            {
                return fail(
                    format!("sleigh/symbol_table/scope {index}"),
                    "dangling parent",
                );
            }
        }
        let mut globals: HashSet<&str> = HashSet::new();
        let mut root = None;
        for (index, symbol) in sla.a.symbols.iter().enumerate() {
            let id = SymbolId::new(index as u32);
            let path = self.symbol_path(id);
            if symbol.scope.slot() >= sla.a.scopes.len() {
                return fail(path, "Bad symbol scope id: undefined");
            }
            let name = sla.text(symbol.name);
            if symbol.scope == ScopeId::new(0) {
                if !globals.insert(name) {
                    return fail(path, "two global symbols share this name");
                }
                if name == "instruction" {
                    if !matches!(symbol.kind, SymbolKind::Subtable(_)) {
                        return fail(path, "the global symbol `instruction` is not a subtable");
                    }
                    root = Some(id);
                }
            }
            match symbol.kind {
                SymbolKind::Value { expr } | SymbolKind::ValueMap { expr, .. } => {
                    self.value_expr(&path, expr)?;
                }
                SymbolKind::Name { expr, table } => {
                    self.value_expr(&path, expr)?;
                    if table.range().end > sla.a.name_table.len() {
                        return fail(path, "dangling name table");
                    }
                }
                SymbolKind::VarnodeList { expr, table } => {
                    self.value_expr(&path, expr)?;
                    for entry in sla.varnode_table(table).iter().flatten() {
                        self.require_varnode(&path, *entry)?;
                    }
                }
                SymbolKind::Varnode { space, size, .. } => {
                    if !self.space_known(space) {
                        return fail(path, format!("unknown space index {space}"));
                    }
                    if size <= 0 {
                        return fail(path, format!("varnode size {size} is not positive"));
                    }
                }
                SymbolKind::Context { varnode, expr, .. } => {
                    self.require_varnode(&path, varnode)?;
                    if !matches!(self.expr_ok(&path, expr)?, Expr::ContextField(_)) {
                        return fail(path, "the field of a context symbol is not a context field");
                    }
                }
                SymbolKind::Operand(operand) => {
                    self.expr_ok(&path, operand.local_expr)?;
                    if let Some(expr) = operand.defining_expr {
                        self.expr_ok(&path, expr)?;
                    }
                    if operand.defining_expr.is_some() == operand.defining_symbol.is_some() {
                        return fail(
                            path,
                            "an operand needs exactly one of a defining symbol and a defining expression",
                        );
                    }
                    if let Some(sub) = operand.defining_symbol {
                        let ok = sla.symbol(sub).is_some_and(|s| {
                            !matches!(s.kind, SymbolKind::Operand(_) | SymbolKind::UserOp { .. })
                        });
                        if !ok {
                            return fail(path, format!("subsym {sub} is not a definable symbol"));
                        }
                    }
                    self.byte_quantity(&path, "off", operand.offset)?;
                    self.byte_quantity(&path, "minlen", operand.min_length)?;
                    if operand.base < -1 || operand.base >= operand.index {
                        return fail(
                            path,
                            format!(
                                "base {} is not -1 or below index {}",
                                operand.base, operand.index
                            ),
                        );
                    }
                }
                _ => {}
            }
        }
        root.map_or_else(
            || fail("sleigh/symbol_table", "no global subtable `instruction`"),
            Ok,
        )
    }

    fn require_varnode(&self, path: &str, id: SymbolId) -> Result<(), SlaError> {
        match self.sla.symbol(id).map(|symbol| &symbol.kind) {
            Some(SymbolKind::Varnode { .. }) => Ok(()),
            _ => fail(path, format!("symbol {id} is not a varnode symbol")),
        }
    }
}
