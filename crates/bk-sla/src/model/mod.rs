//! The in-memory model of a compiled language: one immutable value of flat
//! arenas addressed by typed `u32` indices (ADR-012, `features/sla.md` 5.1).

pub mod constructor;
pub mod expr;
pub mod handles;
pub mod symbol;
pub mod template;

use constructor::{
    Constructor, ContextChange, DecisionNode, DecisionPair, MaskWord, PatternBlock, PrintPiece,
};
use expr::{Expr, Field};
use handles::{
    BlockId, ConstructorId, DecisionId, ExprId, FieldId, ScopeId, StrId, Strings, SymbolId,
    TemplateId,
};
use symbol::{Header, Scope, SpaceRecord, Symbol, SymbolKind};
use template::{ConstructTpl, HandleTpl, OpTpl, TemplateRef, VarnodeTpl};

/// The arenas a model is made of. The reader and the builder fill them; the
/// [`Sla`] owns them.
#[derive(Clone, Debug, Default)]
pub(crate) struct Arenas {
    pub(crate) strings: Strings,
    pub(crate) source_files: Vec<StrId>,
    pub(crate) spaces: Vec<SpaceRecord>,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) constructors: Vec<Constructor>,
    pub(crate) operand_lists: Vec<SymbolId>,
    pub(crate) print_pieces: Vec<PrintPiece>,
    pub(crate) context_changes: Vec<ContextChange>,
    pub(crate) templates: Vec<ConstructTpl>,
    pub(crate) ops: Vec<OpTpl>,
    pub(crate) varnodes: Vec<VarnodeTpl>,
    pub(crate) handles: Vec<HandleTpl>,
    pub(crate) decisions: Vec<DecisionNode>,
    pub(crate) pairs: Vec<DecisionPair>,
    pub(crate) blocks: Vec<PatternBlock>,
    pub(crate) words: Vec<MaskWord>,
    pub(crate) exprs: Vec<Expr>,
    pub(crate) fields: Vec<Field>,
    pub(crate) value_table: Vec<i64>,
    pub(crate) name_table: Vec<Option<StrId>>,
    pub(crate) varnode_table: Vec<Option<SymbolId>>,
}

impl Arenas {
    /// Bytes held by the arenas (capacity, not length).
    pub(crate) fn heap_bytes(&self) -> usize {
        fn bytes<T>(v: &Vec<T>) -> usize {
            v.capacity() * size_of::<T>()
        }
        self.strings.capacity()
            + bytes(&self.source_files)
            + bytes(&self.spaces)
            + bytes(&self.scopes)
            + bytes(&self.symbols)
            + bytes(&self.constructors)
            + bytes(&self.operand_lists)
            + bytes(&self.print_pieces)
            + bytes(&self.context_changes)
            + bytes(&self.templates)
            + bytes(&self.ops)
            + bytes(&self.varnodes)
            + bytes(&self.handles)
            + bytes(&self.decisions)
            + bytes(&self.pairs)
            + bytes(&self.blocks)
            + bytes(&self.words)
            + bytes(&self.exprs)
            + bytes(&self.fields)
            + bytes(&self.value_table)
            + bytes(&self.name_table)
            + bytes(&self.varnode_table)
    }
}

/// A compiled language: everything a `.sla` file holds.
///
/// Immutable once built, `Send + Sync`; share it as `Arc<Sla>`. Every index
/// stored in a model that passed validation (all models this crate hands
/// out) refers to an existing object of the right kind.
///
/// Equality is structural: two models are equal when they describe the same
/// file, however their arenas are laid out ([`crate::diff`]).
#[derive(Clone, Debug)]
pub struct Sla {
    pub(crate) header: Header,
    pub(crate) default_space: u32,
    pub(crate) root: SymbolId,
    pub(crate) a: Arenas,
}

impl PartialEq for Sla {
    fn eq(&self, other: &Self) -> bool {
        crate::diff::diff(self, other, 1).is_empty()
    }
}

impl Eq for Sla {}

impl Sla {
    /// The attributes of `<sleigh>`.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// A string of the model.
    pub fn text(&self, id: StrId) -> &str {
        self.a.strings.get(id)
    }

    /// The source files, indexed by the constructors' `source`.
    pub fn source_files(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.a.source_files.iter().map(|&id| self.text(id))
    }

    /// The source file with the given index.
    pub fn source_file(&self, index: i32) -> Option<&str> {
        let slot = usize::try_from(index).ok()?;
        self.a.source_files.get(slot).map(|&id| self.text(id))
    }

    /// The address spaces the file declares, in file order (the constant
    /// space, index 0, is implicit).
    pub fn space_records(&self) -> &[SpaceRecord] {
        &self.a.spaces
    }

    /// The index of the default code space.
    pub fn default_space(&self) -> u32 {
        self.default_space
    }

    /// The name of the space with the given index: `const` for 0.
    pub fn space_name(&self, index: u32) -> Option<&str> {
        if index == 0 {
            return Some(crate::spaces::CONSTANT_SPACE_NAME);
        }
        self.a
            .spaces
            .iter()
            .find(|space| space.index == index)
            .map(|space| self.text(space.name))
    }

    /// The scopes, indexed by [`ScopeId`].
    pub fn scopes(&self) -> &[Scope] {
        &self.a.scopes
    }

    /// The symbols, indexed by [`SymbolId`].
    pub fn symbols(&self) -> &[Symbol] {
        &self.a.symbols
    }

    /// One symbol.
    pub fn symbol(&self, id: SymbolId) -> Option<&Symbol> {
        self.a.symbols.get(id.slot())
    }

    /// A symbol's name (empty for an unknown id).
    pub fn symbol_name(&self, id: SymbolId) -> &str {
        self.symbol(id).map_or("", |symbol| self.text(symbol.name))
    }

    /// The global symbol with the given name.
    pub fn global(&self, name: &str) -> Option<SymbolId> {
        self.a
            .symbols
            .iter()
            .position(|symbol| symbol.scope == ScopeId::new(0) && self.text(symbol.name) == name)
            .map(|slot| SymbolId::new(slot as u32))
    }

    /// The root subtable, the global symbol `instruction`.
    pub fn root(&self) -> SymbolId {
        self.root
    }

    /// The values of a value-map symbol's table ([`SymbolKind::ValueMap`]).
    pub fn value_table(&self, table: handles::Span) -> &[i64] {
        self.a.value_table.get(table.range()).unwrap_or_default()
    }

    /// The names of a name symbol's table; `None` marks an unusable entry.
    pub fn name_table(&self, table: handles::Span) -> &[Option<StrId>] {
        self.a.name_table.get(table.range()).unwrap_or_default()
    }

    /// The registers of a varnode-list symbol; `None` marks an unusable entry.
    pub fn varnode_table(&self, table: handles::Span) -> &[Option<SymbolId>] {
        self.a.varnode_table.get(table.range()).unwrap_or_default()
    }

    /// All constructors of all subtables.
    pub fn constructors(&self) -> &[Constructor] {
        &self.a.constructors
    }

    /// One constructor.
    pub fn constructor(&self, id: ConstructorId) -> Option<&Constructor> {
        self.a.constructors.get(id.slot())
    }

    /// A constructor's operand symbols in order.
    pub fn operands(&self, ctor: &Constructor) -> &[SymbolId] {
        self.a.operand_lists.get(ctor.operands.range()).unwrap_or_default()
    }

    /// A constructor's print pieces in order.
    pub fn print_pieces(&self, ctor: &Constructor) -> &[PrintPiece] {
        self.a.print_pieces.get(ctor.print.range()).unwrap_or_default()
    }

    /// A constructor's context changes in order.
    pub fn context_changes(&self, ctor: &Constructor) -> &[ContextChange] {
        self.a
            .context_changes
            .get(ctor.context.range())
            .unwrap_or_default()
    }

    /// The ids of a constructor's templates: main first, then sections by
    /// number.
    pub fn template_ids(&self, ctor: &Constructor) -> impl ExactSizeIterator<Item = TemplateId> {
        ctor.templates.range().map(|slot| TemplateId::new(slot as u32))
    }

    /// A constructor's main template, if its body is not `unimpl`.
    pub fn main_template(&self, ctor: &Constructor) -> Option<TemplateRef<'_>> {
        self.template_ids(ctor)
            .filter_map(|id| self.template(id))
            .find(|template| template.header().section.is_none())
    }

    /// A constructor's template for section `number`.
    pub fn section_template(&self, ctor: &Constructor, number: u32) -> Option<TemplateRef<'_>> {
        self.template_ids(ctor)
            .filter_map(|id| self.template(id))
            .find(|template| template.header().section == Some(number))
    }

    /// One template.
    pub fn template(&self, id: TemplateId) -> Option<TemplateRef<'_>> {
        let header = self.a.templates.get(id.slot())?;
        Some(TemplateRef::new(
            header,
            &self.a.ops,
            &self.a.varnodes,
            &self.a.handles,
        ))
    }

    /// One decision node.
    pub fn decision(&self, id: DecisionId) -> Option<&DecisionNode> {
        self.a.decisions.get(id.slot())
    }

    /// The child of a decision node for field value `value`.
    pub fn decision_child(&self, node: &DecisionNode, value: u32) -> Option<DecisionId> {
        (value < node.num_children()).then(|| DecisionId::new(node.first_child.wrapping_add(value)))
    }

    /// The children of a decision node, in field-value order.
    pub fn children(&self, node: &DecisionNode) -> impl ExactSizeIterator<Item = DecisionId> {
        let first = node.first_child;
        (0..node.num_children()).map(move |value| DecisionId::new(first.wrapping_add(value)))
    }

    /// The pairs of a leaf, in the order they are tried.
    pub fn pairs(&self, node: &DecisionNode) -> &[DecisionPair] {
        self.a.pairs.get(node.pairs.range()).unwrap_or_default()
    }

    /// One pattern block.
    pub fn block(&self, id: BlockId) -> Option<&PatternBlock> {
        self.a.blocks.get(id.slot())
    }

    /// A pattern block's words.
    pub fn block_words(&self, block: &PatternBlock) -> &[MaskWord] {
        self.a.words.get(block.words.range()).unwrap_or_default()
    }

    /// One expression node.
    pub fn expr(&self, id: ExprId) -> Option<&Expr> {
        self.a.exprs.get(id.slot())
    }

    /// One field.
    pub fn field(&self, id: FieldId) -> Option<&Field> {
        self.a.fields.get(id.slot())
    }

    /// The number of context words the file's context fields address
    /// (the largest `end_bit / 32 + 1` over every context field).
    pub fn context_words(&self) -> u32 {
        crate::validate::context_words(&self.a)
    }

    /// Bytes of heap the model's arenas hold.
    pub fn heap_bytes(&self) -> usize {
        self.a.heap_bytes()
    }

    /// The subtable content of a symbol, if it is a subtable.
    pub fn subtable(&self, id: SymbolId) -> Option<&symbol::Subtable> {
        match &self.symbol(id)?.kind {
            SymbolKind::Subtable(table) => Some(table),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use template::ConstTpl;

    #[test]
    fn hot_struct_sizes() {
        assert!(size_of::<ConstTpl>() <= 16, "{}", size_of::<ConstTpl>());
        assert!(size_of::<VarnodeTpl>() <= 48);
        assert!(size_of::<Expr>() <= 16, "{}", size_of::<Expr>());
        assert!(size_of::<DecisionNode>() <= 24, "{}", size_of::<DecisionNode>());
        assert!(size_of::<PatternBlock>() <= 16);
    }

    #[test]
    fn sla_is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<Sla>();
    }
}
