//! The producer's interface: build a model piece by piece, then
//! [`SlaBuilder::finish`] lays it out and runs the reader's validation.
//!
//! Symbols are added in id order (a symbol's id is its position), so a
//! subtable's operands and constructors can refer to symbols declared later
//! as long as they exist when `finish` runs. Expressions are added bottom
//! up: an expression's children must be added before it.

use crate::error::SlaError;
use crate::limits::Limits;
use crate::model::constructor::{
    Constructor, ContextChange, DecisionNode, DecisionPair, DisjointPattern, MaskWord,
    PatternBlock, PrintPiece, normalize_block,
};
use crate::model::expr::{Expr, Field};
use crate::model::handles::{
    BlockId, DecisionId, ExprId, FieldId, HandleId, ScopeId, Span, SymbolId,
};
use crate::model::symbol::{
    Header, Operand, Scope, SpaceKind, SpaceRecord, Subtable, Symbol, SymbolKind,
};
use crate::model::template::Template;
use crate::model::{Arenas, Sla};

/// An address space to declare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceDef {
    /// The element that declares it.
    pub kind: SpaceKind,
    /// Its name.
    pub name: String,
    /// Its index (not 0).
    pub index: u32,
    /// The `bigendian` attribute (normally the language's endianness).
    pub big_endian: bool,
    /// Heritage delay.
    pub delay: i32,
    /// Offset size in bytes.
    pub size: i32,
    /// Bytes per addressable unit.
    pub word_size: i32,
    /// Physical backing.
    pub physical: bool,
}

/// A symbol's content as the builder takes it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SymbolDef {
    /// A user-defined p-code op.
    UserOp {
        /// Its index.
        index: i32,
    },
    /// A value symbol.
    Value {
        /// Its field.
        expr: ExprId,
    },
    /// A value-map symbol.
    ValueMap {
        /// Its field.
        expr: ExprId,
        /// The values (`0xBADBEEF` marks an unusable entry).
        values: Vec<i64>,
    },
    /// A name symbol.
    Name {
        /// Its field.
        expr: ExprId,
        /// The names; `None` marks an unusable entry.
        names: Vec<Option<String>>,
    },
    /// A varnode symbol.
    Varnode {
        /// Space index.
        space: u32,
        /// Offset.
        offset: u64,
        /// Size in bytes.
        size: i32,
    },
    /// A context symbol.
    Context {
        /// The context register's varnode symbol.
        varnode: SymbolId,
        /// Low bit.
        low: i32,
        /// High bit.
        high: i32,
        /// Flow flag.
        flow: bool,
        /// The context field.
        expr: ExprId,
    },
    /// A varnode-list symbol.
    VarnodeList {
        /// Its field.
        expr: ExprId,
        /// The registers; `None` marks an unusable entry.
        entries: Vec<Option<SymbolId>>,
    },
    /// An operand symbol.
    Operand(Operand),
    /// `inst_start`.
    Start,
    /// `inst_next`.
    End,
    /// `inst_next2`.
    Next2,
    /// `epsilon`.
    Epsilon,
    /// A subtable.
    Subtable(TableDef),
}

/// A subtable's constructors and decision tree.
#[derive(Clone, Debug)]
pub struct TableDef {
    /// The constructors in index order.
    pub constructors: Vec<ConstructorDef>,
    /// The decision tree.
    pub decision: DecisionDef,
}

/// One constructor; its parent is the subtable it is given to.
#[derive(Clone, Debug, Default)]
pub struct ConstructorDef {
    /// First white-space print piece, or −1.
    pub first: i32,
    /// Minimum length in bytes.
    pub length: i32,
    /// Source file index.
    pub source: i32,
    /// Source line.
    pub line: i32,
    /// Operand symbols in order.
    pub operands: Vec<SymbolId>,
    /// Print pieces.
    pub print: Vec<PrintDef>,
    /// Context changes in order.
    pub context: Vec<ContextChange>,
    /// Templates: at most one main template and one per section, in any
    /// order (they are written main first, then by section).
    pub templates: Vec<Template>,
}

/// A print piece.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrintDef {
    /// Literal text.
    Text(String),
    /// An operand, by index.
    Operand(i32),
}

/// A decision-tree node with its subtree.
#[derive(Clone, Debug, Default)]
pub struct DecisionDef {
    /// Informational pair count.
    pub number: i32,
    /// Context (true) or instruction bits.
    pub context: bool,
    /// First bit tested.
    pub start_bit: i32,
    /// Bits tested; 0 for a leaf.
    pub size: u8,
    /// A leaf's pairs, in the order they are tried.
    pub pairs: Vec<PairDef>,
    /// An inner node's `2^size` children.
    pub children: Vec<DecisionDef>,
}

/// A constructor reached at a leaf with its pattern.
#[derive(Clone, Debug)]
pub struct PairDef {
    /// The constructor's index in the subtable.
    pub constructor: u32,
    /// The pattern.
    pub pattern: PatternDef,
}

/// A disjoint pattern.
#[derive(Clone, Debug)]
pub enum PatternDef {
    /// Over the instruction bytes.
    Instruction(BlockDef),
    /// Over the context.
    Context(BlockDef),
    /// Context then instruction.
    Combine(BlockDef, BlockDef),
}

/// A pattern block; it is normalised when the model is laid out.
#[derive(Clone, Debug, Default)]
pub struct BlockDef {
    /// Byte offset.
    pub offset: i32,
    /// Non-zero size (0 always true, −1 always false).
    pub nonzero: i32,
    /// The words.
    pub words: Vec<MaskWord>,
}

/// Builds a [`Sla`].
#[derive(Debug, Default)]
pub struct SlaBuilder {
    header: Header,
    files: Vec<String>,
    spaces: Vec<SpaceDef>,
    default_space: String,
    scopes: Vec<Option<ScopeId>>,
    symbols: Vec<(String, ScopeId, SymbolDef)>,
    a: Arenas,
}

impl SlaBuilder {
    /// A builder for a language with the given header.
    pub fn new(header: Header) -> Self {
        Self {
            header,
            ..Self::default()
        }
    }

    /// Adds a source file; returns its index.
    pub fn source_file(&mut self, name: &str) -> i32 {
        self.files.push(name.to_owned());
        self.files.len() as i32 - 1
    }

    /// Declares an address space.
    pub fn space(&mut self, space: SpaceDef) {
        self.spaces.push(space);
    }

    /// Names the default code space.
    pub fn default_space(&mut self, name: &str) {
        name.clone_into(&mut self.default_space);
    }

    /// Adds a scope; the first is the global scope (pass `None`).
    pub fn scope(&mut self, parent: Option<ScopeId>) -> ScopeId {
        self.scopes.push(parent);
        ScopeId::new(self.scopes.len() as u32 - 1)
    }

    /// Adds a token or context field for an expression to use.
    pub fn field(&mut self, field: Field) -> FieldId {
        self.a.fields.push(field);
        FieldId::new(self.a.fields.len() as u32 - 1)
    }

    /// Adds an expression node; its children must already be added.
    pub fn expr(&mut self, expr: Expr) -> ExprId {
        self.a.exprs.push(expr);
        ExprId::new(self.a.exprs.len() as u32 - 1)
    }

    /// Adds a symbol; its id is the number of symbols added before it.
    pub fn symbol(&mut self, name: &str, scope: ScopeId, def: SymbolDef) -> SymbolId {
        self.symbols.push((name.to_owned(), scope, def));
        SymbolId::new(self.symbols.len() as u32 - 1)
    }

    /// Replaces the content of an already added symbol (for a subtable whose
    /// constructors are known only after its operands were added).
    pub fn set_symbol(&mut self, id: SymbolId, def: SymbolDef) -> bool {
        match self.symbols.get_mut(id.slot()) {
            Some(slot) => {
                slot.2 = def;
                true
            }
            None => false,
        }
    }

    /// Lays the model out and validates it with the default limits.
    pub fn finish(self) -> Result<Sla, SlaError> {
        self.finish_with(&Limits::default())
    }

    /// Lays the model out and validates it.
    pub fn finish_with(mut self, limits: &Limits) -> Result<Sla, SlaError> {
        let mut a = std::mem::take(&mut self.a);
        for name in &self.files {
            let id = a.strings.add(name);
            a.source_files.push(id);
        }
        for space in &self.spaces {
            let name = a.strings.add(&space.name);
            a.spaces.push(SpaceRecord {
                kind: space.kind,
                name,
                index: space.index,
                big_endian: space.big_endian,
                delay: space.delay,
                size: space.size,
                word_size: space.word_size,
                physical: space.physical,
            });
        }
        let default_space = self
            .spaces
            .iter()
            .find(|space| space.name == self.default_space)
            .map(|space| space.index)
            .ok_or_else(|| {
                SlaError::structure("sleigh/spaces", format!("Bad 'defaultspace' attribute: {}", self.default_space))
            })?;
        a.scopes = self.scopes.iter().map(|&parent| Scope { parent }).collect();
        let mut layout = Layout { a, limits };
        for (index, (name, scope, def)) in self.symbols.into_iter().enumerate() {
            let id = SymbolId::new(index as u32);
            let kind = layout.kind(id, def)?;
            let name = layout.a.strings.add(&name);
            layout.a.symbols.push(Symbol { name, scope, kind });
        }
        let decoded = crate::read::Decoded {
            header: self.header,
            default_space,
            arenas: layout.a,
        };
        crate::validate::finish(decoded, limits)
    }
}

struct Layout<'l> {
    a: Arenas,
    limits: &'l Limits,
}

impl Layout<'_> {
    fn kind(&mut self, id: SymbolId, def: SymbolDef) -> Result<SymbolKind, SlaError> {
        let a = &mut self.a;
        Ok(match def {
            SymbolDef::UserOp { index } => SymbolKind::UserOp { index },
            SymbolDef::Value { expr } => SymbolKind::Value { expr },
            SymbolDef::ValueMap { expr, values } => {
                let start = a.value_table.len();
                a.value_table.extend(values);
                SymbolKind::ValueMap {
                    expr,
                    table: Span::since(start, &a.value_table),
                }
            }
            SymbolDef::Name { expr, names } => {
                let start = a.name_table.len();
                for name in names {
                    let entry = name
                        .filter(|name| name != "_" && name != "\t")
                        .map(|name| a.strings.add(&name));
                    a.name_table.push(entry);
                }
                SymbolKind::Name {
                    expr,
                    table: Span::since(start, &a.name_table),
                }
            }
            SymbolDef::Varnode {
                space,
                offset,
                size,
            } => SymbolKind::Varnode {
                space,
                offset,
                size,
            },
            SymbolDef::Context {
                varnode,
                low,
                high,
                flow,
                expr,
            } => SymbolKind::Context {
                varnode,
                low,
                high,
                flow,
                expr,
            },
            SymbolDef::VarnodeList { expr, entries } => {
                let start = a.varnode_table.len();
                a.varnode_table.extend(entries);
                SymbolKind::VarnodeList {
                    expr,
                    table: Span::since(start, &a.varnode_table),
                }
            }
            SymbolDef::Operand(operand) => SymbolKind::Operand(operand),
            SymbolDef::Start => SymbolKind::Start,
            SymbolDef::End => SymbolKind::End,
            SymbolDef::Next2 => SymbolKind::Next2,
            SymbolDef::Epsilon => SymbolKind::Epsilon,
            SymbolDef::Subtable(table) => SymbolKind::Subtable(self.table(id, table)?),
        })
    }

    fn table(&mut self, id: SymbolId, table: TableDef) -> Result<Subtable, SlaError> {
        let first = self.a.constructors.len();
        for ctor in table.constructors {
            let constructor = self.constructor(id, ctor);
            self.a.constructors.push(constructor);
        }
        let constructors = Span::since(first, &self.a.constructors);
        let root = self.decision(&table.decision, 0)?;
        let decision = DecisionId::new(self.a.decisions.len() as u32);
        self.a.decisions.push(root);
        Ok(Subtable {
            constructors,
            decision,
        })
    }

    fn constructor(&mut self, parent: SymbolId, def: ConstructorDef) -> Constructor {
        let a = &mut self.a;
        let operands_start = a.operand_lists.len();
        a.operand_lists.extend(def.operands);
        let print_start = a.print_pieces.len();
        for piece in def.print {
            let piece = match piece {
                PrintDef::Text(text) => PrintPiece::Text(a.strings.add(&text)),
                PrintDef::Operand(index) => PrintPiece::Operand(index),
            };
            a.print_pieces.push(piece);
        }
        let context_start = a.context_changes.len();
        a.context_changes.extend(def.context);
        let mut templates = def.templates;
        templates.sort_by_key(|t| t.header.section.map_or(0, |s| u64::from(s) + 1));
        let templates_start = a.templates.len();
        for template in templates {
            let mut header = template.header;
            let varnode_base = a.varnodes.len() as u32;
            a.varnodes.extend_from_slice(&template.varnodes);
            let ops_start = a.ops.len();
            for op in &template.ops {
                let mut op = *op;
                op.varnodes = Span::new(op.varnodes.start() + varnode_base, op.varnodes.len());
                a.ops.push(op);
            }
            header.ops = Span::since(ops_start, &a.ops);
            header.result = header
                .result
                .and_then(|handle| template.handles.get(handle.slot()))
                .map(|handle| {
                    a.handles.push(*handle);
                    HandleId::new(a.handles.len() as u32 - 1)
                });
            a.templates.push(header);
        }
        Constructor {
            parent,
            first: def.first,
            length: def.length,
            source: def.source,
            line: def.line,
            operands: Span::since(operands_start, &a.operand_lists),
            print: Span::since(print_start, &a.print_pieces),
            context: Span::since(context_start, &a.context_changes),
            templates: Span::since(templates_start, &a.templates),
        }
    }

    /// Lays out a subtree like the reader does: children as one run after
    /// their own subtrees. Returns the node for the caller to place.
    fn decision(&mut self, def: &DecisionDef, depth: u32) -> Result<DecisionNode, SlaError> {
        if depth >= self.limits.decision_depth {
            return Err(SlaError::Limit {
                location: crate::error::Location::default(),
                what: "decision-tree depth",
                limit: u64::from(self.limits.decision_depth),
                found: u64::from(depth) + 1,
            });
        }
        let mut children = Vec::with_capacity(def.children.len());
        for child in &def.children {
            children.push(self.decision(child, depth + 1)?);
        }
        let pairs_start = self.a.pairs.len();
        for pair in &def.pairs {
            let pattern = match &pair.pattern {
                PatternDef::Instruction(block) => DisjointPattern::Instruction(self.block(block)),
                PatternDef::Context(block) => DisjointPattern::Context(self.block(block)),
                PatternDef::Combine(context, instruction) => DisjointPattern::Combine {
                    context: self.block(context),
                    instruction: self.block(instruction),
                },
            };
            self.a.pairs.push(DecisionPair {
                constructor: pair.constructor,
                pattern,
            });
        }
        let pairs = Span::since(pairs_start, &self.a.pairs);
        if def.size > 8 || children.len() != if def.size == 0 { 0 } else { 1usize << def.size } {
            return Err(SlaError::structure(
                "decision",
                format!(
                    "decision node of size {} has {} children",
                    def.size,
                    children.len()
                ),
            ));
        }
        let first_child = self.a.decisions.len() as u32;
        self.a.decisions.extend(children);
        Ok(DecisionNode {
            number: def.number,
            start_bit: def.start_bit,
            context: def.context,
            size: def.size,
            first_child,
            pairs,
        })
    }

    fn block(&mut self, def: &BlockDef) -> BlockId {
        let (mut offset, mut nonzero, mut words) = (def.offset, def.nonzero, def.words.clone());
        normalize_block(&mut offset, &mut nonzero, &mut words);
        let start = self.a.words.len();
        self.a.words.extend_from_slice(&words);
        self.a.blocks.push(PatternBlock {
            offset,
            nonzero,
            words: Span::since(start, &self.a.words),
        });
        BlockId::new(self.a.blocks.len() as u32 - 1)
    }
}
