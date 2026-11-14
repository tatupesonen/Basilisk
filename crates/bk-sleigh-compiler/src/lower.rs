//! Lowering an elaborated specification to the compiled-language model
//! (`bk_sla::Sla`) through `SlaBuilder`, applying the operand order the
//! back half chose: handle indices in templates, operand print pieces and
//! operand expressions use the decoding positions (`orderOperands`'s
//! `changeHandleIndex`, `changeIndex` and print-piece remap).

use bk_sla::{
    BlockDef, ConstTpl, ConstructorDef, DecisionDef, Expr, ExprId, Header, Operand, PairDef,
    PatternDef, PrintDef, Sla, SlaBuilder, SlaError, SpaceDef, SymbolDef, TableDef,
};

use crate::decision::{DecisionNode, DecisionTree};
use crate::elaborated::{ContextChange, Elaborated, PrintPiece};
use crate::ids::{OperandId, PExprId, SymbolId};
use crate::pattern::{Block, Disjoint, PExpr, PatValue};
use crate::spaces::SpaceKind;
use crate::symbols::SymbolKind;
use crate::template::{BUILD, Tpl};

/// Why lowering failed: the elaboration holds something the file cannot
/// (an internal inconsistency), or the model failed `bk_sla`'s validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LowerError {
    /// A symbol of a kind that only exists inside the compiler survived the
    /// purge.
    #[error("symbol {0} cannot be written to a compiled language")]
    CompileOnlySymbol(u32),
    /// `bk_sla` rejected the model.
    #[error("the compiled language is not valid: {0}")]
    Invalid(#[from] SlaError),
}

struct Lowering<'e> {
    spec: &'e Elaborated,
    builder: SlaBuilder,
    /// (table symbol, constructor index) of each constructor, by id.
    ctor_place: Vec<(SymbolId, u32)>,
}

impl Lowering<'_> {
    fn field(&mut self, value: &PatValue) -> ExprId {
        match value {
            PatValue::Token(f, _) => {
                let id = self.builder.field(*f);
                self.builder.expr(Expr::TokenField(id))
            }
            PatValue::Context(f) => {
                let id = self.builder.field(*f);
                self.builder.expr(Expr::ContextField(id))
            }
        }
    }

    /// The new index of an operand and the place of its constructor.
    fn operand_ref(&self, op: OperandId) -> Expr {
        let data = self.spec.operands.get(op.slot());
        let ctor = data.and_then(|d| d.ctor);
        let (table, ct) = ctor
            .and_then(|c| self.ctor_place.get(c.slot()).copied())
            .unwrap_or((SymbolId::new(0), 0));
        let index = data
            .zip(ctor)
            .and_then(|(d, c)| {
                self.spec
                    .constructors
                    .get(c.slot())?
                    .handmap
                    .get(d.index as usize)
                    .copied()
            })
            .or_else(|| data.map(|d| d.index))
            .unwrap_or(0);
        Expr::Operand {
            index: index as i32,
            table: bk_sla::SymbolId::new(table.index()),
            ct,
        }
    }

    /// Lowers an expression tree bottom up (children first), iteratively.
    fn expr(&mut self, root: PExprId) -> ExprId {
        enum Step {
            Visit(PExprId),
            Emit(PExprId),
        }
        let mut stack = vec![Step::Visit(root)];
        let mut done: Vec<ExprId> = Vec::new();
        while let Some(step) = stack.pop() {
            match step {
                Step::Visit(id) => {
                    stack.push(Step::Emit(id));
                    match self.spec.patterns.get_expr(id) {
                        Some(PExpr::Binary { left, right, .. }) => {
                            stack.push(Step::Visit(*right));
                            stack.push(Step::Visit(*left));
                        }
                        Some(PExpr::Unary { operand, .. }) => stack.push(Step::Visit(*operand)),
                        _ => {}
                    }
                }
                Step::Emit(id) => {
                    let e = match self.spec.patterns.get_expr(id).copied() {
                        Some(PExpr::Field(v)) => {
                            done.push(self.field(&v));
                            continue;
                        }
                        Some(PExpr::Constant(c)) => Expr::Constant(c),
                        Some(PExpr::Operand(op)) => self.operand_ref(op),
                        Some(PExpr::Start) => Expr::Start,
                        Some(PExpr::End) => Expr::End,
                        Some(PExpr::Next2) => Expr::Next2,
                        Some(PExpr::Binary { op, .. }) => {
                            let right = done.pop().unwrap_or(ExprId::new(0));
                            let left = done.pop().unwrap_or(ExprId::new(0));
                            Expr::Binary { op, left, right }
                        }
                        Some(PExpr::Unary { op, .. }) => {
                            let operand = done.pop().unwrap_or(ExprId::new(0));
                            Expr::Unary { op, operand }
                        }
                        None => Expr::Constant(0),
                    };
                    done.push(self.builder.expr(e));
                }
            }
        }
        done.pop().unwrap_or(ExprId::new(0))
    }

    fn symbol_def(&mut self, id: usize) -> Result<SymbolDef, LowerError> {
        let spec = self.spec;
        let Some(s) = spec.symbols.get(id) else {
            return Err(LowerError::CompileOnlySymbol(id as u32));
        };
        let sym = |s: SymbolId| bk_sla::SymbolId::new(s.index());
        Ok(match &s.kind {
            SymbolKind::UserOp(index) => SymbolDef::UserOp {
                index: *index as i32,
            },
            SymbolKind::Value(v) => SymbolDef::Value {
                expr: self.field(v),
            },
            SymbolKind::ValueMap(v, values) => SymbolDef::ValueMap {
                expr: self.field(v),
                values: values.clone(),
            },
            SymbolKind::Name(v, names) => SymbolDef::Name {
                expr: self.field(v),
                names: names.clone(),
            },
            SymbolKind::VarnodeList(v, list) => SymbolDef::VarnodeList {
                expr: self.field(v),
                entries: list.iter().map(|e| e.map(sym)).collect(),
            },
            SymbolKind::Varnode(vn) => SymbolDef::Varnode {
                space: vn.space,
                offset: vn.offset,
                size: vn.size,
            },
            SymbolKind::Context {
                varnode,
                low,
                high,
                flow,
                field,
            } => SymbolDef::Context {
                varnode: sym(*varnode),
                low: *low as i32,
                high: *high as i32,
                flow: *flow,
                expr: self.field(field),
            },
            SymbolKind::Operand(op) => {
                let data = spec.operands.get(op.slot());
                let layout = spec.operand_layout.get(op.slot()).copied().unwrap_or_default();
                let local = match data {
                    Some(d) => self.expr(d.local_expr),
                    None => self.builder.expr(Expr::Constant(0)),
                };
                let defining_expr = data.and_then(|d| d.def_expr).map(|e| self.expr(e));
                let index = match self.operand_ref(*op) {
                    Expr::Operand { index, .. } => index,
                    _ => 0,
                };
                SymbolDef::Operand(Operand {
                    index,
                    offset: layout.offset,
                    base: layout.base,
                    min_length: layout.min_length,
                    code: data.is_some_and(|d| d.code),
                    defining_symbol: data.and_then(|d| d.def_symbol).map(sym),
                    local_expr: local,
                    defining_expr,
                })
            }
            SymbolKind::Start => SymbolDef::Start,
            SymbolKind::End => SymbolDef::End,
            SymbolKind::Next2 => SymbolDef::Next2,
            SymbolKind::Epsilon => SymbolDef::Epsilon,
            SymbolKind::Subtable(t) => SymbolDef::Subtable(self.table(t.slot())),
            _ => return Err(LowerError::CompileOnlySymbol(id as u32)),
        })
    }

    fn table(&mut self, t: usize) -> TableDef {
        let spec = self.spec;
        let Some(table) = spec.tables.get(t) else {
            return TableDef {
                constructors: Vec::new(),
                decision: DecisionDef::default(),
            };
        };
        let mut constructors = Vec::with_capacity(table.constructors.len());
        for &ctor in &table.constructors {
            let Some(c) = spec.constructors.get(ctor.slot()) else {
                continue;
            };
            let remap = |i: u32| c.handmap.get(i as usize).copied().unwrap_or(i);
            let mut operands = vec![bk_sla::SymbolId::new(0); c.operands.len()];
            for (old, op) in c.operands.iter().enumerate() {
                let symbol = spec.operands.get(op.slot()).map_or(0, |d| d.symbol.index());
                if let Some(slot) = operands.get_mut(remap(old as u32) as usize) {
                    *slot = bk_sla::SymbolId::new(symbol);
                }
            }
            let print = c
                .print
                .iter()
                .map(|p| match p {
                    PrintPiece::Text(t) => PrintDef::Text(t.clone()),
                    PrintPiece::Operand(i) => PrintDef::Operand(remap(*i) as i32),
                })
                .collect();
            let context = c
                .context
                .iter()
                .map(|change| match *change {
                    ContextChange::Op {
                        word,
                        shift,
                        mask,
                        expr,
                    } => bk_sla::ContextChange::Op {
                        word,
                        shift,
                        mask,
                        expr: self.expr(expr),
                    },
                    ContextChange::Commit {
                        symbol,
                        word,
                        mask,
                        flow,
                    } => bk_sla::ContextChange::Commit {
                        symbol: bk_sla::SymbolId::new(symbol.index()),
                        word,
                        mask,
                        flow,
                    },
                })
                .collect();
            let mut templates = Vec::new();
            if let Some(main) = &c.main {
                templates.push(remap_template(main, &c.handmap).to_template(None));
            }
            for (n, tpl) in c.sections.iter().enumerate() {
                if let Some(tpl) = tpl {
                    templates.push(remap_template(tpl, &c.handmap).to_template(Some(n as u32)));
                }
            }
            constructors.push(ConstructorDef {
                first: c.first,
                length: c.length,
                source: c.source as i32,
                line: c.line as i32,
                operands,
                print,
                context,
                templates,
            });
        }
        TableDef {
            constructors,
            decision: decision_def(&table.decision),
        }
    }
}

/// `ConstructTpl::changeHandleIndex`: handle constants everywhere, and the
/// operand number of each `BUILD`.
fn remap_template(tpl: &Tpl, handmap: &[u32]) -> Tpl {
    let map = |c: &mut ConstTpl| {
        if let ConstTpl::Handle { index, .. } = c
            && let Some(&new) = handmap.get(*index as usize)
        {
            *index = new;
        }
    };
    let mut tpl = tpl.clone();
    for op in &mut tpl.ops {
        if op.opcode == BUILD {
            if let Some(vn) = op.inputs.first_mut()
                && let ConstTpl::Real(index) = &mut vn.offset
                && let Some(&new) = usize::try_from(*index).ok().and_then(|i| handmap.get(i))
            {
                *index = u64::from(new);
            }
            continue;
        }
        for vn in op.output.iter_mut().chain(op.inputs.iter_mut()) {
            map(&mut vn.space);
            map(&mut vn.offset);
            map(&mut vn.size);
        }
    }
    if let Some(h) = &mut tpl.result {
        for c in [
            &mut h.space,
            &mut h.size,
            &mut h.ptr_space,
            &mut h.ptr_offset,
            &mut h.ptr_size,
            &mut h.temp_space,
            &mut h.temp_offset,
        ] {
            map(c);
        }
    }
    tpl
}

fn block_def(b: &Block) -> BlockDef {
    BlockDef {
        offset: b.offset,
        nonzero: b.nonzero,
        words: b.words.clone(),
    }
}

fn pattern_def(d: &Disjoint) -> PatternDef {
    match d {
        Disjoint::Instruction(b) => PatternDef::Instruction(block_def(b)),
        Disjoint::Context(b) => PatternDef::Context(block_def(b)),
        Disjoint::Combine { context, instr } => {
            PatternDef::Combine(block_def(context), block_def(instr))
        }
    }
}

/// The tree in the builder's nested form, built without recursion.
fn decision_def(tree: &DecisionTree) -> DecisionDef {
    fn node_def(n: &DecisionNode) -> DecisionDef {
        DecisionDef {
            number: n.number,
            context: n.context,
            start_bit: n.start_bit,
            size: n.size,
            pairs: n
                .pairs
                .iter()
                .map(|(ct, p)| PairDef {
                    constructor: *ct,
                    pattern: pattern_def(p),
                })
                .collect(),
            children: Vec::new(),
        }
    }
    let Some(root) = tree.nodes.first() else {
        return DecisionDef::default();
    };
    // Post-order: build children before attaching them to their parent.
    let mut built: Vec<Option<DecisionDef>> = vec![None; tree.nodes.len()];
    let mut stack = vec![(0_usize, false)];
    while let Some((i, expanded)) = stack.pop() {
        let Some(n) = tree.nodes.get(i) else { continue };
        if expanded || n.children.is_empty() {
            let mut def = node_def(n);
            def.children = n
                .children
                .iter()
                .map(|&c| built.get_mut(c).and_then(Option::take).unwrap_or_default())
                .collect();
            if let Some(slot) = built.get_mut(i) {
                *slot = Some(def);
            }
        } else {
            stack.push((i, true));
            for &c in n.children.iter().rev() {
                stack.push((c, false));
            }
        }
    }
    built
        .first_mut()
        .and_then(Option::take)
        .unwrap_or_else(|| node_def(root))
}

/// Lowers an elaborated specification to a validated compiled language.
pub fn lower(spec: &Elaborated) -> Result<Sla, LowerError> {
    let header = Header {
        big_endian: spec.big_endian,
        align: spec.align,
        unique_base: spec.unique_base,
        max_delay: spec.max_delay,
        unique_mask: spec.unique_mask,
        num_sections: spec.num_sections,
    };
    let mut builder = SlaBuilder::new(header);
    for name in &spec.source_files {
        builder.source_file(name);
    }
    for space in spec.spaces.iter().filter(|s| s.kind != SpaceKind::Constant) {
        let kind = if space.is_other {
            bk_sla::SpaceKind::Other
        } else if space.kind == SpaceKind::Unique {
            bk_sla::SpaceKind::Unique
        } else {
            bk_sla::SpaceKind::Processor
        };
        builder.space(SpaceDef {
            kind,
            name: space.name.clone(),
            index: space.index,
            big_endian: spec.big_endian,
            delay: space.delay,
            size: space.addr_size as i32,
            word_size: space.word_size as i32,
            physical: space.physical,
        });
    }
    if let Some(space) = spec.spaces.iter().find(|s| s.index == spec.default_space) {
        builder.default_space(&space.name);
    }
    for parent in &spec.scopes {
        builder.scope(parent.map(|p| bk_sla::ScopeId::new(p.index())));
    }
    let mut ctor_place = vec![(SymbolId::new(0), 0); spec.constructors.len()];
    for table in &spec.tables {
        for (i, &c) in table.constructors.iter().enumerate() {
            if let Some(slot) = ctor_place.get_mut(c.slot()) {
                *slot = (table.symbol, i as u32);
            }
        }
    }
    let mut lowering = Lowering {
        spec,
        builder,
        ctor_place,
    };
    for id in 0..spec.symbols.len() {
        let def = lowering.symbol_def(id)?;
        let Some(s) = spec.symbols.get(id) else { continue };
        let name = spec.names.resolve(s.name);
        lowering
            .builder
            .symbol(name, bk_sla::ScopeId::new(s.scope.index()), def);
    }
    Ok(lowering.builder.finish()?)
}
