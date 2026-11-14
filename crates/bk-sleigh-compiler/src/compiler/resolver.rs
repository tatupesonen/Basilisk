//! The builder's view of the symbol table inside a constructor or macro
//! (`SleighPcode`, the token classes of `find_symbol`, `getVarnode`).

use bk_sla::ConstTpl;
use bk_sleigh_syntax::Span;

use super::Compiler;
use crate::ids::{OperandId, SymbolId};
use crate::pcode::{DefineError, LabelId, NameRef, SymbolResolver};
use crate::symbols::{AddError, SymbolKind, VarnodeData};
use crate::template::{CONST_SPACE, UNIQUE_SPACE, Vn};

/// The resolver over the compiler's symbol table.
pub(crate) struct CtorResolver<'c, 'a> {
    pub(crate) compiler: &'c mut Compiler<'a>,
}

impl Compiler<'_> {
    /// The varnode of a fixed varnode symbol (`VarnodeSymbol::getVarnode`).
    pub(crate) fn fixed_varnode(vn: &VarnodeData) -> Vn {
        Vn::new(
            ConstTpl::Space(vn.space),
            ConstTpl::Real(vn.offset),
            ConstTpl::Real(u64::from(vn.size as u32)),
        )
    }

    /// `OperandSymbol::getVarnode`.
    pub(crate) fn operand_varnode(&self, op: OperandId) -> Vn {
        let Some(data) = self.operands.get(op.slot()) else {
            return Vn::operand(0, false);
        };
        if data.def_expr.is_some() {
            return Vn::operand(data.index, true);
        }
        match data.def_symbol.and_then(|s| self.kind(s)) {
            Some(SymbolKind::Varnode(vn)) => Self::fixed_varnode(vn),
            Some(
                kind @ (SymbolKind::Epsilon
                | SymbolKind::Start
                | SymbolKind::End
                | SymbolKind::Next2),
            ) => special_varnode(kind).unwrap_or_else(|| Vn::operand(data.index, false)),
            Some(SymbolKind::ValueMap(..) | SymbolKind::Name(..)) => Vn::operand(data.index, true),
            _ => Vn::operand(data.index, false),
        }
    }

    /// What a symbol means to the builder.
    pub(crate) fn name_ref(&self, id: SymbolId) -> NameRef {
        let Some(kind) = self.kind(id) else {
            return NameRef::Unknown;
        };
        match kind {
            SymbolKind::Varnode(vn) => NameRef::Varnode(Self::fixed_varnode(vn)),
            SymbolKind::Epsilon => NameRef::Special(Vn::constant(0, 0)),
            k @ (SymbolKind::Start | SymbolKind::End | SymbolKind::Next2) => {
                special_varnode(k).map_or(NameRef::Other, NameRef::Jump)
            }
            SymbolKind::Operand(op) => NameRef::Operand {
                index: self.operands.get(op.slot()).map_or(0, |o| o.index),
                varnode: self.operand_varnode(*op),
            },
            SymbolKind::Bitrange {
                varnode,
                offset,
                bits,
            } => {
                let parent = match self.kind(*varnode) {
                    Some(SymbolKind::Varnode(vn)) => Self::fixed_varnode(vn),
                    _ => Vn::constant(0, 0),
                };
                NameRef::Bitrange {
                    varnode: parent,
                    offset: *offset,
                    bits: *bits,
                }
            }
            SymbolKind::UserOp(index) => NameRef::UserOp(*index),
            SymbolKind::Macro(m) => match self.macros.get(m.slot()) {
                Some(data) => NameRef::Macro {
                    index: data.index,
                    params: data.params.len() as u32,
                },
                None => NameRef::Other,
            },
            SymbolKind::Label { index, .. } => NameRef::Label(LabelId(*index)),
            SymbolKind::Section(n) => NameRef::Section(*n),
            SymbolKind::Space(i) => NameRef::Space(*i),
            SymbolKind::Subtable(_) => NameRef::Subtable,
            _ => NameRef::Other,
        }
    }

    /// The operand with index `index` of the constructor or macro being
    /// compiled.
    fn current_operand(&self, index: u32) -> Option<OperandId> {
        match (self.cur_ctor, self.cur_macro) {
            (Some(c), _) => self
                .ctors
                .get(c.slot())?
                .operands
                .get(index as usize)
                .copied(),
            (None, Some(m)) => self
                .macros
                .get(m.slot())?
                .params
                .get(index as usize)
                .copied(),
            (None, None) => None,
        }
    }

    /// `newSectionSymbol`: a global section symbol with the next number.
    pub(crate) fn new_section_symbol(&mut self, name: bk_sleigh_syntax::Symbol, at: Span) -> u32 {
        let number = self.sections.len() as u32;
        let id = match self
            .symbols
            .add_global(name, SymbolKind::Section(number), Some(at))
        {
            Ok(id) | Err(AddError::Duplicate(id)) => {
                if self.symbols.lookup_from(crate::ids::ScopeId::GLOBAL, name) != Some(id) {
                    let message = format!("Duplicate symbol name '{}'", self.text(name));
                    self.diags.error_at(at, message);
                }
                id
            }
            Err(AddError::Full) => SymbolId(u32::MAX),
        };
        self.sections.push(id);
        number
    }
}

/// The varnode of `inst_start`, `inst_next`, `inst_next2`, `epsilon`.
fn special_varnode(kind: &SymbolKind) -> Option<Vn> {
    let offset = match kind {
        SymbolKind::Start => ConstTpl::Start,
        SymbolKind::End => ConstTpl::Next,
        SymbolKind::Next2 => ConstTpl::Next2,
        SymbolKind::Epsilon => ConstTpl::Real(0),
        _ => return None,
    };
    Some(Vn::new(
        ConstTpl::Space(CONST_SPACE),
        offset,
        ConstTpl::Real(0),
    ))
}

impl SymbolResolver for CtorResolver<'_, '_> {
    fn lookup(&self, name: &str) -> NameRef {
        let c = &*self.compiler;
        match c.names.get(name).and_then(|n| c.lookup(n)) {
            Some(id) => c.name_ref(id),
            None => NameRef::Unknown,
        }
    }

    fn location_of(&self, name: &str) -> Option<Span> {
        let c = &*self.compiler;
        let id = c.names.get(name).and_then(|n| c.lookup(n))?;
        let symbol = c.symbols.get(id)?;
        if let SymbolKind::Bitrange { varnode, .. } = symbol.kind {
            return c.symbols.get(varnode).and_then(|s| s.defined_at);
        }
        symbol.defined_at
    }

    fn allocate_temp(&mut self) -> u64 {
        self.compiler.unique_addr()
    }

    fn define_local(&mut self, name: &str, varnode: Vn, at: Span) -> Result<(), DefineError> {
        let c = &mut *self.compiler;
        let name = c.intern(name);
        let data = VarnodeData {
            space: UNIQUE_SPACE,
            offset: crate::template::real(&varnode.offset),
            size: crate::template::real(&varnode.size) as i32,
        };
        match c.symbols.add(name, SymbolKind::Varnode(data), Some(at)) {
            Ok(_) => Ok(()),
            Err(AddError::Duplicate(_)) => Err(DefineError(format!(
                "Duplicate symbol name: {}",
                c.text(name)
            ))),
            Err(AddError::Full) => Err(DefineError("Too many symbols".to_owned())),
        }
    }

    fn define_label(&mut self, name: &str, label: LabelId, at: Span) -> Result<(), DefineError> {
        let c = &mut *self.compiler;
        let name = c.intern(name);
        let kind = SymbolKind::Label {
            index: label.0,
            placed: false,
            refs: 0,
        };
        match c.symbols.add(name, kind, Some(at)) {
            Ok(_) => Ok(()),
            Err(AddError::Duplicate(_)) => Err(DefineError(format!(
                "Duplicate symbol name: {}",
                c.text(name)
            ))),
            Err(AddError::Full) => Err(DefineError("Too many symbols".to_owned())),
        }
    }

    fn mark_code_address(&mut self, index: u32) {
        let c = &mut *self.compiler;
        if let Some(op) = c.current_operand(index)
            && let Some(data) = c.operands.get_mut(op.slot())
        {
            data.code = true;
        }
    }

    fn macro_param_is_code(&self, index: u32, param: u32) -> bool {
        let c = &*self.compiler;
        c.macros
            .iter()
            .rev()
            .find(|m| m.index == index)
            .and_then(|m| m.params.get(param as usize))
            .and_then(|op| c.operands.get(op.slot()))
            .is_some_and(|o| o.code)
    }

    fn new_section(&mut self, name: &str, at: Span) -> Result<u32, DefineError> {
        let c = &mut *self.compiler;
        let name = c.intern(name);
        Ok(c.new_section_symbol(name, at))
    }
}
