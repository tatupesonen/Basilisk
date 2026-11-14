//! The p-code template builder (Ghidra's `PcodeCompile`, the semantic
//! actions of `slghparse.y`): compiles the statements of a semantic section
//! into a [`Tpl`].
//!
//! The builder is public and independent of constructors: it asks a
//! [`SymbolResolver`] what each name means at the point of use and to
//! allocate temporaries. The constructor elaborator is one client; p-code
//! snippets (`bk-sleigh-snippet`) are the other, through [`compile_snippet`].
//!
//! Temporaries are allocated exactly where Ghidra's single-pass parser
//! allocates them (spec 4.1): an operator's result after its operands
//! (post-order, left operand first), the temporary of `name = expr` after
//! `expr`, the export temporary of `export *[sp]:n v` at the `export`.

mod bitrange;
mod expr;
mod sizes;
mod snippet;
mod stmt;

use bk_sleigh_syntax::ast::{Nodes, Statement};
use bk_sleigh_syntax::{Interner, Span};

use crate::diag::Diagnostic;
use crate::spaces::SpaceInfo;
use crate::template::{Tpl, Vn};

pub use sizes::{force_size, propagate_size};
pub use snippet::{SnippetResult, compile_snippet};

/// A label of the sections one builder compiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LabelId(pub u32);

/// What a name means at a point of a semantic section. The variants follow
/// the token classes of Ghidra's lexer (`find_symbol`), which decide what
/// the grammar accepts where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameRef {
    /// Nothing of that name is visible.
    Unknown,
    /// A fixed varnode (a register or a local temporary).
    Varnode(Vn),
    /// `epsilon` (a constant 0).
    Special(Vn),
    /// `inst_start`, `inst_next`, `inst_next2`, `inst_dest`, `inst_ref`: a
    /// constant whose offset is an address.
    Jump(Vn),
    /// An operand of the constructor (or a macro parameter), by index, with
    /// the varnode it stands for (`OperandSymbol::getVarnode`).
    Operand {
        /// The operand's index.
        index: u32,
        /// Its varnode template.
        varnode: Vn,
    },
    /// A bit range that is not byte aligned (`BitrangeSymbol`).
    Bitrange {
        /// The varnode it is part of.
        varnode: Vn,
        /// The least significant bit.
        offset: u32,
        /// The number of bits.
        bits: u32,
    },
    /// A user-defined op and its index.
    UserOp(u32),
    /// A macro: its index and number of parameters.
    Macro {
        /// The macro's index in the macro table.
        index: u32,
        /// Its number of parameters.
        params: u32,
    },
    /// A label defined earlier with [`SymbolResolver::define_label`].
    Label(LabelId),
    /// A named section and its number.
    Section(u32),
    /// An address space and its index.
    Space(u32),
    /// A table (not usable in p-code except through an operand).
    Subtable,
    /// Any other kind of symbol (token, field, ...): not usable here.
    Other,
}

/// Why a definition was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefineError(pub String);

/// The builder's view of the symbols around a semantic section.
pub trait SymbolResolver {
    /// What `name` means here.
    fn lookup(&self, name: &str) -> NameRef;
    /// Where the symbol `name` refers to was defined (for messages Ghidra
    /// locates at a symbol's definition); for a bit range, its varnode's.
    fn location_of(&self, name: &str) -> Option<Span>;
    /// Allocates a temporary and returns its offset in the unique space.
    fn allocate_temp(&mut self) -> u64;
    /// Defines a local varnode symbol in the current scope.
    fn define_local(&mut self, name: &str, varnode: Vn, at: Span) -> Result<(), DefineError>;
    /// Defines a label symbol in the current scope.
    fn define_label(&mut self, name: &str, label: LabelId, at: Span) -> Result<(), DefineError>;
    /// Marks operand `index` as used as a code address.
    fn mark_code_address(&mut self, index: u32);
    /// Whether parameter `param` of macro `index` is used as a code address.
    fn macro_param_is_code(&self, index: u32, param: u32) -> bool;
    /// Creates a named section symbol and returns its number, or refuses.
    fn new_section(&mut self, name: &str, at: Span) -> Result<u32, DefineError>;
}

/// The language facts the builder needs.
#[derive(Clone, Debug)]
pub struct BuildEnv {
    /// The address spaces, by index (index 0 is the constant space).
    pub spaces: Vec<SpaceInfo>,
    /// The default code space, if one has been defined.
    pub default_space: Option<u32>,
    /// `-e`: temporaries must be declared with `local`.
    pub enforce_local_key: bool,
}

impl BuildEnv {
    /// The space with the given index.
    pub fn space(&self, index: u32) -> Option<&SpaceInfo> {
        self.spaces.iter().find(|s| s.index == index)
    }

    /// Whether the default space is big endian (`defaultspace->isBigEndian()`).
    fn default_big_endian(&self) -> bool {
        self.default_space
            .and_then(|i| self.space(i))
            .is_some_and(|s| s.big_endian)
    }
}

/// Why compilation of a section stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// A parse error that makes Ghidra's parser abandon the constructor
    /// (`YYERROR`); the diagnostic has been reported.
    Abort,
    /// An error that aborts Ghidra's whole compile ("Unrecoverable error");
    /// basilisk reports it as an ordinary error and stops.
    Fatal(String),
}

#[derive(Clone, Debug)]
struct LabelState {
    name: String,
    section: u32,
    index: u32,
    placed: bool,
    refs: u32,
    at: Span,
}

/// Compiles the sections of one constructor, macro or snippet.
#[derive(Debug)]
pub struct Builder<'b, R: SymbolResolver> {
    env: &'b BuildEnv,
    resolver: &'b mut R,
    names: &'b Interner,
    nodes: &'b Nodes,
    labels: Vec<LabelState>,
    section: u32,
    next_label: u32,
    diagnostics: Vec<Diagnostic>,
}

impl<'b, R: SymbolResolver> Builder<'b, R> {
    /// A builder over the expressions `nodes` whose names are in `names`.
    pub fn new(env: &'b BuildEnv, resolver: &'b mut R, names: &'b Interner, nodes: &'b Nodes) -> Self {
        Self {
            env,
            resolver,
            names,
            nodes,
            labels: Vec::new(),
            section: 0,
            next_label: 0,
            diagnostics: Vec::new(),
        }
    }

    /// The resolver.
    pub fn resolver(&mut self) -> &mut R {
        self.resolver
    }

    /// Compiles the statements of one section (no `<<name>>` markers);
    /// `allow_export` says whether an `export` may end it (the main section
    /// and macro bodies). Labels are numbered from 0 in each section.
    pub fn section(&mut self, statements: &[Statement], allow_export: bool) -> Result<Tpl, Stop> {
        self.section = self.section.wrapping_add(1);
        self.next_label = 0;
        let mut tpl = Tpl::default();
        let count = statements.len();
        for (i, statement) in statements.iter().enumerate() {
            if let Statement::Export { value, span } = statement {
                if !allow_export || i + 1 != count {
                    self.syntax_error(*span);
                    return Err(Stop::Abort);
                }
                tpl.result = Some(self.export(value)?);
                continue;
            }
            let ops = self.statement(statement)?;
            for op in ops {
                if op.opcode == crate::template::DELAY_SLOT {
                    if tpl.delay != 0 {
                        self.error(Some(statement.span()), "Multiple delayslot declarations");
                        return Err(Stop::Abort);
                    }
                    tpl.delay = op.inputs.first().map_or(0, |v| crate::template::real(&v.offset) as u32);
                } else if op.opcode == crate::template::LABEL {
                    tpl.labels = tpl.labels.wrapping_add(1);
                }
                tpl.ops.push(op);
            }
        }
        Ok(tpl)
    }

    /// The number of the section compiled last (sections are numbered from
    /// 1 in the order [`Self::section`] compiles them).
    pub fn current_section(&self) -> u32 {
        self.section
    }

    /// The label problems of the section compiled last; see
    /// [`Self::label_problems_in`].
    pub fn label_problems(&self) -> String {
        self.label_problems_in(self.section)
    }

    /// The label problems of section `section`, as Ghidra's `checkSymbols`
    /// writes them (labels in name order); empty if none.
    pub fn label_problems_in(&self, section: u32) -> String {
        let mut labels: Vec<&LabelState> = self.labels.iter().filter(|l| l.section == section).collect();
        labels.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        let mut text = String::new();
        for label in labels {
            if label.refs == 0 {
                text.push_str("   Label <");
                text.push_str(&label.name);
                text.push_str("> was placed but not used\n");
            } else if !label.placed {
                text.push_str("   Label <");
                text.push_str(&label.name);
                text.push_str("> was referenced but never placed\n");
            }
        }
        text
    }

    /// The diagnostics reported so far.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Takes the diagnostics reported so far.
    pub fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    fn name(&self, ident: bk_sleigh_syntax::ast::Ident) -> &'b str {
        self.names.resolve(ident.name)
    }

    fn error(&mut self, span: Option<Span>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::error(span, message));
    }

    fn error_at(&mut self, span: Option<Span>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::error(span, message).located());
    }

    fn syntax_error(&mut self, span: Span) {
        self.error(Some(span), "syntax error");
    }
}
