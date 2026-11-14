//! The names a snippet can use (`PcodeSnippet`'s symbol tree and its
//! fall-back to the language's global scope, `pcodeparse.y` 640–768).
//!
//! Ghidra looks a name up when it lexes it: first in the snippet's own tree
//! (address spaces, `inst_dest`, `inst_ref`, the parameters, then locals and
//! labels as they are defined), then in the language's global scope, where
//! only user ops, varnodes and `inst_start`/`inst_next`/`inst_next2` are
//! visible. [`Locals`] is the snippet's tree; [`Language`] the precomputed
//! visible part of a `.sla`; [`Resolver`] the view the template builder
//! asks.

use bk_sla::ConstTpl;
use bk_sleigh_compiler::pcode::{DefineError, LabelId, NameRef, SymbolResolver};
use bk_sleigh_compiler::spaces::{SpaceInfo, SpaceKind};
use bk_sleigh_compiler::template::Vn;
use bk_sleigh_syntax::Span;
use rustc_hash::FxHashMap;

use crate::options::{Options, TempAllocator};

/// What a name stands for, as the parser's token classes see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// `SPACESYM`.
    Space,
    /// `USEROPSYM`.
    UserOp,
    /// `VARSYM`.
    Varnode,
    /// `OPERANDSYM`.
    Operand,
    /// `JUMPSYM`: `inst_start`, `inst_next`, `inst_next2`, `inst_dest`,
    /// `inst_ref`.
    Jump,
    /// `LABELSYM`.
    Label,
    /// `STRING`: nothing visible of that name.
    Unknown,
}

/// A visible symbol of the language.
#[derive(Clone, Copy, Debug)]
enum Global {
    UserOp(u32),
    Varnode(Vn),
    Jump(Vn),
}

/// The constant whose offset is an instruction address (`StartSymbol`,
/// `EndSymbol`, `Next2Symbol`, `FlowDestSymbol`, `FlowRefSymbol` and their
/// `getVarnode`): constant space, size 0.
const fn jump_varnode(offset: ConstTpl) -> Vn {
    Vn::new(ConstTpl::Space(0), offset, ConstTpl::Real(0))
}

/// The part of a language a snippet sees, computed once per language.
#[derive(Clone, Debug)]
pub(crate) struct Language {
    globals: FxHashMap<Box<str>, Global>,
    /// Address spaces by index order (the constant space first), with the
    /// options' truncations applied and extra spaces added.
    pub(crate) spaces: Vec<SpaceInfo>,
    pub(crate) default_space: u32,
}

impl Language {
    pub(crate) fn new(sla: &bk_sla::Sla, options: &Options) -> Self {
        let global = bk_sla::ScopeId::new(0);
        let mut globals = FxHashMap::default();
        for symbol in sla.symbols() {
            if symbol.scope != global {
                continue;
            }
            let entry = match symbol.kind {
                bk_sla::SymbolKind::UserOp { index } => Global::UserOp(index as u32),
                bk_sla::SymbolKind::Varnode {
                    space,
                    offset,
                    size,
                } => Global::Varnode(Vn::new(
                    ConstTpl::Space(space),
                    ConstTpl::Real(offset),
                    ConstTpl::Real(u64::from(size as u32)),
                )),
                bk_sla::SymbolKind::Start => Global::Jump(jump_varnode(ConstTpl::Start)),
                bk_sla::SymbolKind::End => Global::Jump(jump_varnode(ConstTpl::Next)),
                bk_sla::SymbolKind::Next2 => Global::Jump(jump_varnode(ConstTpl::Next2)),
                _ => continue,
            };
            globals.insert(sla.text(symbol.name).into(), entry);
        }
        let big_endian = sla.header().big_endian;
        let mut spaces = vec![SpaceInfo {
            name: bk_sla::CONSTANT_SPACE_NAME.to_owned(),
            index: 0,
            kind: SpaceKind::Constant,
            is_other: false,
            big_endian,
            addr_size: 8,
            word_size: 1,
            delay: 0,
            physical: false,
        }];
        for record in sla.space_records() {
            let name = sla.text(record.name);
            let kind = match record.kind {
                bk_sla::SpaceKind::Unique => SpaceKind::Unique,
                bk_sla::SpaceKind::Processor | bk_sla::SpaceKind::Other => SpaceKind::Processor,
            };
            let addr_size = options
                .truncation(name)
                .unwrap_or_else(|| record.size.max(0) as u32);
            spaces.push(SpaceInfo {
                name: name.to_owned(),
                index: record.index,
                kind,
                is_other: record.kind == bk_sla::SpaceKind::Other,
                big_endian: record.big_endian,
                addr_size,
                word_size: record.word_size.max(1) as u32,
                delay: record.delay,
                physical: record.physical,
            });
        }
        for extra in &options.extra_spaces {
            if spaces
                .iter()
                .any(|s| s.name == extra.name || s.index == extra.index)
            {
                tracing::warn!(
                    space = %extra.name,
                    index = extra.index,
                    "extra address space ignored: its name or index is already taken"
                );
                continue;
            }
            spaces.push(SpaceInfo {
                name: extra.name.clone(),
                index: extra.index,
                kind: SpaceKind::Processor,
                is_other: false,
                big_endian: extra.big_endian,
                addr_size: extra.addr_size,
                word_size: extra.word_size.max(1),
                delay: 1,
                physical: true,
            });
        }
        spaces.sort_by_key(|s| s.index);
        Self {
            globals,
            spaces,
            default_space: sla.default_space(),
        }
    }

    fn global(&self, name: &str) -> Option<Global> {
        self.globals.get(name).copied()
    }
}

/// A symbol of the snippet's own tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Local {
    Space(u32),
    Varnode(Vn),
    Operand(u32),
    Jump(Vn),
    /// A label; the id is the builder's (`LabelId(u32::MAX)` while only the
    /// parser knows it).
    Label(LabelId),
}

/// The snippet's own symbol tree.
#[derive(Clone, Debug, Default)]
pub(crate) struct Locals {
    map: FxHashMap<Box<str>, Local>,
}

impl Locals {
    /// The tree before any parameter is added: the spaces and `inst_dest`,
    /// `inst_ref` (`PcodeSnippet::PcodeSnippet`).
    pub(crate) fn new(language: &Language) -> Self {
        let mut map = FxHashMap::default();
        for space in &language.spaces {
            map.insert(space.name.as_str().into(), Local::Space(space.index));
        }
        let mut locals = Self { map };
        // Spaces cannot be named like these, so the inserts succeed.
        locals.insert("inst_dest", Local::Jump(jump_varnode(ConstTpl::FlowDest)));
        locals.insert("inst_ref", Local::Jump(jump_varnode(ConstTpl::FlowRef)));
        locals
    }

    /// Adds a symbol unless the name is taken (`addSymbol`); `false` if it
    /// was.
    pub(crate) fn insert(&mut self, name: &str, symbol: Local) -> bool {
        if self.map.contains_key(name) {
            return false;
        }
        self.map.insert(name.into(), symbol);
        true
    }

    fn get(&self, name: &str) -> Option<Local> {
        self.map.get(name).copied()
    }

    /// The token class of `name` (`PcodeSnippet::lex`).
    pub(crate) fn class(&self, language: &Language, name: &str) -> Class {
        if let Some(local) = self.get(name) {
            return match local {
                Local::Space(_) => Class::Space,
                Local::Varnode(_) => Class::Varnode,
                Local::Operand(_) => Class::Operand,
                Local::Jump(_) => Class::Jump,
                Local::Label(_) => Class::Label,
            };
        }
        match language.global(name) {
            Some(Global::UserOp(_)) => Class::UserOp,
            Some(Global::Varnode(_)) => Class::Varnode,
            Some(Global::Jump(_)) => Class::Jump,
            None => Class::Unknown,
        }
    }
}

/// Names the template builder treats as keywords of the SLEIGH semantic
/// section although the snippet lexer reads them as ordinary names. The
/// parser interns them with [`MANGLE`] appended so the builder looks them up
/// like any other name.
const BUILDER_KEYWORDS: [&str; 8] = [
    "build",
    "cpool",
    "crossbuild",
    "delayslot",
    "export",
    "lzcount",
    "newobject",
    "popcount",
];

/// The suffix of a mangled name; it cannot occur in an identifier.
pub(crate) const MANGLE: char = '#';

/// The name the builder is given for a snippet name.
pub(crate) fn mangle(name: &str) -> std::borrow::Cow<'_, str> {
    if BUILDER_KEYWORDS.contains(&name) {
        std::borrow::Cow::Owned(format!("{name}{MANGLE}"))
    } else {
        std::borrow::Cow::Borrowed(name)
    }
}

/// The snippet name of a name the builder was given.
pub(crate) fn unmangle(name: &str) -> &str {
    name.strip_suffix(MANGLE).unwrap_or(name)
}

/// Removes the mangling from a builder message.
pub(crate) fn unmangle_message(message: String) -> String {
    if !message.contains(MANGLE) {
        return message;
    }
    let mut text = message;
    for word in BUILDER_KEYWORDS {
        text = text.replace(&format!("{word}{MANGLE}"), word);
    }
    text
}

/// The builder's view of the snippet's names and temporaries.
#[derive(Debug)]
pub(crate) struct Resolver<'a> {
    pub(crate) language: &'a Language,
    pub(crate) locals: Locals,
    pub(crate) temps: TempAllocator,
}

impl SymbolResolver for Resolver<'_> {
    fn lookup(&self, name: &str) -> NameRef {
        let name = unmangle(name);
        if let Some(local) = self.locals.get(name) {
            return match local {
                Local::Space(index) => NameRef::Space(index),
                Local::Varnode(vn) => NameRef::Varnode(vn),
                Local::Operand(index) => NameRef::Operand {
                    index,
                    varnode: Vn::operand(index, false),
                },
                Local::Jump(vn) => NameRef::Jump(vn),
                Local::Label(id) => NameRef::Label(id),
            };
        }
        match self.language.global(name) {
            Some(Global::UserOp(index)) => NameRef::UserOp(index),
            Some(Global::Varnode(vn)) => NameRef::Varnode(vn),
            Some(Global::Jump(vn)) => NameRef::Jump(vn),
            None => NameRef::Unknown,
        }
    }

    fn location_of(&self, _name: &str) -> Option<Span> {
        // `PcodeSnippet::getLocation` has no locations.
        None
    }

    fn allocate_temp(&mut self) -> u64 {
        u64::from(self.temps.allocate())
    }

    fn define_local(&mut self, name: &str, varnode: Vn, _at: Span) -> Result<(), DefineError> {
        let name = unmangle(name);
        if self.locals.insert(name, Local::Varnode(varnode)) {
            Ok(())
        } else {
            Err(DefineError(format!("Duplicate symbol name: {name}")))
        }
    }

    fn define_label(&mut self, name: &str, label: LabelId, _at: Span) -> Result<(), DefineError> {
        let name = unmangle(name);
        if self.locals.insert(name, Local::Label(label)) {
            Ok(())
        } else {
            Err(DefineError(format!("Duplicate symbol name: {name}")))
        }
    }

    fn mark_code_address(&mut self, _index: u32) {
        // Snippet destinations cannot be operands (the grammar refuses
        // them), so there is nothing to mark.
    }

    fn macro_param_is_code(&self, _index: u32, _param: u32) -> bool {
        false
    }

    fn new_section(&mut self, name: &str, _at: Span) -> Result<u32, DefineError> {
        Err(DefineError(format!(
            "Unknown section in a p-code snippet: {}",
            unmangle(name)
        )))
    }
}
