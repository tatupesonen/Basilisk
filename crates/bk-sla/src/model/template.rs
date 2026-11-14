//! P-code templates (inventory section 1.7): the values shared by a
//! language's constructors and by p-code snippets compiled for injection.

use bk_pcode::OpCode;

use super::handles::{HandleId, Span};

/// Which part of an operand's resolved handle a [`ConstTpl::Handle`] takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HandleSelect {
    /// The handle's space.
    Space = 0,
    /// The handle's offset.
    Offset = 1,
    /// The handle's size.
    Size = 2,
    /// The handle's offset plus a truncation (`plus`).
    OffsetPlus = 3,
}

impl HandleSelect {
    /// The selector with the file's number `s`.
    pub const fn from_number(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Space),
            1 => Some(Self::Offset),
            2 => Some(Self::Size),
            3 => Some(Self::OffsetPlus),
            _ => None,
        }
    }

    /// The file's number for the selector.
    pub const fn number(self) -> i64 {
        self as i64
    }
}

/// A constant of a template (`ConstTpl`), resolved when p-code is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConstTpl {
    /// `const_real`: the number.
    Real(u64),
    /// `const_handle`: a part of operand `index`'s resolved handle.
    Handle {
        /// The operand index.
        index: u32,
        /// The part taken.
        select: HandleSelect,
        /// For [`HandleSelect::OffsetPlus`] only (0 otherwise): low 16 bits
        /// the byte offset added to a non-constant, high bits the byte count
        /// a constant is shifted right by.
        plus: u64,
    },
    /// `const_start`: the instruction's offset.
    Start,
    /// `const_next`: the next instruction's offset.
    Next,
    /// `const_next2`: the offset of the instruction after the next.
    Next2,
    /// `const_curspace`: the space of the instruction's address.
    CurSpace,
    /// `const_curspace_size`: that space's address size.
    CurSpaceSize,
    /// `const_spaceid`: a fixed address space, by index (0 = constant space).
    Space(u32),
    /// `const_relative`: a label number, to become a relative branch offset.
    Relative(u64),
    /// `const_flowref`: injection only (`inst_ref`).
    FlowRef,
    /// `const_flowref_size`: injection only.
    FlowRefSize,
    /// `const_flowdest`: injection only (`inst_dest`).
    FlowDest,
    /// `const_flowdest_size`: injection only.
    FlowDestSize,
}

impl ConstTpl {
    /// The element name.
    pub const fn element_name(&self) -> &'static str {
        match self {
            Self::Real(_) => "const_real",
            Self::Handle { .. } => "const_handle",
            Self::Start => "const_start",
            Self::Next => "const_next",
            Self::Next2 => "const_next2",
            Self::CurSpace => "const_curspace",
            Self::CurSpaceSize => "const_curspace_size",
            Self::Space(_) => "const_spaceid",
            Self::Relative(_) => "const_relative",
            Self::FlowRef => "const_flowref",
            Self::FlowRefSize => "const_flowref_size",
            Self::FlowDest => "const_flowdest",
            Self::FlowDestSize => "const_flowdest_size",
        }
    }
}

/// A varnode template: space, offset and size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VarnodeTpl {
    /// The space.
    pub space: ConstTpl,
    /// The offset.
    pub offset: ConstTpl,
    /// The size.
    pub size: ConstTpl,
}

/// A handle template, the export of a template (`handle_tpl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HandleTpl {
    /// The space.
    pub space: ConstTpl,
    /// The size.
    pub size: ConstTpl,
    /// The space a pointer points into.
    pub ptr_space: ConstTpl,
    /// The pointer's offset.
    pub ptr_offset: ConstTpl,
    /// The pointer's size.
    pub ptr_size: ConstTpl,
    /// Space of the temporary holding a dynamic value.
    pub temp_space: ConstTpl,
    /// Offset of that temporary.
    pub temp_offset: ConstTpl,
}

impl HandleTpl {
    /// The seven constants in file order.
    pub const fn parts(&self) -> [ConstTpl; 7] {
        [
            self.space,
            self.size,
            self.ptr_space,
            self.ptr_offset,
            self.ptr_size,
            self.temp_space,
            self.temp_offset,
        ]
    }

    /// Builds a handle from the seven constants in file order.
    pub const fn from_parts(parts: [ConstTpl; 7]) -> Self {
        let [
            space,
            size,
            ptr_space,
            ptr_offset,
            ptr_size,
            temp_space,
            temp_offset,
        ] = parts;
        Self {
            space,
            size,
            ptr_space,
            ptr_offset,
            ptr_size,
            temp_space,
            temp_offset,
        }
    }
}

/// An op template: an opcode (or a directive in an opcode's slot), an
/// optional output and the inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpTpl {
    /// The opcode; `BUILD`, `DELAY_SLOT`, `LABEL` and `CROSSBUILD` are
    /// directives in the slots of `MULTIEQUAL`, `INDIRECT`, `PTRADD`, `PTRSUB`.
    pub opcode: OpCode,
    pub(crate) has_output: bool,
    /// The output slot (when present) then the inputs.
    pub(crate) varnodes: Span,
}

impl OpTpl {
    /// Whether the op has an output.
    pub const fn has_output(&self) -> bool {
        self.has_output
    }

    /// The number of inputs.
    pub const fn num_inputs(&self) -> u32 {
        self.varnodes.len().saturating_sub(self.has_output as u32)
    }
}

/// The header of one template (`construct_tpl`): its section, delay, label
/// count, export and ops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstructTpl {
    /// The named section, or `None` for the main section.
    pub section: Option<u32>,
    /// The delay-slot byte count (0 if the template has no `delayslot`).
    pub delay: i32,
    /// The number of local labels.
    pub labels: i32,
    pub(crate) result: Option<HandleId>,
    pub(crate) ops: Span,
}

impl ConstructTpl {
    /// The number of ops.
    pub const fn num_ops(&self) -> u32 {
        self.ops.len()
    }
}

/// A borrowed view of one template, wherever it lives: in a [`Sla`](crate::Sla)
/// or in a standalone [`Template`]. The runtime builds p-code from this.
#[derive(Clone, Copy, Debug)]
pub struct TemplateRef<'a> {
    header: &'a ConstructTpl,
    ops: &'a [OpTpl],
    varnodes: &'a [VarnodeTpl],
    handles: &'a [HandleTpl],
}

impl<'a> TemplateRef<'a> {
    pub(crate) const fn new(
        header: &'a ConstructTpl,
        ops: &'a [OpTpl],
        varnodes: &'a [VarnodeTpl],
        handles: &'a [HandleTpl],
    ) -> Self {
        Self {
            header,
            ops,
            varnodes,
            handles,
        }
    }

    /// The header: section, delay and label count.
    pub fn header(&self) -> &'a ConstructTpl {
        self.header
    }

    /// The ops, in order.
    pub fn ops(&self) -> &'a [OpTpl] {
        self.ops.get(self.header.ops.range()).unwrap_or_default()
    }

    /// The export, if the template has one.
    pub fn result(&self) -> Option<&'a HandleTpl> {
        self.header
            .result
            .and_then(|id| self.handles.get(id.slot()))
    }

    /// The output of an op of this template.
    pub fn output(&self, op: &OpTpl) -> Option<&'a VarnodeTpl> {
        if op.has_output {
            self.varnodes.get(op.varnodes.start() as usize)
        } else {
            None
        }
    }

    /// The inputs of an op of this template.
    pub fn inputs(&self, op: &OpTpl) -> &'a [VarnodeTpl] {
        let range = op.varnodes.range();
        let start = range.start.saturating_add(usize::from(op.has_output));
        self.varnodes
            .get(start.min(range.end)..range.end)
            .unwrap_or_default()
    }
}

/// A template that lives outside a language file, with arenas of its own:
/// for example a p-code snippet compiled for injection
/// (`features/sleigh-snippet.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub(crate) header: ConstructTpl,
    pub(crate) ops: Vec<OpTpl>,
    pub(crate) varnodes: Vec<VarnodeTpl>,
    pub(crate) handles: Vec<HandleTpl>,
}

impl Template {
    /// An empty template of the main section with no export.
    pub fn new() -> Self {
        Self {
            header: ConstructTpl {
                section: None,
                delay: 0,
                labels: 0,
                result: None,
                ops: Span::EMPTY,
            },
            ops: Vec::new(),
            varnodes: Vec::new(),
            handles: Vec::new(),
        }
    }

    /// Sets the section (`None` = main), the delay-slot byte count and the
    /// number of labels.
    pub fn set_header(&mut self, section: Option<u32>, delay: i32, labels: i32) {
        self.header.section = section;
        self.header.delay = delay;
        self.header.labels = labels;
    }

    /// Sets the export.
    pub fn set_result(&mut self, result: Option<HandleTpl>) {
        self.handles.clear();
        self.header.result = result.map(|handle| {
            self.handles.push(handle);
            HandleId::new(0)
        });
    }

    /// Appends an op.
    pub fn push_op(&mut self, opcode: OpCode, output: Option<VarnodeTpl>, inputs: &[VarnodeTpl]) {
        let start = self.varnodes.len();
        if let Some(output) = output {
            self.varnodes.push(output);
        }
        self.varnodes.extend_from_slice(inputs);
        self.ops.push(OpTpl {
            opcode,
            has_output: output.is_some(),
            varnodes: Span::since(start, &self.varnodes),
        });
        self.header.ops = Span::new(0, self.ops.len() as u32);
    }

    /// A borrowed view.
    pub fn as_ref(&self) -> TemplateRef<'_> {
        TemplateRef::new(&self.header, &self.ops, &self.varnodes, &self.handles)
    }
}

impl Default for Template {
    fn default() -> Self {
        Self::new()
    }
}
