//! Inputs of a compile besides the text: parameters, the temporary
//! allocator and the options.

/// A named input or output of a snippet, an operand of the template
/// (`PcodeSnippet::addOperand`). Ghidra numbers a payload's inputs first,
/// then its outputs, from 0 (`InjectPayload::orderParameters`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Parameter {
    /// The name the body uses.
    pub name: String,
    /// The operand (handle) index the template refers to it by.
    pub index: u32,
}

impl Parameter {
    /// A parameter.
    pub fn new(name: impl Into<String>, index: u32) -> Self {
        Self {
            name: name.into(),
            index,
        }
    }
}

/// Where a snippet's temporaries go in the `unique` space.
///
/// Each temporary takes the next offset, which then advances by `step`
/// (`PcodeSnippet::allocateTemp`). The decompiler's injection library
/// starts at the language's `unique_base + 0x200` ([`Self::for_injection`])
/// and carries the allocator from one snippet to the next so no two
/// snippets share a temporary; executable p-code (jump-table helpers,
/// segment operators) always starts at 0x2000 with a fresh allocator
/// ([`Self::for_executable`]). The allocator advances only when a compile
/// succeeds, as Ghidra's library keeps its base when one fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TempAllocator {
    /// The offset the next temporary gets.
    pub next: u32,
    /// The distance between temporaries: 16 in Ghidra's C++, 0x100 in its
    /// Java `PcodeParser`.
    pub step: u32,
}

impl TempAllocator {
    /// The step of Ghidra's C++ snippet compiler.
    pub const STEP: u32 = 16;
    /// `UniqueLayout::INJECT`: where injection temporaries start, above the
    /// language's own (`Translate::getUniqueStart`).
    pub const INJECT_OFFSET: u32 = 0x200;
    /// Where executable p-code's temporaries start (`parseInject`).
    pub const EXECUTABLE_BASE: u32 = 0x2000;

    /// An allocator starting at `next` with the C++ step.
    pub const fn new(next: u32) -> Self {
        Self {
            next,
            step: Self::STEP,
        }
    }

    /// The allocator of the decompiler's injection library for a language
    /// whose `.sla` header has `unique_base`.
    pub const fn for_injection(unique_base: u32) -> Self {
        Self::new(unique_base.wrapping_add(Self::INJECT_OFFSET))
    }

    /// The allocator Ghidra uses for one executable p-code payload.
    pub const fn for_executable() -> Self {
        Self::new(Self::EXECUTABLE_BASE)
    }

    /// Takes the next offset (32-bit arithmetic, as Ghidra's `uint4`).
    pub(crate) fn allocate(&mut self) -> u32 {
        let offset = self.next;
        self.next = self.next.wrapping_add(self.step);
        offset
    }
}

/// An address space the program has besides the language's, visible to
/// snippets compiled after it was added: in Ghidra the `.cspec`'s stack
/// space (`<stackpointer>`, a spacebase space) and overlay spaces. Only
/// spaces of type constant, processor, spacebase and internal are visible
/// to a snippet; the caller passes only those.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtraSpace {
    /// The name the body uses.
    pub name: String,
    /// The space's index in the program's space table.
    pub index: u32,
    /// Size of an address in bytes.
    pub addr_size: u32,
    /// Bytes per addressable unit.
    pub word_size: u32,
    /// Byte order.
    pub big_endian: bool,
}

/// Options of a compile.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Options {
    /// `<truncate_space>` entries of the language definition: a space name
    /// and the address size it is truncated to. They change the size of
    /// `k[space]` destinations and of `&` constants.
    pub truncated_spaces: Vec<(String, u32)>,
    /// Spaces the program has besides the language's.
    pub extra_spaces: Vec<ExtraSpace>,
    /// The longest snippet text accepted, in bytes (ADR-009). Ghidra has no
    /// limit.
    pub max_text_len: usize,
    /// The deepest expression nesting accepted. Ghidra's parser stops with
    /// "memory exhausted" at a stack of 10,000 states; this bound is lower
    /// and counts nesting levels.
    pub max_depth: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            truncated_spaces: Vec::new(),
            extra_spaces: Vec::new(),
            max_text_len: 1 << 20,
            max_depth: 1_000,
        }
    }
}

impl Options {
    /// Adds a `<truncate_space>` entry.
    #[must_use]
    pub fn truncate_space(mut self, name: impl Into<String>, size: u32) -> Self {
        self.truncated_spaces.push((name.into(), size));
        self
    }

    /// Adds an extra address space.
    #[must_use]
    pub fn with_space(mut self, space: ExtraSpace) -> Self {
        self.extra_spaces.push(space);
        self
    }

    /// The truncated address size of a space, if it is truncated.
    pub(crate) fn truncation(&self, name: &str) -> Option<u32> {
        self.truncated_spaces
            .iter()
            .find(|(n, _)| n == name)
            .map(|&(_, size)| size)
    }
}
