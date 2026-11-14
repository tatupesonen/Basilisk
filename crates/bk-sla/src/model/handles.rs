//! Typed indices into the arenas of a [`Sla`](crate::Sla), and the ranges
//! and string handles the model is built from.

use std::ops::Range;

macro_rules! index_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
            /// Wraps a raw index.
            pub const fn new(index: u32) -> Self {
                Self(index)
            }

            /// The raw index.
            pub const fn index(self) -> u32 {
                self.0
            }

            /// The raw index as a `usize`, for slice access.
            pub(crate) const fn slot(self) -> usize {
                self.0 as usize
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

index_type!(
    /// A symbol: its id in the file, which is its index in the symbol table.
    SymbolId
);
index_type!(
    /// A scope: its id in the file. Scope 0 is the global scope.
    ScopeId
);
index_type!(
    /// A constructor, in the model's constructor arena. A subtable's
    /// constructor `i` is `first + i` of its range.
    ConstructorId
);
index_type!(
    /// A pattern-expression node.
    ExprId
);
index_type!(
    /// A token or context field (the payload of a field expression).
    FieldId
);
index_type!(
    /// A p-code template (`construct_tpl`) of a constructor.
    TemplateId
);
index_type!(
    /// A decision-tree node.
    DecisionId
);
index_type!(
    /// A pattern block (`pat_block`).
    BlockId
);
index_type!(
    /// A handle template (`handle_tpl`), the export of a template.
    HandleId
);

/// A contiguous run of entries in one arena.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    start: u32,
    len: u32,
}

impl Span {
    /// The empty run.
    pub const EMPTY: Self = Self { start: 0, len: 0 };

    /// A run of `len` entries from `start`.
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    /// The first entry.
    pub const fn start(self) -> u32 {
        self.start
    }

    /// The number of entries.
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Whether the run is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// The run as a range of slice indices.
    pub fn range(self) -> Range<usize> {
        let start = self.start as usize;
        start..start.saturating_add(self.len as usize)
    }

    /// The span from `start` to the current length of `arena`.
    pub(crate) fn since<T>(start: usize, arena: &[T]) -> Self {
        Self {
            start: start as u32,
            len: arena.len().saturating_sub(start) as u32,
        }
    }
}

/// A string held in the model's string arena; read it with
/// [`Sla::text`](crate::Sla::text).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StrId {
    start: u32,
    len: u32,
}

impl StrId {
    pub(crate) const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    pub(crate) fn range(self) -> Range<usize> {
        let start = self.start as usize;
        start..start.saturating_add(self.len as usize)
    }
}

/// An arena of string bytes with handles into it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Strings {
    text: String,
}

impl Strings {
    pub(crate) fn add(&mut self, value: &str) -> StrId {
        let start = self.text.len() as u32;
        self.text.push_str(value);
        StrId::new(start, value.len() as u32)
    }

    pub(crate) fn get(&self, id: StrId) -> &str {
        self.text.get(id.range()).unwrap_or_default()
    }

    pub(crate) fn has_nul(&self) -> bool {
        self.text.contains('\0')
    }

    pub(crate) fn capacity(&self) -> usize {
        self.text.capacity()
    }
}
