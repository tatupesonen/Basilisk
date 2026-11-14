//! Typed indices into the compiler's arenas.

macro_rules! index_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) u32);

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
            pub const fn slot(self) -> usize {
                self.0 as usize
            }

            /// The id of the next element of an arena that currently holds
            /// `len` elements.
            pub(crate) fn next(len: usize) -> Self {
                Self(u32::try_from(len).unwrap_or(u32::MAX))
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
    /// A symbol. Before the purge (inventory 9.10) this is the creation
    /// index Ghidra's `SymbolTable::addSymbol` hands out; in an
    /// [`Elaborated`](crate::Elaborated) it is the final id written to the
    /// `.sla` file.
    SymbolId
);
index_type!(
    /// A scope: 0 is the global scope.
    ScopeId
);
index_type!(
    /// A subtable, in the order tables are created (the root `instruction`
    /// is table 0).
    TableId
);
index_type!(
    /// A constructor, in the order constructors are created.
    CtorId
);
index_type!(
    /// An operand symbol's data (constructor operands and macro parameters).
    OperandId
);
index_type!(
    /// A pattern-expression node.
    PExprId
);
index_type!(
    /// A pattern-equation node.
    EquationId
);
index_type!(
    /// A macro, by its index in the macro table.
    MacroId
);

impl ScopeId {
    /// The global scope.
    pub const GLOBAL: Self = Self(0);
}
