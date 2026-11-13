//! Limits on what a file may ask the reader to build (`features/sla.md` 4.4).

/// Configurable bounds; exceeding one is an error, never a panic or an
/// unbounded allocation. [`Limits::default`] gives the spec's values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest inflated stream, in bytes (Java: 2 GiB; C++: none).
    pub inflated_size: u64,
    /// Most scopes (`SymbolTable::MAX_TABLES`).
    pub scopes: u64,
    /// Most symbols (`SymbolTable::MAX_SYMBOLS`).
    pub symbols: u64,
    /// Deepest element nesting (corpus maximum 27).
    pub element_depth: u32,
    /// Deepest pattern-expression nesting.
    pub expr_depth: u32,
    /// Deepest decision tree (corpus maximum 19).
    pub decision_depth: u32,
    /// Most operands of one constructor (corpus maximum 27).
    pub operands: u32,
    /// Most inputs of one op template (corpus maximum 10).
    pub op_inputs: u32,
    /// Largest byte quantity: `off`, `minlen`, `length`, `delay`, a pattern
    /// block's offset.
    pub byte_quantity: u32,
    /// Most context words addressed.
    pub context_words: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            inflated_size: 1 << 30,
            scopes: 0x10_0000,
            symbols: 0x100_0000,
            element_depth: 256,
            expr_depth: 64,
            decision_depth: 64,
            operands: 255,
            op_inputs: 255,
            byte_quantity: 65_535,
            context_words: 1_024,
        }
    }
}
