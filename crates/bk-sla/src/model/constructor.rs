//! Constructors, their print pieces and context changes, and the decision
//! trees and patterns that select them (inventory sections 1.4, 1.6).

use super::handles::{BlockId, ExprId, Span, StrId, SymbolId};

/// One constructor of a subtable.
///
/// The operand list, print pieces, context changes and templates are runs of
/// shared arenas; read them through [`Sla`](crate::Sla) (`operands`,
/// `print_pieces`, `context_changes`, `templates`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Constructor {
    /// The subtable the constructor belongs to.
    pub parent: SymbolId,
    /// Index of the first white-space print piece, or −1. It may equal the
    /// number of print pieces (inventory section 2).
    pub first: i32,
    /// Minimum length in bytes of the constructor's own pattern.
    pub length: i32,
    /// Index of the source file in [`Sla::source_files`](crate::Sla::source_files).
    pub source: i32,
    /// Line of the constructor in that file.
    pub line: i32,
    pub(crate) operands: Span,
    pub(crate) print: Span,
    pub(crate) context: Span,
    /// Main template first (if any), then section templates by number.
    pub(crate) templates: Span,
}

impl Constructor {
    /// The number of operands.
    pub const fn num_operands(&self) -> u32 {
        self.operands.len()
    }
}

/// One piece of a constructor's display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrintPiece {
    /// Literal text (`print`).
    Text(StrId),
    /// An operand's display (`opprint`), by operand index.
    Operand(i32),
}

/// A context change performed while an instruction is decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextChange {
    /// `context_op`: set bits of the local context word `word` to an
    /// expression's value: `ctx[word] = (ctx[word] & !mask) | ((value << shift) & mask)`.
    Op {
        /// The context word index.
        word: i32,
        /// Left shift applied to the value.
        shift: i32,
        /// The bits written.
        mask: u32,
        /// The value.
        expr: ExprId,
    },
    /// `commit` (`globalset`): write bits of a context word to the context
    /// database at the address a symbol resolves to.
    Commit {
        /// The symbol giving the address.
        symbol: SymbolId,
        /// The context word index.
        word: i32,
        /// The bits committed.
        mask: u32,
        /// Whether the change flows forward from there.
        flow: bool,
    },
}

/// A decision-tree node.
///
/// A node with `size == 0` is a leaf: an ordered list of pairs, tried in
/// order. Otherwise it has exactly `2^size` children, selected by the value
/// of the `size`-bit field at `start_bit`: the child for value `v` is
/// `first_child + v` ([`Sla::decision_child`](crate::Sla::decision_child)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionNode {
    /// How many pattern/constructor pairs reached the node when the tree was
    /// built (informational).
    pub number: i32,
    /// First bit of the field tested, most significant first.
    pub start_bit: i32,
    /// Whether the field is in the context (else in the instruction bytes).
    pub context: bool,
    /// Width of the field tested, 0..=8; 0 marks a leaf.
    pub size: u8,
    pub(crate) first_child: u32,
    pub(crate) pairs: Span,
}

impl DecisionNode {
    /// The number of children: 0 for a leaf, else `2^size`.
    pub const fn num_children(&self) -> u32 {
        if self.size == 0 { 0 } else { 1 << self.size }
    }

    /// Whether the node is a leaf.
    pub const fn is_leaf(&self) -> bool {
        self.size == 0
    }
}

/// A constructor reached at a leaf, with the pattern it must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionPair {
    /// The constructor's index in its subtable.
    pub constructor: u32,
    /// The pattern.
    pub pattern: DisjointPattern,
}

/// A pattern without alternatives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisjointPattern {
    /// `instruct_pat`: a block over the instruction bytes.
    Instruction(BlockId),
    /// `context_pat`: a block over the context words.
    Context(BlockId),
    /// `combine_pat`: a context block and an instruction block, both of which
    /// must match.
    Combine {
        /// The context block.
        context: BlockId,
        /// The instruction block.
        instruction: BlockId,
    },
}

impl DisjointPattern {
    /// The context block, if any.
    pub const fn context_block(&self) -> Option<BlockId> {
        match *self {
            Self::Context(block) | Self::Combine { context: block, .. } => Some(block),
            Self::Instruction(_) => None,
        }
    }

    /// The instruction block, if any.
    pub const fn instruction_block(&self) -> Option<BlockId> {
        match *self {
            Self::Instruction(block) | Self::Combine { instruction: block, .. } => Some(block),
            Self::Context(_) => None,
        }
    }
}

/// A mask/value block over bytes (inventory section 10, b.1), held in the
/// normalised form `PatternBlock::normalize` gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatternBlock {
    /// Byte offset of the first word.
    pub offset: i32,
    /// Bytes from `offset` to the last byte with a mask bit; 0 = always
    /// true, −1 = always false.
    pub nonzero: i32,
    pub(crate) words: Span,
}

impl PatternBlock {
    /// Whether the block matches everything.
    pub const fn always_true(&self) -> bool {
        self.nonzero == 0
    }

    /// Whether the block matches nothing.
    pub const fn always_false(&self) -> bool {
        self.nonzero == -1
    }
}

/// One 32-bit word of a pattern block; the first byte is the top 8 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MaskWord {
    /// The bits that must match.
    pub mask: u32,
    /// Their values.
    pub value: u32,
}

/// Brings a block into the canonical form of Ghidra's
/// `PatternBlock::normalize` (inventory section 10, b.1): leading zero mask
/// bytes move into the offset, trailing zero words are dropped, and the
/// non-zero size is recomputed. `words` is edited in place.
pub fn normalize_block(offset: &mut i32, nonzero: &mut i32, words: &mut Vec<MaskWord>) {
    if *nonzero <= 0 {
        *offset = 0;
        words.clear();
        return;
    }
    let leading = words.iter().take_while(|word| word.mask == 0).count();
    words.drain(..leading);
    *offset = offset.saturating_add((leading as i32).saturating_mul(4));
    if let Some(first) = words.first() {
        let used = 4 - first.mask.leading_zeros() / 8;
        let suboff = 4 - used;
        if suboff != 0 {
            *offset = offset.saturating_add(suboff as i32);
            let bits = suboff * 8;
            let count = words.len();
            for i in 0..count {
                let next = words.get(i + 1).copied().unwrap_or_default();
                if let Some(word) = words.get_mut(i) {
                    word.mask = (word.mask << bits) | (next.mask >> (32 - bits));
                    word.value = (word.value << bits) | (next.value >> (32 - bits));
                }
            }
            // The last word was shifted with zeros from beyond the end.
        }
        while words.last().is_some_and(|word| word.mask == 0) {
            words.pop();
        }
    }
    let Some(last) = words.last() else {
        *offset = 0;
        *nonzero = 0;
        return;
    };
    let trailing = last.mask.trailing_zeros() / 8;
    *nonzero = (words.len() as i32).saturating_mul(4) - trailing as i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(offset: i32, nonzero: i32, words: &[(u32, u32)]) -> (i32, i32, Vec<(u32, u32)>) {
        let mut offset = offset;
        let mut nonzero = nonzero;
        let mut words: Vec<MaskWord> = words
            .iter()
            .map(|&(mask, value)| MaskWord { mask, value })
            .collect();
        normalize_block(&mut offset, &mut nonzero, &mut words);
        (
            offset,
            nonzero,
            words.iter().map(|word| (word.mask, word.value)).collect(),
        )
    }

    #[test]
    fn normalize_matches_ghidra() {
        // Always true / false drop everything.
        assert_eq!(norm(5, 0, &[(1, 1)]), (0, 0, vec![]));
        assert_eq!(norm(5, -1, &[(1, 1)]), (0, -1, vec![]));
        // Already canonical.
        assert_eq!(
            norm(0, 2, &[(0xffff_0000, 0x1234_0000)]),
            (0, 2, vec![(0xffff_0000, 0x1234_0000)])
        );
        // Leading zero word and zero bytes move into the offset.
        assert_eq!(
            norm(0, 8, &[(0, 0xdead), (0x0000_ff00, 0x0000_1200)]),
            (6, 1, vec![(0xff00_0000, 0x1200_0000)])
        );
        // A shift across words.
        assert_eq!(
            norm(1, 8, &[(0x00ff_ffff, 0x0012_3456), (0xff00_0000, 0x7800_0000)]),
            (2, 4, vec![(0xffff_ffff, 0x1234_5678)])
        );
        // Trailing zero words dropped; all-zero mask becomes always true.
        assert_eq!(
            norm(0, 8, &[(0xff00_0000, 0), (0, 0)]),
            (0, 1, vec![(0xff00_0000, 0)])
        );
        assert_eq!(norm(3, 8, &[(0, 0), (0, 0)]), (0, 0, vec![]));
    }
}
