//! Walking a subtable's decision tree and matching the patterns of a leaf
//! (Ghidra `DecisionNode::resolve`, `DisjointPattern::isMatch`,
//! `PatternBlock::isInstructionMatch`, `isContextMatch`), over the layout of
//! [`crate::language::decide`].

use bk_sla::{ConstructorId, SymbolId};

use super::bytes::WINDOW;
use super::expr::Env;
use crate::error::DecodeError;
use crate::language::decide::{Block, Step, Trees};

impl Env<'_> {
    /// The constructor of subtable `table` that the bytes at `node_offset`
    /// and the local context select.
    pub(crate) fn choose(
        &self,
        table: SymbolId,
        node_offset: u32,
    ) -> Result<ConstructorId, DecodeError> {
        let trees = &self.lang.tables.trees;
        let root = trees
            .roots
            .get(table.index() as usize)
            .filter(|root| root.decision != crate::decode::tree::NONE)
            .ok_or_else(|| self.model("subtable"))?;
        let mut id = root.decision;
        // A validated tree is at most 64 levels deep; the bound only keeps a
        // malformed one from looping.
        for _ in 0..=256 {
            let (value, children, first) = match trees.step(id) {
                Step::Leaf { first, count } => {
                    let pairs = trees
                        .pairs
                        .get(first as usize..first.wrapping_add(count) as usize)
                        .unwrap_or_default();
                    for pair in pairs {
                        if self.block_matches(trees, pair.instruction, node_offset)?
                            && self.context_block_matches(trees, pair.context)?
                        {
                            return (pair.constructor < root.num_constructors)
                                .then(|| {
                                    ConstructorId::new(
                                        root.first_constructor.wrapping_add(pair.constructor),
                                    )
                                })
                                .ok_or_else(|| self.model("decision pair constructor"));
                        }
                    }
                    return Err(DecodeError::NoConstructor {
                        address: self.parse.addr,
                        at: self.lang.raw_text(self.parse.addr),
                    });
                }
                Step::Bits {
                    byte,
                    byte_size,
                    shl,
                    shr,
                    children,
                    first,
                } => {
                    // `Env::instruction_bits` with the arithmetic done.
                    let pos = node_offset.wrapping_add(byte as u32);
                    if pos as usize >= WINDOW {
                        return Err(DecodeError::TooLong {
                            address: self.parse.addr,
                        });
                    }
                    if pos as usize + byte_size as usize > WINDOW {
                        self.parse.overhang.set(true);
                    }
                    let raw = self.parse.window.read(pos, byte_size.min(4));
                    (raw.wrapping_shl(shl).wrapping_shr(shr), children, first)
                }
                Step::Context {
                    start_bit,
                    size,
                    children,
                    first,
                } => (self.context_bits(start_bit, size), children, first),
                Step::Missing => return Err(self.model("decision node")),
            };
            if value >= children {
                return Err(self.model("decision child"));
            }
            id = first.wrapping_add(value);
        }
        Err(self.model("decision tree too deep"))
    }

    /// Ghidra `PatternBlock::isInstructionMatch`.
    #[inline]
    fn block_matches(
        &self,
        trees: &Trees,
        block: Block,
        node_offset: u32,
    ) -> Result<bool, DecodeError> {
        match block {
            Block::True => Ok(true),
            Block::False => Ok(false),
            Block::Missing => Err(self.model("pattern block")),
            Block::Words {
                offset,
                first,
                count,
            } => {
                let words = trees
                    .words
                    .get(first as usize..first.wrapping_add(count) as usize)
                    .unwrap_or_default();
                let mut off = offset;
                for word in words {
                    let data = self.pattern_word(off, node_offset, word.mask)?;
                    if word.mask & data != word.value {
                        return Ok(false);
                    }
                    off = off.wrapping_add(4);
                }
                Ok(true)
            }
        }
    }

    /// Ghidra `PatternBlock::isContextMatch`.
    #[inline]
    fn context_block_matches(&self, trees: &Trees, block: Block) -> Result<bool, DecodeError> {
        match block {
            Block::True => Ok(true),
            Block::False => Ok(false),
            Block::Missing => Err(self.model("pattern block")),
            Block::Words {
                offset,
                first,
                count,
            } => {
                let words = trees
                    .words
                    .get(first as usize..first.wrapping_add(count) as usize)
                    .unwrap_or_default();
                let mut off = offset;
                for word in words {
                    if word.mask & self.context_bytes(off, 4) != word.value {
                        return Ok(false);
                    }
                    off = off.wrapping_add(4);
                }
                Ok(true)
            }
        }
    }
}
