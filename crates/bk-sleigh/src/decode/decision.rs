//! Walking a subtable's decision tree and matching the patterns of a leaf
//! (Ghidra `DecisionNode::resolve`, `DisjointPattern::isMatch`,
//! `PatternBlock::isInstructionMatch`, `isContextMatch`).

use bk_sla::{BlockId, ConstructorId, DisjointPattern, SymbolId};

use super::expr::Env;
use crate::error::DecodeError;

impl Env<'_> {
    /// The constructor of subtable `table` that the bytes at `node_offset`
    /// and the local context select.
    pub(crate) fn choose(
        &self,
        table: SymbolId,
        node_offset: u32,
    ) -> Result<ConstructorId, DecodeError> {
        let subtable = self
            .sla
            .subtable(table)
            .ok_or_else(|| self.model("subtable"))?;
        let mut id = subtable.decision;
        // A validated tree is at most 64 levels deep; the bound only keeps a
        // malformed one from looping.
        for _ in 0..=256 {
            let node = self
                .sla
                .decision(id)
                .ok_or_else(|| self.model("decision node"))?;
            if node.is_leaf() {
                for pair in self.sla.pairs(node) {
                    if self.matches(&pair.pattern, node_offset)? {
                        return subtable
                            .constructor(pair.constructor)
                            .ok_or_else(|| self.model("decision pair constructor"));
                    }
                }
                return Err(DecodeError::NoConstructor {
                    address: self.parse.addr,
                    at: self.lang.raw_text(self.parse.addr),
                });
            }
            let size = u32::from(node.size);
            let value = if node.context {
                self.context_bits(node.start_bit, size)
            } else {
                self.instruction_bits(node.start_bit, size, node_offset)?
            };
            id = self
                .sla
                .decision_child(node, value)
                .ok_or_else(|| self.model("decision child"))?;
        }
        Err(self.model("decision tree too deep"))
    }

    /// Ghidra's `isMatch`; a combined pattern tests the instruction block
    /// first.
    fn matches(&self, pattern: &DisjointPattern, node_offset: u32) -> Result<bool, DecodeError> {
        Ok(match *pattern {
            DisjointPattern::Instruction(block) => self.instruction_match(block, node_offset)?,
            DisjointPattern::Context(block) => self.context_match(block)?,
            DisjointPattern::Combine {
                context,
                instruction,
            } => {
                self.instruction_match(instruction, node_offset)? && self.context_match(context)?
            }
        })
    }

    fn instruction_match(&self, id: BlockId, node_offset: u32) -> Result<bool, DecodeError> {
        let block = self
            .sla
            .block(id)
            .ok_or_else(|| self.model("pattern block"))?;
        if block.nonzero <= 0 {
            return Ok(block.nonzero == 0);
        }
        let mut off = block.offset;
        for word in self.sla.block_words(block) {
            let data = self.pattern_word(off, node_offset, word.mask)?;
            if word.mask & data != word.value {
                return Ok(false);
            }
            off = off.wrapping_add(4);
        }
        Ok(true)
    }

    fn context_match(&self, id: BlockId) -> Result<bool, DecodeError> {
        let block = self
            .sla
            .block(id)
            .ok_or_else(|| self.model("pattern block"))?;
        if block.nonzero <= 0 {
            return Ok(block.nonzero == 0);
        }
        let mut off = block.offset;
        for word in self.sla.block_words(block) {
            if word.mask & self.context_bytes(off, 4) != word.value {
                return Ok(false);
            }
            off = off.wrapping_add(4);
        }
        Ok(true)
    }
}
