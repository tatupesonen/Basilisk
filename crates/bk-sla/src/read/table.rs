//! Decoding subtables: constructors, decision trees and patterns (Ghidra
//! `SubtableSymbol::decode`, `Constructor::decode`, `DecisionNode::decode`,
//! `DisjointPattern::decodeDisjoint`, `PatternBlock::decode`).

use super::decode::{Reader, need, to_i32, to_index, to_u32};
use super::expr::{read_context_change, read_template};
use super::source::Source;
use crate::error::Fail;
use crate::ids::{self, a, e};
use crate::model::constructor::{
    Constructor, DecisionNode, DecisionPair, DisjointPattern, MaskWord, PatternBlock, PrintPiece,
    normalize_block,
};
use crate::model::handles::{BlockId, DecisionId, Span, SymbolId};
use crate::model::symbol::Subtable;

impl<'a, S: Source<'a>> Reader<'a, '_, S> {
    pub(crate) fn subtable(&mut self, numct: i64) -> Result<Subtable, Fail> {
        if numct < 0 {
            return Err(Fail::invalid(format!("negative numct {numct}")));
        }
        let first = self.a.constructors.len();
        let mut decision = None;
        while let Some(id) = self.src.peek()? {
            match id {
                e::CONSTRUCTOR => {
                    self.ctx.constructor = Some((self.a.constructors.len() - first) as u32);
                    let ctor = self.constructor()?;
                    self.a.constructors.push(ctor);
                    self.ctx.constructor = None;
                }
                e::DECISION => {
                    if decision.is_some() {
                        return Err(Fail::invalid("a subtable has more than one decision tree"));
                    }
                    let root = self.decision(0)?;
                    let root_id = DecisionId::new(self.a.decisions.len() as u32);
                    self.a.decisions.push(root);
                    decision = Some(root_id);
                }
                _ => return Err(self.unexpected(id, "<constructor> or <decision>")),
            }
        }
        let constructors = Span::since(first, &self.a.constructors);
        if i64::from(constructors.len()) != numct {
            return Err(Fail::invalid(format!(
                "numct is {numct} but the subtable has {} constructors",
                constructors.len()
            )));
        }
        let decision = decision.ok_or_else(|| Fail::invalid("a subtable has no decision tree"))?;
        Ok(Subtable {
            constructors,
            decision,
        })
    }

    fn constructor(&mut self) -> Result<Constructor, Fail> {
        self.src.open()?;
        let (mut parent, mut first, mut length, mut source, mut line) =
            (None, None, None, None, None);
        while let Some(attr) = self.src.next_attr()? {
            match attr {
                a::PARENT => parent = Some(to_u32(self.src.unsigned()?, "parent")?),
                a::FIRST => first = Some(to_i32(self.src.signed()?, "first")?),
                a::LENGTH => length = Some(to_i32(self.src.signed()?, "length")?),
                a::SOURCE => source = Some(to_i32(self.src.signed()?, "source")?),
                a::LINE => line = Some(to_i32(self.src.signed()?, "line")?),
                _ => {}
            }
        }
        let operands_start = self.a.operand_lists.len();
        let print_start = self.a.print_pieces.len();
        let context_start = self.a.context_changes.len();
        let templates_start = self.a.templates.len();
        while let Some(id) = self.src.peek()? {
            match id {
                e::OPER => {
                    self.src.open()?;
                    let mut operand = None;
                    while let Some(attr) = self.src.next_attr()? {
                        if attr == a::ID {
                            operand = Some(to_u32(self.src.unsigned()?, "id")?);
                        }
                    }
                    let count = self.a.operand_lists.len() - operands_start;
                    if count >= self.limits.operands as usize {
                        return Err(Fail::limit(
                            "operands of one constructor",
                            u64::from(self.limits.operands),
                            count as u64 + 1,
                        ));
                    }
                    self.a
                        .operand_lists
                        .push(SymbolId::new(need(operand, "id")?));
                    self.src.close()?;
                }
                e::PRINT => {
                    self.src.open()?;
                    let mut piece = None;
                    while let Some(attr) = self.src.next_attr()? {
                        if attr == a::PIECE {
                            piece = Some(self.src.string()?);
                        }
                    }
                    let text = self.a.strings.add(need(piece, "piece")?);
                    self.a.print_pieces.push(PrintPiece::Text(text));
                    self.src.close()?;
                }
                e::OPPRINT => {
                    self.src.open()?;
                    let mut index = None;
                    while let Some(attr) = self.src.next_attr()? {
                        if attr == a::ID {
                            index = Some(to_i32(self.src.signed()?, "id")?);
                        }
                    }
                    self.a
                        .print_pieces
                        .push(PrintPiece::Operand(need(index, "id")?));
                    self.src.close()?;
                }
                e::CONTEXT_OP | e::COMMIT => {
                    let change = read_context_change(self, id)?;
                    self.a.context_changes.push(change);
                }
                e::CONSTRUCT_TPL => {
                    let template = read_template(self)?;
                    self.a.templates.push(template);
                }
                _ => return Err(self.unexpected(id, "a constructor child")),
            }
        }
        self.src.close()?;
        let templates = Span::since(templates_start, &self.a.templates);
        if let Some(run) = self.a.templates.get_mut(templates.range()) {
            run.sort_by_key(|template| {
                template.section.map_or(0, |section| u64::from(section) + 1)
            });
            if run
                .windows(2)
                .any(|pair| matches!(pair, [x, y] if x.section == y.section))
            {
                return Err(Fail::invalid("Duplicate main or named section"));
            }
        }
        Ok(Constructor {
            parent: SymbolId::new(need(parent, "parent")?),
            first: need(first, "first")?,
            length: need(length, "length")?,
            source: need(source, "source")?,
            line: need(line, "line")?,
            operands: Span::since(operands_start, &self.a.operand_lists),
            print: Span::since(print_start, &self.a.print_pieces),
            context: Span::since(context_start, &self.a.context_changes),
            templates,
        })
    }

    /// Reads one decision node with its subtree. Its children are placed in
    /// the arena as one contiguous run after their own subtrees; the node
    /// itself is returned for the caller to place.
    fn decision(&mut self, depth: u32) -> Result<DecisionNode, Fail> {
        if depth >= self.limits.decision_depth {
            return Err(Fail::limit(
                "decision-tree depth",
                u64::from(self.limits.decision_depth),
                u64::from(depth) + 1,
            ));
        }
        self.open_expect(ids::ELEM_DECISION)?;
        let (mut number, mut context, mut start_bit, mut size) = (None, None, None, None);
        while let Some(attr) = self.src.next_attr()? {
            match attr {
                a::NUMBER => number = Some(to_i32(self.src.signed()?, "number")?),
                a::CONTEXT => context = Some(self.src.bool()?),
                a::STARTBIT => start_bit = Some(to_i32(self.src.signed()?, "startbit")?),
                a::SIZE => size = Some(self.src.signed()?),
                _ => {}
            }
        }
        let size = need(size, "size")?;
        let size = u8::try_from(size)
            .ok()
            .filter(|&size| size <= 8)
            .ok_or_else(|| Fail::invalid(format!("decision node size {size} is not in 0..=8")))?;
        let pairs_start = self.a.pairs.len();
        let scratch_start = self.decision_scratch.len();
        while let Some(id) = self.src.peek()? {
            match id {
                e::PAIR if size == 0 => {
                    self.src.open()?;
                    let mut constructor = None;
                    while let Some(attr) = self.src.next_attr()? {
                        if attr == a::ID {
                            constructor = Some(to_index(self.src.signed()?, "id")?);
                        }
                    }
                    let pattern = self.pattern()?;
                    self.src.close()?;
                    self.a.pairs.push(DecisionPair {
                        constructor: need(constructor, "id")?,
                        pattern,
                    });
                }
                e::DECISION if size != 0 => {
                    let child = self.decision(depth + 1)?;
                    self.decision_scratch.push(child);
                }
                e::PAIR => return Err(Fail::invalid("a decision node with children has pairs")),
                e::DECISION => return Err(Fail::invalid("a decision leaf has children")),
                _ => return Err(self.unexpected(id, "<pair> or <decision>")),
            }
        }
        self.src.close()?;
        let children = self.decision_scratch.len() - scratch_start;
        let expected = if size == 0 { 0 } else { 1usize << size };
        if children != expected {
            return Err(Fail::invalid(format!(
                "decision node of size {size} has {children} children, expected {expected}"
            )));
        }
        let first_child = self.a.decisions.len() as u32;
        self.a
            .decisions
            .extend(self.decision_scratch.drain(scratch_start..));
        Ok(DecisionNode {
            number: need(number, "number")?,
            start_bit: need(start_bit, "startbit")?,
            context: need(context, "context")?,
            size,
            first_child,
            pairs: if size == 0 {
                Span::since(pairs_start, &self.a.pairs)
            } else {
                Span::EMPTY
            },
        })
    }

    fn pattern(&mut self) -> Result<DisjointPattern, Fail> {
        match self.src.peek()? {
            Some(e::INSTRUCT_PAT) => Ok(DisjointPattern::Instruction(self.wrapped_block()?)),
            Some(e::CONTEXT_PAT) => Ok(DisjointPattern::Context(self.wrapped_block()?)),
            Some(e::COMBINE_PAT) => {
                self.src.open()?;
                if self.src.peek()? != Some(e::CONTEXT_PAT) {
                    self.open_expect(ids::ELEM_CONTEXT_PAT)?;
                }
                let context = self.wrapped_block()?;
                if self.src.peek()? != Some(e::INSTRUCT_PAT) {
                    self.open_expect(ids::ELEM_INSTRUCT_PAT)?;
                }
                let instruction = self.wrapped_block()?;
                self.src.close()?;
                Ok(DisjointPattern::Combine {
                    context,
                    instruction,
                })
            }
            Some(id) => Err(self.unexpected(id, "<instruct_pat>, <context_pat> or <combine_pat>")),
            None => Err(Fail::invalid("a pair has no pattern")),
        }
    }

    /// `instruct_pat` or `context_pat` around one `pat_block`.
    fn wrapped_block(&mut self) -> Result<BlockId, Fail> {
        self.src.open()?;
        let block = self.block()?;
        self.src.close()?;
        Ok(block)
    }

    fn block(&mut self) -> Result<BlockId, Fail> {
        self.open_expect(ids::ELEM_PAT_BLOCK)?;
        let (mut offset, mut nonzero) = (None, None);
        while let Some(attr) = self.src.next_attr()? {
            match attr {
                a::OFF => offset = Some(to_i32(self.src.signed()?, "off")?),
                a::NONZERO => nonzero = Some(to_i32(self.src.signed()?, "nonzero")?),
                _ => {}
            }
        }
        let mut offset = need(offset, "off")?;
        let mut nonzero = need(nonzero, "nonzero")?;
        let mut words = std::mem::take(&mut self.word_scratch);
        words.clear();
        while self.src.peek()?.is_some() {
            self.open_expect(ids::ELEM_MASK_WORD)?;
            let (mut mask, mut value) = (None, None);
            while let Some(attr) = self.src.next_attr()? {
                match attr {
                    a::MASK => mask = Some(to_u32(self.src.unsigned()?, "mask")?),
                    a::VAL => value = Some(to_u32(self.src.unsigned()?, "val")?),
                    _ => {}
                }
            }
            words.push(MaskWord {
                mask: need(mask, "mask")?,
                value: need(value, "val")?,
            });
            self.src.close()?;
        }
        self.src.close()?;
        normalize_block(&mut offset, &mut nonzero, &mut words);
        let start = self.a.words.len();
        self.a.words.extend_from_slice(&words);
        self.word_scratch = words;
        let id = BlockId::new(self.a.blocks.len() as u32);
        self.a.blocks.push(PatternBlock {
            offset,
            nonzero,
            words: Span::since(start, &self.a.words),
        });
        Ok(id)
    }
}
