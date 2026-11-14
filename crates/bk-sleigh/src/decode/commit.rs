//! Writing an instruction's pending `globalset`s to the context store
//! (Ghidra `ParserContext::applyCommits`; inventory section 4.4).

use bk_core::Address;
use bk_sla::SymbolKind;

use super::handles::operand_handle;
use super::resolve::{add, env};
use super::tree::{FixedHandle, Parse};
use crate::context::ContextSink;
use crate::error::DecodeError;
use crate::language::Language;
use crate::language::tables::symbol_def;

/// Applies the commits of a parse whose handles are resolved.
pub(crate) fn apply_commits<S: ContextSink + ?Sized>(
    lang: &Language,
    parse: &Parse,
    sink: &mut S,
) -> Result<(), DecodeError> {
    if parse.commits.is_empty() {
        return Ok(());
    }
    let env = env(lang, parse, Some(parse.naddr));
    let sla = lang.sla();
    for commit in &parse.commits {
        let hand = match sla.symbol(commit.symbol).map(|s| s.kind) {
            Some(SymbolKind::Operand(operand)) => parse
                .nodes
                .get(commit.node as usize)
                .and_then(|node| node.child(operand.index.max(0) as u32))
                .map_or(FixedHandle::UNSET, |child| parse.handle(child)),
            _ => operand_handle(&env, symbol_def(sla, commit.symbol), 0)?,
        };
        let space = parse.addr.space();
        let addr = if hand.space == 0 {
            // A computed value: an offset in addressable units of the
            // instruction's space.
            let word = space
                .and_then(|s| lang.spaces().space(s))
                .map_or(1, |s| u64::from(s.word_size().max(1)));
            match space {
                Some(space) => Address::new(space, hand.offset_offset.wrapping_mul(word)),
                None => continue,
            }
        } else {
            Address::new(hand.space_id(), hand.offset_offset)
        };
        let word = commit.word as usize;
        if commit.flow {
            sink.set_change_point(addr, word, commit.mask, commit.value);
        } else {
            let next = add(lang, addr, 1);
            if next.offset() < addr.offset() {
                sink.set_change_point(addr, word, commit.mask, commit.value);
            } else {
                sink.set_region(addr, Some(next), word, commit.mask, commit.value);
            }
        }
    }
    Ok(())
}
