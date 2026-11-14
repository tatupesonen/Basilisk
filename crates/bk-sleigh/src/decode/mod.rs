//! Decoding instructions: the per-thread [`Decoder`] and the [`Parse`] it
//! produces (Ghidra `Sleigh::resolve`, `resolveHandles`, `applyCommits`, the
//! first steps of `oneInstruction`; inventory sections 4.4, 5, 7.1).

pub(crate) mod bytes;
mod commit;
mod decision;
pub(crate) mod expr;
mod handles;
pub(crate) mod resolve;
pub(crate) mod tree;

use std::sync::Arc;

use bk_core::Address;

pub use bytes::{ByteSource, SliceBytes, WINDOW};
pub use tree::{Commit, FixedHandle, Node, Parse, ParseState};

use crate::context::{ContextSink, ContextSource};
use crate::error::DecodeError;
use crate::language::Language;

/// The most delay-slot instructions [`Decoder::prepare`] folds into one.
const MAX_DELAY_INSTRUCTIONS: usize = 16;

/// What [`Decoder::prepare`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prepared {
    /// The instruction's own length in bytes.
    pub length: u32,
    /// The length including the delay-slot instructions folded into it.
    pub flow_length: u32,
}

/// An instruction's text, owned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Disassembly {
    /// The instruction's address.
    pub address: Address,
    /// Its length in bytes.
    pub length: u32,
    /// The mnemonic.
    pub mnemonic: String,
    /// The operand text.
    pub body: String,
}

/// A per-thread worker that decodes instructions of one language. It owns
/// and reuses every buffer it needs: after warm-up, decoding allocates
/// nothing.
#[derive(Debug)]
pub struct Decoder {
    lang: Arc<Language>,
    main: Parse,
    delays: Vec<Parse>,
    num_delays: usize,
    lookahead: Parse,
    operand_limit: u32,
}

impl Decoder {
    /// A decoder for `lang`.
    pub fn new(lang: Arc<Language>) -> Self {
        Self {
            lang,
            main: Parse::new(),
            delays: Vec::new(),
            num_delays: 0,
            lookahead: Parse::new(),
            operand_limit: u32::MAX,
        }
    }

    /// Ghidra's C++ engine cannot decode a constructor with more than 20
    /// operands (`ParserContext::MAX_OPERAND`); basilisk can. With
    /// `Some(20)` the decoder fails as Ghidra does ("SLEIGH parser out of
    /// state space") — for comparing with Ghidra, not for analysis.
    pub fn set_operand_limit(&mut self, limit: Option<u32>) {
        self.operand_limit = limit.unwrap_or(u32::MAX);
    }

    /// The language.
    pub fn language(&self) -> &Arc<Language> {
        &self.lang
    }

    /// The last instruction decoded.
    pub fn parse(&self) -> &Parse {
        &self.main
    }

    /// The delay-slot instructions the last [`Decoder::prepare`] decoded.
    pub fn delay_slots(&self) -> &[Parse] {
        self.delays.get(..self.num_delays).unwrap_or_default()
    }

    /// Decodes the instruction at `addr`: constructors, offsets, lengths and
    /// pending commits (Ghidra `resolve`). The context store is only read.
    pub fn decode<B, C>(&mut self, addr: Address, bytes: &B, context: &C) -> Result<&Parse, DecodeError>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ?Sized,
    {
        self.num_delays = 0;
        resolve::resolve(&self.lang, &mut self.main, addr, bytes, context, self.operand_limit)?;
        if self.lang.tables.uses_next2 {
            self.main.next2 = Self::next2(&self.lang, &mut self.lookahead, &self.main, bytes, context, self.operand_limit);
        }
        Ok(&self.main)
    }

    /// The address after the instruction after `parse`, decoding that
    /// instruction with the context the store holds now (Ghidra
    /// `getN2addr`; not cached across calls).
    fn next2<B, C>(
        lang: &Language,
        scratch: &mut Parse,
        parse: &Parse,
        bytes: &B,
        context: &C,
        operand_limit: u32,
    ) -> Option<Address>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ?Sized,
    {
        resolve::resolve(lang, scratch, parse.naddr, bytes, context, operand_limit).ok()?;
        Some(resolve::add(lang, parse.naddr, u64::from(scratch.length())))
    }

    /// Resolves the handles of the last instruction decoded (Ghidra
    /// `resolveHandles`).
    pub fn resolve_handles<B, C>(&mut self, bytes: &B, context: &C) -> Result<&Parse, DecodeError>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ?Sized,
    {
        if self.lang.tables.next2_anywhere && self.main.next2.is_none() {
            self.main.next2 = Self::next2(&self.lang, &mut self.lookahead, &self.main, bytes, context, self.operand_limit);
        }
        handles::resolve_handles(&self.lang, &mut self.main)?;
        Ok(&self.main)
    }

    /// Writes the pending commits of the last instruction decoded to `sink`
    /// (Ghidra `applyCommits`). Resolve its handles first: a commit to an
    /// operand's address reads that operand's handle.
    pub fn apply_commits<S: ContextSink + ?Sized>(&self, sink: &mut S) -> Result<(), DecodeError> {
        commit::apply_commits(&self.lang, &self.main, sink)
    }

    /// Appends the mnemonic of the last instruction decoded.
    pub fn mnemonic(&self, out: &mut String) -> Result<(), DecodeError> {
        self.lang.mnemonic(&self.main, out)
    }

    /// Appends the operand text of the last instruction decoded.
    pub fn body(&self, out: &mut String) -> Result<(), DecodeError> {
        self.lang.body(&self.main, out)
    }

    /// Decodes the instruction at `addr` and returns its text as owned
    /// strings (Ghidra `printAssembly`).
    pub fn disassemble<B, C>(&mut self, addr: Address, bytes: &B, context: &C) -> Result<Disassembly, DecodeError>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ?Sized,
    {
        let length = self.decode(addr, bytes, context)?.length();
        let mut mnemonic = String::new();
        let mut body = String::new();
        self.mnemonic(&mut mnemonic)?;
        self.body(&mut body)?;
        Ok(Disassembly {
            address: addr,
            length,
            mnemonic,
            body,
        })
    }

    /// What the engine does before generating p-code for the instruction at
    /// `addr` (Ghidra `oneInstruction` steps 1–3): check the alignment;
    /// decode; resolve handles; apply commits; then, while delay-slot bytes
    /// remain, decode the next instruction with the context as it now is,
    /// resolve its handles and apply its commits. The main and delay-slot
    /// parses stay available ([`Decoder::parse`], [`Decoder::delay_slots`]).
    pub fn prepare<B, C>(&mut self, addr: Address, bytes: &B, context: &mut C) -> Result<Prepared, DecodeError>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ContextSink + ?Sized,
    {
        let align = u64::from(self.lang.alignment());
        if align != 1 && !addr.offset().is_multiple_of(align) {
            return Err(DecodeError::Unaligned {
                address: addr,
                at: self.lang.raw_text(addr),
            });
        }
        self.decode(addr, bytes, &*context)?;
        self.resolve_handles(bytes, &*context)?;
        commit::apply_commits(&self.lang, &self.main, context)?;
        let length = self.main.length();
        let mut fall = length;
        let delay = self.main.delay_slot;
        if delay > 0 {
            let mut covered = 0u32;
            while self.num_delays < MAX_DELAY_INSTRUCTIONS {
                let at = resolve::add(&self.lang, addr, u64::from(fall));
                if self.delays.len() <= self.num_delays {
                    self.delays.push(Parse::new());
                }
                let Some(slot) = self.delays.get_mut(self.num_delays) else {
                    break;
                };
                resolve::resolve(&self.lang, slot, at, bytes, &*context, self.operand_limit)?;
                if self.lang.tables.next2_anywhere {
                    slot.next2 = Self::next2(&self.lang, &mut self.lookahead, slot, bytes, &*context, self.operand_limit);
                }
                handles::resolve_handles(&self.lang, slot)?;
                commit::apply_commits(&self.lang, slot, context)?;
                let len = slot.length();
                self.num_delays += 1;
                fall = fall.wrapping_add(len);
                covered = covered.wrapping_add(len);
                if covered >= delay || len == 0 {
                    break;
                }
            }
            self.main.naddr = resolve::add(&self.lang, addr, u64::from(fall));
        }
        Ok(Prepared {
            length,
            flow_length: fall,
        })
    }
}
