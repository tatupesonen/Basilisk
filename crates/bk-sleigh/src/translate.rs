//! The translator interface (Ghidra `Translate`): this part has the
//! decoding services; p-code generation (`oneInstruction`) is added by the
//! `sleigh-pcode` track.

use std::sync::Arc;

use bk_core::Address;

use crate::context::ContextDb;
use crate::decode::{ByteSource, Decoder};
use crate::error::DecodeError;
use crate::language::Language;

/// What a translator offers about the instruction at an address.
pub trait Translate {
    /// The instruction's length in bytes (Ghidra `instructionLength`).
    fn instruction_length(&mut self, addr: Address) -> Result<u32, DecodeError>;

    /// Appends the instruction's mnemonic and operand text and returns its
    /// length (Ghidra `printAssembly`).
    fn print_assembly(&mut self, addr: Address, mnemonic: &mut String, body: &mut String) -> Result<u32, DecodeError>;
}

/// A language, a context database and a byte source together: the
/// counterpart of Ghidra's `Sleigh` object with its load image and context.
#[derive(Debug)]
pub struct Translator<B> {
    decoder: Decoder,
    context: ContextDb,
    bytes: B,
}

impl<B: ByteSource> Translator<B> {
    /// A translator over `bytes` with the language's initial context.
    pub fn new(lang: Arc<Language>, bytes: B) -> Self {
        let context = lang.initial_context();
        Self {
            decoder: Decoder::new(lang),
            context,
            bytes,
        }
    }

    /// The context database.
    pub fn context(&self) -> &ContextDb {
        &self.context
    }

    /// The context database, for changes.
    pub fn context_mut(&mut self) -> &mut ContextDb {
        &mut self.context
    }

    /// The decoder (holding the last parse).
    pub fn decoder(&self) -> &Decoder {
        &self.decoder
    }

    /// Runs [`Decoder::prepare`] on this translator's bytes and context.
    pub fn prepare(&mut self, addr: Address) -> Result<crate::decode::Prepared, DecodeError> {
        self.decoder.prepare(addr, &self.bytes, &mut self.context)
    }
}

impl<B: ByteSource> Translate for Translator<B> {
    fn instruction_length(&mut self, addr: Address) -> Result<u32, DecodeError> {
        Ok(self.decoder.decode(addr, &self.bytes, &self.context)?.length())
    }

    fn print_assembly(&mut self, addr: Address, mnemonic: &mut String, body: &mut String) -> Result<u32, DecodeError> {
        let length = self.decoder.decode(addr, &self.bytes, &self.context)?.length();
        self.decoder.mnemonic(mnemonic)?;
        self.decoder.body(body)?;
        Ok(length)
    }
}
