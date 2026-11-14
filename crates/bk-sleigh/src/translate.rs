//! The translator interface (Ghidra `Translate`, `CPP/translate.hh`): what
//! the decompiler, the emulator and the disassembler ask of a language, and
//! [`Translator`], a language with a context database and a byte source
//! that implements it.

use std::sync::Arc;

use bk_core::{Address, RegisterLookup as _, SpaceId, SpaceManager, VarnodeData};
use bk_pcode::FloatFormat;

use crate::context::{ContextDb, ContextSink, ContextSource, OffsetRange};
use crate::decode::{ByteSource, Decoder};
use crate::emit::PcodeEmit;
use crate::error::DecodeError;
use crate::language::Language;
use crate::pcode::LiftError;

/// Ranges of the unique space set aside for special temporaries (Ghidra
/// `Translate::UniqueLayout`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UniqueLayout {
    /// The temporary for boolean inversion.
    RuntimeBooleanInvert,
    /// The temporary holding a return value.
    RuntimeReturnLocation,
    /// The effective-address temporary of a truncated dynamic operand.
    RuntimeBitrangeEa,
    /// Temporaries of compiled p-code snippets.
    Inject,
    /// Temporaries of decompiler analysis (a fixed offset).
    Analysis,
}

impl UniqueLayout {
    /// The layout's offset relative to the unique base (absolute for
    /// [`UniqueLayout::Analysis`]).
    pub const fn offset(self) -> u32 {
        match self {
            Self::RuntimeBooleanInvert => 0,
            Self::RuntimeReturnLocation => 0x80,
            Self::RuntimeBitrangeEa => 0x100,
            Self::Inject => 0x200,
            Self::Analysis => 0x1000_0000,
        }
    }
}

impl Language {
    /// The start of a range of the unique space (Ghidra `getUniqueStart`):
    /// `unique_base() + layout` except for [`UniqueLayout::Analysis`].
    pub fn unique_start(&self, layout: UniqueLayout) -> u32 {
        match layout {
            UniqueLayout::Analysis => layout.offset(),
            _ => self.unique_base().wrapping_add(layout.offset()),
        }
    }
}

/// What a translator offers about the instructions of one program.
pub trait Translate {
    /// The instruction's length in bytes (Ghidra `instructionLength`).
    fn instruction_length(&mut self, addr: Address) -> Result<u32, DecodeError>;

    /// Appends the instruction's mnemonic and operand text and returns its
    /// length (Ghidra `printAssembly`).
    fn print_assembly(
        &mut self,
        addr: Address,
        mnemonic: &mut String,
        body: &mut String,
    ) -> Result<u32, DecodeError>;

    /// Lifts the instruction to p-code and returns its flow length (Ghidra
    /// `oneInstruction`).
    fn one_instruction(
        &mut self,
        addr: Address,
        emit: &mut dyn PcodeEmit,
    ) -> Result<u32, LiftError>;

    /// The language.
    fn language(&self) -> &Arc<Language>;

    /// The register called `name` (Ghidra `getRegister`).
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.language().registers().register(name)
    }

    /// The name of the register containing the bytes (Ghidra
    /// `getRegisterName`, with its lookup rule).
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.language()
            .registers()
            .register_name(space, offset, size)
    }

    /// The name of the register at exactly these bytes (Ghidra
    /// `getExactRegisterName`).
    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.language()
            .registers()
            .exact_register_name(space, offset, size)
    }

    /// Every register, ordered by space, offset and then larger sizes first
    /// (Ghidra `getAllRegisters`).
    fn all_registers(&self) -> Vec<(VarnodeData, String)> {
        self.language()
            .registers()
            .all()
            .map(|(vn, name)| (vn, name.to_owned()))
            .collect()
    }

    /// The user op names by index; gaps are `None` (Ghidra `getUserOpNames`).
    fn user_op_names(&self) -> Vec<Option<String>> {
        let lang = self.language();
        (0..lang.num_user_ops())
            .map(|i| lang.user_op_name(i).map(str::to_owned))
            .collect()
    }

    /// The address spaces.
    fn spaces(&self) -> &SpaceManager {
        self.language().spaces()
    }

    /// The floating-point format of `size` bytes (Ghidra `getFloatFormat`).
    fn float_format(&self, size: u32) -> Option<&FloatFormat> {
        self.language().float_formats().get(size)
    }

    /// Instruction alignment in bytes.
    fn alignment(&self) -> u32 {
        self.language().alignment()
    }

    /// Whether the language is big endian.
    fn is_big_endian(&self) -> bool {
        self.language().is_big_endian()
    }

    /// The first unique offset free for analysis.
    fn unique_base(&self) -> u32 {
        self.language().unique_base()
    }

    /// The start of a range of the unique space.
    fn unique_start(&self, layout: UniqueLayout) -> u32 {
        self.language().unique_start(layout)
    }

    /// Sets the default value of a context variable (Ghidra
    /// `setContextDefault`); `false` if there is no such variable.
    fn set_context_default(&mut self, name: &str, value: u32) -> bool;

    /// Whether lifting applies the instructions' context commits (Ghidra
    /// `allowContextSet`).
    fn allow_context_set(&mut self, allow: bool);
}

/// A language, a context database and a byte source together: the
/// counterpart of Ghidra's `Sleigh` object with its load image and context.
#[derive(Debug)]
pub struct Translator<B> {
    decoder: Decoder,
    context: ContextDb,
    bytes: B,
    allow_set: bool,
}

/// The context database with commits dropped (`allowContextSet(false)`).
struct Frozen<'a>(&'a ContextDb);

impl ContextSource for Frozen<'_> {
    fn context_at(&self, addr: Address, out: &mut [u32]) -> OffsetRange {
        self.0.context_at(addr, out)
    }
}

impl ContextSink for Frozen<'_> {
    fn set_change_point(&mut self, _: Address, _: usize, _: u32, _: u32) {}

    fn set_region(&mut self, _: Address, _: Option<Address>, _: usize, _: u32, _: u32) {}
}

impl<B: ByteSource> Translator<B> {
    /// A translator over `bytes` with the language's initial context.
    pub fn new(lang: Arc<Language>, bytes: B) -> Self {
        let context = lang.initial_context();
        Self {
            decoder: Decoder::new(lang),
            context,
            bytes,
            allow_set: true,
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
        Ok(self
            .decoder
            .decode(addr, &self.bytes, &self.context)?
            .length())
    }

    fn print_assembly(
        &mut self,
        addr: Address,
        mnemonic: &mut String,
        body: &mut String,
    ) -> Result<u32, DecodeError> {
        let length = self
            .decoder
            .decode(addr, &self.bytes, &self.context)?
            .length();
        self.decoder.mnemonic(mnemonic)?;
        self.decoder.body(body)?;
        Ok(length)
    }

    fn one_instruction(
        &mut self,
        addr: Address,
        emit: &mut dyn PcodeEmit,
    ) -> Result<u32, LiftError> {
        if self.allow_set {
            self.decoder
                .lift(addr, &self.bytes, &mut self.context, emit)
        } else {
            self.decoder
                .lift(addr, &self.bytes, &mut Frozen(&self.context), emit)
        }
    }

    fn language(&self) -> &Arc<Language> {
        self.decoder.language()
    }

    fn set_context_default(&mut self, name: &str, value: u32) -> bool {
        let Some(var) = self.decoder.language().context_variable(name).cloned() else {
            return false;
        };
        self.context.set_variable_default(&var, value);
        true
    }

    fn allow_context_set(&mut self, allow: bool) {
        self.allow_set = allow;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_layout_offsets() {
        assert_eq!(UniqueLayout::RuntimeBooleanInvert.offset(), 0);
        assert_eq!(UniqueLayout::RuntimeReturnLocation.offset(), 0x80);
        assert_eq!(UniqueLayout::RuntimeBitrangeEa.offset(), 0x100);
        assert_eq!(UniqueLayout::Inject.offset(), 0x200);
        assert_eq!(UniqueLayout::Analysis.offset(), 0x1000_0000);
    }
}
