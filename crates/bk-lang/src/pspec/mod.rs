//! Processor specification files (`.pspec`): what a language adds to its
//! SLEIGH spec — properties, the program counter, context defaults,
//! register groups and aliases, default symbols and memory blocks, volatile
//! memory, segment and jump-table p-code.
//!
//! Ghidra reads a `.pspec` twice: `SleighLanguage.read` takes what the
//! program model needs and `Architecture::parseProcessorConfig` what the
//! decompiler needs. [`ProcessorSpec`] is one complete model for both.
//! Registers and address spaces are named, not resolved: the file is read
//! before any SLEIGH language is loaded.

mod address;
mod context;
mod memory;
mod model;
mod read;
mod registers;
mod segment;
mod symbols;

pub use address::{AddressOffset, AddressRange, AddressResolver, AddressSpec};
pub use context::{ContextBlock, ContextKind, ContextValue};
pub use memory::{ByteMappingRatio, MemoryBlock, MemoryBlockKind};
pub use model::{
    DataSpace, MemoryTag, ProcessorSpec, Property, Section, SegmentedAddress, VarnodeTag, Volatile,
    property_keys,
};
pub use read::{parse, read_file};
pub use registers::RegisterData;
pub use segment::{InjectParameter, JumpAssist, JumpAssistPcode, PcodeInject, SegmentOp};
pub use symbols::{DefaultSymbol, SymbolAddress, SymbolType};
