//! The typed content of a `.pspec` file.

use std::num::ParseIntError;

use super::{
    address::AddressRange,
    context::{ContextBlock, ContextKind},
    memory::MemoryBlock,
    registers::RegisterData,
    segment::{JumpAssist, SegmentOp},
    symbols::DefaultSymbol,
};

/// The property keys Ghidra itself looks up (`GhidraLanguagePropertyKeys`).
/// Files may carry any other key; all are kept.
pub mod property_keys {
    /// The longest instruction of the language, in bytes.
    pub const MAXIMUM_INSTRUCTION_LENGTH: &str = "maximumInstructionLength";
    /// A class that replaces the standard disassembler.
    pub const CUSTOM_DISASSEMBLER_CLASS: &str = "customDisassemblerClass";
    /// Whether references into the middle of the first instruction of a
    /// function are allowed (default false).
    pub const ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS: &str =
        "allowOffcutReferencesToFunctionStarts";
    /// Whether the operand reference analyzer recovers switch tables.
    pub const USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES: &str =
        "useOperandReferenceAnalyzerSwitchTables";
    /// Whether the processor is in the TMS320 family.
    pub const IS_TMS320_FAMILY: &str = "isTMS320Family";
    /// A class that helps display parallel instructions.
    pub const PARALLEL_INSTRUCTION_HELPER_CLASS: &str = "parallelInstructionHelperClass";
    /// Whether addresses never appear directly in code, so scalar operands
    /// are not turned into references.
    pub const ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE: &str = "addressesDoNotAppearDirectlyInCode";
    /// Whether the newer function stack analysis is used.
    pub const USE_NEW_FUNCTION_STACK_ANALYSIS: &str = "useNewFunctionStackAnalysis";
    /// A class that adjusts emulator state around instructions.
    pub const EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS: &str =
        "emulateInstructionStateModifierClass";
    /// User-op libraries for the p-code emulator.
    pub const USEROP_LIBS: &str = "useropLibs";
    /// A class that supplies p-code injection payloads.
    pub const PCODE_INJECT_LIBRARY_CLASS: &str = "pcodeInjectLibraryClass";
    /// Whether shared-return analysis is on by default.
    pub const ENABLE_SHARED_RETURN_ANALYSIS: &str = "enableSharedReturnAnalysis";
    /// Whether shared-return analysis assumes contiguous functions.
    pub const ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY: &str = "enableContiguousFunctionsOnly";
    /// Whether non-returning function analysis is on by default.
    pub const ENABLE_NO_RETURN_ANALYSIS: &str = "enableNoReturnAnalysis";
    /// Whether stored context is reset when a program's language is
    /// upgraded.
    pub const RESET_CONTEXT_ON_UPGRADE: &str = "resetContextOnUpgrade";
    /// The lowest image base for data, used when laying out a program.
    pub const MINIMUM_DATA_IMAGE_BASE: &str = "minimumDataImageBase";
}

/// One `<property>`: a key and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
}

/// `<data_space>`: the address space data goes to by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSpace {
    /// The address space's name.
    pub space: String,
    /// The pointer word size in bytes overriding the space's addressable
    /// unit size; between 1 and 31.
    pub ptr_wordsize: Option<u32>,
}

/// `<segmented_address>`: the space whose addresses are segment:offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentedAddress {
    /// The address space's name.
    pub space: String,
    /// The segmentation type (`real` or `protected` for x86); Ghidra
    /// treats an absent type as the empty string.
    pub segment_type: Option<String>,
}

/// A piece of memory named by a register or by a range (the schema's
/// `memory_tags_type`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryTag {
    /// The storage of the named register.
    Register(String),
    /// A range of addresses.
    Range(AddressRange),
}

/// A storage location named by a register or by a varnode (the schema's
/// `varnode_tags_type`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarnodeTag {
    /// The named register.
    Register(String),
    /// A varnode.
    Varnode {
        /// The address space's name.
        space: String,
        /// The offset in the space.
        offset: u64,
        /// The size in bytes.
        size: u64,
    },
}

/// `<volatile>`: memory whose reads and writes have side effects, and the
/// names the decompiler gives those accesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volatile {
    /// The user-op name shown for a volatile read.
    pub inputop: String,
    /// The user-op name shown for a volatile write.
    pub outputop: String,
    /// The display format; `functional` forces function-call syntax.
    pub format: Option<String>,
    /// The volatile locations. Ghidra's Java side rejects a register here
    /// ("no support for volatile registers yet"); the decompiler accepts
    /// one.
    pub locations: Vec<MemoryTag>,
}

impl Volatile {
    /// Whether volatile accesses are displayed as function calls.
    #[must_use]
    pub fn is_functional(&self) -> bool {
        self.format.as_deref() == Some("functional")
    }
}

/// The kind of a top-level element of a `.pspec`.
///
/// [`ProcessorSpec::sections`] lists these in file order. The order
/// matters to a consumer that resolves register names: a rename in
/// `<register_data>` applies to everything after it and nothing before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Section {
    /// `<properties>`.
    Properties,
    /// `<programcounter>`.
    ProgramCounter,
    /// `<data_space>`.
    DataSpace,
    /// `<inferptrbounds>`.
    InferPtrBounds,
    /// `<segmented_address>`.
    SegmentedAddress,
    /// `<segmentop>`; the n-th occurrence is the n-th of
    /// [`ProcessorSpec::segment_ops`].
    SegmentOp,
    /// `<context_data>`.
    ContextData,
    /// `<volatile>`.
    Volatile,
    /// `<incidentalcopy>`.
    IncidentalCopy,
    /// `<jumpassist>`; the n-th occurrence is the n-th of
    /// [`ProcessorSpec::jump_assists`].
    JumpAssist,
    /// `<register_data>`.
    RegisterData,
    /// `<default_symbols>`.
    DefaultSymbols,
    /// `<default_memory_blocks>`.
    DefaultMemoryBlocks,
}

/// The content of a `.pspec` file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessorSpec {
    /// The properties in file order, one entry per key (a repeated key
    /// keeps its first position and takes the last value).
    pub properties: Vec<Property>,
    /// The name of the program counter register.
    pub program_counter: Option<String>,
    /// The default data space.
    pub data_space: Option<DataSpace>,
    /// Address ranges in which the decompiler may take a constant for a
    /// pointer.
    pub infer_ptr_bounds: Vec<AddressRange>,
    /// The segmented address space.
    pub segmented_address: Option<SegmentedAddress>,
    /// P-code for segmented address calculation, one per space.
    pub segment_ops: Vec<SegmentOp>,
    /// Default context and tracked register values, in file order.
    pub context_data: Vec<ContextBlock>,
    /// Volatile memory.
    pub volatile: Option<Volatile>,
    /// Locations that receive incidental copies the decompiler may ignore.
    pub incidental_copy: Vec<VarnodeTag>,
    /// P-code that describes jump tables for a user-op.
    pub jump_assists: Vec<JumpAssist>,
    /// Register presentation and properties, in file order.
    pub registers: Vec<RegisterData>,
    /// Default labels, in file order.
    pub default_symbols: Vec<DefaultSymbol>,
    /// Default memory blocks, in file order.
    pub default_memory_blocks: Vec<MemoryBlock>,
    /// The kinds of the top-level elements, in file order.
    pub sections: Vec<Section>,
}

impl ProcessorSpec {
    /// The value of the property `key`.
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    /// Whether the property `key` is present.
    #[must_use]
    pub fn has_property(&self, key: &str) -> bool {
        self.property(key).is_some()
    }

    /// The property `key` as a boolean — true exactly when the value is
    /// `true` in any letter case — or `default` when it is absent.
    #[must_use]
    pub fn property_as_bool(&self, key: &str, default: bool) -> bool {
        self.property(key)
            .map_or(default, |v| v.eq_ignore_ascii_case("true"))
    }

    /// The property `key` as a decimal integer, or `default` when it is
    /// absent. A present value that is not an integer is an error, as it
    /// is in Ghidra.
    pub fn property_as_int(&self, key: &str, default: i32) -> Result<i32, ParseIntError> {
        self.property(key).map_or(Ok(default), str::parse)
    }

    /// The `<context_set>` blocks: default values of SLEIGH context fields.
    pub fn context_sets(&self) -> impl Iterator<Item = &ContextBlock> {
        self.context_data
            .iter()
            .filter(|b| b.kind == ContextKind::Context)
    }

    /// The `<tracked_set>` blocks: registers with assumed values.
    pub fn tracked_sets(&self) -> impl Iterator<Item = &ContextBlock> {
        self.context_data
            .iter()
            .filter(|b| b.kind == ContextKind::Tracked)
    }

    /// The `<register_data>` entry for the register called `name`, by its
    /// original or its renamed name.
    #[must_use]
    pub fn register(&self, name: &str) -> Option<&RegisterData> {
        self.registers
            .iter()
            .find(|r| r.name == name || r.rename.as_deref() == Some(name))
    }
}
