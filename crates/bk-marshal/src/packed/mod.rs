//! Reading and writing the packed binary form.
//!
//! Ghidra: `PackedFormat`, `PackedDecode` and `PackedEncode` in `marshal.hh`
//! and `marshal.cc`, with `PatchPackedEncode` from the Java twin.
//!
//! Every record starts with a header byte whose top two bits say what it is:
//! `01` an element start, `10` an element end, `11` an attribute. The low five
//! bits hold the id; if bit `0x20` is set, the next byte holds seven more low
//! bits. An attribute's header is followed by a type byte, `ttttllll`: a type
//! code and a length code. Integers follow in `llll` bytes of seven bits each,
//! most significant first, every byte with its top bit set; a string is a
//! length integer followed by its bytes.

mod decode;
mod encode;

pub use decode::PackedDecoder;
pub use encode::PackedEncoder;

/// The constants of the packed protocol (Ghidra `PackedFormat`).
pub mod format {
    /// Bits of a header byte encoding the record type.
    pub const HEADER_MASK: u8 = 0xc0;
    /// Header of an element start record.
    pub const ELEMENT_START: u8 = 0x40;
    /// Header of an element end record.
    pub const ELEMENT_END: u8 = 0x80;
    /// Header of an attribute record.
    pub const ATTRIBUTE: u8 = 0xc0;
    /// Header bit saying the id continues in the next byte.
    pub const HEADEREXTEND_MASK: u8 = 0x20;
    /// Bits of a header byte holding (part of) the id.
    pub const ELEMENTID_MASK: u8 = 0x1f;
    /// Bits of raw data in a follow-on byte.
    pub const RAWDATA_MASK: u8 = 0x7f;
    /// Number of data bits in a follow-on byte.
    pub const RAWDATA_BITSPERBYTE: u32 = 7;
    /// The bit that is always set in a follow-on byte.
    pub const RAWDATA_MARKER: u8 = 0x80;
    /// Position of the type code in a type byte.
    pub const TYPECODE_SHIFT: u32 = 4;
    /// Bits of a type byte holding the length code.
    pub const LENGTHCODE_MASK: u8 = 0x0f;
    /// Type code of a boolean (length code 0 is false, 1 is true).
    pub const TYPECODE_BOOLEAN: u8 = 1;
    /// Type code of a signed integer that is not negative.
    pub const TYPECODE_SIGNEDINT_POSITIVE: u8 = 2;
    /// Type code of a negative signed integer, stored negated.
    pub const TYPECODE_SIGNEDINT_NEGATIVE: u8 = 3;
    /// Type code of an unsigned integer.
    pub const TYPECODE_UNSIGNEDINT: u8 = 4;
    /// Type code of an address space, stored as its index.
    pub const TYPECODE_ADDRESSSPACE: u8 = 5;
    /// Type code of a special address space, named by the length code.
    pub const TYPECODE_SPECIALSPACE: u8 = 6;
    /// Type code of a string.
    pub const TYPECODE_STRING: u8 = 7;
    /// Special space code of the stack space.
    pub const SPECIALSPACE_STACK: u8 = 0;
    /// Special space code of the join space.
    pub const SPECIALSPACE_JOIN: u8 = 1;
    /// Special space code of the fspec space.
    pub const SPECIALSPACE_FSPEC: u8 = 2;
    /// Special space code of the iop space.
    pub const SPECIALSPACE_IOP: u8 = 3;
    /// Special space code of a spacebase space other than the stack.
    pub const SPECIALSPACE_SPACEBASE: u8 = 4;
}
