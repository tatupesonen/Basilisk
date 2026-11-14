//! A factory entry: the part every type has, and the kind-specific part
//! (Ghidra `Datatype` and its subclasses in `type.hh`).

use std::collections::BTreeMap;

use bk_core::{BitRange, Provenance};
use bk_marshal::SpaceId;

use crate::error::{Result, TypeError};
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};

bitflags::bitflags! {
    /// Boolean properties of a type (Ghidra's `Datatype` flag enum, same
    /// bit values).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct TypeFlags: u32 {
        /// A basic type that is never redefined.
        const CORETYPE = 1;
        /// ASCII character data.
        const CHARTYPE = 2;
        /// An enumeration.
        const ENUMTYPE = 4;
        /// An enumeration whose values are all powers of two.
        const POWEROFTWO = 8;
        /// UTF-16 wide characters.
        const UTF16 = 16;
        /// UTF-32 wide characters.
        const UTF32 = 32;
        /// A structure treated as a string.
        const OPAQUE_STRING = 64;
        /// Instances of different sizes share a name.
        const VARIABLE_LENGTH = 128;
        /// Has a stripped form for formal declarations.
        const HAS_STRIPPED = 0x100;
        /// Is a relative pointer.
        const IS_PTRREL = 0x200;
        /// Not yet completely defined.
        const TYPE_INCOMPLETE = 0x400;
        /// Needs resolution before propagation.
        const NEEDS_RESOLUTION = 0x800;
        /// Three bits of forced display format.
        const FORCE_FORMAT = 0x7000;
        /// Pointer can be truncated and is big endian.
        const TRUNCATE_BIGENDIAN = 0x8000;
        /// A pointer to an array.
        const POINTER_TO_ARRAY = 0x10000;
        /// A warning is associated with the type.
        const WARNING_ISSUED = 0x20000;
        /// Contains bitfields.
        const HAS_BITFIELDS = 0x40000;
    }
}

/// The comparable flags of a function signature (Ghidra
/// `FuncProto::getComparableFlags`, same bit values).
pub mod sigflags {
    /// Takes variable arguments.
    pub const DOTDOTDOT: u32 = 1;
    /// An object-oriented constructor.
    pub const IS_CONSTRUCTOR: u32 = 0x200;
    /// An object-oriented destructor.
    pub const IS_DESTRUCTOR: u32 = 0x400;
    /// A method with a `this` pointer.
    pub const HAS_THISPTR: u32 = 0x800;
    /// All comparable flags.
    pub const COMPARABLE: u32 = DOTDOTDOT | IS_CONSTRUCTOR | IS_DESTRUCTOR | HAS_THISPTR;
}

/// A field of a structure or union (Ghidra `TypeField`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Field {
    /// Identifier within the containing type (by default the offset).
    pub ident: i32,
    /// Byte offset of the field (-1 while unassigned).
    pub offset: i32,
    /// Field name.
    pub name: Box<str>,
    /// Field type.
    pub ty: TypeId,
}

/// A bitfield of a structure (Ghidra `TypeBitField`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BitField {
    /// Bitfield name.
    pub name: Box<str>,
    /// Underlying integer type.
    pub ty: TypeId,
    /// Where the bits are.
    pub bits: BitRange,
    /// Identifier within the containing structure.
    pub ident: i32,
}

impl BitField {
    /// A bitfield known only by its width and position in a declaration;
    /// offsets are assigned by [`TypeFactory::assign_raw_fields`](crate::TypeFactory::assign_raw_fields)
    /// (Ghidra's `TypeBitField(id, numBits, …)`).
    pub fn declared(ident: i32, num_bits: i32, big_endian: bool, name: &str, ty: TypeId) -> Self {
        Self {
            name: name.into(),
            ty,
            bits: BitRange::new(0, num_bits.saturating_add(7) / 8, 0, num_bits, big_endian),
            ident,
        }
    }
}

/// What a function type knows about its prototype (Ghidra's `FuncProto`
/// reduced to what type comparison and printing read, spec 4.7).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct CodeSignature {
    /// Prototype model name; `None` means no model.
    pub model: Option<Box<str>>,
    /// Comparable flags ([`sigflags`]).
    pub flags: u32,
    /// The return type.
    pub output: Option<TypeId>,
    /// Parameter types and names.
    pub params: Vec<(TypeId, Box<str>)>,
    /// First variadic slot, or -1.
    pub first_vararg: i32,
}

/// The enumeration part of an enumeration type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct EnumValues {
    /// Map from value to name.
    pub values: BTreeMap<u64, Box<str>>,
}

/// The pointer part of a pointer type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PointerData {
    /// The pointed-to type.
    pub ptrto: TypeId,
    /// The space pointed into, if the pointer names one.
    pub space: Option<SpaceId>,
    /// Truncated form of the pointer.
    pub truncate: Option<TypeId>,
    /// Size of the addressable unit pointed to.
    pub wordsize: u32,
}

/// The kind-specific part of a type: one variant per class of `type.hh`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeKind {
    /// `TypeBase`: an atomic type.
    Base,
    /// `TypeChar`: a 1-byte character.
    Char,
    /// `TypeUnicode`: a wide character.
    Unicode,
    /// `TypeVoid`.
    Void,
    /// `TypePointer`.
    Pointer(PointerData),
    /// `TypePointerRel`: a pointer at a known offset into a container.
    PointerRel {
        /// The plain pointer part.
        ptr: PointerData,
        /// The container pointed into.
        parent: TypeId,
        /// Byte offset within the container.
        offset: i32,
        /// The plain pointer form, for an ephemeral relative pointer.
        stripped: Option<TypeId>,
    },
    /// `TypeArray`.
    Array {
        /// Element type.
        element: TypeId,
        /// Number of elements.
        count: i32,
    },
    /// `TypeEnum`.
    Enum(Box<EnumValues>),
    /// `TypePartialEnum`: a byte range of an enumeration.
    PartialEnum {
        /// The enumeration.
        parent: TypeId,
        /// Byte offset into it.
        offset: i32,
        /// Undefined type of the same size.
        stripped: TypeId,
    },
    /// `TypeStruct`.
    Struct {
        /// Fields sorted by offset.
        fields: Vec<Field>,
        /// Bitfields.
        bitfields: Vec<BitField>,
    },
    /// `TypeUnion`.
    Union {
        /// Fields.
        fields: Vec<Field>,
    },
    /// `TypePartialStruct`: a byte range of a structure or array.
    PartialStruct {
        /// The structure or array.
        container: TypeId,
        /// Byte offset into it.
        offset: i32,
        /// Undefined type of the same size.
        stripped: TypeId,
    },
    /// `TypePartialUnion`: a byte range of a union.
    PartialUnion {
        /// The union.
        container: TypeId,
        /// Byte offset into it.
        offset: i32,
        /// Undefined type of the same size.
        stripped: TypeId,
    },
    /// `TypeCode`: a function, optionally with a signature.
    Code(Option<Box<CodeSignature>>),
    /// `TypeSpacebase`: an address space viewed as a structure.
    Spacebase {
        /// The space.
        space: SpaceId,
        /// Id of the associated scope.
        scope: u64,
    },
}

/// One type in the factory (Ghidra `Datatype`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeEntry {
    pub(crate) id: u64,
    pub(crate) size: i32,
    pub(crate) flags: TypeFlags,
    pub(crate) metatype: Metatype,
    pub(crate) submeta: SubMetatype,
    pub(crate) typedef_imm: Option<TypeId>,
    pub(crate) alignment: i32,
    pub(crate) align_size: i32,
    pub(crate) name: Box<str>,
    pub(crate) display_name: Box<str>,
    pub(crate) provenance: Provenance,
    pub(crate) kind: TypeKind,
}

impl TypeEntry {
    /// A new anonymous entry (Ghidra `Datatype(s, align, m)`).
    pub(crate) fn new(size: i32, alignment: i32, metatype: Metatype, kind: TypeKind) -> Self {
        Self {
            id: 0,
            size,
            flags: TypeFlags::empty(),
            metatype,
            submeta: metatype.base_sub(),
            typedef_imm: None,
            alignment,
            align_size: size,
            name: "".into(),
            display_name: "".into(),
            provenance: Provenance::Default,
            kind,
        }
    }

    /// Sets name, display name and id together.
    pub(crate) fn set_name(&mut self, name: &str, id: u64) {
        self.name = name.into();
        self.display_name = name.into();
        self.id = id;
    }

    /// Ghidra's 64-bit type id (0 for an anonymous type).
    pub const fn id(&self) -> u64 {
        self.id
    }
    /// The id without the variable-length size adjustment (Ghidra
    /// `getUnsizedId`).
    pub const fn unsized_id(&self) -> u64 {
        if self.flags.contains(TypeFlags::VARIABLE_LENGTH) {
            hash_size(self.id, self.size)
        } else {
            self.id
        }
    }
    /// Size in bytes.
    pub const fn size(&self) -> i32 {
        self.size
    }
    /// Flags.
    pub const fn flags(&self) -> TypeFlags {
        self.flags
    }
    /// The metatype.
    pub const fn metatype(&self) -> Metatype {
        self.metatype
    }
    /// The sub-metatype.
    pub const fn submeta(&self) -> SubMetatype {
        self.submeta
    }
    /// The type this one is a typedef of.
    pub const fn typedef_of(&self) -> Option<TypeId> {
        self.typedef_imm
    }
    /// Expected alignment in bytes.
    pub const fn alignment(&self) -> i32 {
        self.alignment
    }
    /// Size rounded up to the alignment.
    pub const fn align_size(&self) -> i32 {
        self.align_size
    }
    /// The name (empty for an anonymous type).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The name to display.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    /// Who supplied the type (ADR-025 3f). Takes no part in identity.
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }
    /// The kind-specific part.
    pub const fn kind(&self) -> &TypeKind {
        &self.kind
    }

    /// Ghidra `isCoreType`.
    pub const fn is_core(&self) -> bool {
        self.flags.contains(TypeFlags::CORETYPE)
    }
    /// Ghidra `isCharPrint`.
    pub const fn is_char_print(&self) -> bool {
        self.flags.intersects(
            TypeFlags::CHARTYPE
                .union(TypeFlags::UTF16)
                .union(TypeFlags::UTF32)
                .union(TypeFlags::OPAQUE_STRING),
        )
    }
    /// Ghidra `isEnumType`.
    pub const fn is_enum(&self) -> bool {
        self.flags.contains(TypeFlags::ENUMTYPE)
    }
    /// Ghidra `isASCII`.
    pub const fn is_ascii(&self) -> bool {
        self.flags.contains(TypeFlags::CHARTYPE)
    }
    /// Ghidra `isVariableLength`.
    pub const fn is_variable_length(&self) -> bool {
        self.flags.contains(TypeFlags::VARIABLE_LENGTH)
    }
    /// Ghidra `isPointerRel`.
    pub const fn is_pointer_rel(&self) -> bool {
        self.flags.contains(TypeFlags::IS_PTRREL)
    }
    /// Ghidra `isFormalPointerRel`.
    pub const fn is_formal_pointer_rel(&self) -> bool {
        self.flags.contains(TypeFlags::IS_PTRREL) && !self.flags.contains(TypeFlags::HAS_STRIPPED)
    }
    /// Ghidra `hasStripped`.
    pub const fn has_stripped(&self) -> bool {
        self.flags.contains(TypeFlags::HAS_STRIPPED)
    }
    /// Ghidra `isIncomplete`.
    pub const fn is_incomplete(&self) -> bool {
        self.flags.contains(TypeFlags::TYPE_INCOMPLETE)
    }
    /// Ghidra `needsResolution`.
    pub const fn needs_resolution(&self) -> bool {
        self.flags.contains(TypeFlags::NEEDS_RESOLUTION)
    }
    /// Ghidra `hasWarning`.
    pub const fn has_warning(&self) -> bool {
        self.flags.contains(TypeFlags::WARNING_ISSUED)
    }
    /// Ghidra `hasBitfields`.
    pub const fn has_bitfields(&self) -> bool {
        self.flags.contains(TypeFlags::HAS_BITFIELDS)
    }
    /// Ghidra `isPointerToArray`.
    pub const fn is_pointer_to_array(&self) -> bool {
        self.flags.contains(TypeFlags::POINTER_TO_ARRAY)
    }
    /// Ghidra `isOpaqueString`.
    pub const fn is_opaque_string(&self) -> bool {
        self.flags.contains(TypeFlags::OPAQUE_STRING)
    }
    /// Ghidra `inheritForPointer`.
    pub const fn inherit_for_pointer(&self) -> TypeFlags {
        self.flags
            .intersection(TypeFlags::CORETYPE.union(TypeFlags::WARNING_ISSUED))
    }
    /// Ghidra `inheritForPartial`.
    pub const fn inherit_for_partial(&self) -> TypeFlags {
        self.flags.intersection(TypeFlags::WARNING_ISSUED)
    }
    /// The forced display format, 0 for none (Ghidra `getDisplayFormat`).
    pub const fn display_format(&self) -> u32 {
        (self.flags.bits() & TypeFlags::FORCE_FORMAT.bits()) >> 12
    }
    /// Sets the display format (Ghidra `setDisplayFormat`).
    pub(crate) fn set_display_format(&mut self, format: u32) {
        let bits = (self.flags.bits() & !TypeFlags::FORCE_FORMAT.bits())
            | ((format << 12) & TypeFlags::FORCE_FORMAT.bits());
        self.flags = TypeFlags::from_bits_retain(bits);
    }
    /// Ghidra `isPieceStructured`: metatype at or below `Array`.
    pub fn is_piece_structured(&self) -> bool {
        self.metatype <= Metatype::Array
    }

    /// The pointer part, for pointers and relative pointers.
    pub const fn pointer(&self) -> Option<&PointerData> {
        match &self.kind {
            TypeKind::Pointer(p) | TypeKind::PointerRel { ptr: p, .. } => Some(p),
            _ => None,
        }
    }
    /// The fields of a structure or union.
    pub fn fields(&self) -> &[Field] {
        match &self.kind {
            TypeKind::Struct { fields, .. } | TypeKind::Union { fields } => fields,
            _ => &[],
        }
    }
    /// The bitfields of a structure.
    pub fn bitfields(&self) -> &[BitField] {
        match &self.kind {
            TypeKind::Struct { bitfields, .. } => bitfields,
            _ => &[],
        }
    }
    /// The value map of an enumeration.
    pub fn enum_values(&self) -> Option<&BTreeMap<u64, Box<str>>> {
        match &self.kind {
            TypeKind::Enum(e) => Some(&e.values),
            _ => None,
        }
    }
    /// The signature of a function type.
    pub fn signature(&self) -> Option<&CodeSignature> {
        match &self.kind {
            TypeKind::Code(sig) => sig.as_deref(),
            _ => None,
        }
    }
    /// The stripped form (Ghidra `getStripped`).
    pub const fn stripped(&self) -> Option<TypeId> {
        match &self.kind {
            TypeKind::PointerRel { stripped, .. } => *stripped,
            TypeKind::PartialEnum { stripped, .. }
            | TypeKind::PartialStruct { stripped, .. }
            | TypeKind::PartialUnion { stripped, .. } => Some(*stripped),
            _ => None,
        }
    }
    /// The whole type a partial type is part of (Ghidra `getPartialBase`).
    pub const fn partial_base(&self) -> Option<TypeId> {
        match &self.kind {
            TypeKind::PartialEnum { parent: t, .. }
            | TypeKind::PartialStruct { container: t, .. }
            | TypeKind::PartialUnion { container: t, .. } => Some(*t),
            _ => None,
        }
    }
    /// The number of component types (Ghidra `numDepend`); for a partial
    /// union this is answered by the factory, which knows the container.
    pub fn num_depend_local(&self) -> usize {
        match &self.kind {
            TypeKind::Pointer(_) | TypeKind::PointerRel { .. } | TypeKind::Array { .. } => 1,
            TypeKind::Struct { fields, .. } | TypeKind::Union { fields } => fields.len(),
            _ => 0,
        }
    }
}

/// Produces a type id from a name (Ghidra `Datatype::hashName`).
///
/// Bytes are added sign-extended, as on x86-64 where `char` is signed
/// (ADR-021); the result differs from AArch64 Linux for bytes 0x80 and up.
pub fn hash_name(name: &str) -> u64 {
    hash_name_bytes(name.as_bytes())
}

/// [`hash_name`] over raw bytes (names read from a file need not be UTF-8).
pub fn hash_name_bytes(name: &[u8]) -> u64 {
    let mut res: u64 = 123;
    for &byte in name {
        res = res.rotate_left(8);
        res = res.wrapping_add(i64::from(byte as i8) as u64);
        if res & 1 == 0 {
            res ^= 0xfeab_feab;
        }
    }
    res | 0xC000_0000_0000_0000
}

/// Reversibly folds a size into an id (Ghidra `Datatype::hashSize`).
pub const fn hash_size(id: u64, size: i32) -> u64 {
    id ^ (size as i64 as u64).wrapping_mul(0x9825_1033_aecb_abaf)
}

/// Rounds a size up to a multiple of an alignment (Ghidra `calcAlignSize`).
/// A non-positive alignment leaves the size unchanged.
pub const fn calc_align_size(size: i32, align: i32) -> i32 {
    if align <= 0 {
        return size;
    }
    let rem = size % align;
    if rem != 0 {
        size.saturating_add(align - rem)
    } else {
        size
    }
}

/// The display format number for a name (Ghidra `encodeIntegerFormat`).
pub fn encode_integer_format(name: &str) -> Result<u32> {
    Ok(match name {
        "hex" => 1,
        "dec" => 2,
        "oct" => 3,
        "bin" => 4,
        "char" => 5,
        _ => {
            return Err(TypeError::new(format!(
                "Unrecognized integer format: {name}"
            )));
        }
    })
}

/// The name of a display format number (Ghidra `decodeIntegerFormat`).
pub fn decode_integer_format(value: u32) -> Result<&'static str> {
    Ok(match value {
        1 => "hex",
        2 => "dec",
        3 => "oct",
        4 => "bin",
        5 => "char",
        _ => return Err(TypeError::new("Unrecognized integer format encoding")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_name_known_values() {
        assert_eq!(hash_name(""), 0x7b | 0xC000_0000_0000_0000);
        // Sign extension of bytes >= 0x80 changes the result.
        let ascii = hash_name("a");
        assert_ne!(hash_name("\u{e9}"), ascii);
        assert_eq!(hash_size(hash_size(77, 12), 12), 77);
    }

    #[test]
    fn align_and_format() {
        assert_eq!(calc_align_size(5, 4), 8);
        assert_eq!(calc_align_size(8, 4), 8);
        assert_eq!(calc_align_size(3, 0), 3);
        for v in 1..=5 {
            assert_eq!(
                encode_integer_format(decode_integer_format(v).unwrap()).unwrap(),
                v
            );
        }
        assert!(encode_integer_format("x").is_err());
        assert!(decode_integer_format(6).is_err());
    }

    #[test]
    fn entry_size_is_bounded() {
        assert!(size_of::<TypeEntry>() <= 128, "{}", size_of::<TypeEntry>());
    }
}
