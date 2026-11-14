//! How prototype models see data types: through [`ParamTypes`], a small
//! query trait, and opaque [`TypeHandle`]s (spec 4.5, ADR-026).
//!
//! Ghidra's `modelrules.cc` and the IR-free part of `fspec.cc` ask a
//! `Datatype` for its size, aligned size, alignment, metatype, array element
//! and count, and structure or union fields, and ask the `TypeFactory` for
//! three kinds of new type: a pointer, `void` and an unknown base of a size.
//! `FuncProto`'s XML additionally writes type references and reads types.
//! This crate depends on no type model; `bk-decomp-types` (and later the
//! program database's type manager) implement the trait.

use bk_marshal::{Decoder, Encoder};
use serde::{Deserialize, Serialize};

/// An opaque reference to a data type in the implementor's type model
/// (for `bk-decomp-types`, the raw value of its `TypeId`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypeHandle(pub u32);

/// The core meta-type of a data type (Ghidra `type_metatype`), with
/// Ghidra's numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Metatype {
    /// Part of a union.
    PartialUnion = 0,
    /// Part of a structure or array.
    PartialStruct = 1,
    /// Part of an enumeration.
    PartialEnum = 2,
    /// A union.
    Union = 3,
    /// A structure.
    Struct = 4,
    /// Signed enumeration.
    EnumInt = 5,
    /// Unsigned enumeration.
    EnumUint = 6,
    /// An array.
    Array = 7,
    /// A relative pointer.
    PtrRel = 8,
    /// A pointer.
    Ptr = 9,
    /// Floating point.
    Float = 10,
    /// Executable code.
    Code = 11,
    /// Boolean.
    Bool = 12,
    /// Unsigned integer.
    Uint = 13,
    /// Signed integer.
    Int = 14,
    /// Unknown bytes.
    Unknown = 15,
    /// An address space viewed as a structure.
    Spacebase = 16,
    /// The absence of a type.
    Void = 17,
}

impl Metatype {
    /// The metatype with the given name (Ghidra `string2metatype`); `None`
    /// where Ghidra throws "Unknown metatype".
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ptr" => Self::Ptr,
            "ptrrel" => Self::PtrRel,
            "partunion" => Self::PartialUnion,
            "partstruct" => Self::PartialStruct,
            "array" => Self::Array,
            "enum_int" => Self::EnumInt,
            "enum_uint" => Self::EnumUint,
            "struct" => Self::Struct,
            "spacebase" => Self::Spacebase,
            "unknown" => Self::Unknown,
            "uint" => Self::Uint,
            "union" => Self::Union,
            "int" => Self::Int,
            "float" => Self::Float,
            "bool" => Self::Bool,
            "code" => Self::Code,
            "void" => Self::Void,
            _ => return None,
        })
    }

    /// The name Ghidra writes (`metatype2string`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Ptr => "ptr",
            Self::PtrRel => "ptrrel",
            Self::Array => "array",
            Self::PartialEnum => "partenum",
            Self::PartialStruct => "partstruct",
            Self::PartialUnion => "partunion",
            Self::EnumInt => "enum_int",
            Self::EnumUint => "enum_uint",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Spacebase => "spacebase",
            Self::Unknown => "unknown",
            Self::Uint => "uint",
            Self::Int => "int",
            Self::Bool => "bool",
            Self::Code => "code",
            Self::Float => "float",
        }
    }

    /// The storage class of a metatype (Ghidra `metatype2typeclass`).
    pub const fn type_class(self) -> TypeClass {
        match self {
            Self::Float => TypeClass::Float,
            Self::Ptr => TypeClass::Ptr,
            _ => TypeClass::General,
        }
    }
}

/// Data-type classes for assigning storage (Ghidra `type_class`), with
/// Ghidra's numbers; the order is used by the assignment code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TypeClass {
    /// General purpose.
    General = 0,
    /// Floating point.
    Float = 1,
    /// Pointers.
    Ptr = 2,
    /// Hidden return values.
    HiddenRet = 3,
    /// Vectors.
    Vector = 4,
    /// Architecture specific class 1.
    Class1 = 100,
    /// Architecture specific class 2.
    Class2 = 101,
    /// Architecture specific class 3.
    Class3 = 102,
    /// Architecture specific class 4.
    Class4 = 103,
}

impl TypeClass {
    /// The class named in a `.cspec` (Ghidra `string2typeclass`); `None`
    /// where Ghidra throws "Unknown data-type class".
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "class1" => Self::Class1,
            "class2" => Self::Class2,
            "class3" => Self::Class3,
            "class4" => Self::Class4,
            "general" | "unknown" => Self::General,
            "hiddenret" => Self::HiddenRet,
            "float" => Self::Float,
            "ptr" | "pointer" => Self::Ptr,
            "vector" => Self::Vector,
            _ => return None,
        })
    }

    /// The name Ghidra writes (`typeclass2string`'s spelling).
    pub const fn name(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Float => "float",
            Self::Ptr => "ptr",
            Self::HiddenRet => "hiddenret",
            Self::Vector => "vector",
            Self::Class1 => "class1",
            Self::Class2 => "class2",
            Self::Class3 => "class3",
            Self::Class4 => "class4",
        }
    }
}

/// One field of a structure or union: its byte offset and type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeField {
    /// Offset in bytes from the start of the containing type.
    pub offset: i32,
    /// The field's type.
    pub ty: TypeHandle,
}

/// A failure reported by a [`ParamTypes`] implementation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TypeQueryError(pub String);

/// The questions prototype models ask of a type model, and the three kinds
/// of type they create (spec 4.5).
///
/// Queries on a handle the model does not know may answer anything but
/// must not panic. Object safe, so callers can pass `&mut dyn ParamTypes`.
pub trait ParamTypes {
    /// Size in bytes (Ghidra `Datatype::getSize`).
    fn size(&self, ty: TypeHandle) -> i32;
    /// Size rounded up to the alignment (Ghidra `getAlignSize`).
    fn align_size(&self, ty: TypeHandle) -> i32;
    /// Alignment in bytes, at least 1 (Ghidra `getAlignment`).
    fn alignment(&self, ty: TypeHandle) -> i32;
    /// The metatype (Ghidra `getMetatype`).
    fn metatype(&self, ty: TypeHandle) -> Metatype;
    /// The name, for messages and printing (Ghidra `getName`).
    fn name(&self, ty: TypeHandle) -> String;
    /// For an array: its element type and number of elements (Ghidra
    /// `TypeArray::getBase`, `numElements`).
    fn array_element(&self, ty: TypeHandle) -> Option<(TypeHandle, i32)>;
    /// Number of fields of a structure or union (Ghidra `numDepend`); 0 for
    /// other types.
    fn field_count(&self, ty: TypeHandle) -> usize;
    /// The `index`-th field of a structure or union, in offset order
    /// (Ghidra `getField`, `beginField`).
    fn field(&self, ty: TypeHandle, index: usize) -> Option<TypeField>;
    /// For a pointer, the type pointed to (Ghidra `TypePointer::getPtrTo`).
    fn pointed_to(&self, ty: TypeHandle) -> Option<TypeHandle>;
    /// A pointer of `size` bytes to `to`, in a space of the given word size
    /// (Ghidra `TypeFactory::getTypePointer(size, pt, ws)`).
    fn pointer_to(&mut self, to: TypeHandle, size: i32, word_size: u32) -> TypeHandle;
    /// The `void` type (Ghidra `getTypeVoid`).
    fn void(&mut self) -> TypeHandle;
    /// An unknown base type of `size` bytes (Ghidra
    /// `getBase(size, TYPE_UNKNOWN)`).
    fn unknown(&mut self, size: i32) -> TypeHandle;
    /// Writes a reference to the type (Ghidra `Datatype::encodeRef`).
    fn encode_ref(&self, encoder: &mut dyn Encoder, ty: TypeHandle) -> Result<(), TypeQueryError>;
    /// Reads a type from the next element (Ghidra `TypeFactory::decodeType`).
    fn decode_type(&mut self, decoder: &mut dyn Decoder<'_>) -> Result<TypeHandle, TypeQueryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metatype_names_round_trip_except_partenum() {
        for raw in 0u8..=17 {
            let all = [
                Metatype::PartialUnion,
                Metatype::PartialStruct,
                Metatype::PartialEnum,
                Metatype::Union,
                Metatype::Struct,
                Metatype::EnumInt,
                Metatype::EnumUint,
                Metatype::Array,
                Metatype::PtrRel,
                Metatype::Ptr,
                Metatype::Float,
                Metatype::Code,
                Metatype::Bool,
                Metatype::Uint,
                Metatype::Int,
                Metatype::Unknown,
                Metatype::Spacebase,
                Metatype::Void,
            ];
            let meta = all[usize::from(raw)];
            assert_eq!(meta as u8, raw);
            let back = Metatype::from_name(meta.name());
            if meta == Metatype::PartialEnum {
                assert_eq!(back, None);
            } else {
                assert_eq!(back, Some(meta));
            }
        }
    }

    #[test]
    fn type_classes_follow_ghidra() {
        assert_eq!(TypeClass::from_name("pointer"), Some(TypeClass::Ptr));
        assert_eq!(TypeClass::from_name("unknown"), Some(TypeClass::General));
        assert_eq!(TypeClass::from_name("x"), None);
        assert!(TypeClass::Float < TypeClass::Ptr && TypeClass::Vector < TypeClass::Class1);
        assert_eq!(Metatype::Float.type_class(), TypeClass::Float);
        assert_eq!(Metatype::Struct.type_class(), TypeClass::General);
        for c in [TypeClass::General, TypeClass::Float, TypeClass::Class4] {
            assert_eq!(TypeClass::from_name(c.name()), Some(c));
        }
    }
}
