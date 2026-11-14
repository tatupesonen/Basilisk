//! Metatypes, sub-metatypes and type classes (Ghidra `metatype.hh`,
//! `metatype.cc`, and the `sub_metatype`/`type_class` enums of `type.hh`).
//!
//! The numeric values are part of the behaviour: Ghidra compares metatypes
//! and sub-metatypes numerically and indexes tables with them.

use crate::error::TypeError;

/// The core meta-type of a data-type (Ghidra `type_metatype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Metatype {
    /// Part of a union.
    PartialUnion = 0,
    /// Part of a structure or array.
    PartialStruct = 1,
    /// Part of an enumeration (encoding only; held internally as `Uint`).
    PartialEnum = 2,
    /// A union.
    Union = 3,
    /// A structure.
    Struct = 4,
    /// Signed enumeration (encoding only; held internally as `Int`).
    EnumInt = 5,
    /// Unsigned enumeration (encoding only; held internally as `Uint`).
    EnumUint = 6,
    /// An array.
    Array = 7,
    /// A relative pointer (encoding only; held internally as `Ptr`).
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
    /// A space treated as a structure.
    Spacebase = 16,
    /// The absence of a type.
    Void = 17,
}

impl Metatype {
    /// Every metatype in numeric order.
    pub const ALL: [Self; 18] = [
        Self::PartialUnion,
        Self::PartialStruct,
        Self::PartialEnum,
        Self::Union,
        Self::Struct,
        Self::EnumInt,
        Self::EnumUint,
        Self::Array,
        Self::PtrRel,
        Self::Ptr,
        Self::Float,
        Self::Code,
        Self::Bool,
        Self::Uint,
        Self::Int,
        Self::Unknown,
        Self::Spacebase,
        Self::Void,
    ];

    /// The metatype with the given number.
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::ALL.get(usize::from(value)).copied()
    }

    /// The XML name (Ghidra `metatype2string`).
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

    /// The metatype with the given XML name (Ghidra `string2metatype`).
    ///
    /// As in Ghidra, `partenum` is written but not read back.
    pub fn from_name(name: &str) -> Result<Self, TypeError> {
        Ok(match name {
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
            _ => return Err(TypeError::new(format!("Unknown metatype: {name}"))),
        })
    }

    /// The default sub-metatype (Ghidra `Datatype::base2sub`).
    pub const fn base_sub(self) -> SubMetatype {
        match self {
            Self::PartialUnion => SubMetatype::PartialUnion,
            Self::PartialStruct => SubMetatype::PartialStruct,
            Self::PartialEnum => SubMetatype::UintPartialEnum,
            Self::Union => SubMetatype::Union,
            Self::Struct => SubMetatype::Struct,
            Self::EnumInt => SubMetatype::IntEnum,
            Self::EnumUint => SubMetatype::UintEnum,
            Self::Array => SubMetatype::Array,
            Self::PtrRel => SubMetatype::PtrRel,
            Self::Ptr => SubMetatype::Ptr,
            Self::Float => SubMetatype::Float,
            Self::Code => SubMetatype::Code,
            Self::Bool => SubMetatype::Bool,
            Self::Uint => SubMetatype::UintPlain,
            Self::Int => SubMetatype::IntPlain,
            Self::Unknown => SubMetatype::Unknown,
            Self::Spacebase => SubMetatype::Spacebase,
            Self::Void => SubMetatype::Void,
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

/// The finer ordering of types used by propagation (Ghidra `sub_metatype`).
/// A lower number is more specific.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SubMetatype {
    /// A partial union.
    PartialUnion = 0,
    /// A union.
    Union = 1,
    /// A structure.
    Struct = 2,
    /// An array.
    Array = 3,
    /// A pointer into a structure.
    PtrStruct = 4,
    /// A relative pointer.
    PtrRel = 5,
    /// A plain pointer.
    Ptr = 6,
    /// A relative pointer to an unknown field.
    PtrRelUnk = 7,
    /// Floating point.
    Float = 8,
    /// Code.
    Code = 9,
    /// Boolean.
    Bool = 10,
    /// Unsigned wide character.
    UintUnicode = 11,
    /// Signed wide character.
    IntUnicode = 12,
    /// Unsigned enumeration.
    UintEnum = 13,
    /// Unsigned partial enumeration.
    UintPartialEnum = 14,
    /// Signed enumeration.
    IntEnum = 15,
    /// Plain unsigned integer.
    UintPlain = 16,
    /// Plain signed integer.
    IntPlain = 17,
    /// Unsigned 1-byte character.
    UintChar = 18,
    /// Signed 1-byte character.
    IntChar = 19,
    /// A partial structure.
    PartialStruct = 20,
    /// Unknown.
    Unknown = 21,
    /// Spacebase.
    Spacebase = 22,
    /// Void.
    Void = 23,
}

/// Data-type classes for assigning storage (Ghidra `type_class`).
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
    /// The class named by a `.cspec` string (Ghidra `string2typeclass`).
    pub fn from_name(name: &str) -> Result<Self, TypeError> {
        Ok(match name {
            "class1" => Self::Class1,
            "class2" => Self::Class2,
            "class3" => Self::Class3,
            "class4" => Self::Class4,
            "general" | "unknown" => Self::General,
            "hiddenret" => Self::HiddenRet,
            "float" => Self::Float,
            "ptr" | "pointer" => Self::Ptr,
            "vector" => Self::Vector,
            _ => {
                return Err(TypeError::new(format!("Unknown data-type class: {name}")));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metatype_names_round_trip_except_partenum() {
        for meta in Metatype::ALL {
            assert_eq!(Metatype::from_u8(meta as u8), Some(meta));
            let parsed = Metatype::from_name(meta.name());
            if meta == Metatype::PartialEnum {
                assert!(parsed.is_err());
            } else {
                assert_eq!(parsed.unwrap(), meta);
            }
        }
        assert!(Metatype::from_name("").is_err());
    }

    #[test]
    fn base_sub_matches_ghidra_table() {
        let expected = [
            0u8, 20, 14, 1, 2, 15, 13, 3, 5, 6, 8, 9, 10, 16, 17, 21, 22, 23,
        ];
        let got = Metatype::ALL.map(|m| m.base_sub() as u8);
        assert_eq!(got, expected);
    }

    #[test]
    fn type_classes() {
        assert_eq!(TypeClass::from_name("pointer").unwrap(), TypeClass::Ptr);
        assert_eq!(TypeClass::from_name("unknown").unwrap(), TypeClass::General);
        assert!(TypeClass::from_name("x").is_err());
        assert_eq!(Metatype::Float.type_class(), TypeClass::Float);
        assert_eq!(Metatype::Int.type_class(), TypeClass::General);
    }
}
