//! The facts a factory needs from the architecture ([`TypeEnv`]) and the
//! compiler's data organisation ([`DataOrganization`]): Ghidra
//! `TypeFactory::setupSizes`, `decodeDataOrganization`, `decodeAlignmentMap`,
//! `setDefaultAlignmentMap`, `parseEnumConfig`, `getAlignment` and
//! `getPrimitiveAlignSize`.

use bk_marshal::{Decoder, Document, NoSpaces, SpaceId, XmlDecoder};

use crate::error::{Result, TypeError};
use crate::meta::Metatype;
use crate::xml::ids::{
    ELEM_CHAR_SIZE, ELEM_DATA_ORGANIZATION, ELEM_ENTRY, ELEM_ENUM, ELEM_INTEGER_SIZE,
    ELEM_LONG_SIZE, ELEM_POINTER_SIZE, ELEM_SIZE_ALIGNMENT_MAP, ELEM_WCHAR_SIZE, id_table,
};
use bk_marshal::ids::{ATTRIB_SIZE, ATTRIB_VALUE};

/// An address space as the type system sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceInfo {
    /// The space's identity.
    pub id: SpaceId,
    /// Its name, as written in XML.
    pub name: String,
    /// Size of an address in bytes.
    pub addr_size: i32,
    /// Size of the addressable unit in bytes.
    pub word_size: u32,
    /// Whether the space is big endian.
    pub big_endian: bool,
}

/// What a factory needs to know about the architecture, given at
/// construction (spec 4.5). Ghidra reads these from its `Architecture`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeEnv {
    /// Largest size for which a base type is made; bigger requests give an
    /// array of bytes (Ghidra `max_basetype_size`, default 10).
    pub max_basetype_size: i32,
    /// The default data space.
    pub data_space: SpaceInfo,
    /// Address size of the default code space (Ghidra `getDefaultSize`).
    pub code_addr_size: i32,
    /// Size of the stack pointer, if there is a stack space.
    pub stack_pointer_size: Option<i32>,
    /// Inner and base sizes of the data space's segment op, if it supports
    /// far pointers.
    pub far_pointer: Option<(i32, i32)>,
    /// Further spaces that pointer types may name.
    pub other_spaces: Vec<SpaceInfo>,
    /// Name of the default prototype model, given to function types built
    /// without a model.
    pub default_model: Option<String>,
}

impl TypeEnv {
    /// A simple environment: one little- or big-endian data space `ram` of
    /// the given address size with word size 1, a stack pointer of the same
    /// size, and `max_basetype_size` 10.
    pub fn simple(addr_size: i32, big_endian: bool) -> Self {
        Self {
            max_basetype_size: 10,
            data_space: SpaceInfo {
                id: SpaceId::new(1),
                name: "ram".to_owned(),
                addr_size,
                word_size: 1,
                big_endian,
            },
            code_addr_size: addr_size,
            stack_pointer_size: Some(addr_size),
            far_pointer: None,
            other_spaces: Vec::new(),
            default_model: None,
        }
    }

    /// The space with the given identity.
    pub fn space(&self, id: SpaceId) -> Option<&SpaceInfo> {
        std::iter::once(&self.data_space)
            .chain(&self.other_spaces)
            .find(|s| s.id == id)
    }
}

impl bk_marshal::SpaceResolver for TypeEnv {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        std::iter::once(&self.data_space)
            .chain(&self.other_spaces)
            .find(|s| s.name == name)
            .map(|s| s.id)
    }
    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        std::iter::once(&self.data_space)
            .chain(&self.other_spaces)
            .find(|s| u64::from(s.id.index()) == index)
            .map(|s| s.id)
    }
    fn space_count(&self) -> u64 {
        std::iter::once(&self.data_space)
            .chain(&self.other_spaces)
            .map(|s| u64::from(s.id.index()) + 1)
            .max()
            .unwrap_or(0)
    }
    fn stack_space(&self) -> Option<SpaceId> {
        None
    }
    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

/// The compiler's data organisation as the decompiler uses it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DataOrganization {
    /// Size of `int` (0 until known).
    pub size_of_int: i32,
    /// Size of `long`.
    pub size_of_long: i32,
    /// Size of `char`.
    pub size_of_char: i32,
    /// Size of `wchar_t`.
    pub size_of_wchar: i32,
    /// Size of a pointer into the default data space.
    pub size_of_pointer: i32,
    /// Size of the alternate (far) pointer, or 0.
    pub size_of_alt_pointer: i32,
    /// Size of an enumeration.
    pub enum_size: i32,
    /// Whether enumerations are signed (Ghidra `enumtype` is `TYPE_ENUM_INT`).
    pub enum_signed: bool,
    /// Alignment by size; index 0 is 1.
    pub align_map: Vec<i32>,
}

/// The largest size an alignment-map entry may name; a guard against
/// hostile input allocating without bound (ADR-009).
const MAX_ALIGN_ENTRY: i64 = 1 << 16;

impl DataOrganization {
    /// The enumeration metatype the C parser uses.
    pub const fn enum_metatype(&self) -> Metatype {
        if self.enum_signed {
            Metatype::EnumInt
        } else {
            Metatype::EnumUint
        }
    }

    /// Reads a `<data_organization>` element (Ghidra
    /// `decodeDataOrganization`): only the five sizes and the alignment map;
    /// every other child is skipped.
    pub fn decode_data_organization(&mut self, decoder: &mut dyn Decoder<'_>) -> Result<()> {
        let elem = decoder.open_element_expecting(ELEM_DATA_ORGANIZATION)?;
        while let Some(sub) = decoder.open_element()? {
            let field = if sub == ELEM_INTEGER_SIZE {
                Some(&mut self.size_of_int)
            } else if sub == ELEM_LONG_SIZE {
                Some(&mut self.size_of_long)
            } else if sub == ELEM_POINTER_SIZE {
                Some(&mut self.size_of_pointer)
            } else if sub == ELEM_CHAR_SIZE {
                Some(&mut self.size_of_char)
            } else if sub == ELEM_WCHAR_SIZE {
                Some(&mut self.size_of_wchar)
            } else {
                None
            };
            if let Some(field) = field {
                *field = decoder.read_signed_attr(ATTRIB_VALUE)? as i32;
            } else if sub == ELEM_SIZE_ALIGNMENT_MAP {
                self.decode_alignment_map(decoder)?;
            } else {
                decoder.close_element_skipping(sub)?;
                continue;
            }
            decoder.close_element(sub)?;
        }
        decoder.close_element(elem)?;
        Ok(())
    }

    /// Reads the entries of a `<size_alignment_map>` (Ghidra
    /// `decodeAlignmentMap`).
    fn decode_alignment_map(&mut self, decoder: &mut dyn Decoder<'_>) -> Result<()> {
        self.align_map.clear();
        loop {
            if decoder.peek_element() != Some(ELEM_ENTRY.code()) {
                break;
            }
            let Some(entry) = decoder.open_element()? else {
                break;
            };
            let size = decoder.read_signed_attr(ATTRIB_SIZE)?;
            let value = decoder.read_signed_attr(crate::xml::ids::ATTRIB_ALIGNMENT)?;
            if !(0..=MAX_ALIGN_ENTRY).contains(&size) {
                return Err(TypeError::new(format!("Bad alignment map size {size}")));
            }
            let size = size as usize;
            if self.align_map.len() <= size {
                self.align_map.resize(size + 1, -1);
            }
            if let Some(slot) = self.align_map.get_mut(size) {
                *slot = value as i32;
            }
            decoder.close_element(entry)?;
        }
        if self.align_map.is_empty() {
            return Err(TypeError::new("Alignment map empty"));
        }
        if let Some(first) = self.align_map.first_mut() {
            *first = 1;
        }
        let mut current = 1;
        for slot in self.align_map.iter_mut().skip(1) {
            if *slot == -1 {
                *slot = current;
            } else {
                current = *slot;
            }
        }
        Ok(())
    }

    /// Reads an `<enum size= signed=>` element (Ghidra `parseEnumConfig`).
    pub fn decode_enum_config(&mut self, decoder: &mut dyn Decoder<'_>) -> Result<()> {
        let elem = decoder.open_element_expecting(ELEM_ENUM)?;
        self.enum_size = decoder.read_signed_attr(ATTRIB_SIZE)? as i32;
        self.enum_signed = decoder.read_bool_attr(crate::xml::ids::ATTRIB_SIGNED)?;
        decoder.close_element(elem)?;
        Ok(())
    }

    /// Reads `<data_organization>` and `<enum>` from the text of a `.cspec`
    /// file, as Ghidra's `parseCompilerConfig` does, then fills in what is
    /// missing with [`setup_sizes`](Self::setup_sizes).
    pub fn from_cspec(text: &str, env: &TypeEnv) -> Result<Self> {
        let doc = Document::parse(text).map_err(bk_marshal::DecodeError::from)?;
        let ids = id_table();
        let mut org = Self::default();
        for child in doc.root().children() {
            match child.name() {
                "data_organization" => {
                    let mut dec = XmlDecoder::at(child, &ids, &NoSpaces);
                    org.decode_data_organization(&mut dec)?;
                }
                "enum" => {
                    let mut dec = XmlDecoder::at(child, &ids, &NoSpaces);
                    org.decode_enum_config(&mut dec)?;
                }
                _ => {}
            }
        }
        org.setup_sizes(env);
        Ok(org)
    }

    /// Supplies what the compiler specification did not (Ghidra
    /// `setupSizes`).
    pub fn setup_sizes(&mut self, env: &TypeEnv) {
        if self.size_of_int == 0 {
            self.size_of_int = env.stack_pointer_size.map_or(1, |s| s.min(4));
        }
        if self.size_of_long == 0 {
            self.size_of_long = if self.size_of_int == 4 {
                8
            } else {
                self.size_of_int
            };
        }
        if self.size_of_char == 0 {
            self.size_of_char = 1;
        }
        if self.size_of_wchar == 0 {
            self.size_of_wchar = 2;
        }
        if self.size_of_pointer == 0 {
            self.size_of_pointer = env.data_space.addr_size;
        }
        if let Some((inner, base)) = env.far_pointer {
            self.size_of_pointer = inner;
            self.size_of_alt_pointer = inner.saturating_add(base);
        }
        if self.align_map.is_empty() {
            self.align_map = vec![1, 1, 2, 2, 4, 4, 4, 4, 8];
        }
        if self.enum_size == 0 {
            self.enum_size = env.code_addr_size;
            self.enum_signed = false;
        }
    }

    /// The alignment of a primitive of the given size (Ghidra
    /// `getAlignment`). An empty map gives 1 where Ghidra throws.
    pub fn alignment(&self, size: u32) -> i32 {
        let size = size as usize;
        self.align_map
            .get(size)
            .or_else(|| self.align_map.last())
            .copied()
            .unwrap_or(1)
    }

    /// The size of a primitive rounded up to its alignment (Ghidra
    /// `getPrimitiveAlignSize`).
    pub fn primitive_align_size(&self, size: u32) -> i32 {
        let align = self.alignment(size).max(1) as u32;
        let rem = size % align;
        let res = if rem != 0 {
            size.saturating_add(align - rem)
        } else {
            size
        };
        res.min(i32::MAX as u32) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_gcc_like() {
        let env = TypeEnv::simple(8, false);
        let text = r#"<compiler_spec><data_organization>
            <absolute_max_alignment value="0"/><integer_size value="4"/><long_size value="8"/>
            <size_alignment_map><entry size="1" alignment="1"/><entry size="2" alignment="2"/>
            <entry size="4" alignment="4"/><entry size="8" alignment="8"/><entry size="16" alignment="16"/>
            </size_alignment_map></data_organization></compiler_spec>"#;
        let org = DataOrganization::from_cspec(text, &env).unwrap();
        assert_eq!(
            (org.size_of_int, org.size_of_long, org.size_of_pointer),
            (4, 8, 8)
        );
        assert_eq!(
            org.align_map,
            vec![1, 1, 2, 2, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 16]
        );
        assert_eq!(org.alignment(100), 16);
        assert_eq!(org.primitive_align_size(10), 16);
        assert_eq!((org.enum_size, org.enum_signed), (8, false));
    }

    #[test]
    fn defaults_without_spec() {
        let mut env = TypeEnv::simple(2, true);
        env.stack_pointer_size = None;
        env.far_pointer = Some((2, 2));
        let mut org = DataOrganization::default();
        org.setup_sizes(&env);
        assert_eq!((org.size_of_int, org.size_of_long), (1, 1));
        assert_eq!((org.size_of_pointer, org.size_of_alt_pointer), (2, 4));
        assert_eq!(org.align_map.len(), 9);
    }

    #[test]
    fn empty_alignment_map_is_an_error() {
        let env = TypeEnv::simple(4, false);
        let text = "<c><data_organization><size_alignment_map/></data_organization></c>";
        let err = DataOrganization::from_cspec(text, &env).unwrap_err();
        assert_eq!(err.to_string(), "Alignment map empty");
    }
}
