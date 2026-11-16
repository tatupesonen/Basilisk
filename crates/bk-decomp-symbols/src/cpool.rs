//! The constant pool (Ghidra `CPoolRecord`, `ConstantPool`,
//! `ConstantPoolInternal`; cpool.cc; spec 4.14).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bk_decomp_types::{TypeFactory, TypeId};
use bk_marshal::ids::{
    ATTRIB_CONSTRUCTOR, ATTRIB_CONTENT, ATTRIB_DESTRUCTOR, ELEM_DATA, ELEM_VALUE,
};
use bk_marshal::{Decoder, Encoder};

use crate::error::{Result, SymbolError, limits};
use crate::ids::{
    ATTRIB_A, ATTRIB_B, ATTRIB_LENGTH, ATTRIB_TAG, ELEM_CONSTANTPOOL, ELEM_CPOOLREC, ELEM_REF,
    ELEM_TOKEN,
};

/// Record kinds (Ghidra `CPoolRecord` tags).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CPoolTag {
    /// A constant value.
    Primitive = 0,
    /// A string literal.
    StringLiteral = 1,
    /// A reference to a class.
    ClassReference = 2,
    /// A pointer to a method.
    PointerMethod = 3,
    /// A pointer to a field.
    PointerField = 4,
    /// An array length.
    ArrayLength = 5,
    /// An `instanceof` test.
    InstanceOf = 6,
    /// A `checkcast`.
    CheckCast = 7,
}

impl CPoolTag {
    fn name(self) -> &'static str {
        match self {
            Self::PointerMethod => "method",
            Self::PointerField => "field",
            Self::InstanceOf => "instanceof",
            Self::ArrayLength => "arraylength",
            Self::CheckCast => "checkcast",
            Self::StringLiteral => "string",
            Self::ClassReference => "classref",
            Self::Primitive => "primitive",
        }
    }

    /// An unknown name decodes as `primitive`, as in Ghidra.
    fn by_name(name: &str) -> Self {
        match name {
            "method" => Self::PointerMethod,
            "field" => Self::PointerField,
            "instanceof" => Self::InstanceOf,
            "arraylength" => Self::ArrayLength,
            "checkcast" => Self::CheckCast,
            "string" => Self::StringLiteral,
            "classref" => Self::ClassReference,
            _ => Self::Primitive,
        }
    }
}

/// `is_constructor` flag.
pub const IS_CONSTRUCTOR: u32 = 1;
/// `is_destructor` flag.
pub const IS_DESTRUCTOR: u32 = 2;

/// One record (Ghidra `CPoolRecord`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CPoolRecord {
    /// The kind.
    pub tag: CPoolTag,
    /// `IS_CONSTRUCTOR` / `IS_DESTRUCTOR`.
    pub flags: u32,
    /// The token (name) when there is no byte data.
    pub token: String,
    /// The value of a primitive.
    pub value: u64,
    /// The data type.
    pub ty: TypeId,
    /// The bytes of a string literal.
    pub data: Option<Vec<u8>>,
}

impl CPoolRecord {
    /// Ghidra `encode`; byte data is written as hex, which is what the
    /// decoder reads (Ghidra writes the bytes as characters; spec 4.21 #8).
    pub fn encode(&self, enc: &mut dyn Encoder, types: &TypeFactory) -> Result<()> {
        enc.open_element(ELEM_CPOOLREC);
        enc.write_string(ATTRIB_TAG, self.tag.name())?;
        if self.flags & IS_CONSTRUCTOR != 0 {
            enc.write_bool(ATTRIB_CONSTRUCTOR, true);
        }
        if self.flags & IS_DESTRUCTOR != 0 {
            enc.write_bool(ATTRIB_DESTRUCTOR, true);
        }
        if self.tag == CPoolTag::Primitive {
            enc.open_element(ELEM_VALUE);
            enc.write_unsigned(ATTRIB_CONTENT, self.value);
            enc.close_element(ELEM_VALUE);
        }
        if let Some(data) = &self.data {
            enc.open_element(ELEM_DATA);
            enc.write_signed(ATTRIB_LENGTH, data.len() as i64);
            let mut s = String::new();
            for (i, b) in data.iter().enumerate() {
                let _ = write!(s, "{b:02x} ");
                if i % 16 == 15 {
                    s.push('\n');
                }
            }
            enc.write_string(ATTRIB_CONTENT, &s)?;
            enc.close_element(ELEM_DATA);
        } else {
            enc.open_element(ELEM_TOKEN);
            enc.write_string(ATTRIB_CONTENT, &self.token)?;
            enc.close_element(ELEM_TOKEN);
        }
        types.encode_ref(enc, self.ty)?;
        enc.close_element(ELEM_CPOOLREC);
        Ok(())
    }

    /// Ghidra `decode`. Byte data must hold `length` hex tokens (Ghidra
    /// leaves missing bytes indeterminate; spec 4.21 #11).
    pub fn decode(dec: &mut dyn Decoder<'_>, types: &mut TypeFactory) -> Result<Self> {
        let el = dec.open_element_expecting(ELEM_CPOOLREC)?;
        let mut tag = CPoolTag::Primitive;
        let mut flags = 0;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_TAG {
                tag = CPoolTag::by_name(dec.read_string()?);
            } else if attr == ATTRIB_CONSTRUCTOR {
                if dec.read_bool()? {
                    flags |= IS_CONSTRUCTOR;
                }
            } else if attr == ATTRIB_DESTRUCTOR && dec.read_bool()? {
                flags |= IS_DESTRUCTOR;
            }
        }
        let mut value = 0;
        if tag == CPoolTag::Primitive {
            let sub = dec.open_element_expecting(ELEM_VALUE)?;
            value = dec.read_unsigned_attr(ATTRIB_CONTENT)?;
            dec.close_element(sub)?;
        }
        let mut token = String::new();
        let mut data = None;
        let sub = dec.open_element()?.ok_or(SymbolError::CpoolMissingData)?;
        if sub == ELEM_TOKEN.code() {
            dec.read_string_attr(ATTRIB_CONTENT)?.clone_into(&mut token);
        } else {
            let len = dec.read_signed_attr(ATTRIB_LENGTH)?;
            if !(0..limits::MAX_CPOOL_DATA).contains(&len) {
                return Err(SymbolError::CpoolDataSize);
            }
            data = Some(parse_hex_tokens(
                dec.read_string_attr(ATTRIB_CONTENT)?,
                len as usize,
            )?);
        }
        dec.close_element(sub)?;
        if tag == CPoolTag::StringLiteral && data.is_none() {
            return Err(SymbolError::CpoolMissingData);
        }
        let ty = if flags != 0 {
            types.decode_type_with_code_flags(
                dec,
                flags & IS_CONSTRUCTOR != 0,
                flags & IS_DESTRUCTOR != 0,
            )?
        } else {
            types.decode_type(dec)?
        };
        dec.close_element(el)?;
        Ok(Self {
            tag,
            flags,
            token,
            value,
            ty,
            data,
        })
    }
}

/// `count` hex numbers separated by white space (C++ `>> ws >> hex`),
/// each kept to its low byte; an optional `0x` prefix is accepted.
fn parse_hex_tokens(text: &str, count: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(count);
    let mut rest = text;
    for _ in 0..count {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\u{b}');
        let body = rest
            .strip_prefix("0x")
            .or_else(|| rest.strip_prefix("0X"))
            .unwrap_or(rest);
        let digits = body.bytes().take_while(u8::is_ascii_hexdigit).count();
        let token = body.get(..digits).unwrap_or("");
        let value =
            u32::from_str_radix(token, 16).map_err(|_not_hex| SymbolError::CpoolDataByte)?;
        out.push(value as u8);
        rest = body.get(digits..).unwrap_or("");
    }
    Ok(out)
}

/// The key of a record: the first two reference integers (Ghidra
/// `CheapSorter`).
fn key(refs: &[u64]) -> Result<(u64, u64)> {
    let a = *refs.first().ok_or(SymbolError::CpoolNoRefs)?;
    Ok((a, refs.get(1).copied().unwrap_or(0)))
}

/// Records by reference (Ghidra `ConstantPoolInternal`).
#[derive(Clone, Debug, Default)]
pub struct ConstantPool {
    records: BTreeMap<(u64, u64), CPoolRecord>,
}

impl ConstantPool {
    /// An empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Removes every record.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// The record of a reference (Ghidra `getRecord`).
    pub fn record(&self, refs: &[u64]) -> Result<Option<&CPoolRecord>> {
        Ok(self.records.get(&key(refs)?))
    }

    /// Stores a record under a new key (Ghidra `createRecord`).
    pub fn insert(&mut self, refs: &[u64], record: CPoolRecord) -> Result<()> {
        let k = key(refs)?;
        if let Some(old) = self.records.get(&k) {
            return Err(SymbolError::DuplicateCpool {
                token: old.token.clone(),
            });
        }
        self.records.insert(k, record);
        Ok(())
    }

    /// Ghidra `putRecord`: tag, token and type; flags and value 0 (Ghidra
    /// leaves them uninitialised; spec 4.21 #9).
    pub fn put_record(
        &mut self,
        refs: &[u64],
        tag: CPoolTag,
        token: &str,
        ty: TypeId,
    ) -> Result<()> {
        self.insert(
            refs,
            CPoolRecord {
                tag,
                flags: 0,
                token: token.to_owned(),
                value: 0,
                ty,
                data: None,
            },
        )
    }

    /// Ghidra `decodeRecord`.
    pub fn decode_record(
        &mut self,
        refs: &[u64],
        dec: &mut dyn Decoder<'_>,
        types: &mut TypeFactory,
    ) -> Result<()> {
        let k = key(refs)?;
        if let Some(old) = self.records.get(&k) {
            return Err(SymbolError::DuplicateCpool {
                token: old.token.clone(),
            });
        }
        let record = CPoolRecord::decode(dec, types)?;
        self.records.insert(k, record);
        Ok(())
    }

    /// Ghidra `encode`: `<constantpool>` of `<ref a b>` and `<cpoolrec>`
    /// pairs in key order.
    pub fn encode(&self, enc: &mut dyn Encoder, types: &TypeFactory) -> Result<()> {
        enc.open_element(ELEM_CONSTANTPOOL);
        for ((a, b), rec) in &self.records {
            enc.open_element(ELEM_REF);
            enc.write_unsigned(ATTRIB_A, *a);
            enc.write_unsigned(ATTRIB_B, *b);
            enc.close_element(ELEM_REF);
            rec.encode(enc, types)?;
        }
        enc.close_element(ELEM_CONSTANTPOOL);
        Ok(())
    }

    /// Ghidra `decode`.
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>, types: &mut TypeFactory) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_CONSTANTPOOL)?;
        while dec.peek_element().is_some() {
            let r = dec.open_element_expecting(ELEM_REF)?;
            let a = dec.read_unsigned_attr(ATTRIB_A)?;
            let b = dec.read_unsigned_attr(ATTRIB_B)?;
            dec.close_element(r)?;
            self.decode_record(&[a, b], dec, types)?;
        }
        dec.close_element(el)?;
        Ok(())
    }
}
