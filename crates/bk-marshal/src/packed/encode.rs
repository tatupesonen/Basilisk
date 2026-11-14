//! The packed encoder (Ghidra `PackedEncode`; patching from the Java
//! `PatchPackedEncode`).

use super::format::{
    ATTRIBUTE, ELEMENT_END, ELEMENT_START, ELEMENTID_MASK, HEADER_MASK, HEADEREXTEND_MASK,
    LENGTHCODE_MASK, RAWDATA_BITSPERBYTE, RAWDATA_MARKER, RAWDATA_MASK, SPECIALSPACE_FSPEC,
    SPECIALSPACE_IOP, SPECIALSPACE_JOIN, SPECIALSPACE_SPACEBASE, SPECIALSPACE_STACK,
    TYPECODE_ADDRESSSPACE, TYPECODE_BOOLEAN, TYPECODE_SHIFT, TYPECODE_SIGNEDINT_NEGATIVE,
    TYPECODE_SIGNEDINT_POSITIVE, TYPECODE_SPECIALSPACE, TYPECODE_STRING, TYPECODE_UNSIGNEDINT,
};
use crate::encoder::Encoder;
use crate::error::EncodeError;
use crate::ids::{AttributeId, ElementId};
use crate::space::{PackedSpace, SpaceRef};

/// The number of bytes of an integer written at full width, which is the
/// only width [`PackedEncoder::patch_integer_attribute`] can overwrite.
const FULL_WIDTH: usize = 10;

/// Writes a document in the packed form into a byte buffer (Ghidra
/// `PackedEncode`).
#[derive(Debug, Clone, Default)]
pub struct PackedEncoder {
    out: Vec<u8>,
}

impl PackedEncoder {
    /// Creates an encoder with an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an encoder that appends to `buffer`.
    pub fn with_buffer(buffer: Vec<u8>) -> Self {
        Self { out: buffer }
    }

    /// The bytes written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    /// Consumes the encoder and returns the bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// The number of bytes written so far. Recorded just before an element is
    /// opened, it is the position [`PackedEncoder::patch_integer_attribute`]
    /// takes.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Discards everything written so far.
    pub fn clear(&mut self) {
        self.out.clear();
    }

    /// Writes an element or attribute header with its id.
    fn write_header(&mut self, header: u8, id: u32) {
        if id > u32::from(ELEMENTID_MASK) {
            // As in Ghidra, an id that needs more than twelve bits spills
            // into the record-type bits; no registered id is that large.
            let first = header | HEADEREXTEND_MASK | (id >> RAWDATA_BITSPERBYTE) as u8;
            let extend = (id as u8 & RAWDATA_MASK) | RAWDATA_MARKER;
            self.out.extend_from_slice(&[first, extend]);
        } else {
            self.out.push(header | id as u8);
        }
    }

    /// Writes a type byte with the length code filled in, then the value in
    /// seven-bit groups, most significant first.
    fn write_integer(&mut self, type_code: u8, value: u64) {
        let bits = value.bit_width();
        let groups = bits.div_ceil(RAWDATA_BITSPERBYTE);
        self.out.push((type_code << TYPECODE_SHIFT) | groups as u8);
        for group in (0..groups).rev() {
            let piece = (value >> (group * RAWDATA_BITSPERBYTE)) as u8 & RAWDATA_MASK;
            self.out.push(piece | RAWDATA_MARKER);
        }
    }

    fn write_string_with_id(&mut self, id: u32, value: &str) -> Result<(), EncodeError> {
        if value.as_bytes().contains(&0) {
            return Err(EncodeError::StringWithNul);
        }
        self.write_header(ATTRIBUTE, id);
        self.write_integer(TYPECODE_STRING, value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
        Ok(())
    }

    /// Replaces the value of an integer attribute already written (Java
    /// `PatchPackedEncode.patchIntegerAttribute`).
    ///
    /// `position` is the offset of the start record of the element holding
    /// the attribute, as returned by [`PackedEncoder::len`] before the element
    /// was opened. The attribute must have been written at full width (ten
    /// bytes), which happens when the placeholder value has its top bit set,
    /// for example `write_unsigned(attribute, u64::MAX)`. Returns `false`,
    /// changing nothing, if the element or attribute is not found there or
    /// the attribute is not a full-width integer.
    pub fn patch_integer_attribute(
        &mut self,
        position: usize,
        attribute: AttributeId,
        value: u64,
    ) -> bool {
        let Some(at) = self.find_full_width_integer(position, attribute.id()) else {
            return false;
        };
        let Some(slot) = self.out.get_mut(at..at + FULL_WIDTH) else {
            return false;
        };
        for (group, byte) in (0..FULL_WIDTH as u32).rev().zip(slot) {
            *byte =
                ((value >> (group * RAWDATA_BITSPERBYTE)) as u8 & RAWDATA_MASK) | RAWDATA_MARKER;
        }
        true
    }

    /// Finds the data bytes of the full-width integer attribute `id` in the
    /// element starting at `position`.
    fn find_full_width_integer(&self, position: usize, id: u32) -> Option<usize> {
        let byte = |at: usize| self.out.get(at).copied();
        let open = byte(position)?;
        if open & HEADER_MASK != ELEMENT_START {
            return None;
        }
        let mut pos = position + if open & HEADEREXTEND_MASK == 0 { 1 } else { 2 };
        loop {
            let header = byte(pos)?;
            if header & HEADER_MASK != ATTRIBUTE {
                return None;
            }
            pos += 1;
            let mut current = u32::from(header & ELEMENTID_MASK);
            if header & HEADEREXTEND_MASK != 0 {
                current = (current << RAWDATA_BITSPERBYTE) | u32::from(byte(pos)? & RAWDATA_MASK);
                pos += 1;
            }
            let type_byte = byte(pos)?;
            pos += 1;
            let type_code = type_byte >> TYPECODE_SHIFT;
            let length = usize::from(type_byte & LENGTHCODE_MASK);
            let is_integer = matches!(
                type_code,
                TYPECODE_SIGNEDINT_POSITIVE | TYPECODE_SIGNEDINT_NEGATIVE | TYPECODE_UNSIGNEDINT
            );
            if current == id {
                return (is_integer && length == FULL_WIDTH).then_some(pos);
            }
            match type_code {
                TYPECODE_BOOLEAN | TYPECODE_SPECIALSPACE => {}
                TYPECODE_STRING => {
                    let mut size: usize = 0;
                    for _ in 0..length {
                        size =
                            (size << RAWDATA_BITSPERBYTE) | usize::from(byte(pos)? & RAWDATA_MASK);
                        pos += 1;
                    }
                    pos = pos.checked_add(size)?;
                }
                _ => pos += length,
            }
        }
    }
}

impl Encoder for PackedEncoder {
    fn open_element(&mut self, element: ElementId) {
        self.write_header(ELEMENT_START, element.id());
    }

    fn close_element(&mut self, element: ElementId) {
        self.write_header(ELEMENT_END, element.id());
    }

    fn write_bool(&mut self, attribute: AttributeId, value: bool) {
        self.write_header(ATTRIBUTE, attribute.id());
        self.out
            .push((TYPECODE_BOOLEAN << TYPECODE_SHIFT) | u8::from(value));
    }

    fn write_signed(&mut self, attribute: AttributeId, value: i64) {
        self.write_header(ATTRIBUTE, attribute.id());
        let type_code = if value < 0 {
            TYPECODE_SIGNEDINT_NEGATIVE
        } else {
            TYPECODE_SIGNEDINT_POSITIVE
        };
        self.write_integer(type_code, value.unsigned_abs());
    }

    fn write_unsigned(&mut self, attribute: AttributeId, value: u64) {
        self.write_header(ATTRIBUTE, attribute.id());
        self.write_integer(TYPECODE_UNSIGNEDINT, value);
    }

    fn write_string(&mut self, attribute: AttributeId, value: &str) -> Result<(), EncodeError> {
        self.write_string_with_id(attribute.id(), value)
    }

    fn write_string_indexed(
        &mut self,
        attribute: AttributeId,
        index: u32,
        value: &str,
    ) -> Result<(), EncodeError> {
        self.write_string_with_id(attribute.indexed(index).get(), value)
    }

    fn write_space(&mut self, attribute: AttributeId, space: &SpaceRef<'_>) {
        self.write_header(ATTRIBUTE, attribute.id());
        let special = match space.packed {
            PackedSpace::Index(index) => {
                self.write_integer(TYPECODE_ADDRESSSPACE, u64::from(index));
                return;
            }
            PackedSpace::Stack => SPECIALSPACE_STACK,
            PackedSpace::Join => SPECIALSPACE_JOIN,
            PackedSpace::Fspec => SPECIALSPACE_FSPEC,
            PackedSpace::Iop => SPECIALSPACE_IOP,
            PackedSpace::Spacebase => SPECIALSPACE_SPACEBASE,
        };
        self.out
            .push((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | special);
    }

    fn write_enum(&mut self, attribute: AttributeId, value: u64, _name: &str) {
        self.write_header(ATTRIBUTE, attribute.id());
        self.write_integer(TYPECODE_SIGNEDINT_POSITIVE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{
        ATTRIB_ALIGN, ATTRIB_CONTENT, ATTRIB_NAME, ATTRIB_SPACE, ATTRIB_STORAGE, ATTRIB_UNKNOWN,
        ATTRIB_VAL, ELEM_DATA, ELEM_UNKNOWN, ELEM_VOID,
    };

    fn encode(build: impl FnOnce(&mut PackedEncoder)) -> Vec<u8> {
        let mut enc = PackedEncoder::new();
        build(&mut enc);
        enc.into_bytes()
    }

    /// Hand-computed vectors, one for each record kind and type code
    /// (core-marshal.md, acceptance 2).
    #[test]
    fn headers() {
        // Ids up to 0x1f fit the header byte.
        assert_eq!(encode(|e| e.open_element(ELEM_DATA)), [0x41]);
        assert_eq!(encode(|e| e.close_element(ELEM_DATA)), [0x81]);
        assert_eq!(encode(|e| e.open_element(ELEM_VOID)), [0x4a]);
        assert_eq!(
            encode(|e| e.open_element(ElementId::new("x", 0x1f))),
            [0x5f]
        );
        // 0x20 = 0b0_0100000: high bits 0, extension byte 0x80|0x20.
        assert_eq!(
            encode(|e| e.open_element(ElementId::new("x", 0x20))),
            [0x60, 0xa0]
        );
        // 292 = 0b10_0100100: header 0x40|0x20|0b10, extension 0x80|0x24.
        assert_eq!(encode(|e| e.open_element(ELEM_UNKNOWN)), [0x62, 0xa4]);
        assert_eq!(encode(|e| e.close_element(ELEM_UNKNOWN)), [0xa2, 0xa4]);
        // 4095 = twelve one bits, the largest id the format holds.
        assert_eq!(
            encode(|e| e.open_element(ElementId::new("x", 4095))),
            [0x7f, 0xff]
        );
    }

    #[test]
    fn boolean_attribute() {
        assert_eq!(encode(|e| e.write_bool(ATTRIB_ALIGN, true)), [0xc2, 0x11]);
        assert_eq!(encode(|e| e.write_bool(ATTRIB_ALIGN, false)), [0xc2, 0x10]);
        // 149 = 0b1_0010101: header 0xc0|0x20|1, extension 0x80|0x15.
        assert_eq!(
            encode(|e| e.write_bool(ATTRIB_STORAGE, true)),
            [0xe1, 0x95, 0x11]
        );
        // 161 = 0b1_0100001.
        assert_eq!(
            encode(|e| e.write_bool(ATTRIB_UNKNOWN, false)),
            [0xe1, 0xa1, 0x10]
        );
    }

    #[test]
    fn signed_attribute() {
        assert_eq!(encode(|e| e.write_signed(ATTRIB_ALIGN, 0)), [0xc2, 0x20]);
        assert_eq!(
            encode(|e| e.write_signed(ATTRIB_ALIGN, 3)),
            [0xc2, 0x21, 0x83]
        );
        // -0x100: negative type, magnitude 0x100 = 0b10_0000000.
        assert_eq!(
            encode(|e| e.write_signed(ATTRIB_ALIGN, -0x100)),
            [0xc2, 0x32, 0x82, 0x80]
        );
        assert_eq!(
            encode(|e| e.write_signed(ATTRIB_ALIGN, -1)),
            [0xc2, 0x31, 0x81]
        );
        assert_eq!(
            encode(|e| e.write_signed(ATTRIB_ALIGN, i64::MAX)),
            [
                0xc2, 0x29, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
        assert_eq!(
            encode(|e| e.write_signed(ATTRIB_ALIGN, i64::MIN)),
            [
                0xc2, 0x3a, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
            ]
        );
    }

    #[test]
    fn unsigned_attribute() {
        assert_eq!(encode(|e| e.write_unsigned(ATTRIB_ALIGN, 0)), [0xc2, 0x40]);
        assert_eq!(
            encode(|e| e.write_unsigned(ATTRIB_ALIGN, 0x7f)),
            [0xc2, 0x41, 0xff]
        );
        assert_eq!(
            encode(|e| e.write_unsigned(ATTRIB_ALIGN, 0x80)),
            [0xc2, 0x42, 0x81, 0x80]
        );
        assert_eq!(
            encode(|e| e.write_unsigned(ATTRIB_ALIGN, 0x3fff)),
            [0xc2, 0x42, 0xff, 0xff]
        );
        assert_eq!(
            encode(|e| e.write_unsigned(ATTRIB_ALIGN, 0x4000)),
            [0xc2, 0x43, 0x81, 0x80, 0x80]
        );
        assert_eq!(
            encode(|e| e.write_unsigned(ATTRIB_ALIGN, u64::MAX)),
            [
                0xc2, 0x4a, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
    }

    /// The length code is the number of seven-bit groups, at each of the
    /// thresholds in `PackedEncode::writeInteger`.
    #[test]
    fn integer_length_codes() {
        let thresholds: [(u64, u8); 11] = [
            (0, 0),
            (1, 1),
            (0x80, 2),
            (0x4000, 3),
            (0x20_0000, 4),
            (0x1000_0000, 5),
            (0x8_0000_0000, 6),
            (0x400_0000_0000, 7),
            (0x2_0000_0000_0000, 8),
            (0x100_0000_0000_0000, 9),
            (0x8000_0000_0000_0000, 10),
        ];
        for (value, code) in thresholds {
            let bytes = encode(|e| e.write_unsigned(ATTRIB_ALIGN, value));
            assert_eq!(bytes[1], 0x40 | code, "{value:#x}");
            assert_eq!(bytes.len(), 2 + usize::from(code));
            if value > 1 {
                let bytes = encode(|e| e.write_unsigned(ATTRIB_ALIGN, value - 1));
                assert_eq!(bytes[1], 0x40 | (code - 1), "{:#x}", value - 1);
            }
        }
    }

    #[test]
    fn space_attribute() {
        let space = |packed| SpaceRef { name: "n", packed };
        let enc = |packed| encode(|e| e.write_space(ATTRIB_SPACE, &space(packed)));
        assert_eq!(enc(PackedSpace::Index(3)), [0xd4, 0x51, 0x83]);
        assert_eq!(enc(PackedSpace::Index(0)), [0xd4, 0x50]);
        assert_eq!(enc(PackedSpace::Index(200)), [0xd4, 0x52, 0x81, 0xc8]);
        assert_eq!(enc(PackedSpace::Stack), [0xd4, 0x60]);
        assert_eq!(enc(PackedSpace::Join), [0xd4, 0x61]);
        assert_eq!(enc(PackedSpace::Fspec), [0xd4, 0x62]);
        assert_eq!(enc(PackedSpace::Iop), [0xd4, 0x63]);
        assert_eq!(enc(PackedSpace::Spacebase), [0xd4, 0x64]);
    }

    #[test]
    fn string_attribute() {
        assert_eq!(
            encode(|e| e.write_string(ATTRIB_NAME, "").unwrap()),
            [0xce, 0x70]
        );
        assert_eq!(
            encode(|e| e.write_string(ATTRIB_NAME, "hi").unwrap()),
            [0xce, 0x71, 0x82, b'h', b'i']
        );
        let long = "x".repeat(200);
        let bytes = encode(|e| e.write_string(ATTRIB_NAME, &long).unwrap());
        assert_eq!(&bytes[..4], [0xce, 0x72, 0x81, 0xc8]);
        assert_eq!(bytes.len(), 204);
        // Indexed strings use the base id plus the index: 14 + 2 = 16.
        assert_eq!(
            encode(|e| e.write_string_indexed(ATTRIB_NAME, 2, "p").unwrap()),
            [0xd0, 0x71, 0x81, b'p']
        );
        let mut enc = PackedEncoder::new();
        assert_eq!(
            enc.write_string(ATTRIB_NAME, "a\0b"),
            Err(EncodeError::StringWithNul)
        );
        assert_eq!(
            enc.write_string_indexed(ATTRIB_NAME, 1, "\0"),
            Err(EncodeError::StringWithNul)
        );
        assert!(enc.is_empty(), "nothing is written for a rejected string");
    }

    #[test]
    fn enum_attribute_is_a_positive_signed_integer() {
        assert_eq!(
            encode(|e| e.write_enum(ATTRIB_VAL, 1, "COPY")),
            [0xd8, 0x21, 0x81]
        );
        assert_eq!(encode(|e| e.write_enum(ATTRIB_VAL, 0, "x")), [0xd8, 0x20]);
    }

    #[test]
    fn whole_document() {
        let mut enc = PackedEncoder::with_buffer(vec![0xee]);
        enc.open_element(ELEM_DATA);
        enc.write_bool(ATTRIB_CONTENT, true);
        enc.open_element(ELEM_VOID);
        enc.close_element(ELEM_VOID);
        enc.close_element(ELEM_DATA);
        assert_eq!(enc.as_bytes(), [0xee, 0x41, 0xc1, 0x11, 0x4a, 0x8a, 0x81]);
        assert_eq!(enc.len(), 7);
        enc.clear();
        assert!(enc.is_empty());
    }

    #[test]
    fn patching_replaces_a_full_width_integer() {
        let mut enc = PackedEncoder::new();
        enc.open_element(ELEM_VOID);
        enc.close_element(ELEM_VOID);
        let position = enc.len();
        enc.open_element(ELEM_UNKNOWN); // two-byte header
        enc.write_bool(ATTRIB_ALIGN, true);
        enc.write_string(ATTRIB_NAME, &"s".repeat(130)).unwrap(); // two-byte length
        enc.write_unsigned(ATTRIB_STORAGE, 5); // narrow integer
        enc.write_space(
            ATTRIB_SPACE,
            &SpaceRef {
                name: "j",
                packed: PackedSpace::Join,
            },
        );
        enc.write_unsigned(ATTRIB_VAL, u64::MAX); // placeholder
        enc.close_element(ELEM_UNKNOWN);
        let before = enc.as_bytes().to_vec();

        assert!(enc.patch_integer_attribute(position, ATTRIB_VAL, 0x1234));
        let after = enc.as_bytes();
        assert_eq!(after.len(), before.len());
        let data = after.len() - 2 - FULL_WIDTH;
        assert_eq!(after[..data], before[..data]);
        assert_eq!(
            after[data..data + FULL_WIDTH],
            [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xa4, 0xb4]
        );
        assert_eq!(after[data + FULL_WIDTH..], [0xa2, 0xa4]);

        // Not found, not full width, not an element start, out of range.
        assert!(!enc.patch_integer_attribute(position, ATTRIB_CONTENT, 1));
        assert!(!enc.patch_integer_attribute(position, ATTRIB_STORAGE, 1));
        assert!(!enc.patch_integer_attribute(position, ATTRIB_NAME, 1));
        assert!(!enc.patch_integer_attribute(position + 1, ATTRIB_VAL, 1));
        assert!(!enc.patch_integer_attribute(usize::MAX - 1, ATTRIB_VAL, 1));
        assert!(!enc.patch_integer_attribute(0, ATTRIB_VAL, 1));
    }
}
