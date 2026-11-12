//! Helpers shared by the decoder test files.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses a different part of the helpers"
)]

use bk_marshal::ids::{ATTRIBUTES, ELEMENTS};
use bk_marshal::{
    AttributeId, Document, IdTable, PackedDecoder, SpaceId, SpaceResolver, XmlDecoder,
};

pub const ATTRIB_PIECE: AttributeId = AttributeId::new("piece", 94);

/// Spaces 0, 1 and 3 exist (2 is an empty slot); 1 is the stack.
pub struct Spaces;

impl SpaceResolver for Spaces {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        match name {
            "const" => Some(SpaceId::new(0)),
            "stack" => Some(SpaceId::new(1)),
            "ram" => Some(SpaceId::new(3)),
            _ => None,
        }
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        matches!(index, 0 | 1 | 3).then(|| SpaceId::new(index as u32))
    }

    fn space_count(&self) -> u64 {
        4
    }

    fn stack_space(&self) -> Option<SpaceId> {
        Some(SpaceId::new(1))
    }

    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

pub fn ids() -> IdTable {
    IdTable::new(&[ATTRIBUTES, &[ATTRIB_PIECE]], &[ELEMENTS]).unwrap()
}

/// Runs `read` on an XML decoder over `text`.
pub fn xml<T>(text: &str, read: impl FnOnce(&mut XmlDecoder<'_>) -> T) -> T {
    let ids = ids();
    let document = Document::parse(text).unwrap();
    read(&mut XmlDecoder::new(&document, &ids, &Spaces))
}

pub fn packed<T>(bytes: &[u8], read: impl FnOnce(&mut PackedDecoder<'_>) -> T) -> T {
    read(&mut PackedDecoder::new(bytes, &Spaces))
}

/// `<data>` holding the attributes in `bytes`, in the packed form.
pub fn data_with(attributes: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x41];
    bytes.extend_from_slice(attributes);
    bytes.push(0x81);
    bytes
}

pub fn by_name(name: &str) -> Option<i64> {
    match name {
        "COPY" => Some(1),
        "LOAD" => Some(2),
        _ => None,
    }
}
