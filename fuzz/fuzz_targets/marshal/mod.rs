//! The bodies of the `packed_decode` and `xml_decode` targets (track
//! `core-marshal`): a random walk of decoder operations, a full walk of the
//! document, and the address-model decoders of `bk-core`. Every call may
//! fail; none may panic, loop or allocate without bound (ADR-009).
//!
//! Input layout: the first byte is the number of operation bytes that
//! follow; the rest is the document.
//!
//! This file is also compiled into `crates/bk-core/tests/fuzz_regressions.rs`,
//! which replays `fuzz/regressions/<target>/` with the same code, so it uses
//! only `bk-marshal` and `bk-core`.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "shared between the fuzz targets and a replay test"
)]

use bk_core::ids::{ATTRIB_PIECE, ATTRIB_UNIQ, ELEM_ADDR, id_table};
use bk_core::{
    Address, Range, RangeList, SeqNum, Space, SpaceId, SpaceManager, TruncationTag, VarnodeData,
};
use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ELEM_DATA,
};
use bk_marshal::{
    AttributeId, Decoder, Document, ElemCode, ElementId, PackedDecoder, SpaceResolver, XmlDecoder,
};

const ATTRIBUTES: [AttributeId; 7] = [
    ATTRIB_CONTENT,
    ATTRIB_NAME,
    ATTRIB_OFFSET,
    ATTRIB_SIZE,
    ATTRIB_SPACE,
    ATTRIB_UNIQ,
    ATTRIB_PIECE,
];
const ELEMENTS: [ElementId; 2] = [ELEM_ADDR, ELEM_DATA];

/// The `packed_decode` target.
pub fn packed_decode(data: &[u8]) {
    let (ops, document) = split(data);
    let manager = manager();
    drive(&mut PackedDecoder::new(document, &manager), ops);
    walk(&mut PackedDecoder::new(document, &manager), ops);
    address_model(&manager, |resolver| PackedDecoder::new(document, resolver));
}

/// The `xml_decode` target.
pub fn xml_decode(data: &[u8]) {
    let (ops, document) = split(data);
    let Ok(text) = std::str::from_utf8(document) else {
        return;
    };
    let Ok(document) = Document::parse(text) else {
        return;
    };
    let ids = id_table();
    let manager = manager();
    drive(&mut XmlDecoder::new(&document, &ids, &manager), ops);
    walk(&mut XmlDecoder::new(&document, &ids, &manager), ops);
    address_model(&manager, |resolver| {
        XmlDecoder::new(&document, &ids, resolver)
    });
}

/// Splits the input into operation bytes and the document.
fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let Some((&count, rest)) = data.split_first() else {
        return (&[], &[]);
    };
    rest.split_at(usize::from(count).min(rest.len()))
}

/// A small processor's spaces, so that space attributes can resolve.
fn manager() -> SpaceManager {
    let mut m = SpaceManager::new();
    let ram = Space::processor("ram", false, 4, 1, 2, true, 1, 1);
    let spaces = [
        Ok(Space::constant()),
        Ok(Space::other()),
        ram.clone(),
        Space::processor("register", false, 4, 1, 3, true, 0, 0),
        Space::unique(4, false),
        Space::join(5, false),
    ];
    for space in spaces.into_iter().flatten() {
        let _ = m.insert_space(space);
    }
    if let Ok(ram) = ram
        && let Ok(stack) = Space::spacebase("stack", 6, 4, &ram, 1, true, false)
    {
        let _ = m.insert_space(stack);
    }
    let _ = m.set_default_code_space(SpaceId::new(2));
    m
}

fn by_name(name: &str) -> Option<i64> {
    (name == "COPY").then_some(1)
}

fn read(decoder: &mut dyn Decoder<'_>, kind: u8) {
    match kind % 7 {
        0 => {
            let _ = decoder.read_bool();
        }
        1 => {
            let _ = decoder.read_signed();
        }
        2 => {
            let _ = decoder.read_unsigned();
        }
        3 => {
            let _ = decoder.read_string();
        }
        4 => {
            let _ = decoder.read_space();
        }
        5 => {
            let _ = decoder.read_signed_or_string("x", 1);
        }
        _ => {
            let _ = decoder.read_enum(&by_name);
        }
    }
}

fn read_attr(decoder: &mut dyn Decoder<'_>, kind: u8, attribute: AttributeId) {
    match kind % 7 {
        0 => {
            let _ = decoder.read_bool_attr(attribute);
        }
        1 => {
            let _ = decoder.read_signed_attr(attribute);
        }
        2 => {
            let _ = decoder.read_unsigned_attr(attribute);
        }
        3 => {
            let _ = decoder.read_string_attr(attribute);
        }
        4 => {
            let _ = decoder.read_space_attr(attribute);
        }
        5 => {
            let _ = decoder.read_signed_or_string_attr(attribute, "x", 1);
        }
        _ => {
            let _ = decoder.read_enum_attr(attribute, &by_name);
        }
    }
}

/// Interprets each operation byte as one decoder call: the low nibble picks
/// the call, the high nibble its argument.
fn drive(decoder: &mut dyn Decoder<'_>, ops: &[u8]) {
    let mut open: Vec<ElemCode> = Vec::new();
    for &op in ops {
        let arg = op >> 4;
        match op & 0xf {
            0 => {
                let _ = decoder.peek_element();
            }
            1 => {
                if let Ok(Some(code)) = decoder.open_element() {
                    open.push(code);
                }
            }
            2 => {
                let element = ELEMENTS[usize::from(arg) % ELEMENTS.len()];
                if let Ok(code) = decoder.open_element_expecting(element) {
                    open.push(code);
                }
            }
            3 => {
                let _ = decoder.close_element(ElemCode::new(u32::from(arg)));
            }
            4 => {
                if let Some(code) = open.pop() {
                    let _ = decoder.close_element(code);
                }
            }
            5 => {
                if let Some(code) = open.pop() {
                    let _ = decoder.close_element_skipping(code);
                }
            }
            6 | 7 => {
                let _ = decoder.next_attribute();
            }
            8 => decoder.rewind_attributes(),
            9 => {
                let _ = decoder.indexed_attribute(ATTRIB_PIECE);
            }
            10 => {
                let _ = decoder.skip_element();
            }
            11 | 12 => read(decoder, arg),
            _ => read_attr(
                decoder,
                arg,
                ATTRIBUTES[usize::from(arg) % ATTRIBUTES.len()],
            ),
        }
    }
}

/// Opens every element, reads every attribute (as the kind the operation
/// bytes choose, cycling) and closes each element, skipping what is left.
fn walk(decoder: &mut dyn Decoder<'_>, ops: &[u8]) {
    let mut kinds = ops.iter().copied().cycle();
    let mut open: Vec<ElemCode> = Vec::new();
    // Each step opens or closes an element, so the walk ends; the cap guards
    // against a decoder that would not advance.
    for _ in 0..1_000_000 {
        if decoder.peek_element().is_some() {
            let Ok(Some(code)) = decoder.open_element() else {
                return;
            };
            open.push(code);
            while let Ok(Some(_)) = decoder.next_attribute() {
                read(decoder, kinds.next().unwrap_or(3));
            }
            continue;
        }
        let Some(code) = open.pop() else {
            return;
        };
        if decoder.close_element_skipping(code).is_err() {
            return;
        }
    }
}

/// Runs the address-model decoders of `bk-core` over the document, each
/// with a fresh decoder made by `make`, then prints what they created.
fn address_model<'d, D, F>(manager: &'d SpaceManager, make: F)
where
    D: Decoder<'d>,
    F: Fn(&'d dyn SpaceResolver) -> D,
{
    let _ = VarnodeData::decode(&mut make(manager), manager);
    let _ = Address::decode_sized(&mut make(manager), manager);
    let _ = SeqNum::decode(&mut make(manager), manager);
    let _ = Range::decode(&mut make(manager), manager);
    let _ = RangeList::new().decode(&mut make(manager), manager);
    let _ = TruncationTag::decode(&mut make(manager));
    let _ = manager.decode_space(&mut make(manager));
    // A document of spaces, decoded into a fresh manager (space references
    // resolve against the fixture), then each space's raw form printed.
    let mut fresh = SpaceManager::new();
    if fresh.decode_spaces(&mut make(manager)).is_ok() {
        for space in fresh.spaces() {
            let _ = fresh
                .raw_offset(space.id(), u64::MAX)
                .map(|raw| raw.to_string());
        }
    }
    // Decoding join addresses created records; print them back.
    for record in manager.join_records() {
        let _ = record.unified().addr().raw(manager).to_string();
    }
}
