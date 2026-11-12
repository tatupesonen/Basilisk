//! Property tests for the marshalling forms: arbitrary element trees survive
//! encode → decode in both forms, the two decoders agree on the same tree,
//! and neither decoder panics or hangs on arbitrary input.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

use bk_marshal::ids::{
    ATTRIB_ALIGN, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SPACE, ATTRIB_STORAGE, ATTRIB_VAL,
    ATTRIBUTES, ELEM_DATA, ELEM_INPUT, ELEM_OFF, ELEM_VOID, ELEMENTS,
};
use bk_marshal::{
    AttributeId, DecodeError, Decoder, Document, ElemCode, ElementId, Encoder, IdTable,
    PackedDecoder, PackedEncoder, PackedSpace, SpaceId, SpaceRef, SpaceResolver, XmlDecoder,
    XmlEncoder,
};
use proptest::prelude::*;

/// Ids that need the extension byte of the packed header.
const ELEM_BIG: ElementId = ElementId::new("big", 200);
const ELEM_HUGE: ElementId = ElementId::new("huge", 4000);
const ATTRIB_FAR: AttributeId = AttributeId::new("far", 3000);
const ATTRIB_PIECE: AttributeId = AttributeId::new("piece", 94);

const ELEMENT_POOL: [ElementId; 6] = [
    ELEM_DATA, ELEM_INPUT, ELEM_OFF, ELEM_VOID, ELEM_BIG, ELEM_HUGE,
];
const ATTRIBUTE_POOL: [AttributeId; 7] = [
    ATTRIB_ALIGN,
    ATTRIB_ID,
    ATTRIB_NAME,
    ATTRIB_SPACE,
    ATTRIB_VAL,
    ATTRIB_STORAGE,
    ATTRIB_FAR,
];

struct Spaces;

const RAM: SpaceId = SpaceId::new(3);

impl SpaceResolver for Spaces {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        (name == "ram").then_some(RAM)
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        (index == 3).then_some(RAM)
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

fn id_table() -> IdTable {
    IdTable::new(
        &[ATTRIBUTES, &[ATTRIB_FAR, ATTRIB_PIECE]],
        &[ELEMENTS, &[ELEM_BIG, ELEM_HUGE]],
    )
    .unwrap()
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Text(String),
    Space,
}

#[derive(Clone, Debug, PartialEq)]
struct Node {
    element: usize,
    /// Attributes in order; the indices into the pool are distinct.
    attributes: Vec<(usize, Value)>,
    /// Indexed strings (`piece1`, `piece2`, …), written after the attributes.
    pieces: Vec<String>,
    content: Option<String>,
    children: Vec<Self>,
}

/// Any text the packed form can hold: no NUL.
fn text() -> impl Strategy<Value = String> {
    any::<String>().prop_map(|s| s.replace('\0', ""))
}

/// Text content that the XML form reads back unchanged. Ghidra drops pieces
/// of content that are only white space, and a reference starts a new piece,
/// so white space next to an escaped character would be lost; content without
/// white space avoids that (the loss itself is tested in `xml::parse`).
fn content() -> impl Strategy<Value = String> {
    text().prop_filter_map("content must not be empty", |s| {
        let s: String = s
            .chars()
            .filter(|c| !matches!(c, ' ' | '\n' | '\r' | '\t'))
            .collect();
        (!s.is_empty()).then_some(s)
    })
}

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Signed),
        any::<u64>().prop_map(Value::Unsigned),
        // Values near the seven-bit group boundaries of the packed form.
        (0u32..64, -1i64..=1)
            .prop_map(|(bit, delta)| Value::Unsigned((1u64 << bit).wrapping_add_signed(delta))),
        (0u32..63, -1i64..=1, any::<bool>()).prop_map(|(bit, delta, negative)| {
            let magnitude = (1i64 << bit).wrapping_add(delta);
            Value::Signed(if negative {
                magnitude.wrapping_neg()
            } else {
                magnitude
            })
        }),
        text().prop_map(Value::Text),
        Just(Value::Space),
    ]
}

fn node() -> impl Strategy<Value = Node> {
    let leaf = (
        0..ELEMENT_POOL.len(),
        proptest::sample::subsequence((0..ATTRIBUTE_POOL.len()).collect::<Vec<_>>(), 0..=4)
            .prop_shuffle(),
        proptest::collection::vec(value(), 4),
        proptest::collection::vec(text(), 0..3),
        proptest::option::of(content()),
    )
        .prop_map(|(element, which, values, pieces, content)| Node {
            element,
            attributes: which.into_iter().zip(values).collect(),
            pieces,
            content,
            children: Vec::new(),
        });
    leaf.prop_recursive(4, 24, 4, |inner| {
        (inner.clone(), proptest::collection::vec(inner, 0..4)).prop_map(
            |(mut parent, children)| {
                parent.children = children;
                parent
            },
        )
    })
}

fn encode(encoder: &mut dyn Encoder, node: &Node) {
    let element = ELEMENT_POOL[node.element];
    encoder.open_element(element);
    for (which, value) in &node.attributes {
        let attribute = ATTRIBUTE_POOL[*which];
        match value {
            Value::Bool(v) => encoder.write_bool(attribute, *v),
            Value::Signed(v) => encoder.write_signed(attribute, *v),
            Value::Unsigned(v) => encoder.write_unsigned(attribute, *v),
            Value::Text(v) => encoder.write_string(attribute, v).unwrap(),
            Value::Space => {
                encoder.write_space(
                    attribute,
                    &SpaceRef {
                        name: "ram",
                        packed: PackedSpace::Index(3),
                    },
                );
            }
        }
    }
    for (index, piece) in node.pieces.iter().enumerate() {
        encoder
            .write_string_indexed(ATTRIB_PIECE, index as u32, piece)
            .unwrap();
    }
    if let Some(content) = &node.content {
        encoder.write_string(ATTRIB_CONTENT, content).unwrap();
    }
    for child in &node.children {
        encode(encoder, child);
    }
    encoder.close_element(element);
}

fn read_value(decoder: &mut dyn Decoder<'_>, like: &Value) -> Result<Value, DecodeError> {
    Ok(match like {
        Value::Bool(_) => Value::Bool(decoder.read_bool()?),
        Value::Signed(_) => Value::Signed(decoder.read_signed()?),
        Value::Unsigned(_) => Value::Unsigned(decoder.read_unsigned()?),
        Value::Text(_) => Value::Text(decoder.read_string()?.to_owned()),
        Value::Space => {
            assert_eq!(decoder.read_space()?, RAM);
            Value::Space
        }
    })
}

/// Decodes the next element, using `shape` only to choose which typed read
/// to call, and returns what was read.
fn decode(decoder: &mut dyn Decoder<'_>, shape: &Node) -> Result<Node, DecodeError> {
    let peeked = decoder.peek_element();
    let code = decoder.open_element()?.expect("an element");
    assert_eq!(peeked, Some(code));
    let element = ELEMENT_POOL
        .iter()
        .position(|id| code == *id)
        .expect("a known element");
    let mut attributes = Vec::new();
    let mut pieces = Vec::new();
    let mut content = None;
    while let Some(mut attribute) = decoder.next_attribute()? {
        if attribute == ATTRIB_CONTENT {
            // Only the packed form lists the content among the attributes.
            content = Some(decoder.read_string()?.to_owned());
            continue;
        }
        if attribute == bk_marshal::ids::ATTRIB_UNKNOWN {
            attribute = decoder.indexed_attribute(ATTRIB_PIECE)?;
        }
        if let Some(which) = ATTRIBUTE_POOL.iter().position(|id| attribute == *id) {
            let like = &shape.attributes[attributes.len()].1;
            attributes.push((which, read_value(decoder, like)?));
        } else {
            let index = attribute.get() - ATTRIB_PIECE.id();
            assert_eq!(index as usize, pieces.len());
            pieces.push(decoder.read_string()?.to_owned());
        }
    }
    if content.is_none() && shape.content.is_some() {
        content = Some(decoder.read_string_attr(ATTRIB_CONTENT)?.to_owned());
    }
    let mut children = Vec::new();
    for child in &shape.children {
        children.push(decode(decoder, child)?);
    }
    assert_eq!(decoder.peek_element(), None);
    decoder.close_element(code)?;
    Ok(Node {
        element,
        attributes,
        pieces,
        content,
        children,
    })
}

/// One step of a random walk over a decoder.
#[derive(Clone, Debug)]
enum Op {
    Peek,
    Open,
    OpenExpecting(usize),
    Close(u32),
    CloseCurrent,
    CloseSkipping,
    Next,
    Rewind,
    Indexed,
    Skip,
    Read(u8),
    ReadAttr(u8, usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        1 => Just(Op::Peek),
        3 => Just(Op::Open),
        1 => (0..ELEMENT_POOL.len()).prop_map(Op::OpenExpecting),
        1 => any::<u32>().prop_map(Op::Close),
        2 => Just(Op::CloseCurrent),
        1 => Just(Op::CloseSkipping),
        4 => Just(Op::Next),
        1 => Just(Op::Rewind),
        1 => Just(Op::Indexed),
        1 => Just(Op::Skip),
        4 => (0u8..7).prop_map(Op::Read),
        2 => ((0u8..7), 0..ATTRIBUTE_POOL.len() + 1).prop_map(|(kind, which)| Op::ReadAttr(kind, which)),
    ]
}

/// Applies the operations, ignoring every result: the only requirement is
/// that nothing panics.
fn drive(decoder: &mut dyn Decoder<'_>, ops: &[Op]) {
    let by_name = |name: &str| (name == "one").then_some(1);
    let mut open: Vec<ElemCode> = Vec::new();
    for op in ops {
        match op {
            Op::Peek => {
                let _ = decoder.peek_element();
            }
            Op::Open => {
                if let Ok(Some(code)) = decoder.open_element() {
                    open.push(code);
                }
            }
            Op::OpenExpecting(which) => {
                if let Ok(code) = decoder.open_element_expecting(ELEMENT_POOL[*which]) {
                    open.push(code);
                }
            }
            Op::Close(raw) => {
                let _ = decoder.close_element(ElemCode::new(*raw));
            }
            Op::CloseCurrent => {
                if let Some(code) = open.pop() {
                    let _ = decoder.close_element(code);
                }
            }
            Op::CloseSkipping => {
                if let Some(code) = open.pop() {
                    let _ = decoder.close_element_skipping(code);
                }
            }
            Op::Next => {
                let _ = decoder.next_attribute();
            }
            Op::Rewind => decoder.rewind_attributes(),
            Op::Indexed => {
                let _ = decoder.indexed_attribute(ATTRIB_PIECE);
            }
            Op::Skip => {
                let _ = decoder.skip_element();
            }
            Op::Read(kind) => match kind {
                0 => drop(decoder.read_bool()),
                1 => drop(decoder.read_signed()),
                2 => drop(decoder.read_unsigned()),
                3 => drop(decoder.read_string()),
                4 => drop(decoder.read_space()),
                5 => drop(decoder.read_signed_or_string("x", 1)),
                _ => drop(decoder.read_enum(&by_name)),
            },
            Op::ReadAttr(kind, which) => {
                let attribute = ATTRIBUTE_POOL
                    .get(*which)
                    .copied()
                    .unwrap_or(ATTRIB_CONTENT);
                match kind {
                    0 => drop(decoder.read_bool_attr(attribute)),
                    1 => drop(decoder.read_signed_attr(attribute)),
                    2 => drop(decoder.read_unsigned_attr(attribute)),
                    3 => drop(decoder.read_string_attr(attribute)),
                    4 => drop(decoder.read_space_attr(attribute)),
                    5 => drop(decoder.read_signed_or_string_attr(attribute, "x", 1)),
                    _ => drop(decoder.read_enum_attr(attribute, &by_name)),
                }
            }
        }
    }
}

/// Removes the content of elements that have children. With formatting on,
/// Ghidra's XML encoder writes a new line and indent before each child, and
/// that white space becomes part of the preceding content when read back
/// (`<a>text\n  <b/>` holds one piece, `text\n  `), so such content does not
/// survive the formatted form — in Ghidra as here.
fn without_mixed_content(tree: &Node) -> Node {
    let mut copy = tree.clone();
    if !copy.children.is_empty() {
        copy.content = None;
    }
    copy.children = copy.children.iter().map(without_mixed_content).collect();
    copy
}

fn packed_bytes(tree: &Node) -> Vec<u8> {
    let mut encoder = PackedEncoder::new();
    encode(&mut encoder, tree);
    encoder.into_bytes()
}

fn xml_text(tree: &Node, formatting: bool) -> String {
    let mut encoder = XmlEncoder::new(formatting);
    encode(&mut encoder, tree);
    encoder.into_string()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn packed_round_trip(tree in node()) {
        let bytes = packed_bytes(&tree);
        prop_assert!(!bytes.contains(&0), "the packed form never holds a NUL byte");
        let mut decoder = PackedDecoder::new(&bytes, &Spaces);
        let read = decode(&mut decoder, &tree).unwrap();
        prop_assert_eq!(&read, &tree);
        prop_assert_eq!(decoder.peek_element(), None);
        prop_assert_eq!(decoder.position(), bytes.len());
    }

    #[test]
    fn xml_round_trip(tree in node(), formatting in any::<bool>()) {
        let tree = if formatting { without_mixed_content(&tree) } else { tree };
        let text = xml_text(&tree, formatting);
        let ids = id_table();
        let document = Document::parse(&text).unwrap();
        let mut decoder = XmlDecoder::new(&document, &ids, &Spaces);
        let read = decode(&mut decoder, &tree).unwrap();
        prop_assert_eq!(&read, &tree);
        prop_assert_eq!(decoder.peek_element(), None);
    }

    /// The same logical document decodes to the same tree from either form.
    #[test]
    fn xml_and_packed_agree(tree in node(), formatting in any::<bool>()) {
        let tree = if formatting { without_mixed_content(&tree) } else { tree };
        let bytes = packed_bytes(&tree);
        let text = xml_text(&tree, formatting);
        let ids = id_table();
        let document = Document::parse(&text).unwrap();
        let from_xml = decode(&mut XmlDecoder::new(&document, &ids, &Spaces), &tree).unwrap();
        let from_packed = decode(&mut PackedDecoder::new(&bytes, &Spaces), &tree).unwrap();
        prop_assert_eq!(from_xml, from_packed);
    }

    /// Skipping an element lands in the same place as decoding it.
    #[test]
    fn skipping_matches_decoding(first in node(), second in node()) {
        let mut encoder = PackedEncoder::new();
        encoder.open_element(ELEM_DATA);
        encode(&mut encoder, &first);
        encode(&mut encoder, &second);
        encoder.close_element(ELEM_DATA);
        let bytes = encoder.into_bytes();
        let mut decoder = PackedDecoder::new(&bytes, &Spaces);
        let outer = decoder.open_element_expecting(ELEM_DATA).unwrap();
        decoder.skip_element().unwrap();
        let read = decode(&mut decoder, &second).unwrap();
        prop_assert_eq!(&read, &second);
        decoder.close_element(outer).unwrap();

        let mut decoder = PackedDecoder::new(&bytes, &Spaces);
        let outer = decoder.open_element_expecting(ELEM_DATA).unwrap();
        decoder.close_element_skipping(outer).unwrap();
        prop_assert_eq!(decoder.position(), bytes.len());
    }

    #[test]
    fn packed_decoder_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ops in proptest::collection::vec(op(), 0..64),
    ) {
        drive(&mut PackedDecoder::new(&bytes, &Spaces), &ops);
    }

    /// Corrupted encodings of real documents reach deeper into the decoder
    /// than random bytes do.
    #[test]
    fn packed_decoder_never_panics_on_damaged_documents(
        tree in node(),
        damage in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
        cut in any::<prop::sample::Index>(),
        ops in proptest::collection::vec(op(), 0..64),
    ) {
        let mut bytes = packed_bytes(&tree);
        for (at, byte) in damage {
            let at = at.index(bytes.len());
            bytes[at] = byte;
        }
        bytes.truncate(cut.index(bytes.len() + 1));
        drive(&mut PackedDecoder::new(&bytes, &Spaces), &ops);
        // A plain walk must end too.
        let mut decoder = PackedDecoder::new(&bytes, &Spaces);
        while let Ok(Some(code)) = decoder.open_element() {
            while let Ok(Some(_)) = decoder.next_attribute() {}
            if decoder.close_element_skipping(code).is_err() {
                break;
            }
        }
    }

    #[test]
    fn xml_parser_never_panics_on_arbitrary_text(text in any::<String>()) {
        let _ = Document::parse(&text);
    }

    #[test]
    fn xml_parser_never_panics_on_markup_soup(
        text in "[<>/=&;#!\\[\\]?\"' a-cx0-9\\n-]{0,200}",
        ops in proptest::collection::vec(op(), 0..32),
    ) {
        if let Ok(document) = Document::parse(&text) {
            let ids = id_table();
            drive(&mut XmlDecoder::new(&document, &ids, &Spaces), &ops);
        }
    }

    #[test]
    fn xml_decoder_never_panics_on_damaged_documents(
        tree in node(),
        damage in proptest::collection::vec((any::<prop::sample::Index>(), any::<char>()), 0..4),
        ops in proptest::collection::vec(op(), 0..64),
    ) {
        let mut text: Vec<char> = xml_text(&tree, true).chars().collect();
        for (at, replacement) in damage {
            let at = at.index(text.len());
            text[at] = replacement;
        }
        let text: String = text.into_iter().collect();
        if let Ok(document) = Document::parse(&text) {
            let ids = id_table();
            drive(&mut XmlDecoder::new(&document, &ids, &Spaces), &ops);
        }
    }

    /// The integer text forms never panic and agree with Rust's own parsing
    /// where the text is canonical.
    #[test]
    fn integer_text_forms(value in any::<u64>(), signed in any::<i64>(), junk in any::<String>()) {
        use bk_marshal::xml::number::{parse_i64, parse_u64};
        prop_assert_eq!(parse_u64(&format!("{value}")), value);
        prop_assert_eq!(parse_u64(&format!("0x{value:x}")), value);
        prop_assert_eq!(parse_u64(&format!("0{value:o}")), value);
        prop_assert_eq!(parse_i64(&format!("{signed}")), signed);
        prop_assert_eq!(parse_i64(&format!(" {signed}{junk}")), parse_i64(&format!("{signed}{junk}")));
        let _ = parse_u64(&junk);
        let _ = parse_i64(&junk);
    }
}
