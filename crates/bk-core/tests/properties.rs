//! Property tests: encode → decode round trips of the address model in both
//! forms, text round trips, range-list invariants, and decoding arbitrary
//! bytes without panicking.

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

mod common;

use std::collections::BTreeSet;

use bk_core::ids::id_table;
use bk_core::{Address, Range, RangeList, SeqNum, SpaceId, SpaceManager, VarnodeData};
use bk_marshal::{
    Decoder, Document, Encoder, PackedDecoder, PackedEncoder, XmlDecoder, XmlEncoder,
};
use common::{RAM, REGISTER, STACK, UNIQUE, manager};
use proptest::prelude::*;

/// Encodes in both forms and decodes each back.
fn both<T>(
    m: &SpaceManager,
    encode: impl Fn(&mut dyn Encoder),
    decode: impl for<'a> Fn(&mut dyn Decoder<'a>) -> T,
) -> (T, T) {
    let ids = id_table();
    let mut xml = XmlEncoder::new(true);
    encode(&mut xml);
    let text = xml.into_string();
    let doc = Document::parse(&text).unwrap();
    let from_xml = decode(&mut XmlDecoder::new(&doc, &ids, m));
    let mut packed = PackedEncoder::new();
    encode(&mut packed);
    let bytes = packed.into_bytes();
    let from_packed = decode(&mut PackedDecoder::new(&bytes, m));
    (from_xml, from_packed)
}

fn space() -> impl Strategy<Value = SpaceId> {
    prop_oneof![Just(RAM), Just(REGISTER), Just(UNIQUE), Just(STACK)]
}

/// An offset that fits the 4-byte spaces of the fixture.
fn offset() -> impl Strategy<Value = u64> {
    0u64..=0xffff_ffff
}

fn range() -> impl Strategy<Value = Range> {
    (space(), offset(), offset()).prop_map(|(s, a, b)| Range::new(s, a.min(b), a.max(b)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn address_round_trip(s in space(), off in offset(), size in 0u32..64) {
        let m = manager(false);
        let a = Address::new(s, off);
        let (x, p) = both(&m, |e| a.encode(e, &m).unwrap(), |d| Address::decode(d, &m).unwrap());
        prop_assert_eq!((x, p), (a, a));
        let v = VarnodeData::new(s, off, size);
        let (x, p) = both(&m, |e| v.encode(e, &m).unwrap(), |d| VarnodeData::decode(d, &m).unwrap());
        prop_assert_eq!((x, p), (v, v));
    }

    #[test]
    fn seqnum_round_trip(s in space(), off in offset(), uniq: u32) {
        let m = manager(true);
        let seq = SeqNum::new(Address::new(s, off), uniq);
        let (x, p) = both(&m, |e| seq.encode(e, &m).unwrap(), |d| SeqNum::decode(d, &m).unwrap());
        prop_assert_eq!((x, p), (seq, seq));
    }

    #[test]
    fn range_list_round_trip(ranges in prop::collection::vec(range(), 0..12)) {
        let m = manager(false);
        let mut list = RangeList::new();
        for r in &ranges {
            list.insert(*r);
        }
        let (x, p) = both(&m, |e| list.encode(e, &m).unwrap(), |d| {
            let mut decoded = RangeList::new();
            decoded.decode(d, &m).unwrap();
            decoded
        });
        prop_assert_eq!(&x, &list);
        prop_assert_eq!(&p, &list);
    }

    /// After any sequence of insertions and removals, the list holds exactly
    /// the bytes a naive set of offsets would, and its ranges do not overlap.
    #[test]
    fn range_list_matches_a_byte_set(
        ops in prop::collection::vec((any::<bool>(), 0u64..64, 0u64..16), 0..24)
    ) {
        let mut list = RangeList::new();
        let mut bytes = BTreeSet::new();
        for (insert, first, len) in ops {
            let last = first + len;
            if insert {
                list.insert_range(RAM, first, last);
                bytes.extend(first..=last);
            } else {
                list.remove_range(RAM, first, last);
                for b in first..=last {
                    bytes.remove(&b);
                }
            }
        }
        let mut covered = BTreeSet::new();
        let mut previous_last: Option<u64> = None;
        for r in list.iter() {
            prop_assert!(r.first() <= r.last());
            if let Some(prev) = previous_last {
                prop_assert!(r.first() > prev);
            }
            previous_last = Some(r.last());
            covered.extend(r.first()..=r.last());
        }
        prop_assert_eq!(&covered, &bytes);
        for b in 0u64..90 {
            prop_assert_eq!(list.in_range(Address::new(RAM, b), 1), bytes.contains(&b));
        }
    }

    #[test]
    fn join_round_trip(slots in prop::collection::vec(0u64..16, 2..5)) {
        // Pieces of the default size, which the text form implies when it
        // does not name a register.
        let m = manager(false);
        let pieces: Vec<VarnodeData> = slots
            .into_iter()
            .map(|slot| VarnodeData::new(RAM, slot * 0x100, 4))
            .collect();
        let total: u32 = pieces.iter().map(|p| p.size).sum();
        let join = m.find_add_join(pieces.clone(), 0).unwrap().unified().addr();
        let (x, p) = both(&m, |e| join.encode(e, &m).unwrap(), |d| VarnodeData::decode(d, &m).unwrap());
        prop_assert_eq!(x, VarnodeData::from_address(join, total));
        prop_assert_eq!(p, VarnodeData::from_address(join, total));
        // The text form reads back to the same record.
        let text = join.raw(&m).to_string();
        let inner = text.trim_start_matches('{').trim_end_matches('}');
        prop_assert_eq!(m.read(common::JOIN, inner).unwrap(), (join.offset(), total));
    }

    #[test]
    fn text_round_trip(s in space(), off in offset()) {
        let m = manager(false);
        let text = Address::new(s, off).raw(&m).to_string();
        prop_assert_eq!(m.read(s, &text).unwrap().0, off);
    }

    /// Arbitrary bytes never panic the decoders of the address model.
    #[test]
    fn packed_garbage_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let m = manager(false);
        let _ = VarnodeData::decode(&mut PackedDecoder::new(&bytes, &m), &m);
        let _ = SeqNum::decode(&mut PackedDecoder::new(&bytes, &m), &m);
        let _ = Range::decode(&mut PackedDecoder::new(&bytes, &m), &m);
        let _ = RangeList::new().decode(&mut PackedDecoder::new(&bytes, &m), &m);
        let mut fresh = SpaceManager::new();
        let dir = fresh.directory();
        let _ = fresh.decode_spaces(&mut PackedDecoder::new(&bytes, &*dir));
    }
}
