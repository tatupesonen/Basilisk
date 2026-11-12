//! Throughput benchmarks (ADR-012), as ignored tests. Run with
//!
//! ```text
//! BASILISK_GHIDRA_DIR=../ghidra cargo test --release -p bk-marshal --test bench -- --ignored --nocapture --test-threads 1
//! ```
//!
//! and record the printed lines in `docs/PERF.md`. Each measurement is the
//! best of several runs.

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

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ELEM_DATA,
    ELEM_INPUT,
};
use bk_marshal::{
    Decoder, Document, Encoder, IdTable, PackedDecoder, PackedEncoder, PackedSpace, SpaceId,
    SpaceRef, SpaceResolver, XmlDecoder,
};

const ELEMENTS: u32 = 1_000_000;
const RUNS: usize = 5;
/// Times the small `.cspec` is decoded per measurement.
const REPEAT: u32 = 1_000;

/// Spaces 0 to 3, all present.
struct Spaces;

impl SpaceResolver for Spaces {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        (name == "ram").then_some(SpaceId::new(2))
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        (index < 4).then(|| SpaceId::new(index as u32))
    }

    fn space_count(&self) -> u64 {
        4
    }

    fn stack_space(&self) -> Option<SpaceId> {
        None
    }

    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

const RAM: SpaceRef<'static> = SpaceRef {
    name: "ram",
    packed: PackedSpace::Index(2),
};

/// One million `<input>` elements under a `<data>` root, each with a space,
/// an unsigned offset, a signed size, a boolean and a short string: the mix
/// of a p-code dump.
fn encode_document(encoder: &mut dyn Encoder) {
    encoder.open_element(ELEM_DATA);
    for i in 0..ELEMENTS {
        encoder.open_element(ELEM_INPUT);
        encoder.write_space(ATTRIB_SPACE, &RAM);
        encoder.write_unsigned(ATTRIB_OFFSET, 0x40_0000 + u64::from(i) * 4);
        encoder.write_signed(ATTRIB_SIZE, i64::from(i % 16) - 8);
        encoder.write_bool(ATTRIB_ID, i % 3 == 0);
        encoder.write_string(ATTRIB_NAME, "local_10").unwrap();
        encoder.close_element(ELEM_INPUT);
    }
    encoder.close_element(ELEM_DATA);
}

/// Reads the document back the way a consumer would, returning a checksum.
fn decode_document(decoder: &mut dyn Decoder<'_>) -> u64 {
    let mut sum = 0u64;
    let root = decoder.open_element_expecting(ELEM_DATA).unwrap();
    while decoder.peek_element().is_some() {
        let element = decoder.open_element_expecting(ELEM_INPUT).unwrap();
        sum = sum.wrapping_add(u64::from(
            decoder.read_space_attr(ATTRIB_SPACE).unwrap().index(),
        ));
        sum = sum.wrapping_add(decoder.read_unsigned_attr(ATTRIB_OFFSET).unwrap());
        sum = sum.wrapping_add(decoder.read_signed_attr(ATTRIB_SIZE).unwrap() as u64);
        sum = sum.wrapping_add(u64::from(decoder.read_bool_attr(ATTRIB_ID).unwrap()));
        sum = sum.wrapping_add(decoder.read_string_attr(ATTRIB_NAME).unwrap().len() as u64);
        decoder.close_element(element).unwrap();
    }
    decoder.close_element(root).unwrap();
    sum
}

/// Reads the document by iterating each element's attributes in order,
/// the cheaper pattern for the packed form (a lookup by id rescans the
/// element's attributes, as Ghidra's does).
fn decode_document_in_order(decoder: &mut dyn Decoder<'_>) -> u64 {
    let mut sum = 0u64;
    let root = decoder.open_element_expecting(ELEM_DATA).unwrap();
    while decoder.peek_element().is_some() {
        let element = decoder.open_element_expecting(ELEM_INPUT).unwrap();
        while let Some(attribute) = decoder.next_attribute().unwrap() {
            let value = if attribute == ATTRIB_SPACE {
                u64::from(decoder.read_space().unwrap().index())
            } else if attribute == ATTRIB_OFFSET {
                decoder.read_unsigned().unwrap()
            } else if attribute == ATTRIB_SIZE {
                decoder.read_signed().unwrap() as u64
            } else if attribute == ATTRIB_ID {
                u64::from(decoder.read_bool().unwrap())
            } else {
                decoder.read_string().unwrap().len() as u64
            };
            sum = sum.wrapping_add(value);
        }
        decoder.close_element(element).unwrap();
    }
    decoder.close_element(root).unwrap();
    sum
}

fn best(mut run: impl FnMut()) -> Duration {
    (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed()
        })
        .min()
        .unwrap()
}

fn report(what: &str, time: Duration, bytes: usize, elements: u64) {
    let seconds = time.as_secs_f64();
    eprintln!(
        "bench: {what}: {:.1} ms, {:.0} MB/s, {:.1} M elements/s ({bytes} bytes, {elements} elements)",
        seconds * 1e3,
        bytes as f64 / seconds / 1e6,
        elements as f64 / seconds / 1e6,
    );
}

#[test]
#[ignore = "benchmark; run with --release --ignored"]
fn packed_encode_and_decode_one_million_elements() {
    let mut size = 0;
    let time = best(|| {
        let mut encoder = PackedEncoder::new();
        encode_document(&mut encoder);
        size = black_box(encoder.into_bytes()).len();
    });
    report(
        "packed encode, 1M elements",
        time,
        size,
        u64::from(ELEMENTS),
    );

    let mut encoder = PackedEncoder::new();
    encode_document(&mut encoder);
    let bytes = encoder.into_bytes();
    let mut sum = 0;
    let time = best(|| sum = black_box(decode_document(&mut PackedDecoder::new(&bytes, &Spaces))));
    assert_ne!(sum, 0);
    report(
        "packed decode by attribute id, 1M elements",
        time,
        bytes.len(),
        u64::from(ELEMENTS),
    );
    let mut in_order = 0;
    let time = best(|| {
        in_order = black_box(decode_document_in_order(&mut PackedDecoder::new(
            &bytes, &Spaces,
        )));
    });
    assert_eq!(in_order, sum);
    report(
        "packed decode in attribute order, 1M elements",
        time,
        bytes.len(),
        u64::from(ELEMENTS),
    );
}

#[test]
#[ignore = "benchmark; run with --release --ignored"]
fn xml_encode_and_decode_one_million_elements() {
    let ids = IdTable::marshal_only();
    let mut size = 0;
    let time = best(|| {
        let mut encoder = bk_marshal::XmlEncoder::new(false);
        encode_document(&mut encoder);
        size = black_box(encoder.into_string()).len();
    });
    report("xml encode, 1M elements", time, size, u64::from(ELEMENTS));

    let mut encoder = bk_marshal::XmlEncoder::new(false);
    encode_document(&mut encoder);
    let text = encoder.into_string();
    let time = best(|| {
        black_box(Document::parse(&text).unwrap());
    });
    report(
        "xml parse, 1M elements",
        time,
        text.len(),
        u64::from(ELEMENTS),
    );
    let document = Document::parse(&text).unwrap();
    let time = best(|| {
        black_box(decode_document(&mut XmlDecoder::new(
            &document, &ids, &Spaces,
        )));
    });
    report(
        "xml decode by attribute id (parsed), 1M elements",
        time,
        text.len(),
        u64::from(ELEMENTS),
    );
    let time = best(|| {
        black_box(decode_document_in_order(&mut XmlDecoder::new(
            &document, &ids, &Spaces,
        )));
    });
    report(
        "xml decode in attribute order (parsed), 1M elements",
        time,
        text.len(),
        u64::from(ELEMENTS),
    );
}

fn ghidra_dir() -> Option<PathBuf> {
    let dir = match std::env::var_os("BASILISK_GHIDRA_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../ghidra"),
    };
    if dir.join("Ghidra/Processors").is_dir() {
        Some(dir)
    } else {
        eprintln!(
            "skipped: no Ghidra source tree at {} (set BASILISK_GHIDRA_DIR)",
            dir.display()
        );
        None
    }
}

/// Walks a whole document, reading every attribute as a string.
fn walk(decoder: &mut dyn Decoder<'_>) -> usize {
    let mut seen = 0;
    let mut open = Vec::new();
    loop {
        if decoder.peek_element().is_some() {
            open.push(decoder.open_element().unwrap().unwrap());
            while decoder.next_attribute().unwrap().is_some() {
                seen += decoder.read_string().unwrap().len();
            }
            seen += decoder.read_string_attr(ATTRIB_CONTENT).unwrap().len();
            continue;
        }
        match open.pop() {
            Some(element) => decoder.close_element(element).unwrap(),
            None => return seen,
        }
    }
}

#[test]
#[ignore = "benchmark; run with --release --ignored"]
fn xml_decode_largest_cspec() {
    let Some(ghidra) = ghidra_dir() else {
        return;
    };
    let path = ghidra.join("Ghidra/Processors/x86/data/languages/x86-64-golang.cspec");
    let text = std::fs::read_to_string(&path).unwrap();
    let ids = IdTable::marshal_only();
    let elements = Document::parse(&text).unwrap().element_count() as u64;
    let time = best(|| {
        for _ in 0..REPEAT {
            let document = Document::parse(black_box(&text)).unwrap();
            black_box(walk(&mut XmlDecoder::new(&document, &ids, &Spaces)));
        }
    }) / REPEAT;
    report(
        "xml parse + decode, x86-64-golang.cspec",
        time,
        text.len(),
        elements,
    );
}
