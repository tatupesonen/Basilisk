//! The property part of Ghidra's `DecompilerPspecVolatilityTest` (spec 6.5;
//! Ghidra/Features/Decompiler/src/test.slow/java/ghidra/app/plugin/core/
//! decompile/DecompilerPspecVolatilityTest.java). Its inputs are the pspec
//! variants `SleighLanguageVolatilityTest.setUp` writes
//! (Framework/SoftwareModeling/src/test/java/ghidra/app/plugin/processors/
//! sleigh/SleighLanguageVolatilityTest.java:48–117): `PORTF` at `mem:0x31`
//! with an optional `volatile` and `size`, `PORTG` at `mem:0x34`, an
//! optional `<volatile>` range over `mem:0x20–0x57` or one that leaves out
//! `0x31`, and the two elements in either order. Its assertions are whether
//! the decompiler treats `mem:0x31` and `mem:0x34` as volatile, which is the
//! `volatil` bit of the property map after the architecture is set up:
//! `<volatile>` ranges set while the `.pspec` is read
//! (architecture.cc:883–894, `parseProcessorConfig` 1189–1190), the default
//! symbols' `volatile` attribute set or cleared afterwards, in
//! `buildSymbols` (`sleigh_arch.cc:265–318`; the Ghidra-hosted variant,
//! `ghidra_arch.cc:375–425`, applies the same property change and adds no
//! symbol) — so the file order of the two elements never matters.
//!
//! The whole decompilation (the `DAT_mem_0031 = DAT_mem_0031` text) is
//! D17's; the checklist line stays open until then.
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

use std::fmt::Write as _;
use std::sync::Arc;

use bk_core::{Address, Space, SpaceId, SpaceManager};
use bk_decomp_symbols::{ArchEnv, Database, VarnodeFlags, arch, ids};
use bk_decomp_types::{DataOrganization, TypeEnv, TypeFactory};
use bk_marshal::{Document, XmlDecoder};

/// `SleighLanguageVolatilityTest.setUp`'s pspec text, CRLF line ends and
/// all (the `atmega256.pspec` it is based on, cut down).
fn pspec(
    symbol_volatile: Option<bool>,
    symbol_size: Option<u32>,
    memory_volatile: Option<bool>,
    reverse: bool,
) -> String {
    let mut symbols = String::from(
        "  <default_symbols>\r\n\
         \x20   <symbol name=\"RESET\" address=\"code:0x0000\" entry=\"true\"/>\r\n\
         \x20   <symbol name=\"INT0\" address=\"code:0x0002\" entry=\"true\"/>\r\n\
         \x20   <symbol name=\"INT1\" address=\"code:0x0004\" entry=\"true\"/>\r\n\
         \x20   <symbol name=\"PORTE\" address=\"mem:0x2e\"/>\r\n\
         \x20   <symbol name=\"PINF\" address=\"mem:0x2f\"/>\r\n\
         \x20   <symbol name=\"DDRF\" address=\"mem:0x30\"/>\r\n\
         \x20   <symbol name=\"PORTF\" address=\"mem:0x31\"",
    );
    if let Some(v) = symbol_volatile {
        let _ = write!(symbols, " volatile=\"{v}\"");
    }
    if let Some(s) = symbol_size {
        let _ = write!(symbols, " size=\"{s}\"");
    }
    symbols.push_str(
        " />\r\n\
         \x20   <symbol name=\"PING\" address=\"mem:0x32\"/>\r\n\
         \x20   <symbol name=\"DDRG\" address=\"mem:0x33\"/>\r\n\
         \x20   <symbol name=\"PORTG\" address=\"mem:0x34\"/>\r\n\
         \x20   <symbol name=\"TIFR0\" address=\"mem:0x35\"/>\r\n  </default_symbols>\r\n",
    );
    let mut volatile =
        String::from("  <volatile outputop=\"write_volatile\" inputop=\"read_volatile\">\r\n");
    match memory_volatile {
        None => {}
        Some(true) => volatile.push_str("<range space=\"mem\" first=\"0x20\" last=\"0x57\"/>\r\n"),
        Some(false) => volatile.push_str(
            "<range space=\"mem\" first=\"0x20\" last=\"0x30\"/>\r\n\
             <range space=\"mem\" first=\"0x32\" last=\"0x57\"/>\r\n",
        ),
    }
    volatile
        .push_str("    <range space=\"mem\" first=\"0x60\" last=\"0xff\"/>\r\n  </volatile>\r\n");
    let (first, second) = if reverse {
        (&volatile, &symbols)
    } else {
        (&symbols, &volatile)
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n\r\n<processor_spec>\r\n\r\n\
         \x20 <programcounter register=\"PC\"/> \r\n  <data_space space=\"mem\"/>\r\n\
         {first}  \r\n  <context_data>\r\n    <tracked_set space=\"code\">\r\n\
         \x20     <set name=\"R1\" val=\"0\"/>\r\n    </tracked_set>\r\n  </context_data>\r\n  \r\n\
         {second}\r\n  <default_memory_blocks>\r\n\
         \x20   <memory_block name=\"regalias\" start_address=\"mem:0x00\" length=\"0x20\" initialized=\"false\"/>\r\n\
         \x20   <memory_block name=\"iospace\" start_address=\"mem:0x20\" length=\"0x1e0\" initialized=\"false\"/>\r\n\
         \x20   <memory_block name=\"sram\" start_address=\"mem:0x200\" length=\"0x4000\" initialized=\"false\"/>\r\n\
         \x20   <memory_block name=\"codebyte\" start_address=\"codebyte:0x0\" length=\"0x40000\" byte_mapped_address=\"code:0x0\"/>\r\n\
         \x20 </default_memory_blocks>\r\n\r\n\r\n</processor_spec>\r\n"
    )
}

/// The spaces of `avr8` (avr8.sinc:41–46: `code` word-addressed, the
/// default; `mem` byte-addressed, the pspec's data space).
fn avr8_spaces() -> (Arc<SpaceManager>, SpaceId) {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).unwrap();
    m.insert_space(Space::other()).unwrap();
    let code = m
        .insert_space(Space::processor("code", false, 3, 2, 2, true, 1, 1).unwrap())
        .unwrap();
    m.insert_space(Space::processor("register", false, 2, 1, 3, true, 0, 0).unwrap())
        .unwrap();
    let mem = m
        .insert_space(Space::processor("mem", false, 2, 1, 4, true, 1, 1).unwrap())
        .unwrap();
    m.insert_space(Space::processor("codebyte", false, 3, 1, 5, true, 1, 1).unwrap())
        .unwrap();
    m.set_default_code_space(code).unwrap();
    m.set_default_data_space(mem).unwrap();
    (Arc::new(m), mem)
}

/// Whether `mem:0x31` and `mem:0x34` are volatile after the architecture
/// read this pspec.
fn volatility(text: &str) -> (bool, bool) {
    let (spaces, mem) = avr8_spaces();
    let mut db = Database::new(ArchEnv::new(Arc::clone(&spaces)), true);
    let mut types =
        TypeFactory::with_core_types(TypeEnv::simple(2, false), DataOrganization::default())
            .unwrap();
    let table = ids::id_table();
    let doc = Document::parse(text).unwrap();
    let mut default_symbols = None;
    // parseProcessorConfig: <volatile> at once, <default_symbols> kept.
    for el in doc.root().children() {
        match el.name() {
            "volatile" => {
                let mut dec = XmlDecoder::at(el, &table, &*spaces);
                arch::decode_volatile(&mut db, &mut dec).unwrap();
            }
            "default_symbols" => default_symbols = Some(el),
            _ => {}
        }
    }
    db.adjust_caches();
    // buildSymbols, after the specs.
    let el = default_symbols.expect("a <default_symbols> element");
    let mut dec = XmlDecoder::at(el, &table, &*spaces);
    arch::build_default_symbols(&mut db, &mut dec, &mut types).unwrap();
    let volatile = |off| {
        db.property(Address::new(mem, off))
            .contains(VarnodeFlags::VOLATILE)
    };
    (volatile(0x31), volatile(0x34))
}

/// One `setUp` and what the Java test asserts after it: PORTF's volatility
/// and, where asserted, PORTG's.
struct Case {
    test: &'static str,
    symbol_volatile: Option<bool>,
    symbol_size: Option<u32>,
    memory_volatile: Option<bool>,
    reverse: bool,
    portf: bool,
    portg: Option<bool>,
}

const fn case(
    test: &'static str,
    symbol_volatile: Option<bool>,
    symbol_size: Option<u32>,
    memory_volatile: Option<bool>,
    reverse: bool,
    portf: bool,
    portg: Option<bool>,
) -> Case {
    Case {
        test,
        symbol_volatile,
        symbol_size,
        memory_volatile,
        reverse,
        portf,
        portg,
    }
}

/// Every assertion of the three property tests, in the Java order
/// (`testDecompileInterfaceReturnsAFunction` asserts only that a
/// decompilation exists: D17).
const CASES: &[Case] = &[
    case("SymbolPspecSettings", None, None, None, false, false, None),
    case(
        "SymbolPspecSettings",
        Some(false),
        None,
        None,
        false,
        false,
        None,
    ),
    case(
        "SymbolPspecSettings",
        Some(true),
        None,
        None,
        false,
        true,
        None,
    ),
    case(
        "MemoryPspecSettings",
        None,
        None,
        Some(true),
        false,
        true,
        None,
    ),
    case(
        "MemoryPspecSettings",
        None,
        None,
        Some(false),
        false,
        false,
        None,
    ),
    case("MemoryPspecSettings", None, None, None, false, false, None),
    case(
        "MemoryPspecSettings",
        Some(false),
        None,
        Some(true),
        false,
        false,
        None,
    ),
    case(
        "MemoryPspecSettings",
        Some(true),
        None,
        Some(true),
        false,
        true,
        None,
    ),
    case(
        "MemoryPspecSettings",
        Some(false),
        None,
        Some(true),
        true,
        false,
        None,
    ),
    case(
        "SizeOverwritesPORTG",
        Some(true),
        Some(1),
        None,
        false,
        true,
        Some(false),
    ),
    case(
        "SizeOverwritesPORTG",
        Some(false),
        Some(4),
        Some(true),
        false,
        false,
        Some(false),
    ),
    case(
        "SizeOverwritesPORTG",
        Some(true),
        Some(4),
        None,
        false,
        true,
        Some(true),
    ),
];

#[test]
fn decompiler_pspec_volatility_property_assertions() {
    for c in CASES {
        let (portf, portg) = volatility(&pspec(
            c.symbol_volatile,
            c.symbol_size,
            c.memory_volatile,
            c.reverse,
        ));
        let what = format!(
            "testDecompilePORTF{} setUp({:?}, {:?}, {:?}, {})",
            c.test, c.symbol_volatile, c.symbol_size, c.memory_volatile, c.reverse
        );
        assert_eq!(portf, c.portf, "PORTF, {what}");
        if let Some(g) = c.portg {
            assert_eq!(portg, g, "PORTG, {what}");
        }
    }
}

#[test]
fn the_order_of_volatile_and_default_symbols_never_matters() {
    for symbol_volatile in [None, Some(false), Some(true)] {
        for symbol_size in [None, Some(1), Some(4)] {
            for memory_volatile in [None, Some(false), Some(true)] {
                assert_eq!(
                    volatility(&pspec(symbol_volatile, symbol_size, memory_volatile, false)),
                    volatility(&pspec(symbol_volatile, symbol_size, memory_volatile, true)),
                    "setUp({symbol_volatile:?}, {symbol_size:?}, {memory_volatile:?})"
                );
            }
        }
    }
}
