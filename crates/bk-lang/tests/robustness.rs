//! No input makes a reader panic: arbitrary bytes, arbitrary markup, and
//! valid documents with random damage.

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

use bk_lang::{
    Mode,
    ldefs::{self},
    opinion,
    pspec::{self, SymbolAddress},
};
use common::documents::{LDEFS, OPINION, PSPEC};
use proptest::prelude::*;

fn read_all(text: &str) {
    for mode in [Mode::Strict, Mode::Lenient] {
        let _ = ldefs::parse(text, mode);
        let _ = pspec::parse(text, mode);
        if let Ok(parsed) = opinion::parse(text, mode) {
            let _ = parsed.value.resolved();
        }
    }
}

/// A valid document with a few bytes replaced, removed or duplicated:
/// input that gets past the XML parser far more often than random bytes.
fn damaged(document: &'static str) -> impl Strategy<Value = String> {
    let edit = (0..document.len(), 0u8..3, any::<u8>());
    prop::collection::vec(edit, 1..6).prop_map(move |edits| {
        let mut bytes = document.as_bytes().to_vec();
        for (at, kind, byte) in edits {
            let at = at.min(bytes.len().saturating_sub(1));
            match kind {
                0 => bytes[at] = byte,
                1 => {
                    bytes.remove(at);
                }
                _ => bytes.insert(at, byte),
            }
            if bytes.is_empty() {
                bytes.push(b'<');
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn readers_never_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        read_all(&String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn readers_never_panic_on_arbitrary_markup(text in r#"(<[a-z_]{1,12}( [a-zA-Z_]{1,10}="[^"<&]{0,8}")*/?>|</[a-z_]{1,12}>|[a-z ]{0,6}){0,24}"#) {
        read_all(&text);
    }

    #[test]
    fn readers_never_panic_on_damaged_ldefs(text in damaged(LDEFS)) {
        read_all(&text);
    }

    #[test]
    fn readers_never_panic_on_damaged_pspec(text in damaged(PSPEC)) {
        read_all(&text);
    }

    #[test]
    fn readers_never_panic_on_damaged_opinion(text in damaged(OPINION)) {
        read_all(&text);
    }

    #[test]
    fn value_attributes_never_panic(value in r#"[^"<&]{0,24}"#) {
        // Every decoded attribute, fed arbitrary text.
        let pspec = format!(
            r#"<processor_spec><data_space space="s" ptr_wordsize="{value}"/>
            <inferptrbounds><range space="s" first="{value}" last="{value}"/></inferptrbounds>
            <context_data><context_set space="s"><set name="n" val="{value}"/></context_set></context_data>
            <register_data><register name="r" vector_lane_sizes="{value}" hidden="{value}"/></register_data>
            <default_symbols><symbol name="s" address="{value}" size="{value}" type="{value}"/></default_symbols>
            <default_memory_blocks><memory_block name="m" start_address="{value}" length="{value}"
                byte_mapped_address="{value}" mode="{value}" overlay="{value}"/></default_memory_blocks>
            </processor_spec>"#
        );
        if let Ok(parsed) = pspec::parse(&pspec, Mode::Lenient) {
            for block in &parsed.value.context_data {
                for set in &block.values {
                    let _ = set.value();
                }
            }
            for symbol in &parsed.value.default_symbols {
                if let SymbolAddress::At(address) = &symbol.address {
                    let _ = (address.space(), address.offset_text(), address.offset());
                }
            }
        }
        let ldefs = format!(
            r#"<language_definitions><language processor="p" endian="{value}" size="{value}" variant="v"
            version="{value}" slafile="s" processorspec="p" id="{value}"><description/>
            <truncate_space space="s" size="{value}"/><compiler name="n" spec="s" id="i"/></language></language_definitions>"#
        );
        let _ = ldefs::parse(&ldefs, Mode::Lenient);
        let opinion = format!(r#"<opinions><constraint endian="{value}" size="{value}" secondary="{value}"/></opinions>"#);
        let _ = opinion::parse(&opinion, Mode::Lenient);
        let _ = opinion::secondary_attribute_matches(&value, &value);
        let _ = opinion::secondary_attribute_matches("5", &format!("0b{value}"));
        let _ = opinion::secondary_attribute_matches("5", &format!("0x{value}"));
    }
}
