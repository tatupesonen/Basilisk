//! `<default_symbols>`: labels every program of the language starts with.

use roxmltree::Node;

use super::address::AddressSpec;
use crate::{
    error::ParseError,
    reader::{Reader, children_named},
    schema::{DEFAULT_SYMBOLS, SYMBOL},
    value::{decode_bool, decode_i32},
};

/// What a default symbol labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// `code`: an instruction.
    Code,
    /// `code_ptr`: a pointer to code, such as an interrupt vector.
    CodePtr,
}

impl SymbolType {
    /// Parses the `type` attribute; letter case is ignored, as in Ghidra.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.eq_ignore_ascii_case("code") {
            Some(Self::Code)
        } else if text.eq_ignore_ascii_case("code_ptr") {
            Some(Self::CodePtr)
        } else {
            None
        }
    }
}

/// Where a default symbol is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolAddress {
    /// An address as written.
    At(AddressSpec),
    /// `next`: directly after the previous symbol — its address plus its
    /// [`size`](DefaultSymbol::size), or plus nothing when it has none (so
    /// the same address; this is what Ghidra computes). An error when there
    /// is no previous symbol.
    Next,
}

/// One `<symbol>` of `<default_symbols>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultSymbol {
    /// The label.
    pub name: String,
    /// Where it goes.
    pub address: SymbolAddress,
    /// What it labels, if stated.
    pub symbol_type: Option<SymbolType>,
    /// Whether the address is an entry point.
    pub entry: bool,
    /// The size in bytes of the labelled range; `None` (absent or 0) means
    /// one addressable unit.
    pub size: Option<u32>,
    /// Whether the labelled range is volatile (`Some(true)`), explicitly
    /// not volatile inside a volatile region (`Some(false)`), or neither.
    pub volatile: Option<bool>,
    /// A comment for the label.
    pub description: Option<String>,
}

/// Reads a `<default_symbols>` element, appending its symbols in file
/// order.
pub(crate) fn read(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    symbols: &mut Vec<DefaultSymbol>,
) -> Result<(), ParseError> {
    r.check(node, &DEFAULT_SYMBOLS)?;
    for symbol in children_named(node, SYMBOL.name) {
        let def = &SYMBOL;
        r.check(symbol, def)?;
        let address = r.required(symbol, def, "address")?;
        let address = if address.eq_ignore_ascii_case("next") {
            SymbolAddress::Next
        } else {
            SymbolAddress::At(AddressSpec::new(address))
        };
        let size = r
            .decode(symbol, def, "size", "a non-negative size in bytes", |s| {
                decode_i32(s).and_then(|v| u32::try_from(v).ok())
            })?
            .filter(|size| *size != 0);
        symbols.push(DefaultSymbol {
            name: r.required(symbol, def, "name")?.to_owned(),
            address,
            symbol_type: r.decode(symbol, def, "type", "code or code_ptr", SymbolType::parse)?,
            entry: Reader::flag(symbol, "entry"),
            size,
            volatile: symbol.attribute("volatile").and_then(decode_bool),
            description: symbol.attribute("description").map(str::to_owned),
        });
    }
    Ok(())
}
