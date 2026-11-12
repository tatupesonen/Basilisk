//! `<context_data>`: default values of context and tracked registers.

use roxmltree::Node;

use super::address::AddressRange;
use crate::{
    error::ParseError,
    reader::{Reader, children_named},
    schema::{CONTEXT_DATA, CONTEXT_SET, ElementDef, SET, TRACKED_SET},
};

/// Which registers a [`ContextBlock`] sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextKind {
    /// `<context_set>`: SLEIGH context register fields, which steer
    /// instruction decoding.
    Context,
    /// `<tracked_set>`: ordinary registers assumed to hold a value at
    /// function entry.
    Tracked,
}

/// One `<set>`: a register and the value it gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextValue {
    /// The register or context-field name.
    pub name: String,
    /// The value as written: decimal, or hexadecimal after `0x`/`0X`.
    pub val: String,
    /// The optional description.
    pub description: Option<String>,
}

impl ContextValue {
    /// The value as a number. As in Ghidra, text that is not a number
    /// counts as 0 (so does a negative number or one wider than 128 bits).
    #[must_use]
    pub fn value(&self) -> u128 {
        let hex = self
            .val
            .strip_prefix("0x")
            .or_else(|| self.val.strip_prefix("0X"));
        let (digits, radix) = hex.map_or((self.val.as_str(), 10), |h| (h, 16));
        let digits = digits.strip_prefix('+').unwrap_or(digits);
        if digits.starts_with(['+', '-']) {
            return 0;
        }
        u128::from_str_radix(digits, radix).unwrap_or(0)
    }
}

/// One `<context_set>` or `<tracked_set>`: values that hold over a range
/// of addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextBlock {
    /// Whether this sets context fields or tracked registers.
    pub kind: ContextKind,
    /// The addresses the values apply to.
    pub range: AddressRange,
    /// The values, in file order.
    pub values: Vec<ContextValue>,
}

/// Reads a `<context_data>` element, appending its blocks in file order.
pub(crate) fn read(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    blocks: &mut Vec<ContextBlock>,
) -> Result<(), ParseError> {
    r.check(node, &CONTEXT_DATA)?;
    for block in node.children().filter(Node::is_element) {
        let (kind, def): (_, &'static ElementDef) = match block.tag_name().name() {
            "context_set" => (ContextKind::Context, &CONTEXT_SET),
            "tracked_set" => (ContextKind::Tracked, &TRACKED_SET),
            _ => continue,
        };
        r.check(block, def)?;
        let range = AddressRange::read(r, block, def)?;
        let mut values = Vec::new();
        for set in children_named(block, SET.name) {
            r.check(set, &SET)?;
            values.push(ContextValue {
                name: r.required(set, &SET, "name")?.to_owned(),
                val: r.required(set, &SET, "val")?.to_owned(),
                description: set.attribute("description").map(str::to_owned),
            });
        }
        blocks.push(ContextBlock {
            kind,
            range,
            values,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("0", 0)]
    #[case("1", 1)]
    #[case("0x10", 16)]
    #[case("0XfF", 255)]
    #[case("+7", 7)]
    #[case("010", 10)]
    #[case("", 0)]
    #[case("abc", 0)]
    #[case("-1", 0)]
    #[case("0x", 0)]
    #[case("0xffffffffffffffffffff", 0xffff_ffff_ffff_ffff_ffff)]
    fn value_decodes_like_ghidra(#[case] val: &str, #[case] expected: u128) {
        let value = ContextValue {
            name: "r".into(),
            val: val.into(),
            description: None,
        };
        assert_eq!(value.value(), expected);
    }
}
