//! Addresses and address ranges as `.pspec` files write them: parsed, but
//! not resolved against a language's address spaces.

use roxmltree::Node;

use crate::{error::ParseError, reader::Reader, schema::ElementDef, value::decode_u64};

/// An address as written in a `.pspec` attribute: `space:offset` or a bare
/// offset in the language's default space (`ram:0x1000`, `SFR:80`, `FFFE`).
///
/// Ghidra's address parser splits at the last `:`; what precedes it names
/// an address space and what follows is a hexadecimal offset in
/// addressable units, with or without `0x`, optionally followed by
/// `.` and a unit offset for spaces whose units are wider than a byte.
/// Turning that into an address needs the language's spaces — a job for
/// an [`AddressResolver`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressSpec(String);

/// The numeric part of an [`AddressSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressOffset {
    /// The offset in addressable units of the space.
    pub units: u64,
    /// The byte within the unit, from a `.n` suffix; `0` when absent.
    pub unit_offset: u64,
}

impl AddressSpec {
    /// Wraps an address string as written.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The address as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The address-space name: the text before the last `:`, if there is
    /// one.
    #[must_use]
    pub fn space(&self) -> Option<&str> {
        self.0.rfind(':').and_then(|colon| self.0.get(..colon))
    }

    /// The offset text: what follows the last `:`, or the whole string.
    #[must_use]
    pub fn offset_text(&self) -> &str {
        self.0
            .rfind(':')
            .and_then(|colon| self.0.get(colon + 1..))
            .unwrap_or(&self.0)
    }

    /// The offset as a number: hexadecimal with an optional `0x`/`0X`
    /// prefix and an optional `.n` unit-offset suffix. `None` when the text
    /// is not such a number or exceeds 64 bits.
    #[must_use]
    pub fn offset(&self) -> Option<AddressOffset> {
        let text = self.offset_text();
        let text = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        let (units, unit_offset) = match text.split_once('.') {
            Some((units, rest)) if !units.is_empty() => {
                (units, u64::from_str_radix(rest, 16).ok()?)
            }
            _ => (text, 0),
        };
        if units.starts_with(['+', '-']) {
            return None;
        }
        Some(AddressOffset {
            units: u64::from_str_radix(units, 16).ok()?,
            unit_offset,
        })
    }

    /// Resolves the address with `resolver`.
    pub fn resolve<R: AddressResolver + ?Sized>(&self, resolver: &R) -> Option<R::Address> {
        resolver.resolve_address(self)
    }
}

/// Turns the unresolved addresses and ranges of a `.pspec` into real ones.
///
/// Implemented by whatever knows a language's address spaces (the SLEIGH
/// runtime); this crate only carries the text.
pub trait AddressResolver {
    /// The resolved address type.
    type Address;

    /// The address `spec` denotes, or `None` if it names no space of the
    /// language or its offset is out of range.
    fn resolve_address(&self, spec: &AddressSpec) -> Option<Self::Address>;

    /// The first and last address of `range`, or `None` if its space is
    /// unknown or its bounds are out of range.
    fn resolve_range(&self, range: &AddressRange) -> Option<(Self::Address, Self::Address)>;
}

/// A range of addresses in one space (`<range>`, and the range attributes
/// of `<context_set>` and `<tracked_set>`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressRange {
    /// The address space's name.
    pub space: String,
    /// The first offset; the start of the space when absent.
    pub first: Option<u64>,
    /// The last offset, inclusive; the end of the space when absent.
    pub last: Option<u64>,
}

impl AddressRange {
    /// Reads the `space`, `first` and `last` attributes of `node`.
    pub(crate) fn read(
        r: &mut Reader<'_, '_>,
        node: Node<'_, '_>,
        def: &'static ElementDef,
    ) -> Result<Self, ParseError> {
        const OFFSET: &str = "an offset (decimal, 0x hexadecimal or 0 octal)";
        let first = r.decode(node, def, "first", OFFSET, decode_u64)?;
        let last = r.decode(node, def, "last", OFFSET, decode_u64)?;
        if first.is_some() != last.is_some() {
            r.rule(node, def, "first and last must be given together")?;
        }
        Ok(Self {
            space: r.required(node, def, "space")?.to_owned(),
            first,
            last,
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("ram:0x1000", Some("ram"), "0x1000", Some((0x1000, 0)))]
    #[case("SFR:80", Some("SFR"), "80", Some((0x80, 0)))]
    #[case("FFFE", None, "FFFE", Some((0xFFFE, 0)))]
    #[case("0X10", None, "0X10", Some((0x10, 0)))]
    #[case("mem:0x20.1", Some("mem"), "0x20.1", Some((0x20, 1)))]
    #[case("a:b:10", Some("a:b"), "10", Some((0x10, 0)))]
    #[case("ram:", Some("ram"), "", None)]
    #[case("ram:xyz", Some("ram"), "xyz", None)]
    #[case("ram:-1", Some("ram"), "-1", None)]
    #[case("1ffffffffffffffff", None, "1ffffffffffffffff", None)]
    #[case("next", None, "next", None)]
    fn splits_space_and_offset(
        #[case] text: &str,
        #[case] space: Option<&str>,
        #[case] offset_text: &str,
        #[case] offset: Option<(u64, u64)>,
    ) {
        let spec = AddressSpec::new(text);
        assert_eq!(spec.as_str(), text);
        assert_eq!(spec.space(), space);
        assert_eq!(spec.offset_text(), offset_text);
        assert_eq!(spec.offset().map(|o| (o.units, o.unit_offset)), offset);
    }

    struct OneSpace;
    impl AddressResolver for OneSpace {
        type Address = u64;
        fn resolve_address(&self, spec: &AddressSpec) -> Option<u64> {
            matches!(spec.space(), None | Some("ram"))
                .then(|| spec.offset())
                .flatten()
                .map(|o| o.units)
        }
        fn resolve_range(&self, range: &AddressRange) -> Option<(u64, u64)> {
            (range.space == "ram")
                .then(|| (range.first.unwrap_or(0), range.last.unwrap_or(u64::MAX)))
        }
    }

    #[test]
    fn resolver_hook_resolves_addresses_and_ranges() {
        assert_eq!(AddressSpec::new("ram:10").resolve(&OneSpace), Some(0x10));
        assert_eq!(AddressSpec::new("20").resolve(&OneSpace), Some(0x20));
        assert_eq!(AddressSpec::new("io:10").resolve(&OneSpace), None);
        let range = AddressRange {
            space: "ram".into(),
            first: Some(4),
            last: None,
        };
        assert_eq!(OneSpace.resolve_range(&range), Some((4, u64::MAX)));
    }
}
