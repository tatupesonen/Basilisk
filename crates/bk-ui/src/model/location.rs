//! Addresses and locations: the coordinates every view shares.

use std::fmt;

/// An address in the program's default address space.
///
/// Displayed as Ghidra displays addresses: lower-case hexadecimal, at least
/// eight digits, no `0x` prefix.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Address(pub u64);

impl Address {
    /// The address `n` bytes further on, saturating at the top of the space.
    #[must_use]
    pub fn offset(self, n: u64) -> Self {
        Self(self.0.saturating_add(n))
    }

    /// Parses an address typed by a user: hexadecimal with or without `0x`.
    pub fn parse(text: &str) -> Option<Self> {
        let t = text.trim();
        let t = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        if t.is_empty() || t.len() > 16 {
            return None;
        }
        u64::from_str_radix(t, 16).ok().map(Self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

/// Where the user is: an address, and optionally the function holding it.
///
/// One `Location` is "current" for the whole tool (see `nav`); views that
/// follow it scroll to it, views that are pinned keep their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Location {
    /// The code unit (instruction or data) the cursor is on.
    pub address: Address,
}

impl Location {
    /// A location at `address`.
    #[must_use]
    pub fn at(address: Address) -> Self {
        Self { address }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_print_like_ghidra() {
        assert_eq!(Address(0x401000).to_string(), "00401000");
        assert_eq!(Address(0x1_0000_0650).to_string(), "100000650");
    }

    #[test]
    fn addresses_parse_with_or_without_prefix() {
        assert_eq!(Address::parse("0x401000"), Some(Address(0x401000)));
        assert_eq!(Address::parse(" 100000650 "), Some(Address(0x1_0000_0650)));
        assert_eq!(Address::parse("main"), None);
        assert_eq!(Address::parse(""), None);
        assert_eq!(Address::parse("11112222333344445"), None);
    }
}
