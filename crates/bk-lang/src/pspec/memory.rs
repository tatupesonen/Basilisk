//! `<default_memory_blocks>`: memory blocks every program of the language
//! starts with.

use roxmltree::Node;

use super::address::AddressSpec;
use crate::{
    error::{ParseError, ParseErrorKind},
    reader::{Reader, children_named},
    schema::{DEFAULT_MEMORY_BLOCKS, MEMORY_BLOCK},
};

/// How many bytes of a byte-mapped block map onto how many source bytes
/// (`byte_mapped_address="rom:1000/1:2"`: one byte of every two).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteMappingRatio {
    /// Mapped bytes per group, 1 to 127.
    pub mapped: u8,
    /// Source bytes per group, 1 to 127 and at least `mapped`.
    pub source: u8,
}

impl ByteMappingRatio {
    /// Parses `mapped:source`, with the limits Ghidra's `ByteMappingScheme`
    /// sets.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (mapped, source) = text.split_once(':')?;
        let mapped: u8 = mapped.parse().ok()?;
        let source: u8 = source.parse().ok()?;
        ((1..=127).contains(&mapped) && (mapped..=127).contains(&source))
            .then_some(Self { mapped, source })
    }
}

/// What backs a default memory block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryBlockKind {
    /// Its own bytes, zero-filled when `initialized`, otherwise without
    /// content.
    Default {
        /// Whether the block has (zero) bytes.
        initialized: bool,
    },
    /// Each byte mirrors one bit of memory starting at `address`.
    BitMapped {
        /// Where the mapped bits start.
        address: AddressSpec,
    },
    /// Each byte mirrors a byte of memory starting at `address`.
    ByteMapped {
        /// Where the mapped bytes start.
        address: AddressSpec,
        /// Which source bytes are mapped; `None` maps every byte.
        ratio: Option<ByteMappingRatio>,
    },
}

/// One `<memory_block>` of `<default_memory_blocks>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlock {
    /// The block's name.
    pub name: String,
    /// Where the block starts.
    pub start_address: AddressSpec,
    /// The block's length in bytes; always positive.
    pub length: u32,
    /// What backs the block.
    pub kind: MemoryBlockKind,
    /// The access mode in lower case: any of `r`, `w`, `x` and `v`
    /// (volatile). `rw` when the file gives none.
    pub mode: String,
    /// Whether the block is an overlay.
    pub overlay: bool,
}

impl MemoryBlock {
    /// Whether the block is readable.
    #[must_use]
    pub fn is_read(&self) -> bool {
        self.mode.contains('r')
    }

    /// Whether the block is writable.
    #[must_use]
    pub fn is_write(&self) -> bool {
        self.mode.contains('w')
    }

    /// Whether the block is executable.
    #[must_use]
    pub fn is_execute(&self) -> bool {
        self.mode.contains('x')
    }

    /// Whether the block is volatile.
    #[must_use]
    pub fn is_volatile(&self) -> bool {
        self.mode.contains('v')
    }
}

/// Decodes a length as Ghidra's `XmlUtilities.parseInt` does: an optional
/// `-`, then decimal digits or `0x` and hexadecimal digits, truncated to 32
/// bits; the result must be positive.
fn length(text: &str) -> Option<u32> {
    let (negative, digits) = text.strip_prefix('-').map_or((false, text), |d| (true, d));
    let magnitude = match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u64>().ok()?,
    };
    if digits.starts_with(['+', '-']) {
        return None;
    }
    let value = if negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    } as u32 as i32;
    u32::try_from(value).ok().filter(|v| *v > 0)
}

/// Decodes a memory-block boolean. Ghidra's `XmlUtilities.parseBoolean`
/// takes `y`, `n`, `true` and `false` in any case and rejects the rest,
/// which makes it refuse `yes`, `no`, `1` and `0` although the schema
/// allows them; those are accepted here.
fn boolean(text: &str) -> Option<bool> {
    let is = |candidates: &[&str]| candidates.iter().any(|c| text.eq_ignore_ascii_case(c));
    if is(&["y", "true", "yes", "1"]) {
        Some(true)
    } else if is(&["n", "false", "no", "0"]) {
        Some(false)
    } else {
        None
    }
}

/// Reads a `<default_memory_blocks>` element, appending its blocks in file
/// order.
pub(crate) fn read(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    blocks: &mut Vec<MemoryBlock>,
) -> Result<(), ParseError> {
    const BOOLEAN: &str = "a boolean";
    r.check(node, &DEFAULT_MEMORY_BLOCKS)?;
    for block in children_named(node, MEMORY_BLOCK.name) {
        let def = &MEMORY_BLOCK;
        r.check(block, def)?;
        let reject = |message: &str| {
            r.fatal(
                block,
                ParseErrorKind::Rejected {
                    element: def.name,
                    message: message.to_owned(),
                },
            )
        };
        let bit_mapped = block.attribute("bit_mapped_address");
        let byte_mapped = block.attribute("byte_mapped_address");
        let initialized = r.decode(block, def, "initialized", BOOLEAN, boolean)?;
        let given = usize::from(bit_mapped.is_some())
            + usize::from(byte_mapped.is_some())
            + usize::from(initialized.is_some());
        let kind = match (bit_mapped, byte_mapped) {
            (Some(_), Some(_)) => {
                return Err(reject(
                    "may not specify both bit_mapped_address and byte_mapped_address",
                ));
            }
            (Some(_), None) | (None, Some(_)) if initialized.is_some() => {
                return Err(reject(
                    "mapped block specifications must not specify initialized attribute",
                ));
            }
            (Some(address), None) => MemoryBlockKind::BitMapped {
                address: AddressSpec::new(address),
            },
            (None, Some(mapped)) => {
                // "rom:1000/1:2": an address, then the ratio after a slash.
                let (address, ratio) = match mapped.split_once('/') {
                    Some((address, ratio)) if !address.is_empty() => {
                        let ratio = ByteMappingRatio::parse(ratio).ok_or_else(|| {
                            r.invalid(
                                block,
                                def,
                                "byte_mapped_address",
                                mapped,
                                "an address, optionally followed by /mapped:source with 1 <= mapped <= source <= 127",
                            )
                        })?;
                        (address, Some(ratio))
                    }
                    _ => (mapped, None),
                };
                MemoryBlockKind::ByteMapped {
                    address: AddressSpec::new(address),
                    ratio,
                }
            }
            (None, None) => MemoryBlockKind::Default {
                initialized: initialized.unwrap_or(false),
            },
        };
        if given != 1 {
            r.rule(
                block,
                def,
                "exactly one of bit_mapped_address, byte_mapped_address and initialized is required",
            )?;
        }
        let length_text = r.required(block, def, "length")?;
        blocks.push(MemoryBlock {
            name: r.required(block, def, "name")?.to_owned(),
            start_address: AddressSpec::new(r.required(block, def, "start_address")?),
            length: length(length_text)
                .ok_or_else(|| r.invalid(block, def, "length", length_text, "a positive length"))?,
            kind,
            mode: block
                .attribute("mode")
                .map_or_else(|| "rw".to_owned(), str::to_lowercase),
            overlay: r
                .decode(block, def, "overlay", BOOLEAN, boolean)?
                .unwrap_or(false),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("0x100", Some(256))]
    #[case("16", Some(16))]
    #[case("0", None)]
    #[case("-1", None)]
    #[case("", None)]
    #[case("0x", None)]
    #[case("1k", None)]
    #[case("0x80000000", None)]
    #[case("0x100000001", Some(1))]
    #[case("--1", None)]
    fn length_decodes_like_ghidra(#[case] text: &str, #[case] expected: Option<u32>) {
        assert_eq!(length(text), expected);
    }

    #[rstest]
    #[case("1:2", Some((1, 2)))]
    #[case("2:4", Some((2, 4)))]
    #[case("127:127", Some((127, 127)))]
    #[case("2:1", None)]
    #[case("0:1", None)]
    #[case("1:128", None)]
    #[case("1", None)]
    #[case("a:b", None)]
    fn ratio_has_ghidras_limits(#[case] text: &str, #[case] expected: Option<(u8, u8)>) {
        assert_eq!(
            ByteMappingRatio::parse(text).map(|r| (r.mapped, r.source)),
            expected
        );
    }

    #[test]
    fn booleans_take_ghidras_and_the_schemas_spellings() {
        for t in ["y", "Y", "true", "TRUE", "yes", "1"] {
            assert_eq!(boolean(t), Some(true), "{t}");
        }
        for f in ["n", "false", "False", "no", "0"] {
            assert_eq!(boolean(f), Some(false), "{f}");
        }
        assert_eq!(boolean("maybe"), None);
        assert_eq!(boolean(""), None);
    }
}
