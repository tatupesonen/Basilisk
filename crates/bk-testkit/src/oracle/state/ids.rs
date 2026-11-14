//! The names a state dump gives Ghidra's objects (`decomp-oracle.md` 4.3):
//! reproducible keys, never host pointers.

use std::fmt;

use super::codec::Codec;
use crate::oracle::graph::OracleAddress;
use crate::oracle::text::{parse_hex_u64, parse_i32, parse_u32, push_display};

/// A p-code op's sequence number: the instruction address (absent for
/// ops without one) and the one-up `time`. Written `<address>:0x<time>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SeqNum {
    /// `SeqNum::pc`.
    pub addr: Option<OracleAddress>,
    /// `SeqNum::uniq`, one-up per function.
    pub time: u64,
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.addr {
            Some(a) => write!(f, "{a}:{:#x}", self.time),
            None => write!(f, "-:{:#x}", self.time),
        }
    }
}

impl Codec for SeqNum {
    type Value = Self;
    fn parse(text: &str) -> Option<Self> {
        let (addr, time) = text.rsplit_once(':')?;
        Some(Self {
            addr: if addr == "-" {
                None
            } else {
                Some(OracleAddress::parse(addr)?)
            },
            time: parse_hex_u64(time)?,
        })
    }
    fn write(value: &Self, out: &mut String) {
        push_display(out, value);
    }
}

/// Parse `<prefix><digits>` in decimal.
fn prefixed_dec(text: &str, prefix: char) -> Option<u32> {
    text.strip_prefix(prefix).and_then(parse_u32)
}

/// Parse `<prefix><hex digits>` (no `0x`, lower case, no leading zeros).
fn prefixed_hex(text: &str, prefix: char) -> Option<u64> {
    let digits = text.strip_prefix(prefix)?;
    parse_hex_u64(&format!("0x{digits}"))
}

macro_rules! name_type {
    ($(#[$meta:meta])* $name:ident($inner:ty), $prefix:literal, dec) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub $inner);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl Codec for $name {
            type Value = Self;
            fn parse(text: &str) -> Option<Self> {
                prefixed_dec(text, $prefix).map(Self)
            }
            fn write(value: &Self, out: &mut String) {
                push_display(out, value);
            }
        }
    };
    ($(#[$meta:meta])* $name:ident($inner:ty), $prefix:literal, hex) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub $inner);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{:x}", $prefix, self.0)
            }
        }

        impl Codec for $name {
            type Value = Self;
            fn parse(text: &str) -> Option<Self> {
                prefixed_hex(text, $prefix).and_then(|v| <$inner>::try_from(v).ok()).map(Self)
            }
            fn write(value: &Self, out: &mut String) {
                push_display(out, value);
            }
        }
    };
}

name_type!(
    /// A varnode: `v<create index, hex>` (`Varnode::create_index`).
    VarnodeId(u32),
    'v',
    hex
);
name_type!(
    /// A basic block: `b<index>` (`FlowBlock::index`).
    BlockRef(u32),
    'b',
    dec
);
name_type!(
    /// A high variable: `h<n>`, numbered by the smallest member create index.
    HighRef(u32),
    'h',
    dec
);
name_type!(
    /// A data type: `t<n>`, its position in the dump's `@types` table.
    TypeRef(u32),
    't',
    dec
);
name_type!(
    /// A call specification: `c<position in Funcdata::qlst>`.
    CallRef(u32),
    'c',
    dec
);
name_type!(
    /// A jump table: `j<position in Funcdata::jumpvec>`.
    JumpRef(u32),
    'j',
    dec
);
name_type!(
    /// A symbol: `s<symbolId, hex>`.
    SymbolRef(u64),
    's',
    hex
);

/// A varnode's offset with Ghidra's host pointers named (`decomp-oracle.md` 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarnodeOffset {
    /// An ordinary offset (`0x…`).
    Plain(u64),
    /// An `iop`-space varnode: the op it holds (`op:<seqnum>`).
    Op(SeqNum),
    /// An `fspec`-space varnode: the call spec it holds (`call:c<k>`).
    Call(CallRef),
    /// A `LOAD`/`STORE` space constant (`space:<name>`).
    Space(String),
}

impl Codec for VarnodeOffset {
    type Value = Self;
    fn parse(text: &str) -> Option<Self> {
        if let Some(rest) = text.strip_prefix("op:") {
            return SeqNum::parse(rest).map(Self::Op);
        }
        if let Some(rest) = text.strip_prefix("call:") {
            return CallRef::parse(rest).map(Self::Call);
        }
        if let Some(rest) = text.strip_prefix("space:") {
            let ok = !rest.is_empty() && !rest.contains(['\t', ',', '\\']);
            return ok.then(|| Self::Space(rest.to_owned()));
        }
        parse_hex_u64(text).map(Self::Plain)
    }
    fn write(value: &Self, out: &mut String) {
        match value {
            Self::Plain(v) => push_display(out, &format_args!("{v:#x}")),
            Self::Op(s) => {
                out.push_str("op:");
                push_display(out, s);
            }
            Self::Call(c) => {
                out.push_str("call:");
                push_display(out, c);
            }
            Self::Space(name) => {
                out.push_str("space:");
                out.push_str(name);
            }
        }
    }
}

/// A varnode's symbol entry: the symbol and the entry's position in its map
/// entries (`s<id>:<position>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryRef {
    /// The symbol.
    pub symbol: SymbolRef,
    /// Position in `Symbol::mapentry` (-1 when not found).
    pub position: i32,
}

impl Codec for EntryRef {
    type Value = Self;
    fn parse(text: &str) -> Option<Self> {
        let (sym, pos) = text.split_once(':')?;
        Some(Self {
            symbol: SymbolRef::parse(sym)?,
            position: parse_i32(pos)?,
        })
    }
    fn write(value: &Self, out: &mut String) {
        push_display(out, &format_args!("{}:{}", value.symbol, value.position));
    }
}

/// A byte range of a `RangeList`: `<space>:0x<first>-0x<last>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OracleRange {
    /// The address space.
    pub space: String,
    /// The first byte.
    pub first: u64,
    /// The last byte.
    pub last: u64,
}

impl Codec for OracleRange {
    type Value = Self;
    fn parse(text: &str) -> Option<Self> {
        let (space, span) = text.rsplit_once(':')?;
        let (first, last) = span.split_once('-')?;
        let ok = !space.is_empty() && !space.contains([',', '\t', '\\']);
        ok.then_some(())?;
        Some(Self {
            space: space.to_owned(),
            first: parse_hex_u64(first)?,
            last: parse_hex_u64(last)?,
        })
    }
    fn write(value: &Self, out: &mut String) {
        push_display(
            out,
            &format_args!("{}:{:#x}-{:#x}", value.space, value.first, value.last),
        );
    }
}

/// Where a symbol entry is stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntryStorage {
    /// A `MapEntry`'s address.
    Address(OracleAddress),
    /// A `DynamicEntry`'s hash (`hash:0x…`).
    Hash(u64),
    /// Neither (`-`).
    None,
}

impl Codec for EntryStorage {
    type Value = Self;
    fn parse(text: &str) -> Option<Self> {
        if text == "-" {
            return Some(Self::None);
        }
        if let Some(rest) = text.strip_prefix("hash:") {
            return parse_hex_u64(rest).map(Self::Hash);
        }
        OracleAddress::parse(text).map(Self::Address)
    }
    fn write(value: &Self, out: &mut String) {
        match value {
            Self::Address(a) => push_display(out, a),
            Self::Hash(h) => push_display(out, &format_args!("hash:{h:#x}")),
            Self::None => out.push('-'),
        }
    }
}

/// Two decimal numbers `a:b` (a jump table's block position and address index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexPair(pub i32, pub i32);

impl Codec for IndexPair {
    type Value = Self;
    fn parse(text: &str) -> Option<Self> {
        let (a, b) = text.split_once(':')?;
        Some(Self(parse_i32(a)?, parse_i32(b)?))
    }
    fn write(value: &Self, out: &mut String) {
        push_display(out, &format_args!("{}:{}", value.0, value.1));
    }
}
