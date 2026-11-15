//! Field codecs of the state dump: each field of each record has exactly one
//! spelling, read by `parse` and written by `write`, so that a record
//! written back is the same text. The `record!` macro builds a record
//! struct, its reader and its writer from a list of `field: Codec` pairs.

use std::marker::PhantomData;

use crate::oracle::graph::OracleAddress;
use crate::oracle::text::{escape, parse_hex_u64, parse_i32, parse_u32, push_display, unescape};

/// How one field is read and written.
pub(crate) trait Codec {
    /// The field's value.
    type Value;
    /// Read the field's text; `None` when it is not in its one spelling.
    fn parse(text: &str) -> Option<Self::Value>;
    /// Append the field's text.
    fn write(value: &Self::Value, out: &mut String);
}

/// Decimal numbers of a given type.
pub(crate) struct Dec<T>(PhantomData<T>);
/// `0x…` hexadecimal numbers of a given type.
pub(crate) struct Hex<T>(PhantomData<T>);

impl Codec for Dec<u32> {
    type Value = u32;
    fn parse(text: &str) -> Option<u32> {
        parse_u32(text)
    }
    fn write(value: &u32, out: &mut String) {
        push_display(out, value);
    }
}

impl Codec for Dec<i32> {
    type Value = i32;
    fn parse(text: &str) -> Option<i32> {
        parse_i32(text)
    }
    fn write(value: &i32, out: &mut String) {
        push_display(out, value);
    }
}

impl Codec for Hex<u32> {
    type Value = u32;
    fn parse(text: &str) -> Option<u32> {
        parse_hex_u64(text).and_then(|v| u32::try_from(v).ok())
    }
    fn write(value: &u32, out: &mut String) {
        push_display(out, &format_args!("{value:#x}"));
    }
}

impl Codec for Hex<u64> {
    type Value = u64;
    fn parse(text: &str) -> Option<u64> {
        parse_hex_u64(text)
    }
    fn write(value: &u64, out: &mut String) {
        push_display(out, &format_args!("{value:#x}"));
    }
}

/// An escaped text field (may be empty).
pub(crate) struct Text;

impl Codec for Text {
    type Value = String;
    fn parse(text: &str) -> Option<String> {
        unescape(text)
    }
    fn write(value: &String, out: &mut String) {
        out.push_str(&escape(value));
    }
}

/// A non-empty token without commas or escapes (an item of a list field).
pub(crate) struct Token;

impl Codec for Token {
    type Value = String;
    fn parse(text: &str) -> Option<String> {
        let ok = !text.is_empty() && text != "-" && !text.contains([',', '\\', '\t']);
        ok.then(|| text.to_owned())
    }
    fn write(value: &String, out: &mut String) {
        out.push_str(value);
    }
}

/// `0` or `1`.
pub(crate) struct Flag;

impl Codec for Flag {
    type Value = bool;
    fn parse(text: &str) -> Option<bool> {
        match text {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    }
    fn write(value: &bool, out: &mut String) {
        out.push(if *value { '1' } else { '0' });
    }
}

/// `<space>:0x<offset>`.
pub(crate) struct Addr;

impl Codec for Addr {
    type Value = OracleAddress;
    fn parse(text: &str) -> Option<OracleAddress> {
        OracleAddress::parse(text)
    }
    fn write(value: &OracleAddress, out: &mut String) {
        push_display(out, value);
    }
}

/// `-` or a value.
pub(crate) struct Opt<C>(PhantomData<C>);

impl<C: Codec> Codec for Opt<C> {
    type Value = Option<C::Value>;
    fn parse(text: &str) -> Option<Self::Value> {
        if text == "-" {
            Some(None)
        } else {
            C::parse(text).map(Some)
        }
    }
    fn write(value: &Self::Value, out: &mut String) {
        match value {
            Some(v) => C::write(v, out),
            None => out.push('-'),
        }
    }
}

/// A comma-separated list, `-` when empty.
pub(crate) struct List<C>(PhantomData<C>);

impl<C: Codec> Codec for List<C> {
    type Value = Vec<C::Value>;
    fn parse(text: &str) -> Option<Self::Value> {
        if text == "-" {
            return Some(Vec::new());
        }
        text.split(',').map(C::parse).collect()
    }
    fn write(value: &Self::Value, out: &mut String) {
        if value.is_empty() {
            out.push('-');
        }
        for (i, item) in value.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            C::write(item, out);
        }
    }
}

/// Builds a record struct with a reader and a writer from its fields.
macro_rules! record {
    (
        $(#[$meta:meta])*
        $name:ident = $tag:literal {
            $( $(#[$fmeta:meta])* $field:ident : $ty:ty = $codec:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $( $(#[$fmeta])* pub $field: $ty, )*
        }

        impl $name {
            /// The record's tag.
            pub const TAG: &'static str = $tag;

            /// Read the record from its fields (the tag first).
            pub(crate) fn parse(
                record: &$crate::oracle::text::Record<'_>,
            ) -> Result<Self, $crate::oracle::text::ParseError> {
                const NAMES: &[&str] = &[$(stringify!($field)),*];
                record.expect($tag, NAMES.len() + 1, concat!("a ", $tag, " record"))?;
                let mut index = 0_usize;
                $(
                    index += 1;
                    let text = record.field(index);
                    let $field: $ty = <$codec as $crate::oracle::state::codec::Codec>::parse(text)
                        .ok_or_else(|| record.bad(stringify!($field), text))?;
                )*
                let _ = index;
                Ok(Self { $($field),* })
            }

            /// Append the record's line, line break included.
            pub(crate) fn write(&self, out: &mut String) {
                out.push_str($tag);
                $(
                    out.push('\t');
                    <$codec as $crate::oracle::state::codec::Codec>::write(&self.$field, out);
                )*
                out.push('\n');
            }
        }
    };
}

pub(crate) use record;
