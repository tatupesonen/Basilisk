//! The binary reader: a cursor over a provider with a byte order.

mod cursor;
mod int;
pub mod leb128;
mod string;

pub use cursor::BinaryReader;
pub use int::MAX_ARRAY_ELEMENTS;
pub use string::{Charset, MAX_STRING_BYTES};
