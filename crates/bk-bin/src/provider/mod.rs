//! Byte providers: random-access, read-only byte sources with a known length.
//!
//! The [`ByteProvider`] trait is the contract; the other types are the
//! providers Ghidra supplies in `ghidra.app.util.bin`, with its semantics:
//!
//! | Basilisk | Ghidra |
//! |---|---|
//! | [`MemoryProvider`] | `ByteArrayProvider` |
//! | [`FileProvider`] | `FileByteProvider` |
//! | [`SubProvider`] | `ByteProviderWrapper` |
//! | [`UnlimitedProvider`] | `UnlimitedByteProviderWrapper` |
//! | [`RangeMappedProvider`] | `RangeMappedByteProvider` |
//! | [`EmptyProvider`] | `EmptyByteProvider` |
//! | [`FillProvider`] | `StaticValueByteProvider` |
//!
//! There is no counterpart of `SynchronizedByteProvider`: every provider is
//! already safe to read from many threads.

mod file;
mod fill;
mod memory;
mod range_mapped;
mod sub;
mod traits;

pub use file::FileProvider;
pub use fill::{EmptyProvider, FillProvider};
pub use memory::MemoryProvider;
pub use range_mapped::RangeMappedProvider;
pub use sub::{SubProvider, UnlimitedProvider};
pub use traits::ByteProvider;
