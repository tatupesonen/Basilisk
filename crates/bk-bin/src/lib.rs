//! Byte providers and the typed, endian-aware binary reader shared by every
//! basilisk format parser (ELF, PE, Mach-O, DWARF, PDB, …).
//!
//! This crate corresponds to Ghidra's `ghidra.app.util.bin` package:
//!
//! * [`ByteProvider`] and the providers in [`provider`] are the counterparts
//!   of `ByteProvider` and its implementations (`ByteArrayProvider`,
//!   `FileByteProvider`, `ByteProviderWrapper`, `UnlimitedByteProviderWrapper`,
//!   `RangeMappedByteProvider`, `EmptyByteProvider`, `StaticValueByteProvider`).
//! * [`BinaryReader`] is the counterpart of `BinaryReader`: integer, array and
//!   string reads at a cursor or at an explicit index, in either byte order.
//! * [`leb128`] is the counterpart of `ghidra.program.model.data.LEB128` and
//!   `LEB128Info`.
//!
//! Design points that differ from Ghidra (see `docs/features/bin-elf.md`):
//!
//! * Providers take `&self` and are `Send + Sync`: any number of threads can
//!   read one provider without wrapping it in a lock.
//! * Reads borrow instead of copying when the bytes are in memory
//!   ([`ByteProvider::as_slice`], [`ByteProvider::read_bytes`] returning a
//!   [`Cow`](std::borrow::Cow)); the reader takes a slice fast path with no
//!   virtual call in that case.
//! * Every read returns a [`Result`]; nothing panics on any input.
//!
//! # Example
//!
//! ```
//! use bk_bin::{BinaryReader, Endian, MemoryProvider};
//!
//! let provider = MemoryProvider::new(vec![0x34, 0x12, b'h', b'i', 0]);
//! let mut reader = BinaryReader::new(&provider, Endian::Little);
//! assert_eq!(reader.read_u16()?, 0x1234);
//! assert_eq!(reader.read_ascii()?, "hi");
//! assert!(!reader.has_next());
//! # Ok::<(), bk_bin::BinError>(())
//! ```

mod endian;
mod error;
pub mod provider;
mod reader;

pub use endian::Endian;
pub use error::{BinError, Result};
pub use provider::{
    ByteProvider, EmptyProvider, FileProvider, FillProvider, MemoryProvider, RangeMappedProvider,
    SubProvider, UnlimitedProvider,
};
pub use reader::leb128::{self, Leb128Info};
pub use reader::{BinaryReader, Charset, MAX_ARRAY_ELEMENTS, MAX_STRING_BYTES};
