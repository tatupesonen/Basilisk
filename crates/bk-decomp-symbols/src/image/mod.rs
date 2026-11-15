//! Load images (Ghidra `LoadImage`, `RawLoadImage`, `LoadImageXml`;
//! loadimage.cc, loadimage_xml.cc; spec 4.15).

pub mod hex;
mod raw;
mod xml;

use std::fmt;

use bk_core::{Address, RangeList};

use crate::error::DataUnavail;

pub use raw::RawImage;
pub use xml::XmlImage;

/// A symbol the image knows (Ghidra `LoadImageFunc`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadImageFunc {
    /// Its address.
    pub address: Address,
    /// Its name.
    pub name: String,
}

/// A section of the image (Ghidra `LoadImageSection`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadImageSection {
    /// The first address.
    pub address: Address,
    /// The size in bytes.
    pub size: u64,
    /// Ghidra's section flags.
    pub flags: u32,
}

/// The bytes of the program (Ghidra `LoadImage`). Object-safe.
pub trait LoadImage: Send + Sync + fmt::Debug {
    /// Fills `buf` with the bytes at `addr` (Ghidra `loadFill`); the bytes
    /// copied before a failure stay in the buffer.
    fn load_fill(&self, buf: &mut [u8], addr: Address) -> Result<(), DataUnavail>;
    /// The architecture string (Ghidra `getArchType`).
    fn arch_type(&self) -> &str;
    /// The symbols the image knows, in address order.
    fn symbols(&self) -> Vec<LoadImageFunc> {
        Vec::new()
    }
    /// The read-only ranges (Ghidra `getReadonly`).
    fn readonly(&self) -> RangeList {
        RangeList::default()
    }
    /// The sections.
    fn sections(&self) -> Vec<LoadImageSection> {
        Vec::new()
    }
    /// Moves the image by `adjust` addressable units (Ghidra `adjustVma`).
    fn adjust_vma(&mut self, adjust: i64);
}
