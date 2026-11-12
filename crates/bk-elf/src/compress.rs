//! Compressed sections (`SHF_COMPRESSED`).

use std::io::Read;

use bk_bin::BinaryReader;

use crate::header::ElfClass;

/// `ch_type`: zlib (deflate) compression, the only algorithm Ghidra reads.
pub const ELFCOMPRESS_ZLIB: u32 = 1;
/// `ch_type`: Zstandard compression. Recognised by name only.
pub const ELFCOMPRESS_ZSTD: u32 = 2;

/// The header at the start of a compressed section's data (`Elf32_Chdr` /
/// `Elf64_Chdr`; Ghidra's `ElfCompressedSectionHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionHeader {
    /// Compression algorithm.
    pub ch_type: u32,
    /// Size of the uncompressed data in bytes.
    pub ch_size: u64,
    /// Alignment of the uncompressed data.
    pub ch_addralign: u64,
    /// Size of this header in bytes: 12 in a 32-bit file, 24 in a 64-bit one.
    pub header_size: u32,
}

impl CompressionHeader {
    /// Size of the header for a file of class `class`.
    pub const fn size_for(class: ElfClass) -> u32 {
        match class {
            ElfClass::Elf32 => 12,
            ElfClass::Elf64 => 24,
        }
    }

    /// Reads a header at the reader's position.
    pub(crate) fn read(reader: &mut BinaryReader<'_>, class: ElfClass) -> bk_bin::Result<Self> {
        let ch_type = reader.read_u32()?;
        let (ch_size, ch_addralign) = match class {
            ElfClass::Elf32 => (u64::from(reader.read_u32()?), u64::from(reader.read_u32()?)),
            ElfClass::Elf64 => {
                reader.read_u32()?; // ch_reserved
                (reader.read_u64()?, reader.read_u64()?)
            }
        };
        Ok(Self {
            ch_type,
            ch_size,
            ch_addralign,
            header_size: Self::size_for(class),
        })
    }

    /// True when the algorithm can be decompressed (zlib only, as in Ghidra).
    pub const fn is_supported(&self) -> bool {
        self.ch_type == ELFCOMPRESS_ZLIB
    }
}

/// The result of decompressing a section.
///
/// Ghidra wraps the inflater in a fault-tolerant stream: when the compressed
/// data is damaged it keeps what was produced, reports the error and fills
/// the rest of the section with zeros. Here the caller gets what was
/// produced and the error, and decides about padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decompressed {
    /// The decompressed bytes: `ch_size` of them when `error` is `None`,
    /// fewer when decompression stopped early.
    pub data: Vec<u8>,
    /// Why decompression stopped before producing `ch_size` bytes, if it did.
    pub error: Option<String>,
}

/// zlib cannot expand data by more than this factor (the deflate maximum is
/// about 1032:1), so output beyond it can only come from a lying `ch_size`.
const MAX_EXPANSION: u64 = 1040;

/// Inflates `compressed` into at most `ch_size` bytes.
///
/// The output buffer grows with the data actually produced, never with
/// `ch_size` alone, so memory is bounded by a fixed multiple of the input.
pub(crate) fn inflate(compressed: &[u8], ch_size: u64) -> Decompressed {
    let cap = ch_size.min((compressed.len() as u64).saturating_mul(MAX_EXPANSION));
    let mut data = Vec::new();
    let mut decoder = flate2::read::ZlibDecoder::new(compressed).take(cap);
    let error = match decoder.read_to_end(&mut data) {
        Ok(_) if (data.len() as u64) < ch_size => Some(format!(
            "compressed data ended after {} of {ch_size} byte(s)",
            data.len()
        )),
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    };
    Decompressed { data, error }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use bk_bin::Endian;

    use super::*;

    pub(crate) fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn header_layouts() {
        // 32-bit: type, size, align.
        let bytes = [1, 0, 0, 0, 0x10, 0x20, 0, 0, 8, 0, 0, 0];
        let mut r = BinaryReader::from_slice(&bytes, Endian::Little);
        let h = CompressionHeader::read(&mut r, ElfClass::Elf32).unwrap();
        assert_eq!(
            (h.ch_type, h.ch_size, h.ch_addralign, h.header_size),
            (1, 0x2010, 8, 12)
        );
        assert!(h.is_supported());
        assert_eq!(r.position(), 12);
        // 64-bit: type, reserved, size, align — big-endian here.
        let bytes = [
            0, 0, 0, 2, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut r = BinaryReader::from_slice(&bytes, Endian::Big);
        let h = CompressionHeader::read(&mut r, ElfClass::Elf64).unwrap();
        assert_eq!(
            (h.ch_type, h.ch_size, h.ch_addralign, h.header_size),
            (2, 1 << 32, 16, 24)
        );
        assert!(!h.is_supported());
        assert_eq!(r.position(), 24);
        assert!(CompressionHeader::read(&mut r, ElfClass::Elf64).is_err());
    }

    #[test]
    fn inflate_round_trip() {
        let original: Vec<u8> = (0..10_000u32).flat_map(|i| (i % 7).to_le_bytes()).collect();
        let compressed = deflate(&original);
        let out = inflate(&compressed, original.len() as u64);
        assert_eq!(out.error, None);
        assert_eq!(out.data, original);
    }

    #[test]
    fn inflate_stops_at_ch_size() {
        let compressed = deflate(&[7u8; 1000]);
        let out = inflate(&compressed, 10);
        assert_eq!(out.data, [7u8; 10]);
        assert_eq!(out.error, None);
    }

    #[test]
    fn short_or_damaged_data_keeps_what_was_produced() {
        let original = vec![3u8; 5000];
        let compressed = deflate(&original);
        // ch_size claims more than there is.
        let out = inflate(&compressed, 6000);
        assert_eq!(out.data, original);
        assert_eq!(
            out.error.as_deref(),
            Some("compressed data ended after 5000 of 6000 byte(s)")
        );
        // Truncated stream.
        let out = inflate(&compressed[..compressed.len() / 2], 5000);
        assert!(out.data.len() < 5000);
        assert!(out.error.is_some());
        // Not zlib at all.
        let out = inflate(b"definitely not zlib data", 100);
        assert!(out.data.is_empty());
        assert!(out.error.is_some());
        // Empty input.
        let out = inflate(&[], 100);
        assert!(out.data.is_empty() && out.error.is_some());
    }

    #[test]
    fn output_is_bounded_by_the_input_size() {
        // A zip bomb: 4 MiB of zeros compresses to a few kB; ch_size lies
        // and claims 2⁶⁰ bytes. Output must stop at the real data.
        let compressed = deflate(&vec![0u8; 4 << 20]);
        let out = inflate(&compressed, 1 << 60);
        assert_eq!(out.data.len(), 4 << 20);
        assert!(out.data.len() as u64 <= compressed.len() as u64 * MAX_EXPANSION);
        assert!(out.error.is_some());
    }
}
