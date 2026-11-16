//! The `<binaryimage>` load image of the data tests (Ghidra `LoadImageXml`,
//! `loadimage_xml.cc`; spec 4.15).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bk_core::{Address, RangeList, SpaceManager};
use bk_marshal::ids::{ATTRIB_CONTENT, ATTRIB_NAME, ATTRIB_READONLY, ATTRIB_SPACE, ELEM_SYMBOL};
use bk_marshal::{Decoder, Encoder};

use super::hex::{hex_bytes_into, write_hex_lines};
use super::{LoadImage, LoadImageFunc};
use crate::error::{DataUnavail, Result, SymbolError};
use crate::ids::{ATTRIB_ARCH, ELEM_BINARYIMAGE, ELEM_BYTECHUNK};

/// Chunks of bytes by address, symbols and read-only marks.
#[derive(Clone, Debug)]
pub struct XmlImage {
    arch: String,
    spaces: Arc<SpaceManager>,
    chunks: BTreeMap<Address, Vec<u8>>,
    symbols: BTreeMap<Address, String>,
    readonly: BTreeSet<Address>,
}

impl XmlImage {
    /// Ghidra's constructor and `open`: reads a `<binaryimage>` element
    /// (`file` names it in the error for another root) and pads the chunks.
    pub fn decode(
        dec: &mut dyn Decoder<'_>,
        spaces: Arc<SpaceManager>,
        file: &str,
    ) -> Result<Self> {
        if dec.peek_element() != Some(ELEM_BINARYIMAGE.code()) {
            return Err(SymbolError::MissingBinaryImage {
                file: file.to_owned(),
            });
        }
        let el = dec.open_element_expecting(ELEM_BINARYIMAGE)?;
        let arch = dec.read_string_attr(ATTRIB_ARCH)?.to_owned();
        let mut image = Self {
            arch,
            spaces,
            chunks: BTreeMap::new(),
            symbols: BTreeMap::new(),
            readonly: BTreeSet::new(),
        };
        while let Some(sub) = dec.open_element()? {
            if sub == ELEM_SYMBOL.code() {
                let addr = image.decode_addr(dec)?;
                let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
                image.symbols.insert(addr, name);
            } else if sub == ELEM_BYTECHUNK.code() {
                let addr = image.decode_addr(dec)?;
                dec.rewind_attributes();
                while let Some(attr) = dec.next_attribute()? {
                    if attr == ATTRIB_READONLY && dec.read_bool()? {
                        image.readonly.insert(addr);
                    }
                }
                let text = dec.read_string_attr(ATTRIB_CONTENT)?;
                let vec = image.chunks.entry(addr).or_default();
                vec.clear();
                hex_bytes_into(text, vec);
            } else {
                return Err(SymbolError::UnknownImageTag);
            }
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        image.pad();
        Ok(image)
    }

    fn decode_addr(&self, dec: &mut dyn Decoder<'_>) -> Result<Address> {
        let space = dec.read_space_attr(ATTRIB_SPACE)?;
        dec.rewind_attributes();
        let (offset, _) = self.spaces.decode_attributes(space, dec)?;
        Ok(Address::new(space, offset))
    }

    /// The chunks after padding, in address order.
    pub fn chunks(&self) -> impl Iterator<Item = (&Address, &Vec<u8>)> {
        self.chunks.iter()
    }

    /// Whether the chunk at `addr` is marked read-only.
    pub fn is_readonly_chunk(&self, addr: Address) -> bool {
        self.readonly.contains(&addr)
    }

    /// Ghidra `pad`: drops chunks inside the previous kept chunk of their
    /// space, then adds a zero chunk of up to 512 bytes after each chunk
    /// (spec 4.15).
    fn pad(&mut self) {
        let keys: Vec<Address> = self.chunks.keys().copied().collect();
        let mut last: Option<Address> = keys.first().copied();
        for &k in keys.iter().skip(1) {
            if let Some(l) = last
                && l.space() == k.space()
            {
                let len_l = self.chunks.get(&l).map_or(0, Vec::len) as u64;
                let len_k = self.chunks.get(&k).map_or(0, Vec::len) as u64;
                let end1 = l.offset().wrapping_add(len_l).wrapping_sub(1);
                let end2 = k.offset().wrapping_add(len_k).wrapping_sub(1);
                if end1 >= end2 {
                    self.chunks.remove(&k);
                    continue;
                }
            }
            last = Some(k);
        }
        let keys: Vec<(Address, usize)> = self.chunks.iter().map(|(a, v)| (*a, v.len())).collect();
        let mut pads: Vec<(Address, u64)> = Vec::new();
        for (i, (addr, len)) in keys.iter().enumerate() {
            let end = addr.add(&self.spaces, *len as i64);
            if end < *addr {
                continue;
            }
            let highest = self
                .spaces
                .space_of(end)
                .map_or(u64::MAX, bk_core::Space::highest);
            let mut maxsize: u64 = 512;
            let room = highest.wrapping_sub(end.offset()).wrapping_add(1);
            if maxsize > room {
                maxsize = room;
            }
            if let Some((next, _)) = keys.get(i + 1)
                && next.space() == end.space()
            {
                if end.offset() >= next.offset() {
                    continue;
                }
                let room = next.offset() - end.offset();
                if maxsize > room {
                    maxsize = room;
                }
            }
            pads.push((end, maxsize));
        }
        for (addr, n) in pads {
            let vec = self.chunks.entry(addr).or_default();
            vec.resize(vec.len() + n as usize, 0);
        }
    }

    /// Ghidra `encode`: `<binaryimage arch>` with every non-empty chunk and
    /// every symbol.
    pub fn encode(&self, enc: &mut dyn Encoder) -> Result<()> {
        enc.open_element(ELEM_BINARYIMAGE);
        enc.write_string(ATTRIB_ARCH, &self.arch)?;
        for (addr, vec) in &self.chunks {
            if vec.is_empty() {
                continue;
            }
            enc.open_element(ELEM_BYTECHUNK);
            if let Some(space) = addr.space() {
                self.spaces.encode_attributes(enc, space, addr.offset())?;
            }
            if self.readonly.contains(addr) {
                enc.write_bool(ATTRIB_READONLY, true);
            }
            enc.write_string(ATTRIB_CONTENT, &write_hex_lines(vec, ""))?;
            enc.close_element(ELEM_BYTECHUNK);
        }
        for (addr, name) in &self.symbols {
            enc.open_element(ELEM_SYMBOL);
            if let Some(space) = addr.space() {
                self.spaces.encode_attributes(enc, space, addr.offset())?;
            }
            enc.write_string(ATTRIB_NAME, name)?;
            enc.close_element(ELEM_SYMBOL);
        }
        enc.close_element(ELEM_BINARYIMAGE);
        Ok(())
    }
}

impl LoadImage for XmlImage {
    fn load_fill(&self, buf: &mut [u8], addr: Address) -> Result<(), DataUnavail> {
        let mut cur = addr;
        let mut pos = 0usize;
        let mut empty_hit = false;
        let start = self
            .chunks
            .range(..=addr)
            .next_back()
            .or_else(|| self.chunks.iter().next())
            .map(|(k, _)| *k);
        let mut iter = start.map(|s| self.chunks.range(s..));
        while pos < buf.len() {
            let Some((caddr, chunk)) = iter.as_mut().and_then(Iterator::next) else {
                break;
            };
            let over = u32::try_from(chunk.len())
                .ok()
                .and_then(|len| cur.overlap(&self.spaces, 0, *caddr, len));
            let Some(over) = over else {
                empty_hit = true;
                break;
            };
            let over = over as usize;
            let n = (chunk.len() - over.min(chunk.len())).min(buf.len() - pos);
            if let (Some(dst), Some(src)) = (buf.get_mut(pos..pos + n), chunk.get(over..over + n)) {
                dst.copy_from_slice(src);
            }
            pos += n;
            cur = cur.add(&self.spaces, n as i64);
        }
        if pos < buf.len() || empty_hit {
            return Err(DataUnavail {
                addr: cur,
                message: format!("Bytes at {} are not mapped", cur.raw(&self.spaces)),
            });
        }
        Ok(())
    }

    fn arch_type(&self) -> &str {
        &self.arch
    }

    fn symbols(&self) -> Vec<LoadImageFunc> {
        self.symbols
            .iter()
            .map(|(a, n)| LoadImageFunc {
                address: *a,
                name: n.clone(),
            })
            .collect()
    }

    fn readonly(&self) -> RangeList {
        let mut list = RangeList::default();
        for (addr, chunk) in &self.chunks {
            if let Some(space) = addr.space()
                && self.readonly.contains(addr)
            {
                let last = addr
                    .offset()
                    .wrapping_add(chunk.len() as u64)
                    .wrapping_sub(1);
                list.insert_range(space, addr.offset(), last);
            }
        }
        list
    }

    /// Ghidra truncates the offset to 32 bits (spec 4.21 #15); Basilisk
    /// moves by the full 64-bit wrapping amount.
    fn adjust_vma(&mut self, adjust: i64) {
        let spaces = Arc::clone(&self.spaces);
        let shift = |a: Address| {
            let word = spaces.space_of(a).map_or(1, bk_core::Space::word_size);
            a.add(&spaces, adjust.wrapping_mul(i64::from(word)))
        };
        self.chunks = std::mem::take(&mut self.chunks)
            .into_iter()
            .map(|(a, v)| (shift(a), v))
            .collect();
        self.symbols = std::mem::take(&mut self.symbols)
            .into_iter()
            .map(|(a, n)| (shift(a), n))
            .collect();
    }
}
