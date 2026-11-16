//! The string cache (Ghidra `StringManager`, `StringManagerUnicode`;
//! stringmanage.cc; spec 4.13).

use std::collections::BTreeMap;

use bk_core::{Address, SpaceManager};
use bk_marshal::ids::ATTRIB_CONTENT;
use bk_marshal::{Decoder, Encoder};

use crate::database::tree::crc_update;
use crate::error::{Result, SymbolError};
use crate::ids::{ATTRIB_TRUNC, ELEM_BYTES, ELEM_STRING, ELEM_STRINGMANAGE};
use crate::image::LoadImage;
use crate::image::hex::{hex_bytes_into, write_hex_lines};

/// One cached answer (Ghidra `StringData`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StringData {
    /// Whether the string was cut at the character limit.
    pub truncated: bool,
    /// The bytes (UTF-8, or the raw buffer for one-byte characters).
    pub bytes: Vec<u8>,
}

/// What a string query needs of the character type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharType {
    /// Bytes per character (1, 2 or 4; anything else is never a string).
    pub size: usize,
    /// Whether the type is an opaque string (never decoded).
    pub opaque: bool,
}

/// The string cache with Ghidra's limit of 2048 characters.
#[derive(Clone, Debug)]
pub struct StringCache {
    max_chars: usize,
    map: BTreeMap<Address, StringData>,
}

impl Default for StringCache {
    fn default() -> Self {
        Self::new(2048)
    }
}

/// Ghidra `getCodepoint`: one character of `buf` and the bytes it took, or
/// `None` for an invalid encoding.
pub fn codepoint(buf: &[u8], charsize: usize, big_endian: bool) -> Option<(u32, usize)> {
    if buf.len() < charsize {
        return None;
    }
    let read16 = |b: &[u8]| -> u32 {
        match b {
            [x, y, ..] if big_endian => (u32::from(*x) << 8) | u32::from(*y),
            [x, y, ..] => (u32::from(*y) << 8) | u32::from(*x),
            _ => 0,
        }
    };
    let (cp, skip) = match charsize {
        2 => {
            let cp = read16(buf);
            if (0xD800..=0xDBFF).contains(&cp) {
                if buf.len() < 4 {
                    return None;
                }
                let trail = read16(buf.get(2..)?);
                if !(0xDC00..=0xDFFF).contains(&trail) {
                    return None;
                }
                (
                    (cp << 10)
                        .wrapping_add(trail)
                        .wrapping_add(0x10000u32.wrapping_sub(0xD800 << 10).wrapping_sub(0xDC00)),
                    4,
                )
            } else if (0xDC00..=0xDFFF).contains(&cp) {
                return None;
            } else {
                (cp, 2)
            }
        }
        1 => {
            let v = u32::from(*buf.first()?);
            let cont = |i: usize| {
                buf.get(i)
                    .map(|b| u32::from(*b))
                    .filter(|b| b & 0xc0 == 0x80)
            };
            if v & 0x80 == 0 {
                (v, 1)
            } else if v & 0xe0 == 0xc0 {
                if buf.len() < 2 {
                    return None;
                }
                (((v & 0x1f) << 6) | (cont(1)? & 0x3f), 2)
            } else if v & 0xf0 == 0xe0 {
                if buf.len() < 3 {
                    return None;
                }
                let (b2, b3) = (cont(1)?, cont(2)?);
                (((v & 0xf) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f), 3)
            } else if v & 0xf8 == 0xf0 {
                if buf.len() < 4 {
                    return None;
                }
                let (b2, b3, b4) = (cont(1)?, cont(2)?, cont(3)?);
                (
                    ((v & 7) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f),
                    4,
                )
            } else {
                return None;
            }
        }
        4 => {
            let b: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            (
                if big_endian {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                },
                4,
            )
        }
        _ => return None,
    };
    // Ghidra's codepoint is a signed int; every caller treats a negative
    // one (UTF-32 with the top bit set) as invalid.
    if (cp as i32) < 0 || (cp >= 0xd800 && (cp > 0x0010_ffff || cp <= 0xdfff)) {
        return None;
    }
    Some((cp, skip))
}

/// Ghidra `writeUtf8`.
pub fn write_utf8(out: &mut Vec<u8>, codepoint: u32) -> Result<()> {
    let cp = codepoint as i32;
    if cp < 0 {
        return Err(SymbolError::NegativeCodepoint);
    }
    if codepoint < 128 {
        out.push(codepoint as u8);
        return Ok(());
    }
    let bits = 32 - codepoint.leading_zeros();
    if bits > 21 {
        return Err(SymbolError::BadCodepoint);
    }
    if bits < 12 {
        out.push(0xc0 ^ ((codepoint >> 6) & 0x1f) as u8);
        out.push(0x80 ^ (codepoint & 0x3f) as u8);
    } else if bits < 17 {
        out.push(0xe0 ^ ((codepoint >> 12) & 0xf) as u8);
        out.push(0x80 ^ ((codepoint >> 6) & 0x3f) as u8);
        out.push(0x80 ^ (codepoint & 0x3f) as u8);
    } else {
        out.push(0xf0 ^ ((codepoint >> 18) & 7) as u8);
        out.push(0x80 ^ ((codepoint >> 12) & 0x3f) as u8);
        out.push(0x80 ^ ((codepoint >> 6) & 0x3f) as u8);
        out.push(0x80 ^ (codepoint & 0x3f) as u8);
    }
    Ok(())
}

/// Ghidra `checkCharacters`: the number of characters before the
/// terminator, or `None` for an invalid encoding.
pub fn check_characters(buf: &[u8], charsize: usize, big_endian: bool) -> Option<usize> {
    let mut i = 0;
    let mut count = 0;
    while i < buf.len() {
        let (cp, skip) = codepoint(buf.get(i..)?, charsize, big_endian)?;
        if cp == 0 {
            break;
        }
        count += 1;
        i += skip;
    }
    Some(count)
}

/// Ghidra `hasCharTerminator`: `charsize` zero bytes at a multiple of
/// `charsize` (a partial last character is never a terminator here).
fn has_terminator(buf: &[u8], charsize: usize) -> bool {
    charsize > 0
        && buf
            .chunks_exact(charsize)
            .any(|c| c.iter().all(|b| *b == 0))
}

/// Ghidra `calcInternalHash`.
pub fn internal_hash(addr: Address, buf: &[u8]) -> u64 {
    let reg = buf
        .iter()
        .fold(0x7b7c_66a9u32, |r, b| crc_update(r, u32::from(*b)));
    addr.offset() ^ (u64::from(reg) << 32)
}

impl StringCache {
    /// A cache cutting strings at `max_chars` characters.
    pub fn new(max_chars: usize) -> Self {
        Self {
            max_chars,
            map: BTreeMap::new(),
        }
    }

    /// The cached entries in address order.
    pub fn entries(&self) -> impl Iterator<Item = (&Address, &StringData)> {
        self.map.iter()
    }

    /// Removes every entry.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// The cached answer for an address, if any.
    pub fn cached(&self, addr: Address) -> Option<&StringData> {
        self.map.get(&addr)
    }

    /// Stores an answer (the host-backed cache fills it this way).
    pub fn insert(&mut self, addr: Address, data: StringData) {
        self.map.insert(addr, data);
    }

    /// Ghidra `writeUnicode` + `assignStringData`.
    fn assign(
        &self,
        buf: &[u8],
        charsize: usize,
        num_chars: usize,
        big_endian: bool,
    ) -> Result<StringData> {
        let mut data = StringData::default();
        if charsize == 1 && num_chars < self.max_chars {
            data.bytes = buf.to_vec();
        } else {
            let mut out = Vec::new();
            let mut i = 0;
            let mut count = 0;
            let mut ok = true;
            while i < buf.len() {
                let Some((cp, skip)) = buf
                    .get(i..)
                    .and_then(|b| codepoint(b, charsize, big_endian))
                else {
                    ok = false;
                    break;
                };
                if cp == 0 {
                    break;
                }
                write_utf8(&mut out, cp)?;
                i += skip;
                count += 1;
                if count >= self.max_chars {
                    break;
                }
            }
            if !ok {
                return Ok(data);
            }
            out.push(0);
            data.bytes = out;
        }
        data.truncated = num_chars >= self.max_chars;
        Ok(data)
    }

    /// Ghidra `StringManagerUnicode::getStringData`: the cached answer, or
    /// the string read from the image (cached even when empty).
    pub fn string_data(
        &mut self,
        addr: Address,
        ch: CharType,
        image: &dyn LoadImage,
        spaces: &SpaceManager,
    ) -> Result<&StringData> {
        if !self.map.contains_key(&addr) {
            let data = self.read(addr, ch, image, spaces)?;
            self.map.insert(addr, data);
        }
        self.map
            .get(&addr)
            .ok_or(SymbolError::Limit("string cache"))
    }

    fn read(
        &self,
        addr: Address,
        ch: CharType,
        image: &dyn LoadImage,
        spaces: &SpaceManager,
    ) -> Result<StringData> {
        if ch.opaque {
            return Ok(StringData::default());
        }
        let charsize = ch.size;
        let mut buf = vec![0u8; self.max_chars];
        let mut cur = 0usize;
        loop {
            let mut amount = 32;
            let mut new_size = cur + amount;
            if new_size > self.max_chars {
                new_size = self.max_chars;
                amount = new_size - cur;
                if amount == 0 {
                    return Ok(StringData::default());
                }
            }
            let at = addr.add(spaces, cur as i64);
            let Some(slice) = buf.get_mut(cur..new_size) else {
                return Ok(StringData::default());
            };
            if image.load_fill(slice, at).is_err() {
                return Ok(StringData::default());
            }
            let found = has_terminator(slice, charsize);
            cur = new_size;
            if found {
                break;
            }
        }
        let big = addr.is_big_endian(spaces);
        let read = buf.get(..cur).unwrap_or(&[]);
        let Some(num) = check_characters(read, charsize, big) else {
            return Ok(StringData::default());
        };
        self.assign(read, charsize, num, big)
    }

    /// Ghidra `isString`.
    pub fn is_string(
        &mut self,
        addr: Address,
        ch: CharType,
        image: &dyn LoadImage,
        spaces: &SpaceManager,
    ) -> Result<bool> {
        Ok(!self.string_data(addr, ch, image, spaces)?.bytes.is_empty())
    }

    /// Ghidra `registerInternalStringData`: stores `buf` under the constant
    /// address of its hash and returns the hash (0 for an invalid encoding).
    pub fn register_internal(
        &mut self,
        addr: Address,
        buf: &[u8],
        charsize: usize,
        spaces: &SpaceManager,
    ) -> Result<u64> {
        let big = addr.is_big_endian(spaces);
        let Some(num) = check_characters(buf, charsize, big) else {
            return Ok(0);
        };
        let hash = internal_hash(addr, buf);
        let data = self.assign(buf, charsize, num, big)?;
        self.map.insert(Address::constant(hash), data);
        Ok(hash)
    }

    /// Ghidra `encode`: `<stringmanage>` of `<string>` elements.
    pub fn encode(&self, enc: &mut dyn Encoder, spaces: &SpaceManager) -> Result<()> {
        enc.open_element(ELEM_STRINGMANAGE);
        for (addr, data) in &self.map {
            enc.open_element(ELEM_STRING);
            addr.encode(enc, spaces)?;
            enc.open_element(ELEM_BYTES);
            enc.write_bool(ATTRIB_TRUNC, data.truncated);
            enc.write_string(ATTRIB_CONTENT, &write_hex_lines(&data.bytes, "  "))?;
            enc.close_element(ELEM_BYTES);
            enc.close_element(ELEM_STRING);
        }
        enc.close_element(ELEM_STRINGMANAGE);
        Ok(())
    }

    /// Ghidra `decode`; bytes of a repeated address are appended, as in
    /// Ghidra.
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>, spaces: &SpaceManager) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_STRINGMANAGE)?;
        while dec.peek_element() == Some(ELEM_STRING.code()) {
            let s = dec.open_element_expecting(ELEM_STRING)?;
            let addr = Address::decode(dec, spaces)?;
            let b = dec.open_element_expecting(ELEM_BYTES)?;
            let truncated = dec.read_bool_attr(ATTRIB_TRUNC)?;
            let text = dec.read_string_attr(ATTRIB_CONTENT)?;
            let entry = self.map.entry(addr).or_default();
            entry.truncated = truncated;
            hex_bytes_into(text, &mut entry.bytes);
            dec.close_element(b)?;
            dec.close_element(s)?;
        }
        dec.close_element(el)?;
        Ok(())
    }
}
