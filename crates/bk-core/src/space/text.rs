//! Printing and parsing offsets into a space (Ghidra `AddrSpace::printRaw`,
//! `printOffset` and `read`, the `ConstantSpace`, `OtherSpace` and
//! `JoinSpace` overrides, and `Address::printRaw`).

use std::fmt;

use bk_marshal::SpaceId;
use bk_marshal::xml::number::{Radix, scan};

use super::{Space, SpaceKind, SpaceType};
use crate::address::Address;
use crate::error::SpaceError;
use crate::manager::SpaceManager;
use crate::varnode::VarnodeData;

/// How deeply the text of a join address may nest join addresses inside its
/// pieces. Ghidra recurses without limit; a piece naming the join space by
/// its shortcut would otherwise recurse once per character (ADR-009).
pub const MAX_JOIN_READ_DEPTH: usize = 8;

impl Space {
    /// The offset as plain hexadecimal, `0x…` (Ghidra `printOffset`).
    #[expect(
        clippy::unused_self,
        reason = "a method of the space, as in Ghidra, so callers need not assume every space prints offsets alike"
    )]
    pub fn print_offset(&self, offset: u64) -> String {
        format!("{offset:#x}")
    }
}

/// An offset into a space printed in Ghidra's raw form; see
/// [`SpaceManager::raw_offset`].
#[derive(Debug)]
pub struct RawOffset<'m> {
    manager: &'m SpaceManager,
    space: &'m Space,
    offset: u64,
}

impl fmt::Display for RawOffset<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.manager.write_raw_offset(f, self.space, self.offset)
    }
}

impl SpaceManager {
    /// A value that prints `offset` in `space` as Ghidra's `printRaw` does:
    /// zero-padded hexadecimal of the address in addressable units with a
    /// `+n` byte remainder for word-addressed spaces, plain hexadecimal for
    /// the constant and `OTHER` spaces, and the pieces in braces for a join.
    pub fn raw_offset(&self, space: SpaceId, offset: u64) -> Result<RawOffset<'_>, SpaceError> {
        Ok(RawOffset {
            manager: self,
            space: self.require(space)?,
            offset,
        })
    }

    pub(crate) fn write_raw_offset<W: fmt::Write + ?Sized>(
        &self,
        out: &mut W,
        space: &Space,
        offset: u64,
    ) -> fmt::Result {
        match space.kind() {
            SpaceKind::Constant | SpaceKind::Other => write!(out, "{offset:#x}"),
            SpaceKind::Join => self.write_raw_join(out, offset),
            _ => {
                let mut size = space.addr_size();
                if size > 4 {
                    if offset >> 32 == 0 {
                        size = 4;
                    } else if offset >> 48 == 0 {
                        size = 6;
                    }
                }
                let width = 2 * size as usize;
                write!(
                    out,
                    "0x{:0width$x}",
                    space.byte_to_address(offset),
                    width = width
                )?;
                let word_size = u64::from(space.word_size());
                if word_size > 1 {
                    let cut = offset % word_size;
                    if cut != 0 {
                        write!(out, "+{cut}")?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Ghidra `JoinSpace::printRaw`: `{piece,piece}`, padding as `pad:n`,
    /// and `:size` after a single piece. An offset without a join record,
    /// where Ghidra throws, prints as `{unlinked:0x…}`.
    fn write_raw_join<W: fmt::Write + ?Sized>(&self, out: &mut W, offset: u64) -> fmt::Result {
        let Ok(record) = self.find_join(offset) else {
            return write!(out, "{{unlinked:{offset:#x}}}");
        };
        out.write_char('{')?;
        for (index, piece) in record.pieces().iter().enumerate() {
            if index != 0 {
                out.write_char(',')?;
            }
            if piece.addr().is_constant() {
                write!(out, "pad:{}", piece.size)?;
            } else {
                self.write_raw_sized(out, piece.addr(), piece.size)?;
            }
        }
        if record.num_pieces() == 1 {
            write!(out, ":{}", record.unified().size)?;
        }
        out.write_char('}')
    }

    /// Ghidra `Address::printRaw(s)`.
    pub(crate) fn write_raw_address<W: fmt::Write + ?Sized>(
        &self,
        out: &mut W,
        address: Address,
    ) -> fmt::Result {
        match self.space_of(address) {
            Some(space) => self.write_raw_offset(out, space, address.offset()),
            None if address.is_maximal() => out.write_str("maximal_addr"),
            None => out.write_str("invalid_addr"),
        }
    }

    /// Ghidra `Address::printRaw(s, size)`: the register holding the bytes,
    /// with `+n` when they start inside it, or else the space's shortcut and
    /// the raw offset. Returns the size the printed form implies: the
    /// register's size, or the default address size. An address without a
    /// space prints as `invalid_addr` and implies 0.
    pub(crate) fn write_raw_sized<W: fmt::Write + ?Sized>(
        &self,
        out: &mut W,
        address: Address,
        size: u32,
    ) -> Result<u32, fmt::Error> {
        let Some(space) = self.space_of(address) else {
            self.write_raw_address(out, address)?;
            return Ok(0);
        };
        if let Some(name) = self
            .registers()
            .register_name(space.id(), address.offset(), size)
            && let Some(register) = self.registers().register(name)
        {
            out.write_str(name)?;
            let delta = address.offset().wrapping_sub(register.offset);
            if delta != 0 {
                write!(out, "+{delta}")?;
            }
            return Ok(register.size);
        }
        out.write_char(char::from(space.shortcut_byte()))?;
        self.write_raw_offset(out, space, address.offset())?;
        Ok(self.default_size().unwrap_or(0))
    }

    /// Reads an offset into `space` from text and returns it with the size
    /// the text implies (Ghidra `AddrSpace::read` and `JoinSpace::read`).
    ///
    /// The text is a register name or a number (C syntax: `0x` hex, leading
    /// `0` octal), optionally followed by `:size` and then `+delta`, or by
    /// `+delta` alone. A number is in addressable units and is scaled to
    /// bytes. Without `:size` the size is the register's or else the default
    /// address size. For the join space the text is a comma-separated list of
    /// pieces, each a register name or a space's shortcut followed by an
    /// offset as above; the join record is created if needed.
    pub fn read(&self, space: SpaceId, text: &str) -> Result<(u64, u32), SpaceError> {
        self.read_at_depth(space, text, 0)
    }

    fn read_at_depth(
        &self,
        space: SpaceId,
        text: &str,
        depth: usize,
    ) -> Result<(u64, u32), SpaceError> {
        let spc = self.require(space)?;
        if spc.space_type() == SpaceType::Join {
            return self.read_join(text, depth);
        }
        let append = text.find([':', '+']);
        let front = append.and_then(|at| text.get(..at)).unwrap_or(text);
        let (mut offset, mut size) = if let Some(register) = self.registers().register(front) {
            (register.offset, register.size)
        } else {
            let scanned = scan(text, Radix::Auto);
            let offset = spc.address_to_byte(scanned.as_u64());
            let size = self.default_size()?;
            if scanned.consumed == text.len() {
                return Ok((offset, size));
            }
            (offset, size)
        };
        if let Some(tail) = append.and_then(|at| text.get(at..))
            && let Some(explicit) = offset_and_size(tail, &mut offset)
        {
            size = explicit;
        }
        Ok((offset, size))
    }

    fn read_join(&self, text: &str, depth: usize) -> Result<(u64, u32), SpaceError> {
        if depth >= MAX_JOIN_READ_DEPTH {
            return Err(SpaceError::BadJoinString);
        }
        let mut pieces = Vec::new();
        let mut total: u32 = 0;
        for token in text.split_terminator(',') {
            let piece = if let Some(register) = self.registers().register(token) {
                register
            } else {
                let space = token
                    .bytes()
                    .next()
                    .and_then(|shortcut| self.space_by_shortcut(char::from(shortcut)))
                    .ok_or(SpaceError::BadJoinString)?;
                let rest = token.get(1..).ok_or(SpaceError::BadJoinString)?;
                let (offset, size) = self.read_at_depth(space.id(), rest, depth + 1)?;
                VarnodeData::new(space.id(), offset, size)
            };
            total = total.wrapping_add(piece.size);
            pieces.push(piece);
        }
        let record = self.find_add_join(pieces, 0)?;
        Ok((record.unified().offset, total))
    }
}

/// Applies the `:size+delta` or `+delta` suffix of an address string to
/// `offset` and returns the size, if one is given (Ghidra's
/// `get_offset_size`). The delta is a 32-bit value and the size a 32-bit
/// signed one, as in Ghidra, where a size of -1 means "not given".
fn offset_and_size(tail: &str, offset: &mut u64) -> Option<u32> {
    let mut size: i32 = -1;
    let mut delta: u32 = 0;
    if let Some(rest) = tail.strip_prefix(':') {
        let scanned = scan(rest, Radix::Auto);
        size = scanned.as_u64() as i32;
        let after = rest.get(scanned.consumed..).unwrap_or_default();
        if let Some(delta_text) = after.strip_prefix('+') {
            delta = scan(delta_text, Radix::Auto).as_u64() as u32;
        }
    } else if let Some(delta_text) = tail.strip_prefix('+') {
        delta = scan(delta_text, Radix::Auto).as_u64() as u32;
    }
    *offset = offset.wrapping_add(u64::from(delta));
    (size != -1).then_some(size as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes() {
        let mut offset = 0x100;
        assert_eq!(offset_and_size(":4", &mut offset), Some(4));
        assert_eq!(offset, 0x100);
        assert_eq!(offset_and_size(":2+0x10", &mut offset), Some(2));
        assert_eq!(offset, 0x110);
        assert_eq!(offset_and_size("+8", &mut offset), None);
        assert_eq!(offset, 0x118);
        // Ghidra's sentinel: a size of -1 is no size.
        assert_eq!(offset_and_size(":-1", &mut offset), None);
        // strtoul takes a sign, so this is a size of 4, not a delta.
        assert_eq!(offset_and_size(":+4", &mut offset), Some(4));
        assert_eq!(offset, 0x118);
        // No digits after the colon: size 0.
        assert_eq!(offset_and_size(":x+4", &mut offset), Some(0));
        assert_eq!(offset, 0x118);
    }
}
