//! Where instruction bytes come from (the counterpart of Ghidra's
//! `LoadImage::loadFill`), and the 16-byte window the decoder reads.

use bk_core::Address;

/// The number of instruction bytes the decoder fetches and may address.
pub const WINDOW: usize = 16;

/// A source of instruction bytes.
pub trait ByteSource {
    /// Fills `buf` with the 16 bytes starting at `addr`. Bytes the source
    /// does not have are the source's choice (Ghidra's load image decides;
    /// [`SliceBytes`] gives zeros).
    fn load(&self, addr: Address, buf: &mut [u8; WINDOW]);
}

/// Bytes from a slice placed at offset `base` of a space; everything outside
/// the slice reads as zero (what `pcodedump` does).
#[derive(Clone, Copy, Debug)]
pub struct SliceBytes<'a> {
    base: u64,
    data: &'a [u8],
}

impl<'a> SliceBytes<'a> {
    /// The slice `data`, its first byte at offset `base`.
    pub fn new(base: u64, data: &'a [u8]) -> Self {
        Self { base, data }
    }

    /// The bytes.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The offset of the first byte.
    pub fn base(&self) -> u64 {
        self.base
    }
}

impl ByteSource for SliceBytes<'_> {
    fn load(&self, addr: Address, buf: &mut [u8; WINDOW]) {
        let start = addr.offset().wrapping_sub(self.base);
        // The common case, all 16 bytes inside the slice, as one copy.
        if let Some(bytes) = usize::try_from(start)
            .ok()
            .and_then(|at| self.data.get(at..at.checked_add(WINDOW)?))
        {
            buf.copy_from_slice(bytes);
            return;
        }
        for (i, byte) in buf.iter_mut().enumerate() {
            let at = start.wrapping_add(i as u64);
            *byte = usize::try_from(at)
                .ok()
                .and_then(|at| self.data.get(at))
                .copied()
                .unwrap_or(0);
        }
    }
}

impl<T: ByteSource + ?Sized> ByteSource for &T {
    fn load(&self, addr: Address, buf: &mut [u8; WINDOW]) {
        (**self).load(addr, buf);
    }
}

/// The fetched window, padded with zeros so that a read starting at any
/// index below 16 never leaves the array (ADR-024: bytes past index 15 read
/// as zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    bytes: [u8; 2 * WINDOW],
}

impl Default for Window {
    fn default() -> Self {
        Self {
            bytes: [0; 2 * WINDOW],
        }
    }
}

impl Window {
    pub(crate) fn fill<B: ByteSource + ?Sized>(&mut self, source: &B, addr: Address) {
        // Loaded in place: bytes stored one by one and then copied with a
        // wide load would stall store-to-load forwarding on x86-64.
        let (first, rest) = self.bytes.split_at_mut(WINDOW);
        if let Ok(head) = <&mut [u8; WINDOW]>::try_from(first) {
            source.load(addr, head);
        }
        rest.fill(0);
    }

    /// The 16 fetched bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.get(..WINDOW).unwrap_or_default()
    }

    /// `size` (1..=4) bytes at `pos` (below 16) as a big-endian number.
    #[inline]
    pub(crate) fn read(&self, pos: u32, size: u32) -> u32 {
        let pos = pos as usize;
        let word = match self.bytes.get(pos..pos + 4) {
            Some(&[a, b, c, d]) => u32::from_be_bytes([a, b, c, d]),
            _ => 0,
        };
        if size >= 4 {
            word
        } else {
            word.checked_shr(8 * (4 - size)).unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use bk_core::SpaceId;

    use super::*;

    #[test]
    fn slices_read_zero_outside() {
        let data = [1u8, 2, 3];
        let source = SliceBytes::new(0x100, &data);
        let mut buf = [0xffu8; WINDOW];
        source.load(Address::new(SpaceId::new(1), 0xff), &mut buf);
        assert_eq!(&buf[..5], &[0, 1, 2, 3, 0]);
        source.load(Address::new(SpaceId::new(1), 0x102), &mut buf);
        assert_eq!(&buf[..2], &[3, 0]);
        assert_eq!(source.data().len(), 3);
        assert_eq!(source.base(), 0x100);
    }

    #[test]
    fn window_pads_with_zeros() {
        let data: Vec<u8> = (1..=16).collect();
        let mut window = Window::default();
        window.fill(&SliceBytes::new(0, &data), Address::new(SpaceId::new(1), 0));
        assert_eq!(window.read(0, 4), 0x0102_0304);
        assert_eq!(window.read(14, 4), 0x0f10_0000);
        assert_eq!(window.read(15, 1), 0x10);
        assert_eq!(window.read(1, 2), 0x0203);
        assert_eq!(window.bytes().len(), 16);
    }
}
