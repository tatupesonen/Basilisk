//! A raw image over an in-memory byte buffer (Ghidra `RawLoadImage`;
//! loadimage.cc). The caller reads the file; Ghidra opens it in text mode,
//! which translates line ends on Windows (spec 4.21 #14) — Basilisk takes
//! the bytes as given.

use std::sync::Arc;

use bk_core::{Address, SpaceId, SpaceManager};

use super::LoadImage;
use crate::error::DataUnavail;

/// Bytes loaded at `vma` in one space.
#[derive(Clone, Debug)]
pub struct RawImage {
    bytes: Vec<u8>,
    vma: u64,
    space: SpaceId,
    spaces: Arc<SpaceManager>,
}

impl RawImage {
    /// The bytes at offset `vma` of `space`.
    pub fn new(bytes: Vec<u8>, space: SpaceId, vma: u64, spaces: Arc<SpaceManager>) -> Self {
        Self {
            bytes,
            vma,
            space,
            spaces,
        }
    }
}

impl LoadImage for RawImage {
    fn load_fill(&self, buf: &mut [u8], addr: Address) -> Result<(), DataUnavail> {
        let start = addr.offset().wrapping_sub(self.vma);
        let filesize = self.bytes.len() as u64;
        if buf.is_empty() {
            return Ok(());
        }
        if start >= filesize {
            let shortcut = addr.shortcut(&self.spaces).unwrap_or(' ');
            return Err(DataUnavail {
                addr,
                message: format!(
                    "Unable to load {} bytes at {shortcut}{}",
                    buf.len(),
                    addr.raw(&self.spaces)
                ),
            });
        }
        // A read that starts inside the file and runs past its end is
        // filled with zeros.
        let begin = start as usize;
        let avail = self.bytes.get(begin..).unwrap_or(&[]);
        let n = avail.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), avail.get(..n)) {
            dst.copy_from_slice(src);
        }
        if let Some(rest) = buf.get_mut(n..) {
            rest.fill(0);
        }
        Ok(())
    }

    fn arch_type(&self) -> &str {
        "unknown"
    }

    fn adjust_vma(&mut self, adjust: i64) {
        let word = self
            .spaces
            .space(self.space)
            .map_or(1, bk_core::Space::word_size);
        let bytes = (adjust as u64).wrapping_mul(u64::from(word));
        self.vma = self.vma.wrapping_add(bytes);
    }
}
