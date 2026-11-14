//! A provider over a file, read with positional reads through a bounded
//! block cache.

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::{PoisonError, RwLock};

use crate::error::{BinError, Result};
use crate::provider::traits::ByteProvider;

/// A provider that reads its bytes from a file (Ghidra's `FileByteProvider`).
///
/// The file is read with positional reads (`pread` on Unix, `ReadFile` with
/// an offset on Windows), so the provider has no cursor and needs no lock
/// around the file handle. Small reads go through a cache of
/// [`BLOCK_SIZE`](Self::BLOCK_SIZE)-byte blocks, as in Ghidra; reads of a
/// block or more bypass the cache and go straight to the file.
///
/// The cache is direct-mapped and bounded: at most
/// [`CACHE_BLOCKS`](Self::CACHE_BLOCKS) blocks (4 MiB) are held, whatever the
/// size of the file. Each slot has its own reader-writer lock, so threads
/// reading cached blocks share them freely and a thread loading a block
/// only briefly excludes readers of the one slot it replaces. (Ghidra keeps
/// every buffer the garbage collector has not reclaimed and serialises all
/// reads on one monitor.)
///
/// Basilisk forbids `unsafe`, so there is no memory-mapped provider here
/// (ADR-005). A crate that is allowed to map files can hand the mapping to
/// [`MemoryProvider`](crate::MemoryProvider).
pub struct FileProvider {
    file: File,
    len: u64,
    name: String,
    path: String,
    slots: Box<[RwLock<Option<Block>>]>,
}

/// One cached block: the bytes of the file from `index * BLOCK_SIZE` on.
struct Block {
    index: u64,
    bytes: Box<[u8]>,
}

impl FileProvider {
    /// Size of one cache block in bytes (the same as Ghidra's buffer size).
    pub const BLOCK_SIZE: usize = 64 * 1024;

    /// Number of blocks the cache can hold.
    pub const CACHE_BLOCKS: usize = 64;

    /// Opens `path` for reading.
    ///
    /// The length is taken from the file system and verified by reading the
    /// last byte, because some file systems (`/proc`, `/sys`) report sizes
    /// that are not readable; such a file is rejected, as in Ghidra.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let open_error = |source| BinError::Open {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(path).map_err(open_error)?;
        let len = file.metadata().map_err(open_error)?.len();
        if len > 0 {
            let mut last = [0u8; 1];
            read_exact_at(&file, &mut last, len - 1).map_err(|source| {
                open_error(io::Error::new(
                    source.kind(),
                    format!("unable to determine file size (reported as {len}): {source}"),
                ))
            })?;
        }
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let slots = (0..Self::CACHE_BLOCKS).map(|_| RwLock::new(None)).collect();
        Ok(Self {
            file,
            len,
            name,
            path: absolute.display().to_string(),
            slots,
        })
    }

    /// Copies bytes of block `index`, starting `skip` bytes into it, to the
    /// front of `buf`; returns how many were copied (fewer than `buf.len()`
    /// when the block ends first).
    fn copy_from_block(&self, index: u64, skip: usize, buf: &mut [u8]) -> io::Result<usize> {
        let slot_index = usize::try_from(index % Self::CACHE_BLOCKS as u64).unwrap_or(0);
        let Some(slot) = self.slots.get(slot_index) else {
            return Err(io::Error::other("block cache slot missing"));
        };
        {
            let guard = slot.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(block) = guard.as_ref().filter(|b| b.index == index) {
                return Ok(copy_prefix(&block.bytes, skip, buf));
            }
        }
        // Miss: load the block without holding any lock, then install it.
        let start = index.saturating_mul(Self::BLOCK_SIZE as u64);
        let size = usize::try_from(self.len.saturating_sub(start))
            .map_or(Self::BLOCK_SIZE, |rest| rest.min(Self::BLOCK_SIZE));
        let mut bytes = vec![0u8; size].into_boxed_slice();
        read_exact_at(&self.file, &mut bytes, start)?;
        let copied = copy_prefix(&bytes, skip, buf);
        *slot.write().unwrap_or_else(PoisonError::into_inner) = Some(Block { index, bytes });
        Ok(copied)
    }

    fn read_cached(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let block_size = Self::BLOCK_SIZE as u64;
        let mut position = offset;
        let mut remaining = buf;
        while !remaining.is_empty() {
            let skip = usize::try_from(position % block_size).unwrap_or(0);
            let copied = self.copy_from_block(position / block_size, skip, remaining)?;
            if copied == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            position += copied as u64;
            remaining = std::mem::take(&mut remaining)
                .get_mut(copied..)
                .unwrap_or_default();
        }
        Ok(())
    }
}

/// Copies as much of `block[skip..]` as fits to the front of `buf`.
fn copy_prefix(block: &[u8], skip: usize, buf: &mut [u8]) -> usize {
    let available = block.get(skip..).unwrap_or_default();
    let count = available.len().min(buf.len());
    if let (Some(dst), Some(src)) = (buf.get_mut(..count), available.get(..count)) {
        dst.copy_from_slice(src);
    }
    count
}

impl std::fmt::Debug for FileProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileProvider")
            .field("path", &self.path)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl ByteProvider for FileProvider {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len = buf.len() as u64;
        if !self.is_valid_range(offset, len) {
            return Err(BinError::out_of_bounds(offset, len, self.len));
        }
        let result = if buf.len() >= Self::BLOCK_SIZE {
            read_exact_at(&self.file, buf, offset)
        } else {
            self.read_cached(offset, buf)
        };
        result.map_err(|source| BinError::Io {
            offset,
            len,
            source,
        })
    }

    fn name(&self) -> Option<&str> {
        Some(&self.name)
    }

    fn path(&self) -> Option<&str> {
        Some(&self.path)
    }
}

/// Fills `buf` from `file` at `offset`, retrying short and interrupted reads.
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match read_at(file, buf, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                offset += n as u64;
                buf = std::mem::take(&mut buf).get_mut(n..).unwrap_or_default();
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_at(_file: &File, _buf: &mut [u8], _offset: u64) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "positional file reads are not available on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const BS: usize = FileProvider::BLOCK_SIZE;

    /// File content: byte `i` is `(i / 251) as u8 ^ (i % 251) as u8`, which
    /// has no period that divides the block size.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i / 251) ^ (i % 251)) as u8).collect()
    }

    fn file_with(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn names_and_length() {
        let (_dir, path) = file_with(b"abc");
        let p = FileProvider::open(&path).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.name(), Some("data.bin"));
        assert!(Path::new(p.path().unwrap()).is_absolute());
        assert!(p.as_slice().is_none());
        assert!(format!("{p:?}").contains("data.bin"));
    }

    #[test]
    fn empty_file() {
        let (_dir, path) = file_with(b"");
        let p = FileProvider::open(&path).unwrap();
        assert!(p.is_empty());
        assert!(p.read_byte(0).is_err());
        assert!(p.read_bytes(0, 0).unwrap().is_empty());
    }

    #[test]
    fn missing_file_reports_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let err = FileProvider::open(dir.path().join("absent")).unwrap_err();
        assert!(matches!(err, BinError::Open { .. }));
        assert!(err.to_string().contains("absent"), "{err}");
    }

    #[test]
    fn bounds() {
        let (_dir, path) = file_with(&pattern(100));
        let p = FileProvider::open(&path).unwrap();
        assert!(p.read_bytes(0, 100).is_ok());
        assert!(p.read_bytes(100, 0).is_ok());
        assert!(matches!(
            p.read_bytes(99, 2),
            Err(BinError::OutOfBounds {
                offset: 99,
                len: 2,
                ..
            })
        ));
        assert!(p.read_bytes(101, 0).is_err());
        assert!(p.read_byte(u64::MAX).is_err());
    }

    #[test]
    fn every_kind_of_read_matches_the_content() {
        let data = pattern(BS * 3 + 1234);
        let (_dir, path) = file_with(&data);
        let p = FileProvider::open(&path).unwrap();
        let cases: &[(usize, usize)] = &[
            (0, 1),
            (BS - 1, 2),        // straddles two blocks
            (BS - 2, BS + 4),   // three blocks, uncached (>= block)
            (BS + 7, BS - 8),   // largest cached read
            (BS * 3, 1234),     // the short last block
            (BS * 3 + 1233, 1), // last byte
            (0, data.len()),    // everything
            (5, BS * 2),
        ];
        for &(offset, len) in cases {
            let got = p.read_bytes(offset as u64, len).unwrap();
            assert_eq!(
                &*got,
                &data[offset..offset + len],
                "offset {offset} len {len}"
            );
        }
    }

    #[test]
    fn cache_is_bounded_and_evicts() {
        let blocks = FileProvider::CACHE_BLOCKS + 3;
        let data = pattern(BS * blocks);
        let (_dir, path) = file_with(&data);
        let p = FileProvider::open(&path).unwrap();
        // Touch every block twice, in two different orders.
        for i in (0..blocks).chain((0..blocks).rev()) {
            let offset = i * BS + 17;
            assert_eq!(p.read_byte(offset as u64).unwrap(), data[offset]);
        }
        let cached = p
            .slots
            .iter()
            .filter(|s| s.read().unwrap().is_some())
            .count();
        assert_eq!(cached, FileProvider::CACHE_BLOCKS);
        assert_eq!(p.slots.len(), FileProvider::CACHE_BLOCKS);
    }

    #[test]
    fn concurrent_readers_see_consistent_bytes() {
        let data = Arc::new(pattern(BS * 5 + 99));
        let (_dir, path) = file_with(&data);
        let p = Arc::new(FileProvider::open(&path).unwrap());
        let threads: Vec<_> = (0..8usize)
            .map(|t| {
                let (p, data) = (Arc::clone(&p), Arc::clone(&data));
                std::thread::spawn(move || {
                    let mut offset = t * 7919;
                    for _ in 0..2000 {
                        offset = (offset * 31 + 4099) % (data.len() - 8);
                        let got = p.read_bytes(offset as u64, 8).unwrap();
                        assert_eq!(&*got, &data[offset..offset + 8]);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn truncated_after_open_is_an_io_error() {
        let (_dir, path) = file_with(&pattern(BS * 2));
        let p = FileProvider::open(&path).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(10)
            .unwrap();
        let err = p.read_bytes(BS as u64, 4).unwrap_err();
        assert!(matches!(err, BinError::Io { .. }), "{err}");
        let err = p.read_bytes(0, BS + 1).unwrap_err();
        assert!(matches!(err, BinError::Io { .. }), "{err}");
    }
}
