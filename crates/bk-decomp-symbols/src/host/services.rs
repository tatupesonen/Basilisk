//! The caches of the other services over a host (Ghidra
//! `CommentDatabaseGhidra`, `GhidraStringManager`, `ConstantPoolGhidra`,
//! `LoadImageGhidra`, `ContextGhidra`; spec 4.19).

use std::sync::Arc;

use bk_context::TrackedValue;
use bk_core::Address;
use bk_decomp_types::{TypeFactory, TypeId};

use super::ProgramHost;
use crate::comment::{Comment, CommentDb};
use crate::cpool::{CPoolRecord, ConstantPool};
use crate::error::{DataUnavail, HostError, Result};
use crate::image::LoadImage;
use crate::strings::{StringCache, StringData};

/// Comments fetched once per `clear`, whatever the function (Ghidra
/// `CommentDatabaseGhidra::fillCache`).
pub struct HostComments {
    host: Arc<dyn ProgramHost>,
    cache: CommentDb,
    filled: bool,
}

impl std::fmt::Debug for HostComments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostComments")
            .field("filled", &self.filled)
            .finish_non_exhaustive()
    }
}

impl HostComments {
    /// An empty cache.
    pub fn new(host: Arc<dyn ProgramHost>) -> Self {
        Self {
            host,
            cache: CommentDb::new(),
            filled: false,
        }
    }

    /// Ghidra `clear`: the next look-up asks again.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.filled = false;
    }

    /// The cached comments.
    pub fn cache(&self) -> &CommentDb {
        &self.cache
    }

    /// Ghidra `addComment` (into the cache only).
    pub fn add_comment(
        &mut self,
        kind: u32,
        func: Address,
        addr: Address,
        text: &str,
    ) -> Result<()> {
        self.cache.add_comment(kind, func, addr, text)
    }

    /// Ghidra `beginComment`: fills the cache on the first call after a
    /// clear (`mask` is the printer's header and instruction comment types;
    /// nothing is asked when it is 0), then the function's comments.
    pub fn comments(&mut self, func: Address, mask: u32) -> Result<Vec<Comment>> {
        if !self.filled {
            self.filled = true;
            if mask != 0 {
                for c in self.host.comments(func, mask)? {
                    self.cache
                        .add_comment(c.kind, c.func_addr, c.addr, &c.text)?;
                }
            }
        }
        Ok(self.cache.function_range(func).cloned().collect())
    }
}

/// Strings asked once each (Ghidra `GhidraStringManager`).
pub struct HostStrings {
    host: Arc<dyn ProgramHost>,
    cache: StringCache,
    max_chars: usize,
}

impl std::fmt::Debug for HostStrings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostStrings").finish_non_exhaustive()
    }
}

impl HostStrings {
    /// An empty cache with Ghidra's limit.
    pub fn new(host: Arc<dyn ProgramHost>, max_chars: usize) -> Self {
        Self {
            host,
            cache: StringCache::new(max_chars),
            max_chars,
        }
    }

    /// The cached answer, or the host's (an absent string caches as empty).
    pub fn string_data(&mut self, addr: Address, char_type: TypeId) -> Result<StringData> {
        if let Some(d) = self.cache.cached(addr) {
            return Ok(d.clone());
        }
        let data = match self.host.string_data(addr, char_type, self.max_chars)? {
            Some(s) => StringData {
                truncated: s.truncated,
                bytes: s.bytes,
            },
            None => StringData::default(),
        };
        self.cache.insert(addr, data.clone());
        Ok(data)
    }
}

/// Constant-pool records asked once each (Ghidra `ConstantPoolGhidra`).
pub struct HostConstantPool {
    host: Arc<dyn ProgramHost>,
    cache: ConstantPool,
}

impl std::fmt::Debug for HostConstantPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostConstantPool").finish_non_exhaustive()
    }
}

impl HostConstantPool {
    /// An empty cache.
    pub fn new(host: Arc<dyn ProgramHost>) -> Self {
        Self {
            host,
            cache: ConstantPool::new(),
        }
    }

    /// Ghidra `getRecord`: the cached record or the host's; a missing one is
    /// `Could not retrieve constant pool record for reference: 0x…`.
    pub fn record(&mut self, refs: &[u64], _types: &mut TypeFactory) -> Result<CPoolRecord> {
        if let Some(r) = self.cache.record(refs)? {
            return Ok(r.clone());
        }
        let first = refs.first().copied().unwrap_or(0);
        let rec = self
            .host
            .cpool_record(refs)?
            .ok_or(HostError::NoCpoolRecord(first))?;
        self.cache.insert(refs, rec.clone())?;
        Ok(rec)
    }
}

/// The host's bytes as a load image (Ghidra `LoadImageGhidra`).
pub struct HostImage {
    host: Arc<dyn ProgramHost>,
}

impl std::fmt::Debug for HostImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostImage")
    }
}

impl HostImage {
    /// The image of a host.
    pub fn new(host: Arc<dyn ProgramHost>) -> Self {
        Self { host }
    }
}

impl LoadImage for HostImage {
    fn load_fill(&self, buf: &mut [u8], addr: Address) -> Result<(), DataUnavail> {
        self.host.bytes(addr, buf)
    }
    fn arch_type(&self) -> &'static str {
        "ghidra"
    }
    /// Ghidra refuses (`Cannot adjust GHIDRA virtual memory`); the host's
    /// addresses are fixed, so this does nothing.
    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// Tracked registers asked at every look-up (Ghidra `ContextGhidra`).
pub struct HostTracked {
    host: Arc<dyn ProgramHost>,
}

impl std::fmt::Debug for HostTracked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostTracked")
    }
}

impl HostTracked {
    /// Over a host.
    pub fn new(host: Arc<dyn ProgramHost>) -> Self {
        Self { host }
    }

    /// Ghidra `getTrackedSet`.
    pub fn tracked_set(&self, addr: Address) -> Result<Vec<TrackedValue>> {
        Ok(self.host.tracked_registers(addr)?)
    }
}
