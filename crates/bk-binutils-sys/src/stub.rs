//! The interface on platforms where binutils is not built: every operation
//! reports [`RawError::Unavailable`], and the two handle types cannot exist.

use std::convert::Infallible;

use crate::{ArchInfo, RawError, Step};

/// See the built variant; on this platform it cannot be created.
#[derive(Debug)]
pub struct RawDisassembler {
    never: Infallible,
}

impl RawDisassembler {
    /// Always fails with [`RawError::Unavailable`] on this platform.
    pub fn new(
        _arch: u32,
        _mach: u64,
        _big_endian: bool,
        _options: Option<&str>,
    ) -> Result<Self, RawError> {
        Err(RawError::Unavailable)
    }

    /// Unreachable: no value of this type exists on this platform.
    pub fn request(&mut self, _bytes: &[u8], _address: u64) -> Result<Request<'_>, RawError> {
        match self.never {}
    }
}

/// See the built variant; on this platform it cannot be created.
#[derive(Debug)]
pub struct Request<'a> {
    owner: &'a mut RawDisassembler,
}

impl Request<'_> {
    /// Unreachable: no value of this type exists on this platform.
    pub fn step(&mut self, _offset: usize) -> Result<Step<'_>, RawError> {
        match self.owner.never {}
    }

    /// Unreachable: no value of this type exists on this platform.
    pub fn take_message(&mut self) -> Option<String> {
        match self.owner.never {}
    }

    /// Unreachable: no value of this type exists on this platform.
    pub fn len(&self) -> usize {
        match self.owner.never {}
    }

    /// Unreachable: no value of this type exists on this platform.
    pub fn is_empty(&self) -> bool {
        match self.owner.never {}
    }
}

pub(crate) fn architecture_names() -> Result<Vec<String>, RawError> {
    Err(RawError::Unavailable)
}

pub(crate) fn scan_architecture(_name: &str) -> Result<Option<ArchInfo>, RawError> {
    Err(RawError::Unavailable)
}
