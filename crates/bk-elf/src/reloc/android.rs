//! Android packed relocations (`APS2`).
//!
//! The table starts with the four bytes `APS2`, followed by signed LEB128
//! values: the relocation count, the initial offset, and then groups. Each
//! group has a size and flags, and — depending on the flags — one offset
//! delta, `r_info` and addend delta shared by the whole group, or one per
//! relocation. Offsets and addends accumulate across the table.

use bk_bin::BinaryReader;

use crate::diag::{DiagnosticKind, Diagnostics};
use crate::header::ElfClass;
use crate::reloc::{Relocation, RelocationTable};

/// Group flag: all relocations of the group share one `r_info`.
pub const RELOCATION_GROUPED_BY_INFO_FLAG: i64 = 1;
/// Group flag: all relocations of the group share one offset delta.
pub const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: i64 = 2;
/// Group flag: all relocations of the group share one addend delta.
pub const RELOCATION_GROUPED_BY_ADDEND_FLAG: i64 = 4;
/// Group flag: the relocations of the group have addends.
pub const RELOCATION_GROUP_HAS_ADDEND_FLAG: i64 = 8;

/// The identifier at the start of a packed table.
const MAGIC: &[u8; 4] = b"APS2";

/// Why decoding stopped before the declared number of relocations.
#[derive(Debug)]
enum Stop {
    /// All relocations were produced.
    Done,
    /// The file ended in the middle of the table.
    Eof,
    /// A value could not be decoded.
    Read,
    /// A group's size is zero or negative.
    BadGroupSize(i64),
    /// A group claims more relocations than remain.
    GroupTooLarge { size: i64, remaining: i64 },
    /// A group carries addends but the table is a `REL` table.
    UnexpectedAddend,
}

/// The group being decoded.
#[derive(Debug, Clone, Copy)]
struct Group {
    left: i64,
    by_info: bool,
    by_delta: bool,
    by_addend: bool,
    has_addend: bool,
    delta: i64,
    info: i64,
}

/// The decoder proper: yields relocations until it has to stop.
#[derive(Debug, Clone)]
struct Decoder<'a> {
    reader: BinaryReader<'a>,
    class: ElfClass,
    with_addend: bool,
    remaining: i64,
    offset: i64,
    addend: i64,
    group: Option<Group>,
    index: u32,
}

impl<'a> Decoder<'a> {
    /// Positions a decoder after the `APS2` identifier at `file_offset`.
    fn new(reader: BinaryReader<'a>, file_offset: u64, class: ElfClass, with_addend: bool) -> Self {
        Self {
            reader: reader.at(file_offset.wrapping_add(MAGIC.len() as u64)),
            class,
            with_addend,
            remaining: 0,
            offset: 0,
            addend: 0,
            group: None,
            index: 0,
        }
    }

    fn sleb(&mut self) -> Result<i64, Stop> {
        self.reader
            .read_sleb128()
            .map_err(|e| if e.is_eof() { Stop::Eof } else { Stop::Read })
    }

    /// Reads the relocation count and the initial offset. At most
    /// `file_len` relocations will be decoded: a group whose offset delta
    /// and info are shared costs no bytes per relocation, so the declared
    /// count alone bounds nothing.
    fn read_header(&mut self) -> Result<i64, Stop> {
        let count = self.sleb()?;
        if count > 0 {
            self.offset = self.sleb()?;
        }
        self.remaining = count.min(i64::try_from(self.reader.len()).unwrap_or(i64::MAX));
        Ok(count)
    }

    fn start_group(&mut self) -> Result<Group, Stop> {
        let size = self.sleb()?;
        if size <= 0 {
            return Err(Stop::BadGroupSize(size));
        }
        if size > self.remaining {
            return Err(Stop::GroupTooLarge {
                size,
                remaining: self.remaining,
            });
        }
        let flags = self.sleb()?;
        let mut group = Group {
            left: size,
            by_info: flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0,
            by_delta: flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0,
            by_addend: flags & RELOCATION_GROUPED_BY_ADDEND_FLAG != 0,
            has_addend: flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0,
            delta: 0,
            info: 0,
        };
        if group.by_delta {
            group.delta = self.sleb()?;
        }
        if group.by_info {
            group.info = self.sleb()?;
        }
        if group.has_addend && group.by_addend {
            if !self.with_addend {
                return Err(Stop::UnexpectedAddend);
            }
            self.addend = self.addend.wrapping_add(self.sleb()?);
        } else if !group.has_addend {
            self.addend = 0;
        }
        Ok(group)
    }

    fn next(&mut self) -> Result<Relocation, Stop> {
        let mut group = match self.group {
            Some(group) if group.left > 0 => group,
            _ => {
                if self.remaining <= 0 {
                    return Err(Stop::Done);
                }
                self.start_group()?
            }
        };
        let delta = if group.by_delta {
            group.delta
        } else {
            self.sleb()?
        };
        self.offset = self.offset.wrapping_add(delta);
        let info = if group.by_info {
            group.info
        } else {
            self.sleb()?
        };
        let mut addend = 0;
        if self.with_addend && group.has_addend {
            if !group.by_addend {
                self.addend = self.addend.wrapping_add(self.sleb()?);
            }
            addend = self.addend;
        }
        group.left -= 1;
        self.remaining -= 1;
        self.group = Some(group);
        let relocation = Relocation::from_values(
            self.class,
            self.index,
            self.with_addend,
            self.offset as u64,
            info as u64,
            addend,
        );
        self.index = self.index.wrapping_add(1);
        Ok(relocation)
    }
}

/// The outcome of walking a packed table once, when the file is parsed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Scan {
    /// Number of relocations that decode.
    pub(crate) count: u64,
    /// True when the file ended inside the table.
    pub(crate) truncated: bool,
}

/// Walks the packed table at `file_offset` without keeping the relocations:
/// counts those that decode and reports what Ghidra reports while parsing
/// the table. `Err` carries the message of the exception Ghidra throws when
/// the table is not there or is not `APS2`.
///
/// `reader` must read the file itself, not the zero-padding view. The
/// number of relocations is capped at the length of the file.
pub(crate) fn scan(
    reader: BinaryReader<'_>,
    file_offset: u64,
    class: ElfClass,
    with_addend: bool,
    diags: &mut Diagnostics,
) -> Result<Scan, String> {
    let file_len = reader.len();
    let magic_fits = file_offset
        .checked_add(MAGIC.len() as u64)
        .is_some_and(|end| end <= file_len);
    if !magic_fits {
        return Err(format!(
            "Android relocation table not found at file offset {file_offset}"
        ));
    }
    if reader.read_array_at::<4>(file_offset).ok() != Some(*MAGIC) {
        return Err("Unsupported Android relocation table format".to_owned());
    }
    let mut decoder = Decoder::new(reader, file_offset, class, with_addend);
    let mut count = 0u64;
    let stop = match decoder.read_header() {
        Ok(declared) if declared <= 0 => {
            diags.push(
                DiagnosticKind::RelocationTable,
                format!("Unexpected ELF Android APS2 relocation count {declared}"),
            );
            return Ok(Scan {
                count: 0,
                truncated: false,
            });
        }
        Ok(declared) => {
            if declared as u64 > file_len {
                diags.push(
                    DiagnosticKind::CountTruncated,
                    format!(
                        "Android relocation count {declared} exceeds file capacity {file_len}; \
                         truncating"
                    ),
                );
            }
            loop {
                match decoder.next() {
                    Ok(_) => count += 1,
                    Err(stop) => break stop,
                }
            }
        }
        Err(stop) => stop,
    };
    let mut truncated = false;
    match stop {
        Stop::Done => {}
        Stop::Eof => {
            truncated = true;
            diags.push(
                DiagnosticKind::RelocationTableTruncated,
                "Truncated Android relocation table due to unexpected EOF",
            );
        }
        Stop::Read => diags.push(
            DiagnosticKind::RelocationTable,
            "Error reading Android relocation table: Unsupported LEB128 value, too large to fit \
             in 64bit java long variable",
        ),
        Stop::BadGroupSize(size) => diags.push(
            DiagnosticKind::RelocationTable,
            format!("Unexpected ELF Android APS2 Group relocation count {size}"),
        ),
        Stop::GroupTooLarge { size, remaining } => diags.push(
            DiagnosticKind::RelocationTable,
            format!(
                "ELF Android APS2 Group relocation count {size} exceeded total count {remaining}"
            ),
        ),
        Stop::UnexpectedAddend => {
            // Ghidra discards everything decoded so far in this case.
            count = 0;
            diags.push(
                DiagnosticKind::RelocationTable,
                "ELF Android APS2 Relocation processing failed.  Unexpected r_addend in \
                 android.rel section",
            );
        }
    }
    Ok(Scan { count, truncated })
}

/// Iterator over the relocations of an Android packed table.
///
/// It produces the relocations that decoded when the file was parsed and
/// then stops; what cut the table short, if anything, is in the file's
/// diagnostics.
#[derive(Debug, Clone)]
pub struct AndroidIter<'a> {
    decoder: Decoder<'a>,
    left: u64,
    started: bool,
}

impl<'a> AndroidIter<'a> {
    pub(crate) fn new(reader: BinaryReader<'a>, table: &RelocationTable, class: ElfClass) -> Self {
        Self {
            decoder: Decoder::new(reader, table.file_offset, class, table.has_addend),
            left: table.units,
            started: false,
        }
    }
}

impl Iterator for AndroidIter<'_> {
    type Item = Relocation;

    fn next(&mut self) -> Option<Relocation> {
        if self.left == 0 {
            return None;
        }
        if !self.started {
            self.started = true;
            self.decoder.read_header().ok()?;
        }
        let relocation = self.decoder.next().ok()?;
        self.left -= 1;
        Some(relocation)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = usize::try_from(self.left).unwrap_or(usize::MAX);
        (0, Some(left))
    }
}
