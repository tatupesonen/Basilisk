//! One storage resource of a parameter list (Ghidra `ParamEntry`): a
//! register, a joined set of registers, or a stack range from which
//! several parameters are allocated by slot.

mod decode;

use bitflags::bitflags;
use bk_core::{Address, SpaceId, SpaceManager, SpaceType, VarnodeData};

use crate::error::Result;
use crate::types::TypeClass;

pub(crate) use decode::{decode_entry, order_within_group};

bitflags! {
    /// Boolean properties of an entry (Ghidra's `ParamEntry` flag values).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct EntryFlags: u32 {
        /// Big-endian values are left justified within their slot.
        const FORCE_LEFT_JUSTIFY = 1;
        /// Slots are allocated in reverse order.
        const REVERSE_STACK = 2;
        /// Small values are zero extended into the container.
        const SMALLSIZE_ZEXT = 4;
        /// Small values are sign extended into the container.
        const SMALLSIZE_SEXT = 8;
        /// Small values are extended according to their integer type.
        const SMALLSIZE_INTTYPE = 0x20;
        /// Small values are floating-point extended to the full size.
        const SMALLSIZE_FLOATEXT = 0x40;
        /// Extra checks on the most significant part during recovery.
        const EXTRACHECK_HIGH = 0x80;
        /// Extra checks on the least significant part during recovery.
        const EXTRACHECK_LOW = 0x100;
        /// The entry is grouped with others.
        const IS_GROUPED = 0x200;
        /// The entry overlaps an earlier one and consumes no new group.
        const OVERLAPPING = 0x400;
        /// The entry is the first of its storage class.
        const FIRST_STORAGE = 0x800;
        /// The stack entry that assignments spill over into.
        const IS_STACKSPILL = 0x1000;
    }
}

/// How a range relates to the entries of a list (Ghidra's `ParamEntry`
/// containment codes, with their numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Containment {
    /// Neither contains nor is contained by an entry.
    None = 0,
    /// An entry contains the range, but not at its least significant bytes.
    ContainsUnjustified = 1,
    /// An entry contains the range at its least significant bytes.
    ContainsJustified = 2,
    /// The range contains an entry.
    ContainedBy = 3,
}

/// The extension a model assumes for a small value in a container
/// (Ghidra returns the p-code opcode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Extension {
    /// No extension (`CPUI_COPY`).
    Copy,
    /// Zero extension (`CPUI_INT_ZEXT`).
    Zext,
    /// Sign extension (`CPUI_INT_SEXT`).
    Sext,
    /// Extension by the parameter's integer type (`CPUI_PIECE`).
    Piece,
}

impl Extension {
    /// The name of the opcode Ghidra returns.
    pub const fn opcode_name(self) -> &'static str {
        match self {
            Self::Copy => "COPY",
            Self::Zext => "INT_ZEXT",
            Self::Sext => "INT_SEXT",
            Self::Piece => "PIECE",
        }
    }
}

/// One storage resource (Ghidra `ParamEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamEntry {
    pub(crate) flags: EntryFlags,
    pub(crate) class: TypeClass,
    /// Groups this entry belongs to, sorted; never empty.
    pub(crate) groups: Vec<i32>,
    pub(crate) space: SpaceId,
    pub(crate) space_type: SpaceType,
    pub(crate) big_endian: bool,
    pub(crate) base: u64,
    pub(crate) size: i32,
    pub(crate) minsize: i32,
    pub(crate) alignment: i32,
    pub(crate) numslots: i32,
    /// The pieces of a join entry, most significant first.
    pub(crate) join: Option<Box<[VarnodeData]>>,
}

impl ParamEntry {
    /// The first group (Ghidra `getGroup`).
    pub fn group(&self) -> i32 {
        self.groups.first().copied().unwrap_or(0)
    }
    /// All groups the entry overlaps (Ghidra `getAllGroups`).
    pub fn all_groups(&self) -> &[i32] {
        &self.groups
    }
    /// Size of the range in bytes (Ghidra `getSize`).
    pub const fn size(&self) -> i32 {
        self.size
    }
    /// Smallest value the entry holds (Ghidra `getMinSize`).
    pub const fn min_size(&self) -> i32 {
        self.minsize
    }
    /// Slot alignment; 0 for an exclusive entry (Ghidra `getAlign`).
    pub const fn align(&self) -> i32 {
        self.alignment
    }
    /// Number of slots (Ghidra `numslots`).
    pub const fn num_slots(&self) -> i32 {
        self.numslots
    }
    /// The storage class (Ghidra `getType`).
    pub const fn type_class(&self) -> TypeClass {
        self.class
    }
    /// The flags.
    pub const fn flags(&self) -> EntryFlags {
        self.flags
    }
    /// The space of the range (Ghidra `getSpace`).
    pub const fn space(&self) -> SpaceId {
        self.space
    }
    /// The start of the range (Ghidra `getBase`).
    pub const fn base(&self) -> u64 {
        self.base
    }
    /// The pieces of a join entry, most significant first (Ghidra
    /// `getJoinRecord`).
    pub fn join_pieces(&self) -> Option<&[VarnodeData]> {
        self.join.as_deref()
    }
    /// The stack entry that spills take (Ghidra `isStackSpill`).
    pub const fn is_stack_spill(&self) -> bool {
        self.flags.contains(EntryFlags::IS_STACKSPILL)
    }
    /// One parameter only (Ghidra `isExclusion`).
    pub const fn is_exclusion(&self) -> bool {
        self.alignment == 0
    }
    /// Slots allocated in reverse (Ghidra `isReverseStack`).
    pub const fn is_reverse_stack(&self) -> bool {
        self.flags.contains(EntryFlags::REVERSE_STACK)
    }
    /// Part of a `<group>` (Ghidra `isGrouped`).
    pub const fn is_grouped(&self) -> bool {
        self.flags.contains(EntryFlags::IS_GROUPED)
    }
    /// Overlaps an earlier entry (Ghidra `isOverlap`).
    pub const fn is_overlap(&self) -> bool {
        self.flags.contains(EntryFlags::OVERLAPPING)
    }
    /// First in its storage class (Ghidra `isFirstInClass`).
    pub const fn is_first_in_class(&self) -> bool {
        self.flags.contains(EntryFlags::FIRST_STORAGE)
    }
    /// Extra checks on the high part (Ghidra `isParamCheckHigh`).
    pub const fn is_param_check_high(&self) -> bool {
        self.flags.contains(EntryFlags::EXTRACHECK_HIGH)
    }
    /// Extra checks on the low part (Ghidra `isParamCheckLow`).
    pub const fn is_param_check_low(&self) -> bool {
        self.flags.contains(EntryFlags::EXTRACHECK_LOW)
    }
    /// The start of the range as an address.
    pub fn address(&self) -> Address {
        Address::new(self.space, self.base)
    }

    fn is_left_justified(&self) -> bool {
        self.flags.contains(EntryFlags::FORCE_LEFT_JUSTIFY) || !self.big_endian
    }

    fn last(&self) -> u64 {
        self.base.wrapping_add(self.size as u64).wrapping_sub(1)
    }

    /// Whether the group sets of two entries intersect (Ghidra
    /// `groupOverlap`).
    pub fn group_overlap(&self, other: &Self) -> bool {
        let (mut i, mut j) = (0, 0);
        while let (Some(a), Some(b)) = (self.groups.get(i), other.groups.get(j)) {
            match a.cmp(b) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
            }
        }
        false
    }

    /// Whether this entry subsumes the definition of `other` (Ghidra
    /// `subsumesDefinition`).
    pub fn subsumes_definition(&self, other: &Self) -> bool {
        if self.class != TypeClass::General && other.class != self.class {
            return false;
        }
        if self.space != other.space || other.base < self.base {
            return false;
        }
        if other.last() > self.last() {
            return false;
        }
        self.alignment == other.alignment
    }

    /// Whether the whole entry lies in the range (Ghidra `containedBy`).
    pub fn contained_by(&self, addr: Address, size: i32) -> bool {
        if Some(self.space) != addr.space() || self.base < addr.offset() {
            return false;
        }
        let rangeoff = addr.offset().wrapping_add(size as u64).wrapping_sub(1);
        self.last() <= rangeoff
    }

    /// Whether the entry, or any of its pieces, intersects the range
    /// (Ghidra `intersects`).
    pub fn intersects(&self, addr: Address, size: i32) -> bool {
        let rangeend = addr.offset().wrapping_add(size as u64).wrapping_sub(1);
        if let Some(pieces) = &self.join {
            for p in &**pieces {
                if addr.space() != p.space() {
                    continue;
                }
                let pend = p.offset.wrapping_add(u64::from(p.size)).wrapping_sub(1);
                if addr.offset() < p.offset && rangeend < pend {
                    continue;
                }
                if addr.offset() > p.offset && rangeend > pend {
                    continue;
                }
                return true;
            }
        }
        if Some(self.space) != addr.space() {
            return false;
        }
        let thisend = self.last();
        if addr.offset() < self.base && rangeend < thisend {
            return false;
        }
        !(addr.offset() > self.base && rangeend > thisend)
    }

    /// The endian-aware offset of the range within the entry, or `None` when
    /// it is not contained (Ghidra `justifiedContain`, which returns -1).
    pub fn justified_contain(&self, manager: &SpaceManager, addr: Address, size: i32) -> Option<i32> {
        if let Some(pieces) = &self.join {
            let mut res: i32 = 0;
            for p in pieces.iter().rev() {
                match p
                    .addr()
                    .justified_contain(manager, p.size, addr, size as u32, false)
                {
                    None => res = res.wrapping_add(p.size as i32),
                    Some(cur) => return Some(res.wrapping_add(cur as i32)),
                }
            }
            return None;
        }
        if self.alignment == 0 {
            let force = self.flags.contains(EntryFlags::FORCE_LEFT_JUSTIFY);
            return self
                .address()
                .justified_contain(manager, self.size as u32, addr, size as u32, force)
                .map(|v| v as i32);
        }
        if Some(self.space) != addr.space() {
            return None;
        }
        let start = addr.offset();
        if start < self.base {
            return None;
        }
        let end = start.wrapping_add(size as u64).wrapping_sub(1);
        if end < start || end > self.last() {
            return None;
        }
        let start = start.wrapping_sub(self.base);
        let end = end.wrapping_sub(self.base);
        let align = self.alignment as u64;
        if !self.is_left_justified() {
            let res = (end.wrapping_add(1) % align) as i32;
            return Some(if res == 0 { 0 } else { self.alignment.wrapping_sub(res) });
        }
        Some((start % align) as i32)
    }

    /// The location of the parameter that would contain the range (Ghidra
    /// `getContainer`).
    pub fn container(&self, manager: &SpaceManager, addr: Address, size: i32) -> Option<VarnodeData> {
        let endaddr = addr.add(manager, i64::from(size.wrapping_sub(1)));
        if let Some(pieces) = &self.join {
            return pieces.iter().rev().copied().find(|p| {
                addr.overlap(manager, 0, p.addr(), p.size).is_some()
                    && endaddr.overlap(manager, 0, p.addr(), p.size).is_some()
            });
        }
        let entry = self.address();
        addr.overlap(manager, 0, entry, self.size as u32)?;
        endaddr.overlap(manager, 0, entry, self.size as u32)?;
        if self.alignment == 0 {
            return Some(VarnodeData::new(self.space, self.base, self.size as u32));
        }
        let al = addr.offset().wrapping_sub(self.base) % self.alignment as u64;
        let offset = addr.offset().wrapping_sub(al);
        let mut sz = endaddr.offset().wrapping_sub(offset).wrapping_add(1) as i32;
        let al2 = sz % self.alignment;
        if al2 != 0 {
            sz = sz.wrapping_add(self.alignment - al2);
        }
        Some(VarnodeData::new(self.space, offset, sz as u32))
    }

    /// Whether this entry, or one of its pieces, contains `other` (Ghidra
    /// `contains`).
    pub fn contains(&self, other: &Self) -> bool {
        if other.join.is_some() {
            return false;
        }
        match &self.join {
            None => other.contained_by(self.address(), self.size),
            Some(pieces) => pieces
                .iter()
                .any(|p| other.contained_by(p.addr(), p.size as i32)),
        }
    }

    /// The extension assumed for a small value and its container (Ghidra
    /// `assumedExtension`).
    pub fn assumed_extension(
        &self,
        manager: &SpaceManager,
        addr: Address,
        size: i32,
    ) -> (Extension, Option<VarnodeData>) {
        let ext_flags =
            EntryFlags::SMALLSIZE_ZEXT | EntryFlags::SMALLSIZE_SEXT | EntryFlags::SMALLSIZE_INTTYPE;
        if !self.flags.intersects(ext_flags) {
            return (Extension::Copy, None);
        }
        if self.alignment != 0 {
            if size >= self.alignment {
                return (Extension::Copy, None);
            }
        } else if size >= self.size {
            return (Extension::Copy, None);
        }
        if self.join.is_some() || self.justified_contain(manager, addr, size) != Some(0) {
            return (Extension::Copy, None);
        }
        let res = if self.alignment == 0 {
            VarnodeData::new(self.space, self.base, self.size as u32)
        } else {
            let adjust = addr.offset().wrapping_sub(self.base) % self.alignment as u64;
            VarnodeData::new(self.space, addr.offset().wrapping_sub(adjust), self.alignment as u32)
        };
        let ext = if self.flags.contains(EntryFlags::SMALLSIZE_ZEXT) {
            Extension::Zext
        } else if self.flags.contains(EntryFlags::SMALLSIZE_INTTYPE) {
            Extension::Piece
        } else {
            Extension::Sext
        };
        (ext, Some(res))
    }

    /// The slot of the byte `skip` bytes after `addr`, which must lie in the
    /// entry (Ghidra `getSlot`).
    pub fn slot(&self, addr: Address, skip: i32) -> i32 {
        let mut res = self.group();
        if self.alignment != 0 {
            let diff = addr
                .offset()
                .wrapping_add(skip as u64)
                .wrapping_sub(self.base);
            let baseslot = (diff as i32).wrapping_div(self.alignment);
            if self.is_reverse_stack() {
                res = res.wrapping_add(self.numslots.wrapping_sub(1).wrapping_sub(baseslot));
            } else {
                res = res.wrapping_add(baseslot);
            }
        } else if skip != 0 {
            res = self.groups.last().copied().unwrap_or(res);
        }
        res
    }

    /// The address for a value of `size` bytes after `slotnum` slots have
    /// been used, advancing `slotnum`; [`Address::INVALID`] when it does not
    /// fit (Ghidra `getAddrBySlot`, the form without `justifyRight`).
    pub fn addr_by_slot(
        &self,
        manager: &SpaceManager,
        slotnum: &mut i32,
        size: i32,
        type_align: i32,
    ) -> Result<Address> {
        self.addr_by_slot_justified(manager, slotnum, (size, type_align), !self.is_left_justified())
    }

    /// [`ParamEntry::addr_by_slot`] with explicit right justification
    /// (Ghidra `getAddrBySlot` with `justifyRight`). `request` is the size
    /// and the required alignment of the value.
    pub fn addr_by_slot_justified(
        &self,
        manager: &SpaceManager,
        slotnum: &mut i32,
        request: (i32, i32),
        justify_right: bool,
    ) -> Result<Address> {
        let (sz, type_align) = request;
        if sz < self.minsize {
            return Ok(Address::INVALID);
        }
        let mut res;
        let spaceused;
        if self.alignment == 0 {
            if *slotnum != 0 || sz > self.size {
                return Ok(Address::INVALID);
            }
            res = self.address();
            spaceused = self.size;
            if self.flags.contains(EntryFlags::SMALLSIZE_FLOATEXT) && sz != self.size {
                return Ok(manager.construct_float_extension_address(
                    res,
                    self.size as u32,
                    sz as u32,
                )?);
            }
        } else {
            if type_align > self.alignment {
                let tmp = slotnum.wrapping_mul(self.alignment).wrapping_rem(type_align);
                if tmp != 0 {
                    *slotnum = slotnum.wrapping_add((type_align - tmp) / self.alignment);
                }
            }
            let mut slotsused = sz / self.alignment;
            if sz % self.alignment != 0 {
                slotsused += 1;
            }
            if slotnum.wrapping_add(slotsused) > self.numslots {
                return Ok(Address::INVALID);
            }
            spaceused = slotsused.wrapping_mul(self.alignment);
            let index = if self.is_reverse_stack() {
                self.numslots.wrapping_sub(*slotnum).wrapping_sub(slotsused)
            } else {
                *slotnum
            };
            let off = i64::from(index).wrapping_mul(i64::from(self.alignment));
            res = Address::new(self.space, self.base.wrapping_add(off as u64));
            *slotnum = slotnum.wrapping_add(slotsused);
        }
        if justify_right {
            res = res.add(manager, i64::from(spaceused.wrapping_sub(sz)));
        }
        Ok(res)
    }
}
