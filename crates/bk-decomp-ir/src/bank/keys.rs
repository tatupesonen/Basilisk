//! The keys of the two varnode orders (Ghidra `VarnodeCompareLocDef` and
//! `VarnodeCompareDefLoc`, varnode.cc:34–79).
//!
//! A key is derived from the varnode's fields and its defining op's
//! sequence number; deriving `Ord` on the field order gives exactly Ghidra's
//! comparators. The class is `(flags & (input|written)) - 1` in 32-bit
//! unsigned arithmetic, so inputs sort before written varnodes and free ones
//! last. Fields a comparator does not look at for a class are zero, so
//! equal varnodes (two inputs at one place, two outputs of one op) have
//! equal keys, which is what `xref` detects.

use bk_core::Address;

use crate::flags::vflags;

/// A sequence number as the orders compare it: address, then time.
pub(crate) type SeqKey = (Address, u32);

/// The smallest sequence number (Ghidra `SeqNum(m_minimal)`).
pub(crate) const SEQ_MIN: SeqKey = (Address::MINIMAL, 0);
/// The largest sequence number (Ghidra `SeqNum(m_maximal)`).
pub(crate) const SEQ_MAX: SeqKey = (Address::MAXIMAL, u32::MAX);

/// Class of a flag word: `input` 0x08 → 7, `written` 0x10 → 0xf, free → max.
pub(crate) const fn class(flags: u32) -> u32 {
    (flags & (vflags::INPUT | vflags::WRITTEN)).wrapping_sub(1)
}

/// The class value of input varnodes.
pub(crate) const INPUT_CLASS: u32 = class(vflags::INPUT);
/// The class value of written varnodes.
pub(crate) const WRITTEN_CLASS: u32 = class(vflags::WRITTEN);
/// The class value of free varnodes.
pub(crate) const FREE_CLASS: u32 = class(0);

// The loc order sorts input, then written, then free varnodes.
const _: () = assert!(INPUT_CLASS < WRITTEN_CLASS && WRITTEN_CLASS < FREE_CLASS);

/// Location then definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocKey {
    pub(crate) addr: Address,
    pub(crate) size: i32,
    pub(crate) class: u32,
    pub(crate) seq: SeqKey,
    pub(crate) create: u32,
}

/// Definition then location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DefKey {
    pub(crate) class: u32,
    pub(crate) seq: SeqKey,
    pub(crate) addr: Address,
    pub(crate) size: i32,
    pub(crate) create: u32,
}

/// The parts both keys are built from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeyParts {
    /// The address with the pointer-valued offset replaced by its key.
    pub(crate) addr: Address,
    pub(crate) size: i32,
    pub(crate) flags: u32,
    /// The defining op's sequence number (written varnodes).
    pub(crate) seq: SeqKey,
    pub(crate) create: u32,
}

impl KeyParts {
    pub(crate) fn loc(&self) -> LocKey {
        let class = class(self.flags);
        LocKey {
            addr: self.addr,
            size: self.size,
            class,
            seq: if class == WRITTEN_CLASS {
                self.seq
            } else {
                SEQ_MIN
            },
            create: if class == FREE_CLASS { self.create } else { 0 },
        }
    }

    pub(crate) fn def(&self) -> DefKey {
        let class = class(self.flags);
        DefKey {
            class,
            seq: if class == WRITTEN_CLASS {
                self.seq
            } else {
                SEQ_MIN
            },
            addr: self.addr,
            size: self.size,
            create: if class == FREE_CLASS { self.create } else { 0 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bk_core::SpaceId;

    #[test]
    fn classes_order_input_written_free() {
        let a = Address::new(SpaceId::new(3), 0x10);
        let parts = |flags, create| KeyParts {
            addr: a,
            size: 4,
            flags,
            seq: (a, 5),
            create,
        };
        assert_eq!(
            parts(vflags::INPUT, 1).loc(),
            parts(vflags::INPUT, 2).loc(),
            "two inputs at one place are equal"
        );
        assert!(parts(0, 1).loc() < parts(0, 2).loc());
        assert!(parts(vflags::WRITTEN, 9).def() < parts(0, 0).def());
    }
}
