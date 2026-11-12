//! Sequence numbers of p-code operations (Ghidra `SeqNum` in
//! `address.hh`/`address.cc`).

use std::cmp::Ordering;
use std::fmt;

use bk_marshal::{Decoder, Encoder};

use crate::address::Address;
use crate::error::SpaceError;
use crate::ids::{ATTRIB_UNIQ, ELEM_SEQNUM};
use crate::manager::SpaceManager;
use crate::varnode::VarnodeData;

/// A unique identifier for a p-code operation: the address of the
/// instruction it came from and a number unique among the operations
/// (Ghidra `SeqNum`).
///
/// Ghidra's `==` compares only the unique number while its `<` compares the
/// address first; Rust requires the two to agree, so here both compare the
/// address and then the unique number. [`SeqNum::same_time`] is Ghidra's
/// `==`. The `order` field, used for ordering within a basic block, takes no
/// part in comparisons, as in Ghidra.
#[derive(Clone, Copy, Debug)]
pub struct SeqNum {
    pc: Address,
    uniq: u32,
    order: u32,
}

impl SeqNum {
    /// The smallest sequence number (Ghidra `SeqNum(m_minimal)`).
    pub const MINIMAL: Self = Self {
        pc: Address::MINIMAL,
        uniq: 0,
        order: 0,
    };
    /// The largest sequence number (Ghidra `SeqNum(m_maximal)`).
    pub const MAXIMAL: Self = Self {
        pc: Address::MAXIMAL,
        uniq: u32::MAX,
        order: 0,
    };

    /// The sequence number of an operation from the instruction at `pc`.
    pub const fn new(pc: Address, uniq: u32) -> Self {
        Self { pc, uniq, order: 0 }
    }

    /// The address of the instruction the operation came from.
    pub const fn addr(&self) -> Address {
        self.pc
    }

    /// The number that makes this sequence number unique (Ghidra `getTime`).
    pub const fn time(&self) -> u32 {
        self.uniq
    }

    /// The position of the operation within its basic block.
    pub const fn order(&self) -> u32 {
        self.order
    }

    /// Sets the position of the operation within its basic block.
    pub const fn set_order(&mut self, order: u32) {
        self.order = order;
    }

    /// Whether the two have the same unique number, regardless of address
    /// (Ghidra's `operator==`).
    pub const fn same_time(&self, other: &Self) -> bool {
        self.uniq == other.uniq
    }

    /// Writes the sequence number as a `<seqnum>` element: the address's
    /// attributes and `uniq` (Ghidra `encode`).
    pub fn encode<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        manager: &SpaceManager,
    ) -> Result<(), SpaceError> {
        let space = self.pc.space().ok_or(SpaceError::InvalidAddress)?;
        encoder.open_element(ELEM_SEQNUM);
        manager.encode_attributes(encoder, space, self.pc.offset())?;
        encoder.write_unsigned(ATTRIB_UNIQ, u64::from(self.uniq));
        encoder.close_element(ELEM_SEQNUM);
        Ok(())
    }

    /// Reads a `<seqnum>` element as [`SeqNum::encode`] writes it.
    ///
    /// Ghidra's `SeqNum::decode` reads the address from a child element,
    /// which its encoder never writes; this reads it from the element's own
    /// attributes, which is evidently what was meant. A missing `uniq` reads
    /// as `u32::MAX`, as in Ghidra.
    pub fn decode<'a, D: Decoder<'a> + ?Sized>(
        decoder: &mut D,
        manager: &SpaceManager,
    ) -> Result<Self, SpaceError> {
        let element = decoder.open_element_expecting(ELEM_SEQNUM)?;
        let pc = VarnodeData::decode_from_attributes(decoder, manager)?.addr();
        decoder.rewind_attributes();
        let mut uniq = u32::MAX;
        while let Some(attribute) = decoder.next_attribute()? {
            if attribute == ATTRIB_UNIQ {
                uniq = decoder.read_unsigned()? as u32;
                break;
            }
        }
        decoder.close_element(element)?;
        Ok(Self::new(pc, uniq))
    }

    /// A value that prints the sequence number as `address:uniq` (Ghidra
    /// `operator<<`).
    pub fn raw(self, manager: &SpaceManager) -> RawSeqNum<'_> {
        RawSeqNum { manager, seq: self }
    }
}

impl PartialEq for SeqNum {
    fn eq(&self, other: &Self) -> bool {
        self.pc == other.pc && self.uniq == other.uniq
    }
}

impl Eq for SeqNum {}

impl std::hash::Hash for SeqNum {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pc.hash(state);
        self.uniq.hash(state);
    }
}

impl Ord for SeqNum {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pc.cmp(&other.pc).then(self.uniq.cmp(&other.uniq))
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A sequence number printed as Ghidra does; see [`SeqNum::raw`].
#[derive(Debug)]
pub struct RawSeqNum<'m> {
    manager: &'m SpaceManager,
    seq: SeqNum,
}

impl fmt::Display for RawSeqNum<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.manager.write_raw_address(f, self.seq.pc)?;
        write!(f, ":{}", self.seq.uniq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bk_marshal::SpaceId;

    #[test]
    fn seqnum_is_small() {
        assert_eq!(size_of::<SeqNum>(), 24);
    }

    #[test]
    fn seqnum_equality_and_order() {
        let a = SeqNum::new(Address::new(SpaceId::new(1), 0x10), 7);
        let b = SeqNum::new(Address::new(SpaceId::new(1), 0x20), 7);
        assert!(a.same_time(&b));
        assert_ne!(a, b);
        assert!(a < b);
        assert!(SeqNum::MINIMAL < a && b < SeqNum::MAXIMAL);
        let mut c = a;
        c.set_order(9);
        assert_eq!(a, c);
        assert_eq!(c.order(), 9);
    }
}
