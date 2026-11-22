//! High-variable events: what Ghidra's `Varnode` setters tell the varnode's
//! `HighVariable` (`varnode.cc:316`–`651`). The table of high variables lives
//! in the caller (D07); this crate changes only the varnode, so each
//! [`Ssa`] method that corresponds to one of those setters records, for a
//! varnode that has a high, the call the high would have received, in call
//! order, in a queue the caller drains with [`Ssa::take_high_events`].
//!
//! The rules, from the C++ (the queue allocates only once a varnode with a
//! high is touched; loading a dump calls no setter and records nothing):
//!
//! * `setFlags(fl)` / `clearFlags(fl)` (371–393): [`HighEvent::FlagsDirty`],
//!   then [`HighEvent::CoverDirty`] when `fl` includes `coverdirty`, whether
//!   or not any bit changed. Reached by `addDescend`/`eraseDescend` (330–340,
//!   316–326), `setDef` (421–436: `coverdirty` then, for no op, a second
//!   call clearing `written`), `setInput` (varnode.hh:170), `xref`'s
//!   `insert` (varnode.cc:1307), `replace` (1333–1353), `makeFree`
//!   (1317–1327), `calcCover` (254–262), `updateCover` (233–242, clearing
//!   `coverdirty` reports `CoverDirty` too), `setSymbolProperties`,
//!   `setSymbolEntry`, and the setters varnode.hh:168–170, 309–314, 322–325
//!   (`setAddrForce`, `setImplied`, `setExplicit`, `setPrecisLo/Hi`,
//!   `setUnaffected` and their clears). The setters that write `flags`
//!   directly (`setMark`, `setDirectWrite`, `setReturnAddress`,
//!   `setAutoLiveHold`, `setProtoPartial`, the `addlflags` ones, the
//!   indirect-creation marks of `funcdata_op.cc:722`–`760`) report nothing.
//! * `updateType` (both forms, 488–521): [`HighEvent::TypeDirty`] when the
//!   type or lock changed.
//! * `setSymbolProperties` (441–456): the type update's events, then
//!   [`HighEvent::SetSymbol`] when the symbol is type-locked and the entry
//!   is new, then `setFlags`.
//! * `setSymbolEntry` (461–471): `setFlags(mapped[|namelock])`, then
//!   [`HighEvent::SetSymbol`].
//! * `setSymbolReference` (478–484): [`HighEvent::SetSymbolReference`].
//! * `copySymbol` (525–537): [`HighEvent::TypeDirty`], then
//!   [`HighEvent::SetSymbol`] when the copied entry is set.
//! * `clearSymbolLinks` (397–415): per instance of the high, `clearFlags`;
//!   then [`HighEvent::SymbolDirty`] if any instance had an entry.
//! * the destructor (642–651; `VarnodeBank::destroy` and `xref`'s merge,
//!   1277–1311): [`HighEvent::Removed`].

use crate::error::IrResult;
use crate::flags::vflags;
use crate::ids::{EntryRef, HighId, NONE, VarnodeId};
use crate::ssa::Ssa;

/// One call a varnode setter makes on the varnode's `HighVariable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighEvent {
    /// `HighVariable::flagsDirty`.
    FlagsDirty(HighId),
    /// `HighVariable::coverDirty`.
    CoverDirty(HighId),
    /// `HighVariable::typeDirty`.
    TypeDirty(HighId),
    /// `HighVariable::symbolDirty`.
    SymbolDirty(HighId),
    /// `HighVariable::setSymbol(vn)`.
    SetSymbol {
        /// The high.
        high: HighId,
        /// The varnode whose entry the high takes.
        vn: VarnodeId,
    },
    /// `HighVariable::setSymbolReference(entry->getSymbol(), offset)`.
    SetSymbolReference {
        /// The high.
        high: HighId,
        /// The varnode the call came through.
        vn: VarnodeId,
        /// The symbol entry (the high takes its symbol).
        entry: EntryRef,
        /// The byte offset into the symbol.
        offset: i32,
    },
    /// `HighVariable::remove(vn)`: the varnode was deleted.
    Removed {
        /// The high.
        high: HighId,
        /// The deleted varnode.
        vn: VarnodeId,
    },
}

impl Ssa {
    /// The events recorded since the last [`Ssa::take_high_events`], in
    /// call order.
    pub fn high_events(&self) -> &[HighEvent] {
        &self.high_events
    }

    /// Drains the recorded events.
    pub fn take_high_events(&mut self) -> Vec<HighEvent> {
        std::mem::take(&mut self.high_events)
    }

    fn high_of(&self, vn: VarnodeId) -> Option<HighId> {
        self.vns
            .get(vn.index())
            .and_then(|d| HighId::from_packed(d.high))
    }

    /// `Varnode::setFlags`: sets the bits and reports to the high.
    pub(crate) fn vn_set_flags(&mut self, vn: VarnodeId, bits: u32) -> IrResult<()> {
        self.vnd_mut(vn)?.flags |= bits;
        self.flags_dirty(vn, bits);
        Ok(())
    }

    /// `Varnode::clearFlags`: clears the bits and reports to the high.
    pub(crate) fn vn_clear_flags(&mut self, vn: VarnodeId, bits: u32) -> IrResult<()> {
        self.vnd_mut(vn)?.flags &= !bits;
        self.flags_dirty(vn, bits);
        Ok(())
    }

    fn flags_dirty(&mut self, vn: VarnodeId, bits: u32) {
        if let Some(h) = self.high_of(vn) {
            self.high_events.push(HighEvent::FlagsDirty(h));
            if bits & vflags::COVERDIRTY != 0 {
                self.high_events.push(HighEvent::CoverDirty(h));
            }
        }
    }

    pub(crate) fn type_dirty(&mut self, vn: VarnodeId) {
        if let Some(h) = self.high_of(vn) {
            self.high_events.push(HighEvent::TypeDirty(h));
        }
    }

    pub(crate) fn high_set_symbol(&mut self, vn: VarnodeId) {
        if let Some(high) = self.high_of(vn) {
            self.high_events.push(HighEvent::SetSymbol { high, vn });
        }
    }

    /// The varnode is about to be deleted (`~Varnode`).
    pub(crate) fn high_removed(&mut self, vn: VarnodeId) {
        if let Some(high) = self.high_of(vn) {
            self.high_events.push(HighEvent::Removed { high, vn });
        }
    }

    /// `Varnode::setSymbolReference`: changes nothing on the varnode;
    /// reports [`HighEvent::SetSymbolReference`] when it has a high.
    pub fn set_symbol_reference(
        &mut self,
        vn: VarnodeId,
        entry: EntryRef,
        offset: i32,
    ) -> IrResult<()> {
        self.vnd(vn)?;
        if let Some(high) = self.high_of(vn) {
            self.high_events.push(HighEvent::SetSymbolReference {
                high,
                vn,
                entry,
                offset,
            });
        }
        Ok(())
    }

    /// `Varnode::clearSymbolLinks`: for `vn`, or for every live varnode of
    /// its high (Ghidra's instances; here the varnodes that name the same
    /// high, in creation order), drops the entry and clears `namelock`,
    /// `typelock` and `mapped`; [`HighEvent::SymbolDirty`] if any had an
    /// entry.
    pub fn clear_symbol_links(&mut self, vn: VarnodeId) -> IrResult<()> {
        const BITS: u32 = vflags::NAMELOCK | vflags::TYPELOCK | vflags::MAPPED;
        self.vnd(vn)?;
        let Some(high) = self.high_of(vn) else {
            self.vnd_mut(vn)?.entry = NONE;
            return self.vn_clear_flags(vn, BITS);
        };
        let instances: Vec<VarnodeId> = (0..self.vns.len())
            .map(|i| VarnodeId(i as u32))
            .filter(|&v| self.varnode_exists(v) && self.high_of(v) == Some(high))
            .collect();
        let mut found = false;
        for v in instances {
            let d = self.vnd_mut(v)?;
            found |= d.entry != NONE;
            d.entry = NONE;
            self.vn_clear_flags(v, BITS)?;
        }
        if found {
            self.high_events.push(HighEvent::SymbolDirty(high));
        }
        Ok(())
    }
}
