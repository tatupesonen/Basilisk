//! [`Ssa`]: the IR of one function — its varnodes and ops, their two banks,
//! the basic blocks over a `bk-decomp-cfg` graph, and the counters that name
//! what is created next. Ghidra keeps these in `Funcdata` (`vbank`, `obank`,
//! `bblocks`); everything else of `Funcdata` is D07's.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use bk_core::{Address, SpaceId, SpaceManager};
use bk_decomp_cfg::Cfg;

use crate::bank::keys::{DefKey, KeyParts, LocKey, SEQ_MIN, SeqKey};
use crate::data::{BasicData, OpData, Tree, VState, VarnodeData};
use crate::error::{IrError, IrResult};
use crate::flags::vflags;
use crate::ids::{EntryRef, NONE, OpId, VarnodeId};
use crate::list::{ListHead, OpLinks};
use crate::pool::Pool;
use crate::record::Recorder;

/// The per-opcode op lists of `PcodeOpBank`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CodeList {
    /// `storelist`.
    Store = 1,
    /// `loadlist`.
    Load = 2,
    /// `returnlist`.
    Return = 3,
    /// `useroplist` (`CALLOTHER`).
    Userop = 4,
}

impl CodeList {
    /// The list an opcode belongs to (Ghidra `addToCodeList`).
    pub const fn of(opcode: bk_pcode::OpCode) -> Option<Self> {
        match opcode {
            bk_pcode::OpCode::Store => Some(Self::Store),
            bk_pcode::OpCode::Load => Some(Self::Load),
            bk_pcode::OpCode::Return => Some(Self::Return),
            bk_pcode::OpCode::CallOther => Some(Self::Userop),
            _ => None,
        }
    }

    pub(crate) const fn slot(self) -> usize {
        self as usize - 1
    }

    pub(crate) const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Store),
            2 => Some(Self::Load),
            3 => Some(Self::Return),
            4 => Some(Self::Userop),
            _ => None,
        }
    }
}

/// The IR of one function. All structural change goes through its methods
/// (named after `Funcdata`'s); queries borrow it. It is `Send`: a function's
/// IR belongs to one decompilation (ADR-025, ADR-044).
pub struct Ssa {
    pub(crate) spaces: Arc<SpaceManager>,
    pub(crate) unique_space: SpaceId,
    pub(crate) vns: Vec<VarnodeData>,
    pub(crate) vstate: Vec<VState>,
    pub(crate) ops: Vec<OpData>,
    pub(crate) links: Vec<OpLinks>,
    pub(crate) pool: Pool,
    pub(crate) loc: BTreeMap<LocKey, VarnodeId>,
    pub(crate) def: BTreeMap<DefKey, VarnodeId>,
    pub(crate) optree: BTreeMap<SeqKey, OpId>,
    pub(crate) alttree: BTreeMap<SeqKey, OpId>,
    pub(crate) alive: ListHead,
    pub(crate) dead: ListHead,
    pub(crate) code: [ListHead; 4],
    pub(crate) gone: Vec<OpId>,
    /// `vbank.create_index`.
    pub(crate) create_index: u32,
    /// `vbank.uniqbase`.
    pub(crate) uniqbase: u32,
    /// `vbank.uniqid`.
    pub(crate) uniqid: u32,
    /// `obank.uniqid`.
    pub(crate) op_time: u32,
    pub(crate) cfg: Cfg,
    pub(crate) blocks: Vec<BasicData>,
    pub(crate) entries: Vec<EntryRef>,
    pub(crate) entry_index: HashMap<EntryRef, u32>,
    pub(crate) recorder: Option<Box<dyn Recorder>>,
}

impl fmt::Debug for Ssa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ssa")
            .field("varnodes", &self.loc.len())
            .field("ops", &(self.optree.len() + self.alttree.len()))
            .field("blocks", &self.cfg.len())
            .field("create_index", &self.create_index)
            .field("op_time", &self.op_time)
            .field("recorder", &self.recorder.is_some())
            .finish_non_exhaustive()
    }
}

impl Ssa {
    /// An empty function over the given spaces (which carry the processor's
    /// registers). `uniqbase` is the translator's
    /// `getUniqueStart(ANALYSIS)`, where new temporaries start.
    pub fn new(spaces: Arc<SpaceManager>, uniqbase: u32) -> IrResult<Self> {
        let unique_space = spaces
            .unique_space()
            .ok_or(IrError::MissingSpace("unique"))?
            .id();
        Ok(Self {
            spaces,
            unique_space,
            vns: Vec::new(),
            vstate: Vec::new(),
            ops: Vec::new(),
            links: Vec::new(),
            pool: Pool::default(),
            loc: BTreeMap::new(),
            def: BTreeMap::new(),
            optree: BTreeMap::new(),
            alttree: BTreeMap::new(),
            alive: ListHead::default(),
            dead: ListHead::default(),
            code: [ListHead::default(); 4],
            gone: Vec::new(),
            create_index: 0,
            uniqbase,
            uniqid: uniqbase,
            op_time: 0,
            cfg: Cfg::new(),
            blocks: Vec::new(),
            entries: Vec::new(),
            entry_index: HashMap::new(),
            recorder: None,
        })
    }

    /// The address spaces.
    pub fn spaces(&self) -> &SpaceManager {
        &self.spaces
    }

    /// A shared handle to the address spaces.
    pub fn spaces_arc(&self) -> Arc<SpaceManager> {
        Arc::clone(&self.spaces)
    }

    /// The block graph (`Funcdata::bblocks` without its ops).
    pub fn cfg(&self) -> &Cfg {
        &self.cfg
    }

    /// The next create index (`VarnodeBank::getCreateIndex`).
    pub fn next_create_index(&self) -> u32 {
        self.create_index
    }

    /// `VarnodeBank::uniqbase`.
    pub fn unique_base(&self) -> u32 {
        self.uniqbase
    }

    /// The next `unique` offset (`VarnodeBank::uniqid`).
    pub fn next_unique(&self) -> u32 {
        self.uniqid
    }

    /// The next op time (`PcodeOpBank::getUniqId`).
    pub fn next_op_time(&self) -> u32 {
        self.op_time
    }

    /// Sets the next op time (`PcodeOpBank::setUniqId`).
    pub fn set_next_op_time(&mut self, time: u32) {
        self.op_time = time;
    }

    /// Varnode slots allocated (live or not); ids are below this.
    pub fn varnode_bound(&self) -> usize {
        self.vns.len()
    }

    /// Op slots allocated (live, dead or retired); ids are below this.
    pub fn op_bound(&self) -> usize {
        self.ops.len()
    }

    // ----- checked access -----

    pub(crate) fn vnd(&self, vn: VarnodeId) -> IrResult<&VarnodeData> {
        match (self.vns.get(vn.index()), self.vstate.get(vn.index())) {
            (Some(d), Some(s)) if !s.destroyed => Ok(d),
            (Some(_), _) => Err(IrError::DestroyedVarnode(vn)),
            _ => Err(IrError::NoSuchVarnode(vn)),
        }
    }

    pub(crate) fn vnd_mut(&mut self, vn: VarnodeId) -> IrResult<&mut VarnodeData> {
        match (self.vns.get_mut(vn.index()), self.vstate.get(vn.index())) {
            (Some(d), Some(s)) if !s.destroyed => Ok(d),
            (Some(_), _) => Err(IrError::DestroyedVarnode(vn)),
            _ => Err(IrError::NoSuchVarnode(vn)),
        }
    }

    pub(crate) fn vstate(&self, vn: VarnodeId) -> VState {
        self.vstate.get(vn.index()).copied().unwrap_or(VState {
            destroyed: true,
            space_const: false,
        })
    }

    /// An op that exists (retired ones included: Ghidra keeps their memory
    /// until the function is cleared, and queries on them are allowed).
    pub(crate) fn opd_any(&self, op: OpId) -> IrResult<&OpData> {
        self.ops.get(op.index()).ok_or(IrError::NoSuchOp(op))
    }

    /// An op that is not retired.
    pub(crate) fn opd(&self, op: OpId) -> IrResult<&OpData> {
        let d = self.opd_any(op)?;
        if d.tree == Tree::Retired {
            return Err(IrError::RetiredOp(op));
        }
        Ok(d)
    }

    pub(crate) fn opd_mut(&mut self, op: OpId) -> IrResult<&mut OpData> {
        let d = self.ops.get_mut(op.index()).ok_or(IrError::NoSuchOp(op))?;
        if d.tree == Tree::Retired {
            return Err(IrError::RetiredOp(op));
        }
        Ok(d)
    }

    // ----- bank keys -----

    /// The address a varnode sorts by: an `iop` offset is replaced by the
    /// named op's time (Basilisk's key; Ghidra compares the heap pointer).
    pub(crate) fn key_addr(&self, d: &VarnodeData) -> Address {
        let space = d.loc.space();
        if space.is_some() && space == self.spaces.iop_space().map(bk_core::Space::id) {
            let time = self
                .ops
                .get(d.loc.offset() as usize)
                .map_or(u64::MAX, |o| u64::from(o.time));
            if let Some(s) = space {
                return Address::new(s, time);
            }
        }
        d.loc
    }

    pub(crate) fn key_parts(&self, vn: VarnodeId) -> Option<KeyParts> {
        let d = self.vns.get(vn.index())?;
        let seq = d
            .def()
            .and_then(|op| self.ops.get(op.index()))
            .map_or(SEQ_MIN, |o| (o.pc, o.time));
        Some(KeyParts {
            addr: self.key_addr(d),
            size: d.size,
            flags: d.flags,
            seq,
            create: d.create_index,
        })
    }

    /// Takes the varnode out of both orders.
    pub(crate) fn bank_remove(&mut self, vn: VarnodeId) {
        if let Some(k) = self.key_parts(vn) {
            if self.loc.get(&k.loc()) == Some(&vn) {
                self.loc.remove(&k.loc());
            }
            if self.def.get(&k.def()) == Some(&vn) {
                self.def.remove(&k.def());
            }
        }
    }

    /// Puts the varnode into both orders without the `xref` check (free
    /// varnodes are unique by create index).
    pub(crate) fn bank_insert_plain(&mut self, vn: VarnodeId) {
        if let Some(k) = self.key_parts(vn) {
            self.loc.insert(k.loc(), vn);
            self.def.insert(k.def(), vn);
        }
    }

    /// The varnode equal to `vn` in loc order, if another one is there.
    pub(crate) fn bank_twin(&self, vn: VarnodeId) -> Option<VarnodeId> {
        let k = self.key_parts(vn)?;
        self.loc.get(&k.loc()).copied().filter(|&o| o != vn)
    }

    /// Interns a symbol entry reference.
    pub(crate) fn intern_entry(&mut self, e: EntryRef) -> u32 {
        if let Some(&i) = self.entry_index.get(&e) {
            return i;
        }
        let i = self.entries.len() as u32;
        self.entries.push(e);
        self.entry_index.insert(e, i);
        i
    }

    pub(crate) fn entry_of(&self, d: &VarnodeData) -> Option<EntryRef> {
        if d.entry == NONE {
            return None;
        }
        self.entries.get(d.entry as usize).copied()
    }

    /// Whether the varnode's space is the given special space.
    pub(crate) fn is_space(&self, addr: Address, which: SpecialSpace) -> bool {
        let id = match which {
            SpecialSpace::Iop => self.spaces.iop_space(),
            SpecialSpace::Fspec => self.spaces.fspec_space(),
            SpecialSpace::Join => self.spaces.join_space(),
        }
        .map(bk_core::Space::id);
        id.is_some() && addr.space() == id
    }

    /// The flags a new varnode at `addr` starts with (Ghidra's `Varnode`
    /// constructor): `constant` in the constant space, `annotation |
    /// coverdirty` in `fspec`/`iop`, otherwise `coverdirty`.
    pub(crate) fn initial_flags(&self, addr: Address) -> u32 {
        if addr.is_constant() {
            vflags::CONSTANT
        } else if self.is_space(addr, SpecialSpace::Iop) || self.is_space(addr, SpecialSpace::Fspec)
        {
            vflags::ANNOTATION | vflags::COVERDIRTY
        } else {
            vflags::COVERDIRTY
        }
    }
}

/// The special spaces whose offsets are not addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpecialSpace {
    Iop,
    Fspec,
    Join,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssa_is_send() {
        fn send<T: Send + 'static>() {}
        send::<Ssa>();
    }
}
