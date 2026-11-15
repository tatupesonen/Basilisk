//! A dump's varnodes, ops, lists and blocks into an [`Ssa`]. The dump is
//! untrusted: every reference is resolved and checked, every count bounded
//! by the dump's own size, and an inconsistency is an error, never a panic.

use std::collections::HashMap;
use std::sync::Arc;

use bk_core::{Address, RangeList, SpaceManager};
use bk_decomp_cfg::NodeId;
use bk_pcode::OpCode;
use bk_testkit::oracle::StateDump;
use bk_testkit::oracle::graph::OracleAddress;
use bk_testkit::oracle::state::{SeqNum as DumpSeq, VarnodeOffset};

use super::{StateError, dangling, inconsistent};
use crate::data::{OpData, Tree, VState, VarnodeData};
use crate::flags::oflags;
use crate::ids::{CallSpecId, NONE, OpId, VarnodeId};
use crate::list::Thread;
use crate::pool::IdList;
use crate::ssa::{CodeList, Ssa};

fn range<T: TryFrom<u64>>(what: &'static str, v: u64) -> Result<T, StateError> {
    T::try_from(v).map_err(|_| StateError::Range {
        what,
        value: format!("{v:#x}"),
    })
}

struct Loader<'a> {
    dump: &'a StateDump,
    ssa: Ssa,
    ops_by_seq: HashMap<(Address, u32), OpId>,
    vns_by_create: HashMap<u32, VarnodeId>,
    blocks_by_index: HashMap<u32, NodeId>,
}

impl Loader<'_> {
    fn addr(&self, a: &OracleAddress) -> Result<Address, StateError> {
        let s = self
            .ssa
            .spaces
            .space_by_name(&a.space)
            .ok_or_else(|| dangling("space", &a.space))?;
        Ok(Address::new(s.id(), a.offset))
    }

    fn seq_key(&self, s: &DumpSeq) -> Result<(Address, u32), StateError> {
        let pc = match &s.addr {
            Some(a) => self.addr(a)?,
            None => Address::INVALID,
        };
        Ok((pc, range("op time", s.time)?))
    }

    fn op(&self, s: &DumpSeq) -> Result<OpId, StateError> {
        let k = self.seq_key(s)?;
        self.ops_by_seq
            .get(&k)
            .copied()
            .ok_or_else(|| dangling("op", s))
    }

    fn vn(&self, v: bk_testkit::oracle::state::VarnodeId) -> Result<VarnodeId, StateError> {
        self.vns_by_create
            .get(&v.0)
            .copied()
            .ok_or_else(|| dangling("varnode", v))
    }

    fn block(&self, b: bk_testkit::oracle::state::BlockRef) -> Result<NodeId, StateError> {
        self.blocks_by_index
            .get(&b.0)
            .copied()
            .ok_or_else(|| dangling("block", b))
    }

    fn load_blocks(&mut self) -> Result<(), StateError> {
        for e in &self.dump.blocks {
            let b = &e.block;
            let n = self.ssa.add_block(b.flags)?;
            let index = i32::try_from(b.block.0).map_err(|_| StateError::Range {
                what: "block index",
                value: b.block.to_string(),
            })?;
            self.ssa.cfg.set_index(n, index)?;
            self.ssa.cfg.set_numdesc(n, b.numdesc)?;
            if self.blocks_by_index.insert(b.block.0, n).is_some() {
                return Err(inconsistent("block named twice", b.block));
            }
        }
        for e in &self.dump.blocks {
            let n = self.block(e.block.block)?;
            for edge in &e.in_edges {
                let src = self.block(edge.source)?;
                let slot = usize::try_from(edge.slot).map_err(|_| StateError::Range {
                    what: "edge slot",
                    value: edge.slot.to_string(),
                })?;
                if slot > self.dump.blocks.len().saturating_mul(4) + 16 {
                    return Err(StateError::Range {
                        what: "edge slot",
                        value: edge.slot.to_string(),
                    });
                }
                self.ssa.cfg.add_edge_at(src, slot, n, edge.label)?;
            }
            if let Some(d) = e.block.idom {
                let d = self.block(d)?;
                self.ssa.cfg.set_idom(n, Some(d))?;
            }
            let mut ranges = RangeList::default();
            for r in &e.block.cover {
                let s = self
                    .ssa
                    .spaces
                    .space_by_name(&r.space)
                    .ok_or_else(|| dangling("space", &r.space))?;
                ranges.insert_range(s.id(), r.first, r.last);
            }
            self.ssa.set_block_ranges(n, ranges)?;
        }
        self.ssa.cfg.check_slots()?;
        Ok(())
    }

    fn load_ops(&mut self) -> Result<(), StateError> {
        for r in &self.dump.ops {
            let (pc, time) = self.seq_key(&r.seq)?;
            let opcode = OpCode::from_name(&r.opcode).ok_or_else(|| dangling("opcode", &r.opcode))?;
            let tree = match r.tree.as_str() {
                "main" => Tree::Main,
                "alt" => Tree::Alt,
                t => return Err(inconsistent("op tree", t)),
            };
            let dead = match r.liveness.as_str() {
                "alive" => false,
                "dead" => true,
                t => return Err(inconsistent("op liveness", t)),
            };
            if dead != (r.flags & oflags::DEAD != 0) {
                return Err(inconsistent("dead flag against liveness", &r.seq));
            }
            let parent = match r.parent {
                Some(b) => self.block(b)?.get(),
                None => NONE,
            };
            let id = OpId::new(self.ssa.ops.len() as u32);
            if self.ops_by_seq.insert((pc, time), id).is_some() {
                return Err(inconsistent("sequence number used twice", &r.seq));
            }
            self.ssa.ops.push(OpData {
                pc,
                time,
                order: r.order,
                flags: r.flags,
                addl: r.addl_flags,
                parent,
                output: NONE,
                inputs: IdList::default(),
                opcode: opcode.value(),
                tree,
            });
            self.ssa.links.push(crate::list::OpLinks::default());
            match tree {
                Tree::Alt => self.ssa.alttree.insert((pc, time), id),
                _ => self.ssa.optree.insert((pc, time), id),
            };
        }
        Ok(())
    }

    fn offset(&self, space: &str, off: &VarnodeOffset) -> Result<(Address, bool), StateError> {
        let s = self
            .ssa
            .spaces
            .space_by_name(space)
            .ok_or_else(|| dangling("space", space))?;
        let id = s.id();
        Ok(match off {
            VarnodeOffset::Plain(v) => (Address::new(id, *v), false),
            VarnodeOffset::Op(seq) => (Address::new(id, u64::from(self.op(seq)?.get())), false),
            VarnodeOffset::Call(c) => (Address::new(id, u64::from(c.0)), false),
            VarnodeOffset::DeadCall => (Address::new(id, u64::from(CallSpecId::DEAD.get())), false),
            VarnodeOffset::Space(name) => {
                let sp = self
                    .ssa
                    .spaces
                    .space_by_name(name)
                    .ok_or_else(|| dangling("space", name))?;
                (Address::new(id, u64::from(sp.index())), true)
            }
        })
    }

    fn load_varnodes(&mut self) -> Result<(), StateError> {
        let next = self.dump.function.counters.next_create_index;
        for r in &self.dump.varnodes {
            if r.id.0 >= next {
                return Err(inconsistent("create index not below the next one", r.id));
            }
            let (loc, space_const) = self.offset(&r.space, &r.offset)?;
            let def = match &r.def {
                Some(s) => self.op(s)?.get(),
                None => NONE,
            };
            let mut readers = IdList::default();
            for s in &r.readers {
                let op = self.op(s)?;
                readers.push(&mut self.ssa.pool, op.get());
            }
            let entry = match r.entry {
                Some(e) => self.ssa.intern_entry(crate::ids::EntryRef {
                    symbol: e.symbol.0,
                    position: e.position,
                }),
                None => NONE,
            };
            let id = VarnodeId::new(self.ssa.vns.len() as u32);
            if self.vns_by_create.insert(r.id.0, id).is_some() {
                return Err(inconsistent("create index used twice", r.id));
            }
            self.ssa.vns.push(VarnodeData {
                flags: r.flags,
                addl: range("varnode addlflags", u64::from(r.addl_flags))?,
                merge_group: i16::try_from(r.merge_group).map_err(|_| StateError::Range {
                    what: "merge group",
                    value: r.merge_group.to_string(),
                })?,
                size: r.size,
                create_index: r.id.0,
                loc,
                def,
                high: r.high.map_or(NONE, |h| h.0),
                ty: r.data_type.map_or(NONE, |t| t.0),
                entry,
                consumed: r.consumed,
                nzm: r.nzm,
                readers,
                cover: None,
            });
            self.ssa.vstate.push(VState {
                destroyed: false,
                space_const,
            });
        }
        Ok(())
    }

    fn link_ops(&mut self) -> Result<(), StateError> {
        let mut uses: HashMap<(u32, u32), usize> = HashMap::new();
        for (i, r) in self.dump.ops.iter().enumerate() {
            let op = OpId::new(i as u32);
            if let Some(out) = r.output {
                let vn = self.vn(out)?;
                if self.ssa.vns.get(vn.index()).map(|d| d.def) != Some(op.get()) {
                    return Err(inconsistent("op output not defined by it", &r.seq));
                }
                if let Some(d) = self.ssa.ops.get_mut(op.index()) {
                    d.output = vn.get();
                }
            }
            let mut ids = Vec::with_capacity(r.inputs.len());
            for &v in &r.inputs {
                let vn = self.vn(v)?;
                *uses.entry((vn.get(), op.get())).or_default() += 1;
                ids.push(vn.get());
            }
            let pool = &mut self.ssa.pool;
            if let Some(d) = self.ssa.ops.get_mut(op.index()) {
                d.inputs.assign(pool, &ids);
            }
        }
        // Every reader list must be exactly the ops reading the varnode.
        let mut seen: HashMap<(u32, u32), usize> = HashMap::new();
        for (i, d) in self.ssa.vns.iter().enumerate() {
            for &op in d.readers.as_slice(&self.ssa.pool) {
                *seen.entry((i as u32, op)).or_default() += 1;
            }
            if d.def != NONE
                && self.ssa.ops.get(d.def as usize).map(|o| o.output) != Some(i as u32)
            {
                return Err(inconsistent("varnode def without matching op output", d.create_index));
            }
        }
        if seen != uses {
            return Err(inconsistent("reader lists differ from op inputs", ""));
        }
        Ok(())
    }

    fn load_lists(&mut self) -> Result<(), StateError> {
        let mut placed = vec![false; self.ssa.ops.len()];
        for l in &self.dump.op_lists {
            let (thread, code) = match l.name.as_str() {
                "alive" | "dead" => (Thread::Life, None),
                "store" => (Thread::Code, Some(CodeList::Store)),
                "load" => (Thread::Code, Some(CodeList::Load)),
                "return" => (Thread::Code, Some(CodeList::Return)),
                "userop" => (Thread::Code, Some(CodeList::Userop)),
                n => return Err(inconsistent("op list", n)),
            };
            for s in &l.ops {
                let op = self.op(s)?;
                let flags = self.ssa.opd_any(op)?.flags;
                let links = &mut self.ssa.links;
                match (l.name.as_str(), code) {
                    ("alive" | "dead", _) => {
                        if placed.get(op.index()).copied().unwrap_or(true) {
                            return Err(inconsistent("op in two life lists", s));
                        }
                        if let Some(p) = placed.get_mut(op.index()) {
                            *p = true;
                        }
                        let dead = l.name == "dead";
                        if dead != (flags & oflags::DEAD != 0) {
                            return Err(inconsistent("op in the wrong life list", s));
                        }
                        let head = if dead { &mut self.ssa.dead } else { &mut self.ssa.alive };
                        head.push_back(links, thread, op);
                    }
                    (_, Some(c)) => {
                        if links.get(op.index()).is_some_and(|x| x.code_list != 0)
                            || CodeList::of(self.ssa.ops.get(op.index()).and_then(OpData::opcode).unwrap_or(OpCode::Copy)) != Some(c)
                        {
                            return Err(inconsistent("op in a wrong opcode list", s));
                        }
                        if let Some(head) = self.ssa.code.get_mut(c.slot()) {
                            head.push_back(links, thread, op);
                        }
                        if let Some(x) = links.get_mut(op.index()) {
                            x.code_list = c as u8;
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(i) = placed.iter().position(|p| !p) {
            return Err(inconsistent("op in no life list", i));
        }
        Ok(())
    }

    fn load_block_ops(&mut self) -> Result<(), StateError> {
        for e in &self.dump.blocks {
            let n = self.block(e.block.block)?;
            for s in &e.block.ops {
                let op = self.op(s)?;
                if self.ssa.opd_any(op)?.parent != n.get() {
                    return Err(inconsistent("op listed in a block that is not its parent", s));
                }
                if self.ssa.links.get(op.index()).is_some_and(|l| {
                    l.prev(Thread::Block).is_some() || l.next(Thread::Block).is_some()
                }) || self.ssa.first_op(n) == Some(op)
                {
                    return Err(inconsistent("op listed twice in blocks", s));
                }
                let links = &mut self.ssa.links;
                if let Some(b) = self.ssa.blocks.get_mut(n.index()) {
                    b.ops.push_back(links, Thread::Block, op);
                }
            }
        }
        for (i, d) in self.ssa.ops.iter().enumerate() {
            if d.parent != NONE {
                let n = NodeId::new(d.parent);
                if !self.ssa.block_ops(n).contains(&OpId::new(i as u32)) {
                    return Err(inconsistent("op's parent block does not list it", i));
                }
            }
        }
        Ok(())
    }

    fn load_banks(&mut self) -> Result<(), StateError> {
        for i in 0..self.ssa.vns.len() {
            let vn = VarnodeId::new(i as u32);
            let k = self
                .ssa
                .key_parts(vn)
                .ok_or_else(|| inconsistent("varnode key", i))?;
            if self.ssa.loc.insert(k.loc(), vn).is_some() || self.ssa.def.insert(k.def(), vn).is_some()
            {
                return Err(inconsistent(
                    "two varnodes equal in the bank order",
                    self.ssa.varnode_create_index(vn),
                ));
            }
        }
        Ok(())
    }
}

/// Loads the IR part of `dump` over `spaces` (see
/// [`spaces_from_dump`](super::spaces_from_dump)).
pub fn load(dump: &StateDump, spaces: Arc<SpaceManager>) -> Result<Ssa, StateError> {
    let k = &dump.function.counters;
    let mut ssa = Ssa::new(spaces, range("unique base", k.uniq_base)?)?;
    ssa.uniqid = range("next unique offset", k.next_unique)?;
    ssa.create_index = k.next_create_index;
    ssa.op_time = range("next op time", k.next_op_time)?;
    let mut l = Loader {
        dump,
        ssa,
        ops_by_seq: HashMap::new(),
        vns_by_create: HashMap::new(),
        blocks_by_index: HashMap::new(),
    };
    let entry = l.addr(&dump.function.function.entry)?;
    l.ssa.set_entry(entry);
    l.load_blocks()?;
    l.load_ops()?;
    l.load_varnodes()?;
    l.link_ops()?;
    l.load_lists()?;
    l.load_block_ops()?;
    l.load_banks()?;
    Ok(l.ssa)
}
