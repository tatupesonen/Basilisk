//! The structural invariants of an [`Ssa`] (spec 6, test 6), checked from
//! the outside of the mutation interface: what Ghidra's banks keep true
//! between any two `Funcdata` calls (`varnode.cc`, `op.cc`,
//! `funcdata_op.cc`). The property tests, the fuzz target and the corpus
//! test call it after every step; it is a diagnostic, not a repair.

use std::collections::{BTreeSet, HashMap};

use bk_pcode::OpCode;

use crate::data::Tree;
use crate::flags::{oflags, vflags};
use crate::ids::{OpId, VarnodeId};
use crate::list::Thread;
use crate::ssa::{CodeList, Ssa};

impl Ssa {
    /// Every broken invariant, one line each; empty when the state is
    /// consistent:
    ///
    /// * the loc and def orders hold exactly the live varnodes, under the
    ///   keys their fields give;
    /// * a varnode is `written` exactly when it has a defining op, and that
    ///   op has it as output (and conversely);
    /// * each varnode's reader list is, as a multiset, the slots of live
    ///   ops that read it; a free varnode that is not a space base has at
    ///   most one reader (`Varnode::addDescend`, `varnode.cc`);
    /// * the trees hold exactly the ops that are not retired, under their
    ///   sequence numbers; `alttree` holds only `INDIRECT`s;
    /// * an op is in the alive list exactly when it is not `dead`, and in a
    ///   block exactly when it is alive; each block's ops name the block as
    ///   parent and their `order` increases;
    /// * each op of an opcode list has an opcode of that list and each op
    ///   with such an opcode is in its list once.
    pub fn invariant_violations(&self) -> Vec<String> {
        let mut bad = Vec::new();
        self.check_varnodes(&mut bad);
        self.check_readers(&mut bad);
        self.check_ops(&mut bad);
        self.check_blocks(&mut bad);
        bad
    }

    fn live_varnodes(&self) -> impl Iterator<Item = VarnodeId> + '_ {
        (0..self.vns.len() as u32)
            .map(VarnodeId)
            .filter(|v| self.vstate.get(v.index()).is_some_and(|s| !s.destroyed))
    }

    fn live_ops(&self) -> impl Iterator<Item = OpId> + '_ {
        (0..self.ops.len() as u32).map(OpId).filter(|o| {
            self.ops
                .get(o.index())
                .is_some_and(|d| d.tree != Tree::Retired)
        })
    }

    fn check_varnodes(&self, bad: &mut Vec<String>) {
        let mut live = 0usize;
        for vn in self.live_varnodes() {
            live += 1;
            let (Some(d), Some(k)) = (self.vns.get(vn.index()), self.key_parts(vn)) else {
                continue;
            };
            if self.loc.get(&k.loc()) != Some(&vn) {
                bad.push(format!("{vn}: not in loc order under its key"));
            }
            if self.def.get(&k.def()) != Some(&vn) {
                bad.push(format!("{vn}: not in def order under its key"));
            }
            let written = d.flags & vflags::WRITTEN != 0;
            match d.def() {
                Some(op) => {
                    if !written {
                        bad.push(format!("{vn}: has a def but is not written"));
                    }
                    let out = self
                        .ops
                        .get(op.index())
                        .and_then(|o| (o.tree != Tree::Retired).then(|| o.output()).flatten());
                    if out != Some(vn) {
                        bad.push(format!("{vn}: def {op} does not output it"));
                    }
                }
                None if written => bad.push(format!("{vn}: written without a def")),
                None => {}
            }
            if d.flags & vflags::INPUT != 0 && written {
                bad.push(format!("{vn}: both input and written"));
            }
        }
        if self.loc.len() != live || self.def.len() != live {
            bad.push(format!(
                "orders hold {} (loc) and {} (def) varnodes, {live} are live",
                self.loc.len(),
                self.def.len()
            ));
        }
    }

    fn check_readers(&self, bad: &mut Vec<String>) {
        let mut reads: HashMap<(VarnodeId, OpId), usize> = HashMap::new();
        for op in self.live_ops() {
            for vn in self.op_inputs(op).into_iter().flatten() {
                if !self.varnode_exists(vn) {
                    bad.push(format!("{op}: reads destroyed {vn}"));
                }
                *reads.entry((vn, op)).or_default() += 1;
            }
            if let Some(out) = self.op_output(op) {
                if !self.varnode_exists(out) {
                    bad.push(format!("{op}: outputs destroyed {out}"));
                } else if self.varnode_def(out) != Some(op) {
                    bad.push(format!("{op}: output {out} names another def"));
                }
            }
        }
        let mut listed: HashMap<(VarnodeId, OpId), usize> = HashMap::new();
        for vn in self.live_varnodes() {
            let readers = self.readers(vn);
            let flags = self.varnode_flags(vn);
            let free = flags & (vflags::INPUT | vflags::WRITTEN) == 0;
            if free && flags & vflags::SPACEBASE == 0 && readers.len() > 1 {
                bad.push(format!("{vn}: free with {} readers", readers.len()));
            }
            for op in readers {
                *listed.entry((vn, op)).or_default() += 1;
            }
        }
        if reads != listed {
            let a: BTreeSet<_> = reads.iter().map(|(k, n)| (k.0, k.1, *n)).collect();
            let b: BTreeSet<_> = listed.iter().map(|(k, n)| (k.0, k.1, *n)).collect();
            for (vn, op, n) in a.symmetric_difference(&b).take(8) {
                bad.push(format!("reader lists and slots disagree: {vn} {op} x{n}"));
            }
        }
    }

    fn check_ops(&self, bad: &mut Vec<String>) {
        let alive: BTreeSet<OpId> = self.ops_alive().into_iter().collect();
        let dead: BTreeSet<OpId> = self.ops_dead().into_iter().collect();
        let mut in_trees = 0usize;
        for op in self.live_ops() {
            let Some(d) = self.ops.get(op.index()) else {
                continue;
            };
            in_trees += 1;
            let tree = match d.tree {
                Tree::Main => &self.optree,
                _ => &self.alttree,
            };
            if tree.get(&(d.pc, d.time)) != Some(&op) {
                bad.push(format!("{op}: not in its tree under its sequence number"));
            }
            if d.tree == Tree::Alt && d.opcode() != Some(OpCode::Indirect) {
                bad.push(format!("{op}: in alttree but not an INDIRECT"));
            }
            let is_dead = d.flags & oflags::DEAD != 0;
            if is_dead != dead.contains(&op) || is_dead == alive.contains(&op) {
                bad.push(format!("{op}: alive/dead flag and lists disagree"));
            }
            if is_dead == d.parent_raw().is_some() {
                bad.push(format!(
                    "{op}: dead={is_dead} but parent {:?}",
                    d.parent_raw()
                ));
            }
            let want = d.opcode().and_then(CodeList::of);
            let has = self.links.get(op.index()).map_or(0, |l| l.code_list);
            if want.map_or(0, |c| c as u8) != has {
                bad.push(format!("{op}: in opcode list {has}, opcode wants {want:?}"));
            }
        }
        if self.optree.len() + self.alttree.len() != in_trees {
            bad.push("the trees hold retired or unknown ops".to_owned());
        }
        for list in [
            CodeList::Store,
            CodeList::Load,
            CodeList::Return,
            CodeList::Userop,
        ] {
            let ops = self.ops_of(list);
            let unique: BTreeSet<_> = ops.iter().collect();
            if unique.len() != ops.len() {
                bad.push(format!("{list:?} list holds an op twice"));
            }
            for op in ops {
                let opc = self
                    .ops
                    .get(op.index())
                    .and_then(crate::data::OpData::opcode);
                if opc.and_then(CodeList::of) != Some(list) {
                    bad.push(format!("{op}: in the {list:?} list with opcode {opc:?}"));
                }
            }
        }
    }

    fn check_blocks(&self, bad: &mut Vec<String>) {
        let mut placed = 0usize;
        for b in self.cfg.nodes().iter().copied() {
            let Ok(d) = self.bdata(b) else {
                continue;
            };
            let ops = d.ops.collect(&self.links, Thread::Block);
            placed += ops.len();
            let mut last: Option<u32> = None;
            for op in ops {
                let Some(o) = self.ops.get(op.index()) else {
                    bad.push(format!("block {}: unknown {op}", b.get()));
                    continue;
                };
                if o.parent != b.get() {
                    bad.push(format!(
                        "{op}: in block {} but parent {}",
                        b.get(),
                        o.parent
                    ));
                }
                if last.is_some_and(|l| l >= o.order) {
                    bad.push(format!("{op}: order {} does not increase", o.order));
                }
                last = Some(o.order);
            }
        }
        let parented = self
            .live_ops()
            .filter(|o| {
                self.ops
                    .get(o.index())
                    .and_then(crate::data::OpData::parent_raw)
                    .is_some()
            })
            .count();
        if placed != parented {
            bad.push(format!(
                "{placed} ops in block lists, {parented} name a parent"
            ));
        }
    }
}
