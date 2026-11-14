//! Template optimisation (`ConsistencyChecker::optimizeAll`, `optimize`,
//! `optimizeGather1`, `optimizeGather2`, `findValidRule`,
//! `applyOptimization`, `checkUnusedTemps`; `UniqueState`,
//! `OptimizeRecord`, `slgh_compile.cc` 215-289, 1237-1683).

use std::collections::BTreeMap;

use bk_pcode::OpCode;
use bk_sla::ConstTpl;

use super::CheckFatal;
use super::sizes::Checker;
use crate::compiler::{Compiler, CtorData};
use crate::ids::CtorId;
use crate::template::{
    BUILD, CROSSBUILD, DELAY_SLOT, LABEL, MACROBUILD, Op, Tpl, Vn, is_const_space, is_unique_space,
    real,
};

/// How a temporary is used in a constructor (`OptimizeRecord`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    offset: u64,
    size: i32,
    write_op: i32,
    read_op: i32,
    in_slot: i32,
    write_count: i32,
    read_count: i32,
    write_section: i32,
    read_section: i32,
}

impl Record {
    const fn new(offset: u64, size: i32) -> Self {
        Self {
            offset,
            size,
            write_op: -1,
            read_op: -1,
            in_slot: -1,
            write_count: 0,
            read_count: 0,
            write_section: -2,
            read_section: -2,
        }
    }

    fn update_read(&mut self, op: i32, slot: i32, section: i32) {
        self.read_op = op;
        self.read_count = self.read_count.wrapping_add(1);
        self.in_slot = slot;
        self.read_section = section;
    }

    fn update_write(&mut self, op: i32, section: i32) {
        self.write_op = op;
        self.write_count = self.write_count.wrapping_add(1);
        self.write_section = section;
    }

    fn update_export(&mut self) {
        self.write_op = 0;
        self.read_op = 0;
        self.write_count = 2;
        self.read_count = 2;
        self.read_section = -2;
        self.write_section = -2;
    }

    fn update_combine(&mut self, that: &Self) {
        if that.write_count != 0 {
            self.write_op = that.write_op;
            self.write_section = that.write_section;
        }
        if that.read_count != 0 {
            self.read_op = that.read_op;
            self.in_slot = that.in_slot;
            self.read_section = that.read_section;
        }
        self.write_count = self.write_count.wrapping_add(that.write_count);
        self.read_count = self.read_count.wrapping_add(that.read_count);
    }

    /// The merging constructor.
    fn merged(records: &[Self]) -> Self {
        let mut min = u64::MAX;
        let mut max = u64::MAX;
        for r in records {
            if min == u64::MAX || r.offset < min {
                min = r.offset;
            }
            let end = r.offset.wrapping_add(i64::from(r.size) as u64);
            if max == u64::MAX || end > max {
                max = end;
            }
        }
        let mut result = Self::new(min, max.wrapping_sub(min) as i32);
        for r in records {
            result.update_combine(r);
        }
        result
    }
}

/// The records of one constructor, disjoint, by offset (`UniqueState`).
/// Keys are truncated to 32 bits as Ghidra's insertions do.
#[derive(Default, Debug)]
struct UniqueState {
    recs: BTreeMap<u64, Record>,
}

fn key(offset: u64) -> u64 {
    u64::from(offset as u32)
}

impl UniqueState {
    fn end_of(k: u64, r: &Record) -> u64 {
        k.wrapping_add(i64::from(r.size) as u64)
    }

    /// `getDefinitions`: the keys of the records covering the range, with
    /// gaps filled by new records.
    fn definitions(&mut self, offset: u64, size: i32) -> Vec<u64> {
        let size = if size == 0 { 1 } else { size };
        let mut result = Vec::new();
        let mut cursor = offset;
        if let Some((&k, r)) = self.recs.range(..offset).next_back()
            && Self::end_of(k, r) > offset
        {
            cursor = Self::end_of(k, r);
            result.push(k);
        }
        let end = offset.wrapping_add(i64::from(size) as u64);
        let keys: Vec<u64> = self
            .recs
            .range(offset..)
            .map(|(&k, _)| k)
            .take_while(|&k| k < end)
            .collect();
        for k in keys {
            if k > cursor {
                let gap = key(cursor);
                self.recs
                    .entry(gap)
                    .or_insert_with(|| Record::new(cursor, k.wrapping_sub(cursor) as i32));
                result.push(gap);
            }
            result.push(k);
            if let Some(r) = self.recs.get(&k) {
                cursor = Self::end_of(k, r);
            }
        }
        if end > cursor {
            let gap = key(cursor);
            self.recs
                .entry(gap)
                .or_insert_with(|| Record::new(cursor, end.wrapping_sub(cursor) as i32));
            result.push(gap);
        }
        result
    }

    /// `set`: adds a record, merging what it overlaps.
    fn set(&mut self, rec: Record) {
        let keys = self.definitions(rec.offset, rec.size);
        let mut records: Vec<Record> = keys
            .iter()
            .filter_map(|k| self.recs.get(k).copied())
            .collect();
        records.push(rec);
        let merged = Record::merged(&records);
        let lo = merged.offset;
        let hi = merged.offset.wrapping_add(i64::from(merged.size) as u64);
        if lo <= hi {
            let doomed: Vec<u64> = self.recs.range(lo..hi).map(|(&k, _)| k).collect();
            for k in doomed {
                self.recs.remove(&k);
            }
        }
        self.recs.entry(key(merged.offset)).or_insert(merged);
    }
}

/// `possibleIntersection`.
fn possible_intersection(a: &Vn, b: &Vn) -> bool {
    if is_const_space(&a.space) || is_const_space(&b.space) {
        return false;
    }
    if is_unique_space(&a.space) != is_unique_space(&b.space) {
        return false;
    }
    let (ConstTpl::Space(sa), ConstTpl::Space(sb)) = (a.space, b.space) else {
        return true;
    };
    if sa != sb {
        return false;
    }
    let (ConstTpl::Real(off2), ConstTpl::Real(size2)) = (b.offset, b.size) else {
        return true;
    };
    let (ConstTpl::Real(off1), ConstTpl::Real(size1)) = (a.offset, a.size) else {
        return true;
    };
    if off2.wrapping_add(size2).wrapping_sub(1) < off1 {
        return false;
    }
    if off2 > off1.wrapping_add(size1).wrapping_sub(1) {
        return false;
    }
    true
}

/// `readWriteInterference`.
fn interferes(vn: &Vn, op: &Op, check_read: bool) -> bool {
    if matches!(
        op.opcode,
        OpCode::Load
            | OpCode::Store
            | OpCode::Branch
            | OpCode::CBranch
            | OpCode::BranchInd
            | OpCode::Call
            | OpCode::CallInd
            | OpCode::CallOther
            | OpCode::Return
    ) || [BUILD, CROSSBUILD, DELAY_SLOT, MACROBUILD, LABEL].contains(&op.opcode)
    {
        return true;
    }
    if check_read && op.inputs.iter().any(|i| possible_intersection(vn, i)) {
        return true;
    }
    op.output
        .as_ref()
        .is_some_and(|o| possible_intersection(vn, o))
}

fn section(ctor: &CtorData, k: i32) -> Option<&Tpl> {
    if k < 0 {
        ctor.main.as_ref()
    } else {
        ctor.named.get(k as usize).and_then(Option::as_ref)
    }
}

fn section_mut(ctor: &mut CtorData, k: i32) -> Option<&mut Tpl> {
    super::sizes::section_mut(ctor, k)
}

/// `examineVn`.
fn examine(state: &mut UniqueState, vn: &Vn, op: i32, slot: i32, section: i32) {
    if !is_unique_space(&vn.space) {
        return;
    }
    let ConstTpl::Real(offset) = vn.offset else {
        return;
    };
    let size = real(&vn.size) as i32;
    if slot >= 0 {
        for k in state.definitions(offset, size) {
            if let Some(r) = state.recs.get_mut(&k) {
                r.update_read(op, slot, section);
            }
        }
    } else {
        let mut rec = Record::new(offset, size);
        rec.update_write(op, section);
        state.set(rec);
    }
}

fn gather(state: &mut UniqueState, ctor: &CtorData, k: i32) {
    let Some(tpl) = section(ctor, k) else { return };
    for (i, op) in tpl.ops.iter().enumerate() {
        for (j, input) in op.inputs.iter().enumerate() {
            examine(state, input, i as i32, j as i32, k);
        }
        if let Some(out) = &op.output {
            examine(state, out, i as i32, -1, k);
        }
    }
    let Some(hand) = &tpl.result else { return };
    if is_unique_space(&hand.ptr_space)
        && let ConstTpl::Real(offset) = hand.ptr_offset
    {
        for key in state.definitions(offset, real(&hand.ptr_size) as i32) {
            if let Some(r) = state.recs.get_mut(&key) {
                r.update_export();
            }
        }
    }
    if is_unique_space(&hand.space)
        && matches!(hand.ptr_space, ConstTpl::Real(_))
        && let ConstTpl::Real(offset) = hand.ptr_offset
    {
        for key in state.definitions(offset, real(&hand.size) as i32) {
            if let Some(r) = state.recs.get_mut(&key) {
                r.update_export();
            }
        }
    }
}

/// `findValidRule`: a temporary written once and read once through a
/// `COPY` that can be removed; returns the record and the rewrite form.
fn find_rule(ctor: &CtorData, state: &UniqueState) -> Result<Option<(Record, u8)>, CheckFatal> {
    for rec in state.recs.values() {
        if !(rec.write_count == 1 && rec.read_count == 1 && rec.read_section == rec.write_section) {
            continue;
        }
        let Some(tpl) = section(ctor, rec.read_section) else {
            continue;
        };
        if rec.write_op >= rec.read_op {
            return Err(CheckFatal("Read of temporary before write".to_owned()));
        }
        let (Some(write), Some(read)) = (
            tpl.ops.get(rec.write_op as usize),
            tpl.ops.get(rec.read_op as usize),
        ) else {
            continue;
        };
        let (Some(write_vn), Some(read_vn)) =
            (write.output.as_ref(), read.inputs.get(rec.in_slot as usize))
        else {
            continue;
        };
        if !write_vn.same(read_vn) {
            continue;
        }
        let between = tpl
            .ops
            .get(rec.write_op as usize + 1..rec.read_op as usize)
            .unwrap_or_default();
        if read.opcode == OpCode::Copy
            && let Some(vn) = read.output.as_ref()
            && !between.iter().any(|op| interferes(vn, op, true))
        {
            return Ok(Some((*rec, 0)));
        }
        if write.opcode == OpCode::Copy
            && let Some(vn) = write.inputs.first()
            && !between.iter().any(|op| interferes(vn, op, false))
        {
            return Ok(Some((*rec, 1)));
        }
    }
    Ok(None)
}

/// `applyOptimization`.
fn apply(ctor: &mut CtorData, rec: &Record, form: u8) {
    let Some(tpl) = section_mut(ctor, rec.read_section) else {
        return;
    };
    let (read, write) = (rec.read_op as usize, rec.write_op as usize);
    if form == 0 {
        let out = tpl.ops.get(read).and_then(|op| op.output);
        if let Some(op) = tpl.ops.get_mut(write) {
            op.output = out;
        }
        if read < tpl.ops.len() {
            tpl.ops.remove(read);
        }
    } else {
        let input = tpl.ops.get(write).and_then(|op| op.inputs.first().copied());
        if let (Some(op), Some(input)) = (tpl.ops.get_mut(read), input)
            && let Some(slot) = op.inputs.get_mut(rec.in_slot as usize)
        {
            *slot = input;
        }
        if write < tpl.ops.len() {
            tpl.ops.remove(write);
        }
    }
}

impl Compiler<'_> {
    /// `optimize`: removes unnecessary `COPY`s through temporaries until
    /// none is left, then checks the temporaries. Each round removes an op,
    /// so the loop ends (spec 4.5).
    fn optimize(&mut self, checker: &mut Checker, ctor: CtorId) -> Result<(), CheckFatal> {
        let Some(c) = self.ctors.get_mut(ctor.slot()) else {
            return Ok(());
        };
        let sections = c.named.len() as i32;
        let mut state = UniqueState::default();
        loop {
            state.recs.clear();
            for k in -1..sections {
                gather(&mut state, c, k);
            }
            match find_rule(c, &state)? {
                Some((rec, form)) => apply(c, &rec, form),
                None => break,
            }
        }
        let at = c.at;
        for rec in state.recs.values() {
            if rec.read_count == 0 {
                if self.options.warn_dead_temps {
                    self.diags
                        .warning_at(at, "Temporary is written but not read");
                }
                checker.write_no_read = checker.write_no_read.saturating_add(1);
            } else if rec.write_count == 0 {
                self.diags.error_at(at, "Temporary is read but not written");
                checker.read_no_write = checker.read_no_write.saturating_add(1);
            }
        }
        Ok(())
    }

    /// `optimizeAll`.
    pub(crate) fn optimize_all(&mut self, checker: &mut Checker) -> Result<(), CheckFatal> {
        for table in checker.postorder.clone() {
            for ctor in self.table_ctors(table) {
                self.optimize(checker, ctor)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_writes_merge() {
        let mut state = UniqueState::default();
        let mut a = Record::new(0x100, 4);
        a.update_write(0, -1);
        state.set(a);
        let mut b = Record::new(0x102, 4);
        b.update_write(1, -1);
        state.set(b);
        assert_eq!(state.recs.len(), 1);
        let r = &state.recs[&0x100];
        assert_eq!((r.offset, r.size, r.write_count), (0x100, 6, 2));
        let keys = state.definitions(0x200, 2);
        assert_eq!(keys, vec![0x200]);
        assert_eq!(state.recs[&0x200].write_count, 0);
    }
}
