//! Ghidra's debug trace (`OPACTION_DEBUG`, funcdata.cc:1118–1232) as a
//! recorder: per unit, the before-text of every op it touched, printed with
//! the after-text when the unit ends, in the record grammar of
//! `decomp-oracle.md` 4.9.

use std::any::Any;
use std::fmt::Write as _;

use bk_core::Address;

use super::Recorder;
use crate::ids::{OpId, UnitId};
use crate::print::{RawNames, RawOut};
use crate::ssa::Ssa;

/// One traced range (`debugSetRange`): ops whose address is in
/// `low..=high` (when given) and whose time is in `times` (when given).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceRange {
    /// The address range; `None` traces the whole function.
    pub addrs: Option<(Address, Address)>,
    /// The time range.
    pub times: Option<(u32, u32)>,
}

/// The trace recorder. Records are appended to [`TraceRecorder::output`].
pub struct TraceRecorder {
    names: Box<dyn RawNames + Send>,
    ranges: Vec<TraceRange>,
    active: bool,
    name: String,
    modified: Vec<(OpId, String)>,
    count: u32,
    /// The records written so far.
    pub output: String,
}

impl std::fmt::Debug for TraceRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceRecorder")
            .field("ranges", &self.ranges)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl TraceRecorder {
    /// A recorder printing ops with `names`, tracing nothing until a range
    /// is added.
    pub fn new(names: Box<dyn RawNames + Send>) -> Self {
        Self {
            names,
            ranges: Vec::new(),
            active: false,
            name: String::new(),
            modified: Vec::new(),
            count: 0,
            output: String::new(),
        }
    }

    /// `debugSetRange`.
    pub fn add_range(&mut self, range: TraceRange) {
        self.ranges.push(range);
    }

    /// The number of records written (`opactdbg_count`).
    pub fn count(&self) -> u32 {
        self.count
    }

    /// `debugCheckRange`.
    fn in_range(&self, ssa: &Ssa, op: OpId) -> bool {
        let addr = ssa.op_addr(op);
        let time = ssa.op_time(op);
        self.ranges.iter().any(|r| {
            if let Some((lo, hi)) = r.addrs
                && (addr < lo || hi < addr)
            {
                return false;
            }
            if let Some((lo, hi)) = r.times
                && (lo > time || hi < time)
            {
                return false;
            }
            true
        })
    }

    /// `debugModClear`: abandons the current unit.
    pub fn clear(&mut self) {
        self.modified.clear();
        self.active = false;
    }
}

impl Recorder for TraceRecorder {
    fn begin_unit(&mut self, _ssa: &Ssa, _unit: UnitId, name: &str) {
        if !self.ranges.is_empty() {
            self.active = true;
            name.clone_into(&mut self.name);
        }
    }

    fn op_changing(&mut self, ssa: &Ssa, op: OpId) {
        if !self.active || self.modified.iter().any(|(o, _)| *o == op) {
            return;
        }
        if !self.in_range(ssa, op) {
            return;
        }
        let mut out = RawOut::new();
        ssa.op_debug_text(&mut out, op, &*self.names);
        self.modified.push((op, out.text));
    }

    fn end_unit(&mut self, ssa: &Ssa) {
        if !self.active {
            return;
        }
        self.active = false;
        if self.modified.is_empty() {
            return;
        }
        // One stream per record, as `debugModPrint` builds it: the
        // after-texts share its number base.
        let mut rec = RawOut::new();
        let _ = writeln!(rec.text, "DEBUG {}: {}", self.count, self.name);
        self.count += 1;
        for (op, before) in std::mem::take(&mut self.modified) {
            rec.text.push_str(&before);
            rec.text.push_str("\n   ");
            ssa.op_debug_text(&mut rec, op, &*self.names);
            rec.text.push('\n');
        }
        rec.text.push('\n');
        self.output.push_str(&rec.text);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
