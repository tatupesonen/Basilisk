//! The recorder hook of the mutation interface (ADR-025 3a) and Ghidra's
//! debug trace as one recorder.
//!
//! Every mutation method that Ghidra instruments with `debugModCheck`
//! (twelve in `funcdata_op.cc`, one per reader in `destroyVarnode`) calls
//! [`Recorder::op_changing`] before it changes the op; the driver brackets a
//! unit with [`Ssa::begin_unit`](crate::Ssa::begin_unit) and
//! [`Ssa::end_unit`](crate::Ssa::end_unit) (Ghidra `debugActivate`,
//! `debugModPrint`). Without a recorder the cost is one branch.

mod trace;

pub use trace::{TraceRange, TraceRecorder};

use crate::ids::{OpId, UnitId};
use crate::ssa::Ssa;

/// Watches the mutations of one function. Object-safe (plugin binding
/// constraint 8): providers attach any implementation at run time.
pub trait Recorder: Send {
    /// A unit (action or rule) starts (Ghidra `debugActivate`).
    fn begin_unit(&mut self, ssa: &Ssa, unit: UnitId, name: &str);
    /// `op` is about to change (Ghidra `debugModCheck`). `ssa` is the state
    /// before the change.
    fn op_changing(&mut self, ssa: &Ssa, op: OpId);
    /// The unit ends (Ghidra `debugModPrint`).
    fn end_unit(&mut self, ssa: &Ssa);
    /// Lets a caller get the concrete recorder back (for reading its
    /// records after the run).
    fn as_any(&self) -> &dyn std::any::Any;
}

impl Ssa {
    /// Attaches a recorder, returning the previous one.
    pub fn set_recorder(
        &mut self,
        recorder: Option<Box<dyn Recorder>>,
    ) -> Option<Box<dyn Recorder>> {
        std::mem::replace(&mut self.recorder, recorder)
    }

    /// The attached recorder.
    pub fn recorder(&self) -> Option<&dyn Recorder> {
        self.recorder.as_deref()
    }

    /// Starts a unit (Ghidra `debugActivate`).
    pub fn begin_unit(&mut self, unit: UnitId, name: &str) {
        if let Some(mut r) = self.recorder.take() {
            r.begin_unit(self, unit, name);
            self.recorder = Some(r);
        }
    }

    /// Ends the current unit (Ghidra `debugModPrint`).
    pub fn end_unit(&mut self) {
        if let Some(mut r) = self.recorder.take() {
            r.end_unit(self);
            self.recorder = Some(r);
        }
    }

    /// Reports that `op` is about to change.
    pub(crate) fn note_change(&mut self, op: OpId) {
        if let Some(mut r) = self.recorder.take() {
            r.op_changing(self, op);
            self.recorder = Some(r);
        }
    }
}

#[cfg(test)]
mod tests;
