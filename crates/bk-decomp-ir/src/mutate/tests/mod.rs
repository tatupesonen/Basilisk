//! Spec 6, test 4(a): hand-derived unit tests for every method of the
//! mutation interface (4.5), each citing the C++ lines it follows.

use std::sync::{Arc, Mutex};

use crate::ids::{OpId, UnitId};
use crate::record::Recorder;
use crate::ssa::Ssa;

mod insert;
mod op;
mod varnode;

/// A recorder that keeps the ops reported as changing (`debugModCheck`).
struct Log(Arc<Mutex<Vec<OpId>>>);

impl Recorder for Log {
    fn begin_unit(&mut self, _ssa: &Ssa, _unit: UnitId, _name: &str) {}

    fn op_changing(&mut self, _ssa: &Ssa, op: OpId) {
        if let Ok(mut v) = self.0.lock() {
            v.push(op);
        }
    }

    fn end_unit(&mut self, _ssa: &Ssa) {}

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
