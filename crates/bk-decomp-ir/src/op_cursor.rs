//! A key cursor over the main op tree for `ActionPool`'s walk
//! (`ActionPool::apply`/`processOp`, action.cc:806–875): the cursor stays
//! on an op while rules run on it and moves only when told, to the op
//! after it *at that time*. So an op a rule inserts with a later sequence
//! number is visited in the same pass, and the op under the cursor may be
//! retired after the move (`op_state++; data.opDeadAndGone(op)`).

use std::ops::Bound;

use crate::bank::keys::SeqKey;
use crate::error::IrResult;
use crate::ids::OpId;
use crate::ssa::Ssa;

/// A position in the main op tree (Ghidra's `PcodeOpTree::const_iterator
/// op_state`), held as a sequence key so the tree may change between
/// steps. If the op it names has left the tree (undefined in Ghidra), it
/// stands on the next op in sequence order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpCursor {
    at: Option<SeqKey>,
}

impl OpCursor {
    fn key_at(self, ssa: &Ssa) -> Option<(SeqKey, OpId)> {
        let k = self.at?;
        ssa.optree.range(k..).next().map(|(k, o)| (*k, *o))
    }

    /// The op under the cursor (`*op_state`), `None` at the end.
    pub fn current(self, ssa: &Ssa) -> Option<OpId> {
        self.key_at(ssa).map(|(_, o)| o)
    }

    /// Moves to the op after the current one in the tree as it is now
    /// (`op_state++`).
    pub fn advance(&mut self, ssa: &Ssa) {
        self.at = self.key_at(ssa).and_then(|(k, _)| {
            ssa.optree
                .range((Bound::Excluded(k), Bound::Unbounded))
                .next()
                .map(|(k, _)| *k)
        });
    }

    /// Whether the cursor is at the end (`op_state == endOpMain()`).
    pub fn at_end(self, ssa: &Ssa) -> bool {
        self.current(ssa).is_none()
    }
}

impl Ssa {
    /// A cursor on the first op of the main tree (`beginOpMain()`).
    pub fn op_cursor_main(&self) -> OpCursor {
        OpCursor {
            at: self.optree.keys().next().copied(),
        }
    }

    /// `Funcdata::opDeadAndGone` (funcdata.hh:485, `PcodeOpBank::destroy`,
    /// op.cc:1047–1060): retires a dead op: out of its tree, the dead list
    /// and its opcode list, onto the retired list. A live op is Ghidra's
    /// error "Deleting integrated op".
    pub fn op_dead_and_gone(&mut self, op: OpId) -> IrResult<()> {
        self.bank_destroy_op(op)
    }
}

#[cfg(test)]
mod tests {
    use bk_pcode::OpCode;

    use crate::testing::fx;

    #[test]
    fn the_pool_walk_sees_later_inserts_and_survives_retiring_the_op_it_left() {
        let mut fix = fx(1);
        let a = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
        let b = fix.emit(0, OpCode::Copy, 0x200, Some(4), &[]);
        let mut cur = fix.ssa.op_cursor_main();
        let mut seen = Vec::new();
        let mut inserted = None;
        while let Some(op) = cur.current(&fix.ssa) {
            seen.push(op);
            if op == a {
                // A rule on `a` inserts an op at 0x180 (after `a`, before
                // `b`) and one at 0x080 (before the cursor), and kills `b`.
                let mid = fix.emit(0, OpCode::Copy, 0x180, Some(8), &[]);
                fix.emit(0, OpCode::Copy, 0x080, Some(12), &[]);
                inserted = Some(mid);
                fix.ssa.op_destroy(b).unwrap();
            }
            if fix.ssa.op_is_dead(op) {
                // processOp: advance, then opDeadAndGone.
                cur.advance(&fix.ssa);
                fix.ssa.op_dead_and_gone(op).unwrap();
                continue;
            }
            cur.advance(&fix.ssa);
        }
        assert_eq!(seen, [a, inserted.unwrap(), b]);
        assert!(fix.ssa.ops_retired().contains(&b));
        assert!(cur.at_end(&fix.ssa));
        // A live op is not retired.
        assert!(fix.ssa.op_dead_and_gone(a).is_err());
        fix.ok();
    }

    #[test]
    fn a_cursor_whose_op_left_the_tree_stands_on_the_next() {
        let mut fix = fx(1);
        let a = fix.emit(0, OpCode::Copy, 0x100, Some(0), &[]);
        let b = fix.emit(0, OpCode::Copy, 0x200, Some(4), &[]);
        let cur = fix.ssa.op_cursor_main();
        fix.ssa.op_destroy(a).unwrap();
        fix.ssa.op_dead_and_gone(a).unwrap();
        assert_eq!(cur.current(&fix.ssa), Some(b));
        let mut c2 = cur;
        c2.advance(&fix.ssa);
        assert_eq!(c2.current(&fix.ssa), None);
    }
}
