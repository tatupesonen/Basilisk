//! Spec 6, tests 3 and 6 (properties): random sequences of mutation calls
//! keep the invariants of [`Ssa::invariant_violations`]; a refused call of
//! a single-step method changes nothing; inserting the same varnodes and
//! ops in another order gives the same bank orders. No call may panic.

use std::fmt::Write as _;

use bk_core::Address;
use bk_pcode::OpCode;
use proptest::prelude::*;

use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;
use crate::testing::{Fx, fx};

const OPCODES: [OpCode; 10] = [
    OpCode::Copy,
    OpCode::IntAdd,
    OpCode::MultiEqual,
    OpCode::Call,
    OpCode::Return,
    OpCode::Store,
    OpCode::Load,
    OpCode::Indirect,
    OpCode::Branch,
    OpCode::CallOther,
];

/// One call; ids are picked modulo what exists.
#[derive(Clone, Debug)]
enum Act {
    Const(u8),
    Reg(u8, u8),
    Unique,
    Op(u8, u8, u8),
    Indirect(u16),
    SetOpcode(u16, u8),
    SetInput(u16, u16, u8),
    UnsetInput(u16, u8),
    SetOutput(u16, u16),
    UnsetOutput(u16),
    SwapInput(u16, u8, u8),
    RemoveInput(u16, u8),
    InsertInput(u16, u16, u8),
    Insert(u16, u8, Option<u16>),
    InsertBefore(u16, u16),
    InsertAfter(u16, u16),
    InsertBegin(u16, u8),
    InsertEnd(u16, u8),
    Uninsert(u16),
    Unlink(u16),
    Destroy(u16),
    DestroyRaw(u16),
    DestroyRecursive(u16),
    Clone(u16),
    SetInputVarnode(u16),
    DestroyVarnode(u16),
    TotalReplace(u16, u16),
    TotalReplaceConstant(u16, u8),
    ClearDead,
}

fn act() -> impl Strategy<Value = Act> {
    let id = any::<u16>;
    prop_oneof![
        any::<u8>().prop_map(Act::Const),
        (0..8u8, 0..3u8).prop_map(|(o, s)| Act::Reg(o, s)),
        Just(Act::Unique),
        (any::<u8>(), 0..4u8, 0..6u8).prop_map(|(o, n, p)| Act::Op(o, n, p)),
        id().prop_map(Act::Indirect),
        (id(), any::<u8>()).prop_map(|(o, c)| Act::SetOpcode(o, c)),
        (id(), id(), 0..4u8).prop_map(|(o, v, s)| Act::SetInput(o, v, s)),
        (id(), 0..4u8).prop_map(|(o, s)| Act::UnsetInput(o, s)),
        (id(), id()).prop_map(|(o, v)| Act::SetOutput(o, v)),
        id().prop_map(Act::UnsetOutput),
        (id(), 0..4u8, 0..4u8).prop_map(|(o, a, b)| Act::SwapInput(o, a, b)),
        (id(), 0..4u8).prop_map(|(o, s)| Act::RemoveInput(o, s)),
        (id(), id(), 0..4u8).prop_map(|(o, v, s)| Act::InsertInput(o, v, s)),
        (id(), 0..3u8, proptest::option::of(id())).prop_map(|(o, b, x)| Act::Insert(o, b, x)),
        (id(), id()).prop_map(|(o, x)| Act::InsertBefore(o, x)),
        (id(), id()).prop_map(|(o, x)| Act::InsertAfter(o, x)),
        (id(), 0..3u8).prop_map(|(o, b)| Act::InsertBegin(o, b)),
        (id(), 0..3u8).prop_map(|(o, b)| Act::InsertEnd(o, b)),
        id().prop_map(Act::Uninsert),
        id().prop_map(Act::Unlink),
        id().prop_map(Act::Destroy),
        id().prop_map(Act::DestroyRaw),
        id().prop_map(Act::DestroyRecursive),
        id().prop_map(Act::Clone),
        id().prop_map(Act::SetInputVarnode),
        id().prop_map(Act::DestroyVarnode),
        (id(), id()).prop_map(|(a, b)| Act::TotalReplace(a, b)),
        (id(), any::<u8>()).prop_map(|(a, v)| Act::TotalReplaceConstant(a, v)),
        Just(Act::ClearDead),
    ]
}

/// Everything structural, as text, for "nothing changed" comparisons.
fn fingerprint(ssa: &Ssa) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "loc {:?}", ssa.loc_order().collect::<Vec<_>>());
    let _ = writeln!(s, "def {:?}", ssa.def_order().collect::<Vec<_>>());
    let _ = writeln!(s, "alive {:?} dead {:?}", ssa.ops_alive(), ssa.ops_dead());
    for (i, v) in ssa.vns.iter().enumerate() {
        let vn = VarnodeId(i as u32);
        let _ = writeln!(
            s,
            "{vn} {} {:x} {:?} {:?}",
            ssa.varnode_exists(vn),
            v.flags,
            v.def(),
            ssa.readers(vn).collect::<Vec<_>>()
        );
    }
    for (i, o) in ssa.ops.iter().enumerate() {
        let op = OpId(i as u32);
        let _ = writeln!(
            s,
            "{op} {:?} {:x} {:?} {:?} {:?} {} {:?}",
            o.opcode(),
            o.flags,
            ssa.op_inputs(op).collect::<Vec<_>>(),
            o.output(),
            o.parent_raw(),
            o.order,
            o.tree
        );
    }
    s
}

struct Run {
    fx: Fx,
    vns: Vec<VarnodeId>,
    ops: Vec<OpId>,
    pc: u64,
}

fn pick<T: Copy>(list: &[T], i: u16) -> Option<T> {
    (!list.is_empty()).then(|| list[usize::from(i) % list.len()])
}

impl Run {
    /// Runs one call. Returns whether it was refused and is a single-step
    /// method (one that must then have changed nothing).
    #[expect(
        clippy::many_single_char_names,
        reason = "the match arms name an action's operands as the Act variants do"
    )]
    fn step(&mut self, a: &Act) -> bool {
        let blocks = self.fx.blocks.clone();
        let block = |b: u8| blocks[usize::from(b) % blocks.len()];
        let f = &mut self.fx;
        let env = &mut f.env;
        macro_rules! need {
            ($e:expr) => {
                match $e {
                    Some(x) => x,
                    None => return false,
                }
            };
        }
        let (res, atomic): (Result<(), crate::IrError>, bool) = match *a {
            Act::Const(v) => {
                let r = f.ssa.new_constant(env, 4, u64::from(v));
                if let Ok(vn) = r {
                    self.vns.push(vn);
                }
                (r.map(drop), true)
            }
            Act::Reg(o, s) => {
                let at = Address::new(f.reg, u64::from(o) * 4);
                let r = f.ssa.new_varnode(env, 1 << s, at, None);
                if let Ok(vn) = r {
                    self.vns.push(vn);
                }
                (r.map(drop), true)
            }
            Act::Unique => {
                let r = f.ssa.new_unique(env, 4, None);
                if let Ok(vn) = r {
                    self.vns.push(vn);
                }
                (r.map(drop), true)
            }
            Act::Op(o, n, p) => {
                self.pc += 4;
                let at = Address::new(f.ram, 0x1000 + u64::from(p) * 0x10);
                let r = f.ssa.new_op(usize::from(n), at).and_then(|op| {
                    let opc = OPCODES[usize::from(o) % OPCODES.len()];
                    // An INDIRECT made by changing an opcode stays in
                    // optree; only `new_indirect` makes alttree ones.
                    let opc = if opc == OpCode::Indirect {
                        OpCode::Copy
                    } else {
                        opc
                    };
                    f.ssa.op_set_opcode(op, opc)?;
                    Ok(op)
                });
                if let Ok(op) = r {
                    self.ops.push(op);
                }
                (r.map(drop), false)
            }
            Act::Indirect(t) => {
                let t = need!(pick(&self.ops, t));
                let r = f.ssa.new_indirect(env, t);
                if let Ok(op) = r {
                    self.ops.push(op);
                }
                (r.map(drop), false)
            }
            Act::SetOpcode(o, c) => {
                let o = need!(pick(&self.ops, o));
                let opc = OPCODES[usize::from(c) % OPCODES.len()];
                (f.ssa.op_set_opcode(o, opc), true)
            }
            Act::SetInput(o, v, s) => {
                let (o, v) = (need!(pick(&self.ops, o)), need!(pick(&self.vns, v)));
                (f.ssa.op_set_input(env, o, v, usize::from(s)), true)
            }
            Act::UnsetInput(o, s) => (
                f.ssa
                    .op_unset_input(need!(pick(&self.ops, o)), usize::from(s)),
                true,
            ),
            Act::SetOutput(o, v) => {
                let (o, v) = (need!(pick(&self.ops, o)), need!(pick(&self.vns, v)));
                (f.ssa.op_set_output(env, o, v).map(drop), true)
            }
            Act::UnsetOutput(o) => (f.ssa.op_unset_output(need!(pick(&self.ops, o))), true),
            Act::SwapInput(o, x, y) => {
                let o = need!(pick(&self.ops, o));
                (f.ssa.op_swap_input(o, usize::from(x), usize::from(y)), true)
            }
            Act::RemoveInput(o, s) => (
                f.ssa
                    .op_remove_input(need!(pick(&self.ops, o)), usize::from(s)),
                true,
            ),
            Act::InsertInput(o, v, s) => {
                let (o, v) = (need!(pick(&self.ops, o)), need!(pick(&self.vns, v)));
                (f.ssa.op_insert_input(env, o, v, usize::from(s)), false)
            }
            Act::Insert(o, b, x) => {
                let o = need!(pick(&self.ops, o));
                let before = x.and_then(|x| pick(&self.ops, x));
                let blk = block(b);
                (f.ssa.op_insert(o, blk, before), true)
            }
            Act::InsertBefore(o, x) => {
                let (o, x) = (need!(pick(&self.ops, o)), need!(pick(&self.ops, x)));
                (f.ssa.op_insert_before(o, x), true)
            }
            Act::InsertAfter(o, x) => {
                let (o, x) = (need!(pick(&self.ops, o)), need!(pick(&self.ops, x)));
                (f.ssa.op_insert_after(o, x), true)
            }
            Act::InsertBegin(o, b) => {
                let o = need!(pick(&self.ops, o));
                let blk = block(b);
                (f.ssa.op_insert_begin(o, blk), true)
            }
            Act::InsertEnd(o, b) => {
                let o = need!(pick(&self.ops, o));
                let blk = block(b);
                (f.ssa.op_insert_end(o, blk), true)
            }
            Act::Uninsert(o) => (f.ssa.op_uninsert(need!(pick(&self.ops, o))), true),
            Act::Unlink(o) => (f.ssa.op_unlink(need!(pick(&self.ops, o))), false),
            Act::Destroy(o) => (f.ssa.op_destroy(need!(pick(&self.ops, o))), false),
            Act::DestroyRaw(o) => (f.ssa.op_destroy_raw(need!(pick(&self.ops, o))), false),
            Act::DestroyRecursive(o) => {
                (f.ssa.op_destroy_recursive(need!(pick(&self.ops, o))), false)
            }
            Act::Clone(o) => {
                self.pc += 1;
                let o = need!(pick(&self.ops, o));
                let at = Address::new(f.ram, 0x9000 + self.pc);
                let r = f.ssa.clone_op(env, o, at, 0);
                if let Ok(op) = r {
                    self.ops.push(op);
                }
                (r.map(drop), false)
            }
            Act::SetInputVarnode(v) => {
                let v = need!(pick(&self.vns, v));
                let r = f.ssa.set_input_varnode(env, v);
                if let Ok(vn) = r {
                    self.vns.push(vn);
                }
                (r.map(drop), false)
            }
            Act::DestroyVarnode(v) => (f.ssa.destroy_varnode(need!(pick(&self.vns, v))), false),
            Act::TotalReplace(x, y) => {
                let (x, y) = (need!(pick(&self.vns, x)), need!(pick(&self.vns, y)));
                (f.ssa.total_replace(env, x, y), false)
            }
            Act::TotalReplaceConstant(x, v) => {
                let x = need!(pick(&self.vns, x));
                (f.ssa.total_replace_constant(env, x, u64::from(v)), false)
            }
            Act::ClearDead => (f.ssa.clear_dead_varnodes(), false),
        };
        res.is_err() && atomic
    }
}

proptest! {
    #[test]
    fn random_mutations_keep_the_invariants(acts in proptest::collection::vec(act(), 1..80)) {
        let mut run = Run { fx: fx(3), vns: Vec::new(), ops: Vec::new(), pc: 0 };
        for a in &acts {
            let before = fingerprint(&run.fx.ssa);
            let refused_atomic = run.step(a);
            let bad = run.fx.ssa.invariant_violations();
            prop_assert!(bad.is_empty(), "after {:?}: {:#?}", a, bad);
            if refused_atomic {
                prop_assert_eq!(fingerprint(&run.fx.ssa), before, "refused {:?} changed the state", a);
            }
        }
    }

    #[test]
    fn bank_orders_do_not_depend_on_creation_order(
        spec in proptest::collection::btree_map(0..32u64, (0..3u8, any::<bool>()), 1..24),
        seed in any::<u64>(),
    ) {
        // Spec 6 test 3: the same varnodes (distinct storage; inputs or
        // free) and ops (distinct sequence numbers) created in another order
        // sort the same.
        let items: Vec<(u64, (u8, bool))> = spec.into_iter().collect();
        let mut shuffled = items.clone();
        let mut state = seed | 1;
        for i in (1..shuffled.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            shuffled.swap(i, (state % (i as u64 + 1)) as usize);
        }
        let build = |list: &[(u64, (u8, bool))]| {
            let mut f = fx(1);
            for &(off, (s, input)) in list {
                let vn = f.regvn(off * 8, 1 << s);
                if input {
                    f.ssa.set_input_varnode(&mut f.env, vn).unwrap();
                }
                let at = Address::new(f.ram, 0x100 + off);
                f.ssa.new_op_at(0, at, u32::from(s)).unwrap();
            }
            let key = |v: VarnodeId| (f.ssa.varnode_addr(v), f.ssa.varnode_size(v), f.ssa.is_input(v));
            let loc: Vec<_> = f.ssa.loc_order().map(key).collect();
            let def: Vec<_> = f.ssa.def_order().map(key).collect();
            let ops: Vec<_> = f.ssa.ops_main().map(|o| (f.ssa.op_addr(o), f.ssa.op_time(o))).collect();
            (loc, def, ops)
        };
        prop_assert_eq!(build(&items), build(&shuffled));
    }
}
