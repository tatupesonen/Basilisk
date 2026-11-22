//! `TypeOp::printRaw` for each op form (typeop.cc), `PcodeOp::printDebug`
//! and the op texts of the state dump, on top of the varnode and address
//! printing of [`super::raw`].

use bk_pcode::OpCode;

use super::raw::{RawNames, RawOut};
use crate::ids::{OpId, VarnodeId};
use crate::props::{RawForm, props};
use crate::ssa::Ssa;

impl Ssa {
    /// The space a `LOAD`/`STORE`/`SEGMENTOP` space constant names.
    fn space_name_of_const(&self, vn: Option<VarnodeId>) -> String {
        let Some(vn) = vn else {
            return String::new();
        };
        let idx = self.varnode_offset(vn);
        self.spaces
            .space_at(idx as u32)
            .map_or_else(String::new, |s| s.name().to_owned())
    }

    /// `FlowBlock::printShortHeader`: `Block_<index>` and `:<start>`.
    pub(crate) fn short_header(&self, out: &mut RawOut, b: bk_decomp_cfg::NodeId) {
        out.s("Block_");
        out.dec(self.cfg.index(b).map_or(0, |i| i as u64));
        let start = self.block_start(b);
        if !start.is_invalid() {
            out.c(':');
            self.addr_raw(out, start);
        }
    }

    fn operator_name(&self, op: OpId, names: &dyn RawNames) -> String {
        let Some(opc) = self.op_opcode(op) else {
            return String::new();
        };
        let p = props(opc);
        let size = |v: Option<VarnodeId>| v.map_or(0, |v| self.varnode_size(v));
        let in0 = self.op_input(op, 0);
        let in1 = self.op_input(op, 1);
        let out = self.op_output(op);
        match opc {
            OpCode::IntZExt | OpCode::IntSExt | OpCode::SubPiece => {
                format!("{}{}{}", p.name, size(in0), size(out))
            }
            OpCode::IntCarry | OpCode::IntSCarry | OpCode::IntSBorrow => {
                format!("{}{}", p.name, size(in0))
            }
            OpCode::Piece => format!("{}{}{}", p.name, size(in0), size(in1)),
            OpCode::CallOther => {
                if self.op_parent(op).is_some()
                    && let Some(name) =
                        in0.and_then(|v| names.userop_name(self, op, self.varnode_offset(v)))
                {
                    return name;
                }
                let mut s = RawOut::new();
                s.s(p.name);
                s.c('[');
                self.vn_raw(&mut s, in0, names);
                s.c(']');
                s.text
            }
            _ => p.name_java(names.java_operators()).to_owned(),
        }
    }

    fn list_raw(&self, out: &mut RawOut, op: OpId, from: usize, names: &dyn RawNames) {
        for i in from..self.op_num_inputs(op) {
            if i != from {
                out.c(',');
            }
            self.vn_raw(out, self.op_input(op, i), names);
        }
    }

    fn out_assign(&self, out: &mut RawOut, op: OpId, names: &dyn RawNames) {
        if let Some(o) = self.op_output(op) {
            self.vn_raw(out, Some(o), names);
            out.s(" = ");
        }
    }

    /// `PcodeOp::printRaw` (the `TypeOp`'s form) into a stream.
    pub fn op_raw(&self, out: &mut RawOut, op: OpId, names: &dyn RawNames) {
        let Some(opc) = self.op_opcode(op) else {
            return;
        };
        let prop = props(opc);
        let output = self.op_output(op);
        let input = |slot| self.op_input(op, slot);
        let count = self.op_num_inputs(op);
        match prop.form {
            RawForm::Binary(sym) => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                self.vn_raw(out, input(0), names);
                out.c(' ');
                let s = if sym == prop.name {
                    self.operator_name(op, names)
                } else {
                    sym.to_owned()
                };
                out.s(&s);
                out.c(' ');
                self.vn_raw(out, input(1), names);
            }
            RawForm::Unary(sym) => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                let s = if sym == prop.name {
                    self.operator_name(op, names)
                } else {
                    sym.to_owned()
                };
                out.s(&s);
                out.c(' ');
                self.vn_raw(out, input(0), names);
            }
            RawForm::Func => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                out.s(&self.operator_name(op, names));
                out.c('(');
                self.vn_raw(out, input(0), names);
                for k in 1..count {
                    out.c(',');
                    self.vn_raw(out, input(k), names);
                }
                out.c(')');
            }
            RawForm::Copy => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                self.vn_raw(out, input(0), names);
            }
            RawForm::Load => {
                self.vn_raw(out, output, names);
                out.s(" = *(");
                out.s(&self.space_name_of_const(input(0)));
                out.c(',');
                self.vn_raw(out, input(1), names);
                out.c(')');
            }
            RawForm::Store => {
                out.s("*(");
                out.s(&self.space_name_of_const(input(0)));
                out.c(',');
                self.vn_raw(out, input(1), names);
                out.s(") = ");
                self.vn_raw(out, input(2), names);
            }
            RawForm::Branch => {
                out.s(prop.name);
                out.c(' ');
                let outs = self.op_parent(op).map(|b| self.outs(b));
                match outs.as_deref() {
                    Some([only]) => self.short_header(out, only.node),
                    _ => self.vn_raw(out, input(0), names),
                }
            }
            RawForm::Cbranch => {
                out.s(prop.name);
                out.c(' ');
                let outs = self.op_parent(op).map(|b| self.outs(b));
                let mut false_out = None;
                match outs.as_deref() {
                    Some([f, t]) => {
                        false_out = Some(f.node);
                        self.short_header(out, t.node);
                    }
                    _ => self.vn_raw(out, input(0), names),
                }
                out.s(" if (");
                self.vn_raw(out, input(1), names);
                out.s(if self.op_is_boolean_flip(op) {
                    " == 0)"
                } else {
                    " != 0)"
                });
                if let Some(f) = false_out {
                    out.s(" else ");
                    self.short_header(out, f);
                }
            }
            RawForm::Branchind => {
                out.s(prop.name);
                out.c(' ');
                self.vn_raw(out, input(0), names);
            }
            RawForm::Call | RawForm::Callind => {
                self.out_assign(out, op, names);
                out.s(prop.name);
                if prop.form == RawForm::Call {
                    out.c(' ');
                }
                self.vn_raw(out, input(0), names);
                if count > 1 {
                    out.c('(');
                    self.list_raw(out, op, 1, names);
                    out.c(')');
                }
            }
            RawForm::Callother => {
                self.out_assign(out, op, names);
                out.s(&self.operator_name(op, names));
                if count > 1 {
                    out.c('(');
                    self.list_raw(out, op, 1, names);
                    out.c(')');
                }
            }
            RawForm::Return => {
                out.s(prop.name);
                if count >= 1 {
                    out.c('(');
                    self.vn_raw(out, input(0), names);
                    out.c(')');
                }
                if count > 1 {
                    out.c(' ');
                    self.list_raw(out, op, 1, names);
                }
            }
            RawForm::Multi => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                self.vn_raw(out, input(0), names);
                if count == 1 {
                    out.c(' ');
                    out.s(prop.name);
                }
                for k in 1..count {
                    out.c(' ');
                    out.s(prop.name);
                    out.c(' ');
                    self.vn_raw(out, input(k), names);
                }
            }
            RawForm::Indirect => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                if self.op_is_indirect_creation(op) {
                    out.s("[create] ");
                } else {
                    self.vn_raw(out, input(0), names);
                    out.c(' ');
                    out.s(prop.name);
                    out.c(' ');
                }
                self.vn_raw(out, input(1), names);
            }
            RawForm::Cast => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                out.s(prop.name);
                out.c(' ');
                self.vn_raw(out, input(0), names);
            }
            RawForm::Ptradd => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                self.vn_raw(out, input(0), names);
                out.c(' ');
                out.s(prop.name);
                out.c(' ');
                self.vn_raw(out, input(1), names);
                out.s("(*");
                self.vn_raw(out, input(2), names);
                out.c(')');
            }
            RawForm::Ptrsub => {
                self.vn_raw(out, output, names);
                out.s(" = ");
                self.vn_raw(out, input(0), names);
                out.c(' ');
                out.s(prop.name);
                out.c(' ');
                self.vn_raw(out, input(1), names);
            }
            RawForm::Segment => {
                self.out_assign(out, op, names);
                out.s(prop.name);
                out.c('(');
                out.s(&self.space_name_of_const(input(0)));
                out.c(',');
                self.vn_raw(out, input(1), names);
                out.c(',');
                self.vn_raw(out, input(2), names);
                out.c(')');
            }
            RawForm::Cpoolref => {
                self.out_assign(out, op, names);
                out.s(prop.name);
                let refs: Vec<u64> = (1..count)
                    .map(|k| input(k).map_or(0, |v| self.varnode_offset(v)))
                    .collect();
                if let Some(tok) = names.cpool_token(&refs) {
                    out.c('_');
                    out.s(&tok);
                }
                out.c('(');
                self.vn_raw(out, input(0), names);
                for k in 2..count {
                    out.c(',');
                    self.vn_raw(out, input(k), names);
                }
                out.c(')');
            }
            RawForm::New => {
                self.out_assign(out, op, names);
                out.s(prop.name);
                out.c('(');
                self.vn_raw(out, input(0), names);
                for k in 1..count {
                    out.c(',');
                    self.vn_raw(out, input(k), names);
                }
                out.c(')');
            }
        }
    }

    /// The op as the state dump's `@ops` writes it: `printRaw` after its
    /// sequence number in a fresh stream.
    pub fn op_text(&self, op: OpId, names: &dyn RawNames) -> String {
        let mut out = RawOut::new();
        self.seq_raw(&mut out, self.op_addr(op), self.op_time(op));
        let prefix = out.text.len();
        out.s(":\t");
        let prefix = prefix + 2;
        self.op_raw(&mut out, op, names);
        out.text.get(prefix..).unwrap_or("").to_owned()
    }

    /// `PcodeOp::printDebug`: `<seqnum>: ` then `**` for a dead op or one in
    /// no block, else `printRaw`.
    pub fn op_debug_text(&self, out: &mut RawOut, op: OpId, names: &dyn RawNames) {
        self.seq_raw(out, self.op_addr(op), self.op_time(op));
        out.s(": ");
        if self.op_is_dead(op) || self.op_parent(op).is_none() {
            out.s("**");
        } else {
            self.op_raw(out, op, names);
        }
    }
}
