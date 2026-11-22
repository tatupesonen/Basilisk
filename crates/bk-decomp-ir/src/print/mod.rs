//! Text dumps: `print raw` (`Funcdata::printRaw`, `BlockBasic::printRaw`),
//! the op texts of the state dump, and `print tree varnode`
//! (`Funcdata::printVarnodeTree`, `Varnode::printInfo`).

mod op;
mod raw;

pub use raw::{CallName, NoNames, RawNames, RawOut};

use crate::error::{IrError, IrResult};
use crate::flags::vflags;
use crate::ids::VarnodeId;
use crate::ssa::Ssa;
use bk_decomp_cfg::NodeId;

impl Ssa {
    /// `BlockBasic::printRaw`: `Basic Block <index> <start>-<stop>` and one
    /// line per op.
    pub fn block_raw(&self, out: &mut RawOut, b: NodeId, names: &dyn RawNames) {
        out.text.push_str("Basic Block ");
        self.flow_header(out, b);
        out.text.push('\n');
        for op in self.block_ops(b) {
            self.seq_raw(out, self.op_addr(op), self.op_time(op));
            out.text.push_str(":\t");
            self.op_raw(out, op, names);
            out.text.push('\n');
        }
    }

    /// `FlowBlock::printHeader`.
    fn flow_header(&self, out: &mut RawOut, b: NodeId) {
        out.hex = false;
        let _ = std::fmt::Write::write_fmt(
            &mut out.text,
            format_args!("{}", self.cfg.index(b).unwrap_or(0)),
        );
        let (start, stop) = (self.block_start(b), self.block_stop(b));
        if !start.is_invalid() && !stop.is_invalid() {
            out.text.push(' ');
            self.addr_raw(out, start);
            out.text.push('-');
            self.addr_raw(out, stop);
        }
    }

    /// `BlockBasic::printRawImpliedGoto`: a `[ goto … ]` line when `b`
    /// falls through to a block other than `next` without a branch.
    pub fn block_raw_implied_goto(&self, out: &mut RawOut, b: NodeId, next: NodeId) {
        let outs = self.outs(b);
        let [only] = outs.as_slice() else {
            return;
        };
        if only.node == next {
            return;
        }
        if self.last_op(b).is_some_and(|op| self.op_is_branch(op)) {
            return;
        }
        self.addr_raw(out, self.block_stop(b));
        out.text.push_str(":   \t[ goto ");
        self.short_header(out, only.node);
        out.text.push_str(" ]\n");
    }

    /// `Funcdata::printRaw` (the console's `print raw`): the blocks with
    /// their implied gotos after the graph's header line, or the ops in
    /// sequence order when there are no blocks.
    pub fn print_raw(&self, names: &dyn RawNames) -> IrResult<String> {
        let mut out = RawOut::new();
        let blocks: Vec<NodeId> = self.cfg.nodes().to_vec();
        if blocks.is_empty() {
            if self.optree.is_empty() && self.alttree.is_empty() {
                return Err(IrError::NoBlocks("No operations to print"));
            }
            out.text.push_str("Raw operations: \n");
            for op in self.ops_main() {
                self.seq_raw(&mut out, self.op_addr(op), self.op_time(op));
                out.text.push_str(":\t");
                self.op_raw(&mut out, op, names);
                out.text.push('\n');
            }
            return Ok(out.text);
        }
        out.hex = false;
        out.text.push_str("0\n");
        let mut last: Option<NodeId> = None;
        for b in blocks {
            if let Some(l) = last {
                self.block_raw_implied_goto(&mut out, l, b);
            }
            self.block_raw(&mut out, b, names);
            last = Some(b);
        }
        Ok(out.text)
    }

    /// `Varnode::printInfo`, without the host address (`internal=`).
    pub fn varnode_info(&self, out: &mut RawOut, vn: VarnodeId, names: &dyn RawNames) {
        out.text.push_str(&names.type_name(self.varnode_type(vn)));
        out.text.push_str(" = ");
        self.vn_raw(out, Some(vn), names);
        let f = self.varnode_flags(vn);
        let words = [
            (self.is_addr_tied(vn), " tied"),
            (f & vflags::MAPPED != 0, " mapped"),
            (f & vflags::PERSIST != 0, " persistent"),
            (f & vflags::TYPELOCK != 0, " tlock"),
            (f & vflags::NAMELOCK != 0, " nlock"),
            (f & vflags::SPACEBASE != 0, " base"),
            (f & vflags::UNAFFECTED != 0, " unaff"),
            (f & vflags::IMPLIED != 0, " implied"),
            (f & vflags::ADDRFORCE != 0, " addrforce"),
            (f & vflags::READONLY != 0, " readonly"),
        ];
        for (on, w) in words {
            if on {
                out.text.push_str(w);
            }
        }
        out.hex = true;
        let _ = std::fmt::Write::write_fmt(
            &mut out.text,
            format_args!(
                " (consumed=0x{:x}) (create=0x{:x})\n",
                self.varnode_consume(vn),
                self.varnode_create_index(vn)
            ),
        );
    }

    /// `Funcdata::printVarnodeTree` (`print tree varnode`) without
    /// `internal=`: every varnode in def order.
    pub fn print_varnode_tree(&self, names: &dyn RawNames) -> String {
        let mut out = RawOut::new();
        for vn in self.def_order() {
            self.varnode_info(&mut out, vn, names);
        }
        out.text
    }
}
