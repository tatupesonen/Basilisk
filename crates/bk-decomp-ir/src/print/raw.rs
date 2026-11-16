//! `Varnode::printRaw` and `TypeOp::printRaw` (varnode.cc:742,
//! typeop.cc), byte for byte.
//!
//! Ghidra prints into a C++ stream whose number base is sticky: printing an
//! address leaves it hexadecimal, a `+n` register offset leaves it decimal,
//! and later numbers (sizes, sequence-number times) come out in whatever
//! base was left. [`RawOut`] models that state, so the text equals the
//! console's in every case, not only the common one.

use std::fmt::Write as _;

use bk_core::{Address, Space, SpaceKind};

use crate::ids::{CallSpecId, OpId, VarnodeId};
use crate::ssa::Ssa;
use crate::varnode::OffsetKind;

/// A call spec's name as `FspecSpace::printRaw` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallName {
    /// `FuncCallSpecs::getName` (may be empty).
    pub name: String,
    /// `getEntryAddress`, printed as `func_<addr>` when the name is empty.
    pub entry: Address,
}

/// The names `print raw` needs that the IR does not hold: call specs (D07),
/// user ops and constant-pool tokens (the architecture), and whether Java
/// operators are selected. Object-safe.
pub trait RawNames {
    /// The call spec an `fspec` varnode names; `None` prints `func_` and an
    /// invalid address.
    fn call_name(&self, call: CallSpecId) -> Option<CallName>;
    /// `UserPcodeOp::getOperatorName` for the `CALLOTHER` `op` with user-op
    /// index `index`; `None` when the architecture has no such user op.
    fn userop_name(&self, ssa: &Ssa, op: OpId, index: u64) -> Option<String>;
    /// The token of the constant-pool record with these references
    /// (`CPoolRecord::getToken`), if there is one.
    fn cpool_token(&self, refs: &[u64]) -> Option<String>;
    /// `Datatype::printRaw` of a varnode's type (for `printInfo`).
    fn type_name(&self, ty: Option<bk_decomp_types::TypeId>) -> String {
        ty.map_or_else(|| "<null>".to_owned(), |t| format!("t{}", t.raw()))
    }
    /// `TypeOp::selectJavaOperators` was called with `true`.
    fn java_operators(&self) -> bool {
        false
    }
}

/// Names for nothing: every call spec prints `func_invalid_addr`, user ops
/// print `syscall[...]`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoNames;

impl RawNames for NoNames {
    fn call_name(&self, _call: CallSpecId) -> Option<CallName> {
        None
    }
    fn userop_name(&self, _ssa: &Ssa, _op: OpId, _index: u64) -> Option<String> {
        None
    }
    fn cpool_token(&self, _refs: &[u64]) -> Option<String> {
        None
    }
}

/// A text stream with C++'s sticky number base.
#[derive(Clone, Debug, Default)]
pub struct RawOut {
    /// The text.
    pub text: String,
    /// Whether integers currently print in hexadecimal.
    pub hex: bool,
}

impl RawOut {
    /// A fresh stream (decimal).
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn s(&mut self, t: &str) {
        self.text.push_str(t);
    }

    pub(super) fn c(&mut self, ch: char) {
        self.text.push(ch);
    }

    /// An unsigned integer in the current base (no `0x`).
    pub(super) fn num(&mut self, v: u64) {
        if self.hex {
            let _ = write!(self.text, "{v:x}");
        } else {
            let _ = write!(self.text, "{v}");
        }
    }

    /// A signed integer in the current base (C++ prints negative values in
    /// hex as their two's complement of the type's width).
    pub(super) fn inum(&mut self, v: i32) {
        if self.hex {
            let _ = write!(self.text, "{:x}", v as u32);
        } else {
            let _ = write!(self.text, "{v}");
        }
    }

    pub(super) fn dec(&mut self, v: u64) {
        self.hex = false;
        self.num(v);
    }
}

impl Ssa {
    /// `AddrSpace::printRaw` (and the overrides of the constant, `OTHER` and
    /// join spaces) for a space whose offsets are addresses.
    pub(super) fn space_raw(&self, out: &mut RawOut, space: &Space, offset: u64) {
        match space.kind() {
            SpaceKind::Constant | SpaceKind::Other => {
                let _ = write!(out.text, "{offset:#x}");
                out.hex = true;
            }
            SpaceKind::Join => self.join_raw(out, offset),
            _ => {
                let mut size = space.addr_size();
                if size > 4 {
                    if offset >> 32 == 0 {
                        size = 4;
                    } else if offset >> 48 == 0 {
                        size = 6;
                    }
                }
                let width = 2 * size as usize;
                let _ = write!(out.text, "0x{:0width$x}", space.byte_to_address(offset));
                out.hex = true;
                let word = u64::from(space.word_size());
                if word > 1 {
                    let cut = offset % word;
                    if cut != 0 {
                        out.c('+');
                        out.dec(cut);
                    }
                }
            }
        }
    }

    /// `JoinSpace::printRaw`. Without the join record (a loaded dump does
    /// not carry them) it prints `{unlinked:0x…}`.
    pub(super) fn join_raw(&self, out: &mut RawOut, offset: u64) {
        let Ok(record) = self.spaces.find_join(offset) else {
            let _ = write!(out.text, "{{unlinked:{offset:#x}}}");
            out.hex = true;
            return;
        };
        out.c('{');
        for (i, piece) in record.pieces().iter().enumerate() {
            if i != 0 {
                out.c(',');
            }
            if piece.addr().is_constant() {
                out.s("pad:");
                out.dec(u64::from(piece.size));
            } else {
                self.addr_raw_sized(out, piece.addr(), piece.size as i32, None);
            }
        }
        if record.num_pieces() == 1 {
            out.c(':');
            out.num(u64::from(record.unified().size));
        }
        out.c('}');
    }

    /// `Address::printRaw(s)`.
    pub(crate) fn addr_raw(&self, out: &mut RawOut, addr: Address) {
        match self.spaces.space_of(addr) {
            Some(space) => self.space_raw(out, space, addr.offset()),
            None if addr.is_maximal() => out.s("maximal_addr"),
            None => out.s("invalid_addr"),
        }
    }

    /// The shortcut and raw offset of an address (`getShortcut()` then
    /// `printRaw`), as Ghidra's error messages print it.
    pub(crate) fn shortcut_addr(&self, addr: Address) -> String {
        let mut out = RawOut::new();
        if let Some(c) = addr.shortcut(&self.spaces) {
            out.c(c);
        }
        self.addr_raw(&mut out, addr);
        out.text
    }

    /// `SeqNum` as `operator<<` prints it: the address, `:`, the time in
    /// the stream's current base.
    pub(crate) fn seq_raw(&self, out: &mut RawOut, pc: Address, time: u32) {
        self.addr_raw(out, pc);
        out.c(':');
        out.num(u64::from(time));
    }

    /// An op's sequence number as a fresh stream prints it.
    pub fn seq_text(&self, op: OpId) -> String {
        let mut out = RawOut::new();
        self.seq_raw(&mut out, self.op_addr(op), self.op_time(op));
        out.text
    }

    /// `Address::printRaw(s, size)`: the register holding the bytes (with
    /// `+n`) or the shortcut and raw offset; returns the size the form
    /// implies. `vn` lets the pointer-valued spaces print what they name.
    pub(super) fn addr_raw_sized(
        &self,
        out: &mut RawOut,
        addr: Address,
        size: i32,
        vn: Option<(VarnodeId, &dyn RawNames)>,
    ) -> i32 {
        let default = self.spaces.default_size().unwrap_or(0) as i32;
        let Some(space) = self.spaces.space_of(addr) else {
            self.addr_raw(out, addr);
            return 0;
        };
        let regs = self.spaces.registers();
        if let Some(name) = regs.register_name(space.id(), addr.offset(), size.max(0) as u32)
            && let Some(reg) = regs.register(name)
        {
            out.s(name);
            let off = addr.offset().wrapping_sub(reg.offset);
            if off != 0 {
                out.c('+');
                out.dec(off);
            }
            return reg.size as i32;
        }
        if let Some(c) = space.shortcut() {
            out.c(c);
        }
        match (space.kind(), vn) {
            (SpaceKind::Iop, Some((v, names))) => self.iop_raw(out, v, names),
            (SpaceKind::Fspec, Some((v, names))) => self.fspec_raw(out, v, names),
            _ => self.space_raw(out, space, addr.offset()),
        }
        default
    }

    /// `IopSpace::printRaw`: the named op's sequence number, or for a branch
    /// `code_` and its target block's start.
    pub(super) fn iop_raw(&self, out: &mut RawOut, vn: VarnodeId, _names: &dyn RawNames) {
        let OffsetKind::Op(op) = self.varnode_offset_kind(vn) else {
            return;
        };
        if self.ops.get(op.index()).is_none() {
            let _ = write!(out.text, "{:#x}", op.get());
            out.hex = true;
            return;
        }
        if !self.op_is_branch(op) {
            self.seq_raw(out, self.op_addr(op), self.op_time(op));
            return;
        }
        let Some(bs) = self.op_parent(op) else {
            out.s("code_");
            return;
        };
        let outs = self.outs(bs);
        let target = if outs.len() == 2 {
            outs.get(usize::from(!self.op_is_fallthru_true(op)))
        } else {
            outs.first()
        };
        out.s("code_");
        if let Some(t) = target {
            let start = self.block_start(t.node);
            if let Some(c) = start.shortcut(&self.spaces) {
                out.c(c);
            }
            self.addr_raw(out, start);
        }
    }

    /// `FspecSpace::printRaw`: the call spec's name, or `func_` and its
    /// entry address.
    pub(super) fn fspec_raw(&self, out: &mut RawOut, vn: VarnodeId, names: &dyn RawNames) {
        let OffsetKind::Call(call) = self.varnode_offset_kind(vn) else {
            return;
        };
        match names.call_name(call) {
            Some(c) if !c.name.is_empty() => out.s(&c.name),
            Some(c) => {
                out.s("func_");
                self.addr_raw(out, c.entry);
            }
            None => out.s("func_invalid_addr"),
        }
    }

    /// `Varnode::printRaw` into a stream.
    pub fn vn_raw(&self, out: &mut RawOut, vn: Option<VarnodeId>, names: &dyn RawNames) {
        let Some(vn) = vn else {
            out.s("<null>");
            return;
        };
        let Some(d) = self.vns.get(vn.index()) else {
            out.s("<null>");
            return;
        };
        let (addr, size, flags, def) = (d.loc, d.size, d.flags, d.def());
        let expect = self.addr_raw_sized(out, addr, size, Some((vn, names)));
        if expect != size {
            out.c(':');
            out.inum(size);
        }
        if flags & crate::flags::vflags::INPUT != 0 {
            out.s("(i)");
        }
        if flags & crate::flags::vflags::WRITTEN != 0
            && let Some(def) = def
        {
            out.c('(');
            self.seq_raw(out, self.op_addr(def), self.op_time(def));
            out.c(')');
        }
        if flags & (crate::flags::vflags::INSERT | crate::flags::vflags::CONSTANT) == 0 {
            out.s("(free)");
        }
    }

    /// `Varnode::printRaw` in a fresh stream.
    pub fn varnode_text(&self, vn: VarnodeId, names: &dyn RawNames) -> String {
        let mut out = RawOut::new();
        self.vn_raw(&mut out, Some(vn), names);
        out.text
    }
}
