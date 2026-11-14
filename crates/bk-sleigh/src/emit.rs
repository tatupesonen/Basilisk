//! The receiving end of p-code generation (Ghidra `PcodeEmit`): the trait
//! and three emitters — one that collects into its own arena, one that
//! counts, and one that writes `pcodedump`'s `P` records.

use std::fmt::Write as _;

use bk_core::{Address, RegisterLookup as _, SpaceKind, VarnodeData};
use bk_pcode::OpCode;

use crate::language::Language;

/// Receives the p-code ops of an instruction, in order.
///
/// `inputs` borrows the decoder's buffer for the duration of the call; an
/// emitter that keeps the ops copies them. The opcode is never one of the
/// template directives (`BUILD`, `DELAY_SLOT`, `LABEL`, `CROSSBUILD`).
pub trait PcodeEmit {
    /// One op at the instruction address `addr`.
    fn op(
        &mut self,
        addr: Address,
        opcode: OpCode,
        output: Option<VarnodeData>,
        inputs: &[VarnodeData],
    );
}

/// One op an emitter collected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectedOp {
    /// The instruction address the op belongs to.
    pub addr: Address,
    /// The opcode.
    pub opcode: OpCode,
    /// The output, if any.
    pub output: Option<VarnodeData>,
    start: u32,
    len: u32,
}

/// Collects ops into its own arena (two vectors, reused after
/// [`PcodeCollector::clear`]).
#[derive(Clone, Debug, Default)]
pub struct PcodeCollector {
    ops: Vec<CollectedOp>,
    vars: Vec<VarnodeData>,
}

impl PcodeCollector {
    /// An empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forgets every op, keeping the buffers.
    pub fn clear(&mut self) {
        self.ops.clear();
        self.vars.clear();
    }

    /// The ops collected, in order.
    pub fn ops(&self) -> &[CollectedOp] {
        &self.ops
    }

    /// The inputs of a collected op.
    pub fn inputs(&self, op: &CollectedOp) -> &[VarnodeData] {
        let start = op.start as usize;
        self.vars
            .get(start..start.saturating_add(op.len as usize))
            .unwrap_or_default()
    }
}

impl PcodeEmit for PcodeCollector {
    fn op(
        &mut self,
        addr: Address,
        opcode: OpCode,
        output: Option<VarnodeData>,
        inputs: &[VarnodeData],
    ) {
        let start = self.vars.len() as u32;
        self.vars.extend_from_slice(inputs);
        self.ops.push(CollectedOp {
            addr,
            opcode,
            output,
            start,
            len: inputs.len() as u32,
        });
    }
}

/// Counts ops and varnodes, keeping nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PcodeCounter {
    /// Ops received.
    pub ops: u64,
    /// Varnodes received (outputs and inputs).
    pub varnodes: u64,
}

impl PcodeEmit for PcodeCounter {
    fn op(
        &mut self,
        _addr: Address,
        _opcode: OpCode,
        output: Option<VarnodeData>,
        inputs: &[VarnodeData],
    ) {
        self.ops += 1;
        self.varnodes += inputs.len() as u64 + u64::from(output.is_some());
    }
}

/// Writes each op as a `pcodedump` `P` record (format version 1 of
/// `tools/reference/README.md`), byte for byte as the oracle does.
#[derive(Debug)]
pub struct PcodeRecords<'a> {
    lang: &'a Language,
    out: &'a mut String,
    /// Ops written.
    pub count: u64,
}

impl<'a> PcodeRecords<'a> {
    /// A writer appending to `out`.
    pub fn new(lang: &'a Language, out: &'a mut String) -> Self {
        Self {
            lang,
            out,
            count: 0,
        }
    }
}

impl PcodeEmit for PcodeRecords<'_> {
    fn op(
        &mut self,
        _addr: Address,
        opcode: OpCode,
        output: Option<VarnodeData>,
        inputs: &[VarnodeData],
    ) {
        self.count += 1;
        write_record(self.lang, self.out, opcode, output.as_ref(), inputs);
    }
}

/// Appends one `P` record.
pub fn write_record(
    lang: &Language,
    out: &mut String,
    opcode: OpCode,
    output: Option<&VarnodeData>,
    inputs: &[VarnodeData],
) {
    out.push_str("P\t");
    out.push_str(opcode.name());
    out.push('\t');
    match output {
        Some(vn) => write_varnode(lang, out, vn, false),
        None => out.push('-'),
    }
    let space_ref = matches!(opcode, OpCode::Load | OpCode::Store);
    for (i, vn) in inputs.iter().enumerate() {
        out.push('\t');
        write_varnode(lang, out, vn, space_ref && i == 0);
    }
    out.push('\n');
}

/// Appends a varnode as `pcodedump` prints it: `(space,0xoffset,size)`,
/// with the exact register name when there is one, or `(const,index,8,name)`
/// for a space-id constant.
pub fn write_varnode(lang: &Language, out: &mut String, vn: &VarnodeData, space_ref: bool) {
    let spaces = lang.spaces();
    let space = vn.space().and_then(|id| spaces.space(id));
    out.push('(');
    out.push_str(space.map_or("?", bk_core::Space::name));
    out.push(',');
    if space_ref {
        let named = vn.space_from_const().and_then(|id| spaces.space(id));
        let _ = write!(out, "{:#x},{}", vn.offset, vn.size);
        out.push(',');
        out.push_str(named.map_or("?", bk_core::Space::name));
    } else {
        let _ = write!(out, "{:#x},{}", vn.offset, vn.size);
        if let Some(space) = space
            && !matches!(space.kind(), SpaceKind::Constant)
            && let Some(name) = lang
                .registers()
                .exact_register_name(space.id(), vn.offset, vn.size)
        {
            out.push(',');
            out.push_str(name);
        }
    }
    out.push(')');
}
