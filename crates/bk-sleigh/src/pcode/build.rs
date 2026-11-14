//! Building templates into the op buffer (Ghidra `PcodeBuilder::build`,
//! `SleighBuilder::appendBuild`, `buildEmpty`, `setLabel`, `dump`;
//! inventory 7.2–7.4). Delay slots and crossbuild are in `nested`.

use bk_core::{Address, SpaceId, VarnodeData};
use bk_pcode::OpCode;
use bk_sla::{ConstTpl, ConstructorId, HandleSelect, OpTpl, TemplateRef};

use super::buffer::{OpBuffer, RawOp};
use super::error::{LiftError, LiftLimit};
use super::location::{CONST, Handles, Walk, locate, pointer};
use super::{BuildFeature, BuildObserver};
use crate::context::ContextSource;
use crate::decode::{ByteSource, Parse};
use crate::language::Language;
use crate::language::tables::OpDef;

/// The deepest the builder recurses (`BUILD`, delay slots and crossbuild
/// together; ADR-009).
const MAX_BUILD_DEPTH: u32 = 512;

/// The unique-space offset of the effective-address temporary
/// (`UniqueLayout::RUNTIME_BITRANGE_EA`).
pub(crate) const RUNTIME_BITRANGE_EA: u32 = 0x100;

/// Everything one build reads and writes. Crossbuild targets that must be
/// decoded on demand go into scratch parses handed down the recursion.
pub(crate) struct Builder<'a, B: ?Sized, C: ?Sized, O> {
    pub(crate) lang: &'a Language,
    /// Bytes and context for decoding crossbuild targets; `None` for a
    /// free-standing template (no delay slots, no crossbuild).
    pub(crate) source: Option<(&'a B, &'a C)>,
    /// The instruction and its delay-slot instructions, already prepared.
    pub(crate) parses: &'a [&'a Parse],
    pub(crate) buf: &'a mut OpBuffer,
    pub(crate) obs: &'a mut O,
    /// The instruction being lifted (for errors).
    pub(crate) address: Address,
    pub(crate) unique_mask: u64,
    pub(crate) operand_limit: u32,
    pub(crate) label_count: u32,
    pub(crate) label_base: u32,
    pub(crate) depth: u32,
}

impl<B, C, O> Builder<'_, B, C, O>
where
    B: ByteSource + ?Sized,
    C: ContextSource + ?Sized,
    O: BuildObserver,
{
    /// The unique bits for a template of the instruction at `addr`.
    pub(crate) fn unique_bits(&self, addr: Address) -> u64 {
        (addr.offset() & self.unique_mask) << 8
    }

    /// The constructor at the walk's node.
    fn ctor_of(w: &Walk<'_>) -> Option<ConstructorId> {
        match w.handles {
            Handles::Node { parse, node } => {
                parse.nodes.get(node).and_then(crate::Node::constructor)
            }
            Handles::Params(_) => None,
        }
    }

    /// The error for reaching a constructor without p-code while building
    /// the instruction of `w`.
    pub(crate) fn unimplemented(&self, w: &Walk<'_>) -> LiftError {
        let mut text = String::new();
        if let Handles::Node { parse, .. } = w.handles {
            use std::fmt::Write as _;
            let _ = write!(text, "{}: ", self.lang.raw_text(parse.addr).raw());
            let _ = self.lang.mnemonic(parse, &mut text);
            text.push_str("  ");
            let _ = self.lang.body(parse, &mut text);
        }
        LiftError::Unimplemented {
            address: self.address,
            text,
            flow_length: 0,
        }
    }

    /// Ghidra `PcodeBuilder::build`: `tpl` (or `None` for `unimpl`) in
    /// section `section` with the walk `w`.
    pub(crate) fn build(
        &mut self,
        tpl: Option<TemplateRef<'_>>,
        section: Option<u32>,
        w: Walk<'_>,
        slots: &mut [Parse],
    ) -> Result<(), LiftError> {
        let tpl = tpl.ok_or_else(|| self.unimplemented(&w))?;
        if self.depth >= MAX_BUILD_DEPTH {
            return Err(LiftError::Limit {
                address: self.address,
                limit: LiftLimit::BuildDepth,
            });
        }
        self.depth += 1;
        let ctor = Self::ctor_of(&w);
        self.obs.template(ctor, section);
        if section.is_some() {
            self.obs.feature(BuildFeature::NamedSection);
        }
        let old_base = self.label_base;
        self.label_base = self.label_count;
        self.label_count = self
            .label_count
            .saturating_add(u32::try_from(tpl.header().labels).unwrap_or(0));
        for (index, op) in tpl.ops().iter().enumerate() {
            self.obs.op_template(ctor, section, index as u32);
            match op.opcode {
                OpCode::MultiEqual => self.append_build(tpl, op, section, w, slots)?,
                OpCode::Indirect => self.delay_slot(w, slots)?,
                OpCode::PtrAdd => {
                    let id = Self::real(tpl, op, 0).wrapping_add(u64::from(self.label_base));
                    let id = u32::try_from(id).unwrap_or(u32::MAX);
                    self.buf.place_label(id, self.address)?;
                }
                OpCode::PtrSub => self.cross_build(tpl, op, section, w, slots)?,
                _ => self.dump(tpl, op, &w)?,
            }
        }
        self.label_base = old_base;
        self.depth -= 1;
        Ok(())
    }

    /// The real value of input `i` of a directive.
    fn real(tpl: TemplateRef<'_>, op: &OpTpl, i: usize) -> u64 {
        match tpl.inputs(op).get(i).map(|vn| vn.offset) {
            Some(ConstTpl::Real(value) | ConstTpl::Relative(value)) => value,
            _ => u64::MAX,
        }
    }

    /// Ghidra `appendBuild`.
    fn append_build(
        &mut self,
        tpl: TemplateRef<'_>,
        op: &OpTpl,
        section: Option<u32>,
        w: Walk<'_>,
        slots: &mut [Parse],
    ) -> Result<(), LiftError> {
        let index = u32::try_from(Self::real(tpl, op, 0)).unwrap_or(u32::MAX);
        let Some((child, ctor)) = self.subtable_child(&w, index) else {
            return Ok(());
        };
        let child_walk = w.at(child);
        let lang = self.lang;
        match section {
            Some(s) => match template_of(lang, ctor, Some(s)) {
                Some(t) => self.build(Some(t), section, child_walk, slots),
                None => self.build_empty(child_walk, s, slots),
            },
            None => self.build(template_of(lang, ctor, None), None, child_walk, slots),
        }
    }

    /// The node and constructor of operand `index` of the walk's node, when
    /// the operand is a subtable.
    fn subtable_child(&self, w: &Walk<'_>, index: u32) -> Option<(u32, ConstructorId)> {
        let Handles::Node { parse, node } = w.handles else {
            return None;
        };
        let n = parse.nodes.get(node)?;
        let info = self.lang.tables.ctor(n.constructor()?)?;
        let op = self.lang.tables.op(info, index)?;
        if !matches!(op.def, OpDef::Subtable(_)) {
            return None;
        }
        let child = n.child(index)?;
        let ctor = parse.nodes.get(child as usize)?.constructor()?;
        Some((child, ctor))
    }

    /// Ghidra `buildEmpty`: every subtable operand of the walk's node is an
    /// implied `BUILD` in section `section`.
    pub(crate) fn build_empty(
        &mut self,
        w: Walk<'_>,
        section: u32,
        slots: &mut [Parse],
    ) -> Result<(), LiftError> {
        let Handles::Node { parse, node } = w.handles else {
            return Ok(());
        };
        if self.depth >= MAX_BUILD_DEPTH {
            return Err(LiftError::Limit {
                address: self.address,
                limit: LiftLimit::BuildDepth,
            });
        }
        self.depth += 1;
        let num = parse.nodes.get(node).map_or(0, crate::Node::num_children);
        for i in 0..num {
            let Some((child, ctor)) = self.subtable_child(&w, i) else {
                continue;
            };
            let lang = self.lang;
            match template_of(lang, ctor, Some(section)) {
                Some(t) => self.build(Some(t), Some(section), w.at(child), slots)?,
                None => self.build_empty(w.at(child), section, slots)?,
            }
        }
        self.depth -= 1;
        Ok(())
    }

    fn push(
        &mut self,
        opcode: OpCode,
        output: Option<u32>,
        inputs: u32,
        num_inputs: u32,
    ) -> Result<(), LiftError> {
        self.buf.push(
            RawOp {
                opcode,
                output,
                inputs,
                num_inputs,
            },
            self.address,
        )?;
        Ok(())
    }

    /// The effective-address temporary of a truncated dynamic operand.
    fn ea(&self, size: u32) -> VarnodeData {
        let space = self
            .lang
            .spaces()
            .unique_space()
            .map_or(SpaceId::new(CONST), bk_core::Space::id);
        VarnodeData::new(
            space,
            u64::from(self.lang.unique_base().wrapping_add(RUNTIME_BITRANGE_EA)),
            size,
        )
    }

    /// The truncation added to a dynamic operand's pointer, if any.
    fn offset_plus(vn: &bk_sla::VarnodeTpl) -> u64 {
        match vn.offset {
            ConstTpl::Handle {
                select: HandleSelect::OffsetPlus,
                plus,
                ..
            } => plus & 0xffff,
            _ => 0,
        }
    }

    /// Writes `ptr` (and, for a truncated operand, the `INT_ADD` that
    /// offsets it) into slot `ptr_slot` before the `LOAD`/`STORE`.
    fn pointer_into(
        &mut self,
        vn: &bk_sla::VarnodeTpl,
        w: &Walk<'_>,
        space_slot: u32,
    ) -> Result<(), LiftError> {
        let (ptr, space) = pointer(self.lang, vn, w);
        self.buf.set(
            space_slot,
            VarnodeData::new(SpaceId::new(CONST), u64::from(space), 8),
        );
        let ptr_slot = space_slot + 1;
        self.buf.set(ptr_slot, ptr);
        let plus = Self::offset_plus(vn);
        if plus != 0 {
            self.obs.feature(BuildFeature::TruncatedDynamic);
            let add = self.buf.alloc(2, self.address)?;
            self.buf.set(add, ptr);
            self.buf.set(
                add + 1,
                VarnodeData::new(SpaceId::new(CONST), plus, ptr.size),
            );
            self.buf.set(ptr_slot, self.ea(ptr.size));
            self.push(OpCode::IntAdd, Some(ptr_slot), add, 2)?;
        }
        Ok(())
    }

    /// Reports a varnode template that reads the unset handle of a subtable
    /// operand whose constructor exports nothing.
    fn check_unset(&mut self, vn: &bk_sla::VarnodeTpl, w: &Walk<'_>) {
        for c in [vn.space, vn.offset, vn.size] {
            let ConstTpl::Handle { index, .. } = c else {
                continue;
            };
            if w.handle(index) != crate::decode::FixedHandle::UNSET {
                continue;
            }
            let exports_nothing = self.subtable_child(w, index).is_some_and(|(_, ctor)| {
                template_of(self.lang, ctor, None).is_none_or(|t| t.result().is_none())
            });
            if exports_nothing {
                self.obs.feature(BuildFeature::UnsetHandle);
            }
        }
    }

    /// Ghidra `SleighBuilder::dump`: one op with the loads and stores its
    /// dynamic operands need.
    fn dump(&mut self, tpl: TemplateRef<'_>, op: &OpTpl, w: &Walk<'_>) -> Result<(), LiftError> {
        let inputs = tpl.inputs(op);
        if O::WATCHES {
            for vn in tpl.output(op).into_iter().chain(inputs) {
                self.check_unset(vn, w);
            }
        }
        if inputs.len() > super::buffer::MAX_VARNODES_PER_OP {
            return Err(LiftError::TooManyVarnodes {
                address: self.address,
            });
        }
        // The inputs first, as one run; then the loads of dynamic ones, in
        // input order, before the op.
        let base = self.buf.vars.len() as u32;
        let mut dynamic_inputs = false;
        for vn in inputs {
            let (temp, dynamic) = locate(self.lang, vn, w)?;
            self.buf.vars.push(temp);
            dynamic_inputs |= dynamic;
        }
        if dynamic_inputs {
            for (i, vn) in inputs.iter().enumerate() {
                if !super::location::is_dynamic(vn, w) {
                    continue;
                }
                self.obs.feature(BuildFeature::DynamicLoad);
                let load = self.buf.alloc(2, self.address)?;
                self.pointer_into(vn, w, load)?;
                self.push(OpCode::Load, Some(base + i as u32), load, 2)?;
            }
        }
        if let Some(first) = inputs.first()
            && matches!(first.offset, ConstTpl::Relative(_))
        {
            let mut vn = self.buf.get(base);
            vn.offset = vn.offset.wrapping_add(u64::from(self.label_base));
            self.buf.set(base, vn);
            self.buf.add_label_ref(base);
            self.obs.feature(BuildFeature::RelativeBranch);
        }
        let num = inputs.len() as u32;
        let Some(out) = tpl.output(op) else {
            return self.push(op.opcode, None, base, num);
        };
        let (temp, dynamic) = locate(self.lang, out, w)?;
        if dynamic {
            self.obs.feature(BuildFeature::DynamicStore);
            let store = self.buf.alloc(3, self.address)?;
            self.buf.set(store + 2, temp);
            self.push(op.opcode, Some(store + 2), base, num)?;
            self.pointer_into(out, w, store)?;
            self.push(OpCode::Store, None, store, 3)?;
        } else {
            let slot = self.buf.vars.len() as u32;
            self.buf.vars.push(temp);
            self.push(op.opcode, Some(slot), base, num)?;
        }
        Ok(())
    }
}

/// The template of `ctor` for `section` (`None` = main).
pub(crate) fn template_of(
    lang: &Language,
    ctor: ConstructorId,
    section: Option<u32>,
) -> Option<TemplateRef<'_>> {
    let sla = lang.sla();
    match section {
        None => lang.tables.main_template(sla, ctor),
        Some(s) => sla.section_template(sla.constructor(ctor)?, s),
    }
}
