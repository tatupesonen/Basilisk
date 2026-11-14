//! Instructions built inside another (Ghidra `SleighBuilder::delaySlot`,
//! `appendCrossBuild`; inventory 7.6).
//!
//! Each nested instruction gets a fresh [`Walk`] value that lives only for
//! its build, so an error anywhere inside returns with nothing to restore
//! (Ghidra's `delaySlot` and `appendCrossBuild` leave the builder pointing
//! at a dead walker when the nested build throws, which crashes
//! `oneInstruction`'s error handler: `docs/research/pcodedump-crashes.md`).

use bk_core::{Address, SpaceId};
use bk_sla::{ConstTpl, OpTpl, TemplateRef};

use super::build::{Builder, template_of};
use super::error::{LiftError, LiftLimit};
use super::location::{Handles, Walk, fix, fix_space};
use super::{BuildFeature, BuildObserver};
use crate::context::ContextSource;
use crate::decode::{ByteSource, Parse, ParseState, handles, resolve};

/// The most delay-slot instructions one `DELAY_SLOT` builds.
const MAX_DELAY_INSTRUCTIONS: u32 = 16;

impl<'a, B, C, O> Builder<'a, B, C, O>
where
    B: ByteSource + ?Sized,
    C: ContextSource + ?Sized,
    O: BuildObserver,
{
    /// A parse prepared with the instruction, at `addr`.
    fn prepared_at(&self, addr: Address) -> Option<&'a Parse> {
        let parses: &'a [&'a Parse] = self.parses;
        parses
            .iter()
            .copied()
            .find(|p| p.addr == addr && p.state == ParseState::Handles)
    }

    /// `DELAY_SLOT`: build the instructions after the walk's instruction
    /// until its delay-slot bytes are covered (at least one, as Ghidra's
    /// do-while does).
    pub(crate) fn delay_slot(&mut self, w: Walk<'_>, slots: &mut [Parse]) -> Result<(), LiftError> {
        let Handles::Node { parse, .. } = w.handles else {
            return Err(LiftError::DirectiveInTemplate {
                address: self.address,
                directive: "DELAY_SLOT",
            });
        };
        if self.source.is_none() {
            return Err(LiftError::DirectiveInTemplate {
                address: self.address,
                directive: "DELAY_SLOT",
            });
        }
        self.obs.feature(BuildFeature::DelaySlot);
        let wanted = parse.delay_slot;
        let mut fall = parse.length();
        let mut covered = 0u32;
        let lang = self.lang;
        for _ in 0..MAX_DELAY_INSTRUCTIONS {
            let at = resolve::add(self.lang, parse.addr, u64::from(fall));
            let delayed = self.prepared_at(at).ok_or(LiftError::DelaySlotMissing {
                address: self.address,
            })?;
            let walk = Walk::of(delayed, 0, self.unique_bits(at));
            let tpl = delayed
                .nodes
                .first()
                .and_then(|n| n.constructor())
                .and_then(|c| template_of(lang, c, None));
            self.build(tpl, None, walk, slots)?;
            let len = delayed.length();
            fall = fall.wrapping_add(len);
            covered = covered.wrapping_add(len);
            if covered >= wanted {
                return Ok(());
            }
        }
        Err(LiftError::Limit {
            address: self.address,
            limit: LiftLimit::Nesting,
        })
    }

    /// `CROSSBUILD addr, section`: build `section` of the instruction at
    /// `addr`, with its handles and unique bits but the current
    /// instruction's addresses.
    pub(crate) fn cross_build(
        &mut self,
        tpl: TemplateRef<'_>,
        op: &OpTpl,
        section: Option<u32>,
        w: Walk<'_>,
        slots: &mut [Parse],
    ) -> Result<(), LiftError> {
        if section.is_some() {
            return Err(LiftError::CrossBuildInSection {
                address: self.address,
            });
        }
        let Some((bytes, context)) = self.source else {
            return Err(LiftError::DirectiveInTemplate {
                address: self.address,
                directive: "CROSSBUILD",
            });
        };
        let inputs = tpl.inputs(op);
        let (Some(target_vn), Some(sec_vn)) = (inputs.first(), inputs.get(1)) else {
            return Err(self.model("CROSSBUILD inputs"));
        };
        let number = match sec_vn.offset {
            ConstTpl::Real(n) => u32::try_from(n).unwrap_or(u32::MAX),
            _ => return Err(self.model("CROSSBUILD section")),
        };
        let space = fix_space(&target_vn.space, &w)?;
        let offset = fix(self.lang, &target_vn.offset, &w)?;
        let offset = self
            .lang
            .spaces()
            .space_at(space)
            .map_or(offset, |s| s.wrap_offset(offset));
        let target = Address::new(SpaceId::new(space), offset);
        self.obs.feature(BuildFeature::CrossBuild);
        self.obs.crossbuild_target(target);
        let unique = self.unique_bits(target);
        if let Some(found) = self.prepared_at(target) {
            let walk = cross_walk(found, &w, unique);
            return self.build_section(found, walk, number, slots);
        }
        let Some((slot, rest)) = slots.split_first_mut() else {
            return Err(LiftError::Limit {
                address: self.address,
                limit: LiftLimit::Nesting,
            });
        };
        let failed = LiftError::CrossBuildTarget {
            address: self.address,
            target,
        };
        resolve::resolve(self.lang, slot, target, bytes, context, self.operand_limit)
            .map_err(|_| failed.clone())?;
        handles::resolve_handles(self.lang, slot).map_err(|_| failed)?;
        let found: &Parse = slot;
        let walk = cross_walk(found, &w, unique);
        self.build_section(found, walk, number, rest)
    }

    /// The root constructor's section `number` of `target`, or implied
    /// builds where it has none.
    fn build_section(
        &mut self,
        target: &Parse,
        walk: Walk<'_>,
        number: u32,
        slots: &mut [Parse],
    ) -> Result<(), LiftError> {
        let ctor = target.nodes.first().and_then(|n| n.constructor());
        match ctor.and_then(|c| template_of(self.lang, c, Some(number))) {
            Some(t) => self.build(Some(t), Some(number), walk, slots),
            None => self.build_empty(walk, number, slots),
        }
    }

    fn model(&self, what: &'static str) -> LiftError {
        LiftError::Decode(crate::error::DecodeError::Model {
            address: self.address,
            what,
        })
    }
}

/// The walk of a crossbuild target: its handles, space and unique bits, and
/// the addresses of the instruction being built (Ghidra's cross context).
fn cross_walk<'p>(target: &'p Parse, outer: &Walk<'_>, unique: u64) -> Walk<'p> {
    Walk {
        start: outer.start,
        next: outer.next,
        next2: outer.next2,
        flow: outer.flow,
        ..Walk::of(target, 0, unique)
    }
}
