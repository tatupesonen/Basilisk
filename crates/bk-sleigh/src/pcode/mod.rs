//! P-code generation (Ghidra `Sleigh::oneInstruction`, `SleighBuilder`,
//! `PcodeCacher`, `InjectPayloadSleigh::inject`; inventory section 7,
//! `features/sleigh-pcode.md`).
//!
//! [`Decoder::lift`] prepares the instruction (part 1), builds its root
//! template into the decoder's op buffer, resolves relative branches and
//! hands the ops to a [`PcodeEmit`](crate::PcodeEmit). Nothing reaches the
//! emitter unless the whole instruction built.
//! [`Decoder::build_template`] builds a free-standing template with
//! parameter handles, for injection.

pub(crate) mod buffer;
mod build;
mod error;
mod location;
mod nested;

use bk_core::{Address, VarnodeData};
use bk_sla::{ConstructorId, TemplateRef};

pub use error::{LiftError, LiftLimit};

use crate::context::{ContextDb, ContextSink, ContextSource};
use crate::decode::{ByteSource, Decoder, Parse, SliceBytes};
use crate::emit::PcodeEmit;
use build::{Builder, template_of};
use location::{Handles, Walk};

/// The most crossbuild targets decoded on demand that can be alive at once
/// (crossbuild inside a crossbuilt section's delay slot, …).
const CROSS_SLOTS: usize = 8;

/// A construct the builder met, reported to a [`BuildObserver`] (the
/// differential test's feature columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BuildFeature {
    /// A `DELAY_SLOT` directive was built.
    DelaySlot,
    /// A `CROSSBUILD` directive was built.
    CrossBuild,
    /// A template of a named section was built.
    NamedSection,
    /// A relative branch was recorded (and later resolved).
    RelativeBranch,
    /// A `LOAD` was added for a dynamic input.
    DynamicLoad,
    /// A `STORE` was added for a dynamic output.
    DynamicStore,
    /// An `INT_ADD` was added for a truncated dynamic operand.
    TruncatedDynamic,
    /// A template read the handle of a subtable operand whose constructor
    /// exports nothing. basilisk reads the constant 0 of size 0; Ghidra's
    /// C++ reads whatever an earlier parse left in that slot.
    UnsetHandle,
}

/// Watches a build: which templates and op templates were built and which
/// constructs were met. Every method does nothing by default; `()` is the
/// observer [`Decoder::lift`] uses.
pub trait BuildObserver {
    /// Whether the observer wants per-varnode checks such as
    /// [`BuildFeature::UnsetHandle`] (off for `()`, so lifting pays nothing).
    const WATCHES: bool = true;

    /// A template of `ctor` (`None` for a free-standing template) in
    /// `section` (`None` = main) is being built.
    fn template(&mut self, ctor: Option<ConstructorId>, section: Option<u32>) {
        let _ = (ctor, section);
    }

    /// Op template `index` of that template is being built.
    fn op_template(&mut self, ctor: Option<ConstructorId>, section: Option<u32>, index: u32) {
        let _ = (ctor, section, index);
    }

    /// A construct was met.
    fn feature(&mut self, feature: BuildFeature) {
        let _ = feature;
    }

    /// A crossbuild targets the instruction at `target`.
    fn crossbuild_target(&mut self, target: Address) {
        let _ = target;
    }
}

impl BuildObserver for () {
    const WATCHES: bool = false;
}

/// What a free-standing template is built with (Ghidra
/// `InjectContextSleigh`): the addresses its constants refer to and the
/// varnodes its operands stand for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectContext {
    /// `inst_start`: the instruction address; ops are emitted here.
    pub inst_start: Address,
    /// `inst_next`.
    pub inst_next: Address,
    /// The call or reference address (`inst_dest`, `inst_ref`).
    pub call_addr: Option<Address>,
    /// `(operand index, varnode)` for each input and output parameter.
    pub params: Vec<(u32, VarnodeData)>,
}

impl Decoder {
    /// Lifts the instruction at `addr` to p-code (Ghidra `oneInstruction`):
    /// prepare it (alignment, decode, handles, commits, delay slots), build
    /// its root template, resolve relative branches and pass every op to
    /// `emit`. Returns the flow length (the instruction and its delay
    /// slots). On error nothing has been emitted.
    pub fn lift<B, C, E>(
        &mut self,
        addr: Address,
        bytes: &B,
        context: &mut C,
        emit: &mut E,
    ) -> Result<u32, LiftError>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ContextSink + ?Sized,
        E: PcodeEmit + ?Sized,
    {
        self.lift_observed(addr, bytes, context, emit, &mut ())
    }

    /// [`Decoder::lift`] reporting the build to `obs`.
    pub fn lift_observed<B, C, E, O>(
        &mut self,
        addr: Address,
        bytes: &B,
        context: &mut C,
        emit: &mut E,
        obs: &mut O,
    ) -> Result<u32, LiftError>
    where
        B: ByteSource + ?Sized,
        C: ContextSource + ContextSink + ?Sized,
        E: PcodeEmit + ?Sized,
        O: BuildObserver,
    {
        self.buf.clear();
        let prepared = self
            .prepare_inner(addr, bytes, context)
            .map_err(|(e, in_delay)| {
                if in_delay {
                    LiftError::DelaySlot {
                        address: addr,
                        source: e,
                    }
                } else {
                    LiftError::from(e)
                }
            })?;
        if self.cross.len() < CROSS_SLOTS {
            self.cross.resize_with(CROSS_SLOTS, Parse::new);
        }
        let lang = std::sync::Arc::clone(&self.lang);
        let main = &self.main;
        let mut parses: [&Parse; 1 + crate::decode::MAX_DELAY_INSTRUCTIONS] =
            [main; 1 + crate::decode::MAX_DELAY_INSTRUCTIONS];
        let delays = self.delays.get(..self.num_delays).unwrap_or_default();
        for (slot, d) in parses.iter_mut().skip(1).zip(delays) {
            *slot = d;
        }
        let parses = parses.get(..=delays.len()).unwrap_or_default();
        let mut builder = Builder {
            lang: &lang,
            source: Some((bytes, &*context)),
            parses,
            buf: &mut self.buf,
            obs,
            address: addr,
            unique_mask: u64::from(lang.unique_mask()),
            operand_limit: self.operand_limit,
            label_count: 0,
            label_base: 0,
            depth: 0,
        };
        let walk = Walk::of(main, 0, builder.unique_bits(addr));
        let tpl = main
            .nodes
            .first()
            .and_then(crate::Node::constructor)
            .and_then(|c| template_of(&lang, c, None));
        let built = builder.build(tpl, None, walk, &mut self.cross);
        let built = built.and_then(|()| self.buf.resolve_relatives(addr));
        if let Err(mut e) = built {
            if let LiftError::Unimplemented { flow_length, .. } = &mut e {
                *flow_length = prepared.flow_length;
            }
            return Err(e);
        }
        self.buf.emit(addr, emit);
        Ok(prepared.flow_length)
    }

    /// Builds a free-standing template with parameter handles (Ghidra
    /// `InjectPayloadSleigh::inject`): no delay slots or crossbuild, unique
    /// mask 0, relative branches resolved, ops emitted at `ctx.inst_start`.
    pub fn build_template<E>(
        &mut self,
        template: TemplateRef<'_>,
        ctx: &InjectContext,
        emit: &mut E,
    ) -> Result<(), LiftError>
    where
        E: PcodeEmit + ?Sized,
    {
        self.build_template_observed(template, ctx, emit, &mut ())
    }

    /// [`Decoder::build_template`] reporting the build to `obs`.
    pub fn build_template_observed<E, O>(
        &mut self,
        template: TemplateRef<'_>,
        ctx: &InjectContext,
        emit: &mut E,
        obs: &mut O,
    ) -> Result<(), LiftError>
    where
        E: PcodeEmit + ?Sized,
        O: BuildObserver,
    {
        self.buf.clear();
        let lang = std::sync::Arc::clone(&self.lang);
        let addr = ctx.inst_start;
        let mut builder: Builder<'_, SliceBytes<'_>, ContextDb, O> = Builder {
            lang: &lang,
            source: None,
            parses: &[],
            buf: &mut self.buf,
            obs,
            address: addr,
            unique_mask: 0,
            operand_limit: self.operand_limit,
            label_count: 0,
            label_base: 0,
            depth: 0,
        };
        let walk = Walk {
            handles: Handles::Params(&ctx.params),
            start: addr,
            next: ctx.inst_next,
            next2: None,
            next2_error: None,
            flow: ctx.call_addr,
            cur_space: addr.space().map_or(0, bk_core::SpaceId::index),
            unique: 0,
        };
        builder.build(Some(template), None, walk, &mut [])?;
        self.buf.resolve_relatives(addr)?;
        self.buf.emit(addr, emit);
        Ok(())
    }
}
