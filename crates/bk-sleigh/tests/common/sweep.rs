//! basilisk's side of `pcodedump`'s linear sweep: the library's sweep
//! (`bk_sleigh::dump`, every record including `P` and `U`), with what the
//! harness needs to judge differences and coverage collected per record.

use std::sync::Arc;

use bk_core::Address;
use bk_sla::ConstructorId;
use bk_sleigh::dump::{self, SweepObserver};
use bk_sleigh::{BuildFeature, BuildObserver, ContextDb, Decoder, Language};

/// The feature columns of the coverage table, in order.
pub(crate) const FEATURES: [BuildFeature; 8] = [
    BuildFeature::DelaySlot,
    BuildFeature::CrossBuild,
    BuildFeature::NamedSection,
    BuildFeature::RelativeBranch,
    BuildFeature::DynamicLoad,
    BuildFeature::DynamicStore,
    BuildFeature::TruncatedDynamic,
    BuildFeature::UnsetHandle,
];

/// Column names of [`FEATURES`].
pub(crate) const FEATURE_NAMES: [&str; 8] = [
    "delay",
    "crossbuild",
    "section",
    "relative",
    "load",
    "store",
    "truncated",
    "unset",
];

/// What one instruction's build touched.
#[derive(Clone, Debug, Default)]
pub(crate) struct Built {
    /// Constructors whose main template was built.
    pub(crate) templates: Vec<u32>,
    /// (constructor, section or `u32::MAX`, op index) built.
    pub(crate) ops: Vec<(u32, u32, u32)>,
    pub(crate) features: [u64; 8],
    pub(crate) cross_targets: Vec<u64>,
}

/// One record of a sweep (an `I` record with its `P`/`U` lines, or an `E`
/// record), with what the harness needs to judge differences.
#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub(crate) address: u64,
    /// The record's lines without the final newline.
    pub(crate) line: String,
    /// Constructors of every node, for an `I` record.
    pub(crate) constructors: Vec<u32>,
    pub(crate) root_constructor: Option<u32>,
    /// Ghidra's C++ cannot decode a constructor with more than 20 operands.
    pub(crate) too_many_operands: bool,
    /// A delay-slot instruction folded into this one has more than 20
    /// operands.
    pub(crate) delay_over_20: bool,
    pub(crate) reads_past_window: bool,
    pub(crate) committed: bool,
    pub(crate) uses_next2: bool,
    pub(crate) built: Built,
}

/// The sweep's records and its `T` record.
#[derive(Clone, Debug, Default)]
pub(crate) struct Sweep {
    pub(crate) records: Vec<Record>,
    pub(crate) instructions: u64,
    pub(crate) errors: u64,
}

impl Sweep {
    pub(crate) fn t_line(&self) -> String {
        format!("T\t{}\t{}", self.instructions, self.errors)
    }
}

/// The context `pcodedump` starts from: the `.pspec` defaults, then each
/// `--context` value set over the whole default code space.
pub(crate) fn start_context(lang: &Language, context: &[(String, u32)]) -> ContextDb {
    let mut db = lang.initial_context();
    for (name, value) in context {
        assert!(
            lang.set_context_everywhere(&mut db, name, *value),
            "no context variable {name}"
        );
    }
    db
}

#[derive(Default)]
struct Collect {
    records: Vec<Record>,
    built: Built,
}

impl BuildObserver for Collect {
    fn template(&mut self, ctor: Option<ConstructorId>, section: Option<u32>) {
        if let (Some(c), None) = (ctor, section) {
            self.built.templates.push(c.index());
        }
    }

    fn op_template(&mut self, ctor: Option<ConstructorId>, section: Option<u32>, index: u32) {
        if let Some(c) = ctor {
            self.built
                .ops
                .push((c.index(), section.unwrap_or(u32::MAX), index));
        }
    }

    fn feature(&mut self, feature: BuildFeature) {
        if let Some(i) = FEATURES.iter().position(|f| *f == feature) {
            self.built.features[i] += 1;
        }
    }

    fn crossbuild_target(&mut self, target: Address) {
        self.built.cross_targets.push(target.offset());
    }
}

impl SweepObserver for Collect {
    fn record(&mut self, address: u64, text: &str, decoder: Option<&Decoder>) {
        let built = std::mem::take(&mut self.built);
        let line = text.strip_suffix('\n').unwrap_or(text).to_owned();
        let mut record = Record {
            address,
            line,
            constructors: Vec::new(),
            root_constructor: None,
            too_many_operands: false,
            delay_over_20: false,
            reads_past_window: false,
            committed: false,
            uses_next2: false,
            built,
        };
        if let Some(decoder) = decoder {
            let parse = decoder.parse();
            record.constructors = parse.constructors().map(ConstructorId::index).collect();
            record.root_constructor = record.constructors.first().copied();
            record.too_many_operands = parse.max_operands() > 20;
            record.reads_past_window = parse.reads_past_window()
                || decoder
                    .delay_slots()
                    .iter()
                    .any(bk_sleigh::Parse::reads_past_window);
            record.committed = !parse.commits().is_empty();
            record.uses_next2 = parse.next2().is_some();
            record.delay_over_20 = decoder.delay_slots().iter().any(|d| d.max_operands() > 20);
        }
        self.records.push(record);
    }
}

/// Runs the sweep over `data` placed at `base`.
pub(crate) fn sweep(
    lang: &Arc<Language>,
    base: u64,
    data: &[u8],
    context: &[(String, u32)],
) -> Sweep {
    let mut db = start_context(lang, context);
    let mut decoder = Decoder::new(Arc::clone(lang));
    // Fail as Ghidra's C++ does on more than 20 operands, so both sweeps stay
    // in step; basilisk's own decoding of those is checked separately.
    decoder.set_operand_limit(Some(20));
    let mut collect = Collect::default();
    let mut out = String::new();
    let counts = dump::sweep(
        &mut decoder,
        &mut db,
        base,
        data,
        false,
        &mut out,
        &mut collect,
    );
    Sweep {
        records: collect.records,
        instructions: counts.instructions,
        errors: counts.errors,
    }
}
