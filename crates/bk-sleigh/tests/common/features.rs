//! A search for samples that exercise the p-code constructs a language's
//! `.sla` contains (delay slots, dynamic loads and stores, truncations, …)
//! but the directed samples do not reach: random fillings of the root
//! pairs, lifted by basilisk; a sample that meets a missing construct is
//! added to the plan, and the oracle then confirms it like any other.

use std::collections::BTreeMap;
use std::sync::Arc;

use bk_core::Address;
use bk_sleigh::{
    BuildFeature, BuildObserver, ContextDb, ContextSink, ContextSource, Decoder, Language,
    OffsetRange, PcodeCounter, SliceBytes,
};

use super::directed::{Config, Plan, Rng, fill_sample};
use super::sweep::{FEATURES, start_context};
use super::templates::TemplateCoverage;

/// Reads a context database and drops commits.
struct ReadOnly<'a>(&'a ContextDb);

impl ContextSource for ReadOnly<'_> {
    fn context_at(&self, addr: Address, out: &mut [u32]) -> OffsetRange {
        self.0.context_at(addr, out)
    }
}

impl ContextSink for ReadOnly<'_> {
    fn set_change_point(&mut self, _: Address, _: usize, _: u32, _: u32) {}
    fn set_region(&mut self, _: Address, _: Option<Address>, _: usize, _: u32, _: u32) {}
}

#[derive(Default)]
struct Seen([bool; 8]);

impl BuildObserver for Seen {
    fn feature(&mut self, feature: BuildFeature) {
        if let Some(i) = FEATURES.iter().position(|f| *f == feature) {
            self.0[i] = true;
        }
    }
}

/// The features `sample` exercises when lifted at address 0.
fn features(decoder: &mut Decoder, db: &ContextDb, sample: &[u8; 16]) -> [bool; 8] {
    let addr = Address::new(decoder.language().default_space(), 0);
    let mut seen = Seen::default();
    let _ = decoder.lift_observed(
        addr,
        &SliceBytes::new(0, sample),
        &mut ReadOnly(db),
        &mut PcodeCounter::default(),
        &mut seen,
    );
    seen.0
}

/// Adds up to `per_feature` samples for each construct the `.sla` contains
/// that the plan's samples do not exercise, trying `attempts` fillings.
pub(crate) fn extend_for_features(
    lang: &Arc<Language>,
    plan: &mut Plan,
    rng: &mut Rng,
    attempts: usize,
    per_feature: usize,
) {
    let present = TemplateCoverage::of(lang).present;
    let mut decoder = Decoder::new(Arc::clone(lang));
    let mut contexts: BTreeMap<Config, ContextDb> = BTreeMap::new();
    let mut found = [0usize; 8];
    let mut usable = Vec::new();
    for (config, samples) in &plan.groups {
        let db = contexts
            .entry(config.clone())
            .or_insert_with(|| start_context(lang, config));
        for (target, sample) in samples {
            for (n, hit) in found.iter_mut().zip(features(&mut decoder, db, sample)) {
                *n += usize::from(hit);
            }
            if let Some(target) = target {
                usable.push((config.clone(), *target));
            }
        }
    }
    let wanted = |found: &[usize; 8]| (0..7).any(|i| present[i] && found[i] < per_feature);
    usable.dedup();
    if usable.is_empty() || !wanted(&found) {
        return;
    }
    let sla = lang.sla();
    let mut subtable_pairs = BTreeMap::new();
    let mut sample = [0u8; 16];
    for _ in 0..attempts {
        if !wanted(&found) {
            break;
        }
        let (config, target) = usable[rng.below(usable.len())].clone();
        fill_sample(
            sla,
            &plan.targets[target],
            true,
            &mut subtable_pairs,
            rng,
            &mut sample,
        );
        let db = &contexts[&config];
        let hits = features(&mut decoder, db, &sample);
        if (0..7).any(|i| hits[i] && present[i] && found[i] < per_feature) {
            for (n, hit) in found.iter_mut().zip(hits) {
                *n += usize::from(hit);
            }
            plan.groups
                .entry(config.clone())
                .or_default()
                .push((None, sample));
        }
    }
}
