//! Running the differential test for one language and judging coverage
//! (`features/sleigh-decode.md` 6.2).

use std::collections::BTreeSet;
use std::sync::Arc;

use bk_sleigh::{Decoder, Language, SliceBytes};
use bk_testkit::ReferenceDir;

use super::directed::{Rng, extend_for_coverage, pack, plan, seed};
use super::{Tolerated, compare, is_crash, locate_crash, sweep, try_oracle};

/// The base address of every stream.
pub const BASE: u64 = 0;

/// How much of each kind of input to use.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub samples_per_pair: usize,
    pub random_bytes: usize,
    pub max_streams: usize,
    pub coverage_attempts: usize,
}

/// Extra byte streams for a language (real code), each with its
/// configuration.
#[derive(Clone, Debug)]
pub struct Extra {
    pub name: String,
    pub base: u64,
    pub bytes: Vec<u8>,
    pub config: Vec<(String, u32)>,
}

/// What one language's run found.
#[derive(Clone, Debug, Default)]
pub struct LanguageResult {
    pub id: String,
    pub constructors: usize,
    pub exercised: BTreeSet<u32>,
    pub targeted: usize,
    pub confirmed: BTreeSet<usize>,
    pub inexpressible: usize,
    pub over_20: usize,
    pub over_20_decoded: usize,
    pub shadowed: usize,
    pub no_hit: usize,
    pub tolerated: Tolerated,
    pub failures: Vec<String>,
    pub invocations: usize,
    /// Instructions whose processing crashes the oracle (address and bytes).
    pub oracle_crashes: Vec<String>,
}

impl LanguageResult {
    pub fn pair_rate(&self) -> f64 {
        self.confirmed.len() as f64 / self.targeted.max(1) as f64
    }

    pub fn ctor_rate(&self) -> f64 {
        self.exercised.len() as f64 / self.constructors.max(1) as f64
    }

    /// One row of the coverage table.
    pub fn row(&self) -> String {
        format!(
            "{}\tconstructors {}\texercised {}\tpairs {}\tconfirmed {}\tinexpressible {}\tover-20 {} (basilisk decodes {})\ttolerated {}/{}/{}\tshadowed {}\tno-hit {}\toracle-crashes {}",
            self.id,
            self.constructors,
            self.exercised.len(),
            self.targeted,
            self.confirmed.len(),
            self.inexpressible,
            self.over_20,
            self.over_20_decoded,
            self.tolerated.over_20_operands,
            self.tolerated.past_byte_16,
            self.tolerated.next2_and_commit,
            self.shadowed,
            self.no_hit,
            self.oracle_crashes.len(),
        )
    }
}

fn run_stream(
    reference: &ReferenceDir,
    lang: &Arc<Language>,
    id: &str,
    base: u64,
    bytes: &[u8],
    config: &[(String, u32)],
    result: &mut LanguageResult,
    label: &str,
) -> Vec<(u64, bool, Vec<u32>)> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let theirs = match try_oracle(reference, id, base, bytes, config) {
        Ok(theirs) => theirs,
        Err(error) if is_crash(&error) => {
            // Ghidra's engine crashes on one instruction: split the stream
            // around it (both sweeps restart their context there).
            let (start, end) = locate_crash(reference, id, base, bytes, config);
            let hex: String = bytes[start..end].iter().map(|b| format!("{b:02x}")).collect();
            result.oracle_crashes.push(format!("{label} {config:?} at {:#x}: {hex}", base + start as u64));
            let mut seen = run_stream(reference, lang, id, base, &bytes[..start], config, result, label);
            seen.extend(run_stream(reference, lang, id, base + end as u64, &bytes[end..], config, result, label));
            return seen;
        }
        Err(error) => panic!("pcodedump {id}: {error}"),
    };
    let ours = sweep(lang, base, bytes, config);
    let cmp = compare(&theirs, &ours);
    result.invocations += 1;
    result.tolerated.add(&cmp.tolerated);
    for failure in cmp.failures.iter().filter(|f| !f.is_empty()).take(5) {
        result.failures.push(format!("{label} {config:?}: {failure}"));
    }
    let mut seen = Vec::with_capacity(ours.records.len());
    for (record, ok) in ours.records.iter().zip(&cmp.confirmed) {
        if *ok {
            result.exercised.extend(record.constructors.iter().copied());
        }
        seen.push((record.address, *ok, record.constructors.clone()));
    }
    seen
}

/// Runs directed samples, a random sweep and the extra streams for one
/// language.
pub fn run_language(reference: &ReferenceDir, lang: &Arc<Language>, id: &str, budget: Budget, extras: &[Extra]) -> LanguageResult {
    let mut result = LanguageResult {
        id: id.to_owned(),
        constructors: lang.sla().constructors().len(),
        ..LanguageResult::default()
    };
    let highest = lang
        .spaces()
        .space(lang.default_space())
        .map_or(u64::MAX, bk_core::Space::highest);
    let max_bytes = usize::try_from(highest.saturating_add(1).min(1 << 20)).unwrap_or(1 << 20);
    let mut rng = Rng::new(seed(id));
    let mut plan = plan(lang, budget.samples_per_pair, &mut rng);
    extend_for_coverage(lang, &mut plan, &mut rng, budget.coverage_attempts);
    result.targeted = plan.targets.len();
    result.inexpressible = plan.inexpressible.len();
    result.over_20 = plan.over_20.len();
    result.shadowed = plan.shadowed.len();
    result.no_hit = (0..plan.targets.len())
        .filter(|t| !plan.hit.contains(t) && !plan.shadowed.contains(t))
        .count();
    // Constructors with more than 20 operands: basilisk must decode them.
    let mut decoder = Decoder::new(Arc::clone(lang));
    let db = lang.initial_context();
    for &target in &plan.over_20 {
        let mut sample = [0u8; 16];
        rng.fill(&mut sample);
        if let Some(block) = &plan.targets[target].instruction {
            super::directed::impose(&mut sample, &mut [0; 16], block, 0, false);
        }
        let addr = bk_core::Address::new(lang.default_space(), 0);
        if let Ok(parse) = decoder.decode(addr, &SliceBytes::new(0, &sample), &db)
            && parse.root().and_then(|r| r.constructor()).map(|c| c.index()) == Some(plan.targets[target].constructor)
        {
            result.over_20_decoded += 1;
        }
    }
    for stream in pack(lang, &plan, BASE, budget.max_streams, max_bytes) {
        let seen = run_stream(reference, lang, id, BASE, &stream.bytes, &stream.config, &mut result, "directed");
        let mut records = seen.iter().peekable();
        for &(start, target) in &stream.starts {
            let addr = BASE + start;
            while records.peek().is_some_and(|r| r.0 < addr) {
                records.next();
            }
            if let Some((at, ok, ctors)) = records.peek()
                && *at == addr
                && *ok
                && ctors.contains(&plan.targets[target].constructor)
            {
                result.confirmed.insert(target);
            }
        }
    }
    if budget.random_bytes > 0 {
        let mut bytes = vec![0u8; budget.random_bytes.min(max_bytes)];
        rng.fill(&mut bytes);
        run_stream(reference, lang, id, BASE, &bytes, &[], &mut result, "random");
    }
    for extra in extras {
        run_stream(reference, lang, id, extra.base, &extra.bytes, &extra.config, &mut result, &extra.name);
    }
    result
}
