//! Directed samples (`features/sleigh-decode.md` 6.2): for every pair at
//! every leaf of the root decision tree, random bytes with the pair's
//! pattern imposed, grouped by the context configuration the pair needs and
//! packed into oracle streams by basilisk's own lengths.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bk_core::Address;
use bk_sla::{DecisionId, DisjointPattern, Sla, SymbolId, SymbolKind};
use bk_sleigh::{ContextVar, Decoder, Language, SliceBytes};

use super::sweep::start_context;

/// A `--context` configuration: variable names and values, in order.
pub(crate) type Config = Vec<(String, u32)>;

/// A prefix: its target index, configuration and the operand offset of the
/// re-entered root table.
type Prefix = (usize, Config, i32);

/// A sample: its target (none for one added for constructor coverage) and
/// bytes.
pub(crate) type Sample = (Option<usize>, [u8; 16]);

/// A deterministic generator (`SplitMix64`).
#[derive(Clone, Debug)]
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub(crate) fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// A seed derived from a name.
pub(crate) fn seed(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A block as (offset, mask/value words).
#[derive(Clone, Debug, Default)]
pub(crate) struct Block {
    pub(crate) offset: i32,
    pub(crate) words: Vec<(u32, u32)>,
}

/// One pair of one leaf of the root tree.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) leaf: u32,
    pub(crate) constructor: u32,
    pub(crate) instruction: Option<Block>,
    pub(crate) context: Option<Block>,
}

fn block(sla: &Sla, id: bk_sla::BlockId) -> Option<Block> {
    let b = sla.block(id)?;
    if b.always_true() {
        return Some(Block::default());
    }
    Some(Block {
        offset: b.offset,
        words: sla
            .block_words(b)
            .iter()
            .map(|w| (w.mask, w.value))
            .collect(),
    })
}

/// Every pair at every leaf of a subtable's decision tree, in tree order.
pub(crate) fn leaf_pairs(sla: &Sla, table: SymbolId) -> Vec<Target> {
    let Some(subtable) = sla.subtable(table) else {
        return Vec::new();
    };
    let base = subtable.constructors.start();
    let mut out = Vec::new();
    let mut stack: Vec<DecisionId> = vec![subtable.decision];
    while let Some(id) = stack.pop() {
        let Some(node) = sla.decision(id) else {
            continue;
        };
        if node.is_leaf() {
            for pair in sla.pairs(node) {
                let (context, instruction) = match pair.pattern {
                    DisjointPattern::Instruction(b) => (None, block(sla, b)),
                    DisjointPattern::Context(b) => (block(sla, b), None),
                    DisjointPattern::Combine {
                        context,
                        instruction,
                    } => (block(sla, context), block(sla, instruction)),
                };
                out.push(Target {
                    leaf: id.index(),
                    constructor: base + pair.constructor,
                    instruction,
                    context,
                });
            }
        } else {
            stack.extend(sla.children(node).collect::<Vec<_>>().into_iter().rev());
        }
    }
    out
}

/// The context variables that express a context block, with their values
/// (unconstrained bits 0); `None` when some constrained bit is in no
/// variable.
pub(crate) fn configuration(lang: &Language, block: &Block) -> Option<Config> {
    // Masked bits as (global bit index, value).
    let mut bits = Vec::new();
    for (k, &(mask, value)) in block.words.iter().enumerate() {
        for bit in 0..32u32 {
            if mask & (0x8000_0000 >> bit) != 0 {
                let global = i64::from(block.offset) * 8 + k as i64 * 32 + i64::from(bit);
                bits.push((global, value & (0x8000_0000 >> bit) != 0));
            }
        }
    }
    let mut vars: Vec<&ContextVar> = lang.context_variables().iter().collect();
    vars.sort_by_key(|v| (v.end_bit() - v.start_bit(), v.name().to_owned()));
    let mut chosen: Vec<&ContextVar> = Vec::new();
    for &(bit, _) in &bits {
        if chosen.iter().any(|v| covers(v, bit)) {
            continue;
        }
        let var = vars.iter().find(|v| covers(v, bit))?;
        chosen.push(var);
    }
    let mut out: Config = chosen
        .iter()
        .map(|var| {
            let mut value = 0u32;
            for &(bit, set) in &bits {
                if set && covers(var, bit) {
                    value |= 1 << (i64::from(var.end_bit()) - bit);
                }
            }
            (var.name().to_owned(), value)
        })
        .collect();
    out.sort();
    Some(out)
}

fn covers(var: &ContextVar, bit: i64) -> bool {
    i64::from(var.start_bit()) <= bit && bit <= i64::from(var.end_bit())
}

/// Imposes a block at `offset` of a 16-byte sample; `false` (and nothing
/// changed) when it conflicts with bits fixed before or leaves the window.
pub(crate) fn impose(
    sample: &mut [u8; 16],
    fixed: &mut [u8; 16],
    block: &Block,
    offset: i32,
    check: bool,
) -> bool {
    let mut edits = Vec::new();
    for (k, &(mask, value)) in block.words.iter().enumerate() {
        for i in 0..4 {
            let m = (mask >> (24 - 8 * i)) as u8;
            if m == 0 {
                continue;
            }
            let v = (value >> (24 - 8 * i)) as u8;
            let pos = i64::from(offset) + i64::from(block.offset) + 4 * k as i64 + i64::from(i);
            let Ok(pos) = usize::try_from(pos) else {
                return false;
            };
            if pos >= 16 {
                return false;
            }
            if check
                && (fixed[pos] & m) != 0
                && (sample[pos] & fixed[pos] & m) != (v & fixed[pos] & m)
            {
                return false;
            }
            edits.push((pos, m, v));
        }
    }
    for (pos, m, v) in edits {
        sample[pos] = (sample[pos] & !m) | (v & m);
        fixed[pos] |= m;
    }
    true
}

/// The directed samples of one language, grouped by configuration.
#[derive(Clone, Debug, Default)]
pub(crate) struct Plan {
    pub(crate) targets: Vec<Target>,
    /// Configuration → samples as (target index, bytes); samples added for
    /// constructor coverage have no target.
    pub(crate) groups: BTreeMap<Config, Vec<Sample>>,
    /// Targets whose context block no named variable expresses.
    pub(crate) inexpressible: Vec<usize>,
    /// Targets whose constructor has more than 20 operands (kept out of the
    /// oracle streams).
    pub(crate) over_20: Vec<usize>,
    /// Targets for which some sample decodes to the targeted constructor.
    pub(crate) hit: BTreeSet<usize>,
    /// Targets an earlier pair of the same leaf always wins over (no input
    /// can select them, in Ghidra or here).
    pub(crate) shadowed: BTreeSet<usize>,
}

/// How many random fillings are tried per sample to find one basilisk
/// decodes to the targeted constructor (earlier pairs of a leaf may shadow
/// it for some fillings).
const ATTEMPTS: usize = 48;

/// How many fillings are tried for a pair's first sample before giving up.
const EXTENDED_ATTEMPTS: usize = 2048;

/// Random bytes with a target's instruction pattern imposed and, when
/// `nested`, a random leaf pattern of each sub-table operand at that
/// operand's offset (when compatible).
pub(crate) fn fill_sample(
    sla: &Sla,
    target: &Target,
    nested: bool,
    subtable_pairs: &mut BTreeMap<u32, Vec<Target>>,
    rng: &mut Rng,
    sample: &mut [u8; 16],
) {
    rng.fill(sample);
    let mut fixed = [0u8; 16];
    if let Some(block) = &target.instruction {
        impose(sample, &mut fixed, block, 0, false);
    }
    if !nested {
        return;
    }
    let Some(ctor) = sla.constructor(bk_sla::ConstructorId::new(target.constructor)) else {
        return;
    };
    for &operand in sla.operands(ctor) {
        let Some(SymbolKind::Operand(op)) = sla.symbol(operand).map(|s| s.kind) else {
            continue;
        };
        let Some(table) = op.defining_symbol.filter(|&t| sla.subtable(t).is_some()) else {
            continue;
        };
        if op.base >= 0 {
            continue;
        }
        let pairs = subtable_pairs
            .entry(table.index())
            .or_insert_with(|| leaf_pairs(sla, table));
        if pairs.is_empty() {
            continue;
        }
        let pick = &pairs[rng.below(pairs.len())];
        if let Some(block) = &pick.instruction {
            impose(sample, &mut fixed, block, op.offset, true);
        }
    }
}

/// Root pairs (with their configuration and operand offset) whose
/// constructor has the root table itself as an operand placed from the
/// constructor's start: prefixes such as x86's.
fn prefixes(lang: &Language, targets: &[Target]) -> Vec<Prefix> {
    let sla = lang.sla();
    let mut out = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        let config = match &target.context {
            Some(block) if !block.words.is_empty() => match configuration(lang, block) {
                Some(config) => config,
                None => continue,
            },
            _ => Vec::new(),
        };
        let Some(ctor) = sla.constructor(bk_sla::ConstructorId::new(target.constructor)) else {
            continue;
        };
        for &operand in sla.operands(ctor) {
            if let Some(SymbolKind::Operand(op)) = sla.symbol(operand).map(|s| s.kind)
                && op.defining_symbol == Some(sla.root())
                && op.base < 0
            {
                out.push((index, config.clone(), op.offset));
            }
        }
    }
    // One entry per distinct prefix constructor, so that a constructor
    // reached by many leaves is not tried more often than the others.
    let mut seen = BTreeSet::new();
    out.retain(|(index, config, offset)| {
        seen.insert((targets[*index].constructor, config.clone(), *offset))
    });
    out
}

/// How many prefix + pair combinations are tried for a pair no plain
/// sample reaches.
const NESTED_ATTEMPTS: usize = 30_000;

/// Tries prefix + pair combinations until basilisk's parse contains the
/// pair's constructor.
fn nested_sample(
    lang: &Arc<Language>,
    decoder: &mut Decoder,
    targets: &[Target],
    prefixes: &[Prefix],
    target: &Target,
    rng: &mut Rng,
    contexts: &mut BTreeMap<Config, bk_sleigh::ContextDb>,
) -> Option<(Config, [u8; 16])> {
    let addr = Address::new(lang.default_space(), 0);
    let mut sample = [0u8; 16];
    for _ in 0..NESTED_ATTEMPTS {
        let (prefix, config, offset) = &prefixes[rng.below(prefixes.len())];
        rng.fill(&mut sample);
        let mut fixed = [0u8; 16];
        if let Some(block) = &targets[*prefix].instruction {
            impose(&mut sample, &mut fixed, block, 0, false);
        }
        if let Some(block) = &target.instruction
            && !impose(&mut sample, &mut fixed, block, *offset, true)
        {
            continue;
        }
        let db = contexts
            .entry(config.clone())
            .or_insert_with(|| start_context(lang, config));
        let hit = decoder
            .decode(addr, &SliceBytes::new(0, &sample), &*db)
            .is_ok_and(|p| p.constructors().any(|c| c.index() == target.constructor));
        if hit {
            return Some((config.clone(), sample));
        }
    }
    None
}

/// Adds samples, found by decoding random fillings with basilisk, whose
/// parses reach constructors no planned sample reaches (`attempts`
/// fillings in all).
pub(crate) fn extend_for_coverage(
    lang: &Arc<Language>,
    plan: &mut Plan,
    rng: &mut Rng,
    attempts: usize,
) {
    let sla = lang.sla();
    let mut decoder = Decoder::new(Arc::clone(lang));
    let addr = Address::new(lang.default_space(), 0);
    let mut contexts: BTreeMap<Config, bk_sleigh::ContextDb> = BTreeMap::new();
    let mut covered = BTreeSet::new();
    let mut usable = Vec::new();
    for (config, samples) in &plan.groups {
        let db = contexts
            .entry(config.clone())
            .or_insert_with(|| start_context(lang, config));
        for (target, sample) in samples {
            if let Ok(parse) = decoder.decode(addr, &SliceBytes::new(0, sample), &*db) {
                covered.extend(parse.constructors().map(bk_sla::ConstructorId::index));
            }
            if let Some(target) = target {
                usable.push((config.clone(), *target));
            }
        }
    }
    usable.dedup();
    if usable.is_empty() {
        return;
    }
    let mut subtable_pairs = BTreeMap::new();
    let mut sample = [0u8; 16];
    let prefixes = prefixes(lang, &plan.targets);
    for n in 0..attempts {
        let (mut config, target) = usable[rng.below(usable.len())].clone();
        fill_sample(
            sla,
            &plan.targets[target],
            true,
            &mut subtable_pairs,
            rng,
            &mut sample,
        );
        if n % 2 == 1 && !prefixes.is_empty() {
            // Behind a prefix that re-enters the root table, so that its
            // context operations set what the target needs.
            let (prefix, prefix_config, offset) = &prefixes[rng.below(prefixes.len())];
            let mut inner = [0u8; 16];
            fill_sample(
                sla,
                &plan.targets[target],
                true,
                &mut subtable_pairs,
                rng,
                &mut inner,
            );
            let mut fixed = [0u8; 16];
            rng.fill(&mut sample);
            if let Some(block) = &plan.targets[*prefix].instruction {
                impose(&mut sample, &mut fixed, block, 0, false);
            }
            let shift = usize::try_from(*offset).unwrap_or(16).min(16);
            for (i, byte) in inner.iter().enumerate() {
                if let Some(slot) = sample.get_mut(shift + i)
                    && fixed.get(shift + i) == Some(&0)
                {
                    *slot = *byte;
                }
            }
            config.clone_from(prefix_config);
            contexts
                .entry(config.clone())
                .or_insert_with(|| start_context(lang, &config));
        }
        let db = &contexts[&config];
        let Ok(parse) = decoder.decode(addr, &SliceBytes::new(0, &sample), db) else {
            continue;
        };
        if parse.constructors().any(|c| !covered.contains(&c.index())) {
            covered.extend(parse.constructors().map(bk_sla::ConstructorId::index));
            plan.groups
                .entry(config.clone())
                .or_default()
                .push((None, sample));
        }
    }
}

/// Builds the samples: `per_pair` for each root leaf pair.
pub(crate) fn plan(lang: &Arc<Language>, per_pair: usize, rng: &mut Rng) -> Plan {
    let sla = lang.sla();
    let targets = leaf_pairs(sla, sla.root());
    let mut subtable_pairs: BTreeMap<u32, Vec<Target>> = BTreeMap::new();
    let mut contexts: BTreeMap<Config, bk_sleigh::ContextDb> = BTreeMap::new();
    let mut decoder = Decoder::new(Arc::clone(lang));
    let addr = Address::new(lang.default_space(), 0);
    let mut out = Plan::default();
    let prefixes = prefixes(lang, &targets);
    for (index, target) in targets.iter().enumerate() {
        let config = match &target.context {
            Some(block) if !block.words.is_empty() => {
                if let Some(config) = configuration(lang, block) {
                    config
                } else {
                    out.inexpressible.push(index);
                    continue;
                }
            }
            _ => Vec::new(),
        };
        let ctor = sla.constructor(bk_sla::ConstructorId::new(target.constructor));
        if ctor.is_some_and(|c| c.num_operands() > 20) {
            out.over_20.push(index);
            continue;
        }
        for n in 0..per_pair {
            let db = contexts
                .entry(config.clone())
                .or_insert_with(|| start_context(lang, &config));
            let mut sample = [0u8; 16];
            let budget = if n == 0 { EXTENDED_ATTEMPTS } else { ATTEMPTS };
            for _ in 0..budget {
                fill_sample(
                    sla,
                    target,
                    n % 2 == 1,
                    &mut subtable_pairs,
                    rng,
                    &mut sample,
                );
                let hit = decoder
                    .decode(addr, &SliceBytes::new(0, &sample), &*db)
                    .ok()
                    .and_then(|p| p.root().and_then(bk_sleigh::Node::constructor))
                    .is_some_and(|c| c.index() == target.constructor);
                if hit {
                    out.hit.insert(index);
                    break;
                }
            }
            if !out.hit.contains(&index) && n == 0 && !prefixes.is_empty() {
                // Reach the pair through a constructor that re-enters the root
                // table, so its context operations set what the pair needs.
                if let Some((config, found)) = nested_sample(
                    lang,
                    &mut decoder,
                    &targets,
                    &prefixes,
                    target,
                    rng,
                    &mut contexts,
                ) {
                    out.hit.insert(index);
                    out.groups
                        .entry(config)
                        .or_default()
                        .push((Some(index), found));
                    continue;
                }
            }
            out.groups
                .entry(config.clone())
                .or_default()
                .push((Some(index), sample));
        }
    }
    out.shadowed = shadowed(&targets, sla);
    out.targets = targets;
    out
}

/// Whether every input matching `b` also matches `a` (a's constrained bits
/// are a subset of b's, with equal values).
fn subsumes(a: Option<&Block>, b: Option<&Block>) -> bool {
    let bits = |block: Option<&Block>| -> BTreeMap<i64, (u8, u8)> {
        let mut map = BTreeMap::new();
        if let Some(block) = block {
            for (k, &(mask, value)) in block.words.iter().enumerate() {
                for i in 0..4 {
                    let m = (mask >> (24 - 8 * i)) as u8;
                    if m != 0 {
                        let v = (value >> (24 - 8 * i)) as u8;
                        map.insert(
                            i64::from(block.offset) + 4 * k as i64 + i64::from(i),
                            (m, v & m),
                        );
                    }
                }
            }
        }
        map
    };
    let (a, b) = (bits(a), bits(b));
    a.iter().all(|(pos, &(m, v))| {
        b.get(pos)
            .is_some_and(|&(bm, bv)| bm & m == m && bv & m == v)
    })
}

/// The pairs shadowed by an earlier pair of their leaf. Leaves are runs of
/// consecutive targets with a shared origin, so a pair is compared with the
/// pairs before it back to the start of its leaf.
fn shadowed(targets: &[Target], sla: &Sla) -> BTreeSet<usize> {
    let _ = sla;
    let mut out = BTreeSet::new();
    for (i, t) in targets.iter().enumerate() {
        let leaf = t.leaf;
        for j in (0..i).rev() {
            let earlier = &targets[j];
            if earlier.leaf != leaf {
                break;
            }
            if subsumes(earlier.instruction.as_ref(), t.instruction.as_ref())
                && subsumes(earlier.context.as_ref(), t.context.as_ref())
            {
                out.insert(i);
                break;
            }
        }
    }
    out
}

/// One oracle invocation: bytes, configuration, and where each sample
/// starts.
#[derive(Clone, Debug)]
pub(crate) struct Stream {
    pub(crate) config: Config,
    pub(crate) bytes: Vec<u8>,
    /// (offset in the stream, target index).
    pub(crate) starts: Vec<(u64, usize)>,
}

/// Packs each group's samples into streams by basilisk's lengths. A sample
/// that basilisk does not decode to its target in the context the stream has
/// reached (after earlier samples' commits) starts a new stream while fewer
/// than `max_streams` exist; a sample that does not decode to its target
/// even then is dropped, so that it cannot shift the samples after it.
pub(crate) fn pack(
    lang: &Arc<Language>,
    plan: &Plan,
    base: u64,
    max_streams: usize,
    max_bytes: usize,
) -> Vec<Stream> {
    let mut streams = Vec::new();
    let space = lang.default_space();
    let mut decoder = Decoder::new(Arc::clone(lang));
    decoder.set_operand_limit(Some(20));
    let fresh = |config: &Config| Stream {
        config: config.clone(),
        bytes: Vec::new(),
        starts: Vec::new(),
    };
    for (config, samples) in &plan.groups {
        let mut current = fresh(config);
        let mut db = start_context(lang, config);
        let mut dirty = false;
        let mut previous: Option<(usize, usize, Option<bk_sla::ConstructorId>)> = None;
        for (target, sample) in samples {
            if current.bytes.len() + 16 > max_bytes {
                streams.push(std::mem::replace(&mut current, fresh(config)));
                db = start_context(lang, config);
                dirty = false;
                previous = None;
            }
            let want = target.map(|t| plan.targets[t].constructor);
            // Decoding at the end of the stream reads only the sample's own
            // 16 bytes.
            let attempt = |decoder: &mut Decoder, db: &bk_sleigh::ContextDb, pos: usize| {
                let addr = Address::new(space, base + pos as u64);
                let bytes = SliceBytes::new(base + pos as u64, sample);
                decoder.decode(addr, &bytes, db).ok().map(|parse| {
                    let hit =
                        want.is_none_or(|want| parse.constructors().any(|c| c.index() == want));
                    (
                        hit,
                        (parse.length() as usize).clamp(1, 16),
                        !parse.commits().is_empty(),
                    )
                })
            };
            let mut outcome = attempt(&mut decoder, &db, current.bytes.len());
            if !outcome.is_some_and(|o| o.0) && dirty && streams.len() + 1 < max_streams {
                streams.push(std::mem::replace(&mut current, fresh(config)));
                db = start_context(lang, config);
                dirty = false;
                previous = None;
                outcome = attempt(&mut decoder, &db, 0);
            }
            let Some((true, len, committed)) = outcome else {
                continue;
            };
            let _pos = current.bytes.len();
            // The previous instruction may read bytes past its length (a
            // little-endian token longer than the constructor): it must
            // still decode as it did with this sample's bytes after it.
            if let Some((prev_pos, prev_len, prev_root)) = previous {
                let mut window: Vec<u8> = current.bytes[prev_pos..].to_vec();
                window.extend_from_slice(sample);
                let addr = Address::new(space, base + prev_pos as u64);
                let same = decoder
                    .decode(addr, &SliceBytes::new(base + prev_pos as u64, &window), &db)
                    .is_ok_and(|p| {
                        p.length() as usize == prev_len
                            && p.root().and_then(bk_sleigh::Node::constructor) == prev_root
                    });
                if !same {
                    // End the stream with the previous instruction.
                    if streams.len() + 1 >= max_streams {
                        continue;
                    }
                    streams.push(std::mem::replace(&mut current, fresh(config)));
                    db = start_context(lang, config);
                    dirty = false;
                    previous = None;
                    if !attempt(&mut decoder, &db, 0).is_some_and(|o| o.0) {
                        continue;
                    }
                }
            }
            let pos = current.bytes.len();
            let addr = Address::new(space, base + pos as u64);
            let source = SliceBytes::new(base + pos as u64, sample);
            let root = decoder
                .decode(addr, &source, &db)
                .ok()
                .and_then(|p| p.root().and_then(bk_sleigh::Node::constructor));
            let _ = decoder.prepare(addr, &source, &mut db);
            if let Some(target) = target {
                current.starts.push((pos as u64, *target));
            }
            current.bytes.extend_from_slice(&sample[..len]);
            previous = Some((pos, len, root));
            dirty |= committed;
        }
        if !current.bytes.is_empty() {
            streams.push(current);
        }
    }
    streams
}
