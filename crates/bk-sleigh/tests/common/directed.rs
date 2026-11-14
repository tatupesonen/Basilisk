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

/// A deterministic generator (SplitMix64).
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// A seed derived from a name.
pub fn seed(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

/// A block as (offset, mask/value words).
#[derive(Clone, Debug, Default)]
pub struct Block {
    pub offset: i32,
    pub words: Vec<(u32, u32)>,
}

/// One pair of one leaf of the root tree.
#[derive(Clone, Debug)]
pub struct Target {
    pub leaf: u32,
    pub constructor: u32,
    pub instruction: Option<Block>,
    pub context: Option<Block>,
}

fn block(sla: &Sla, id: bk_sla::BlockId) -> Option<Block> {
    let b = sla.block(id)?;
    if b.always_true() {
        return Some(Block::default());
    }
    Some(Block {
        offset: b.offset,
        words: sla.block_words(b).iter().map(|w| (w.mask, w.value)).collect(),
    })
}

/// Every pair at every leaf of a subtable's decision tree, in tree order.
pub fn leaf_pairs(sla: &Sla, table: SymbolId) -> Vec<Target> {
    let Some(subtable) = sla.subtable(table) else {
        return Vec::new();
    };
    let base = subtable.constructors.start();
    let mut out = Vec::new();
    let mut stack: Vec<DecisionId> = vec![subtable.decision];
    while let Some(id) = stack.pop() {
        let Some(node) = sla.decision(id) else { continue };
        if node.is_leaf() {
            for pair in sla.pairs(node) {
                let (context, instruction) = match pair.pattern {
                    DisjointPattern::Instruction(b) => (None, block(sla, b)),
                    DisjointPattern::Context(b) => (block(sla, b), None),
                    DisjointPattern::Combine { context, instruction } => (block(sla, context), block(sla, instruction)),
                };
                out.push(Target {
                    leaf: id.index(),
                    constructor: base + pair.constructor,
                    instruction,
                    context,
                });
            }
        } else {
            let children: Vec<_> = sla.children(node).collect();
            stack.extend(children.into_iter().rev());
        }
    }
    out
}

/// The context variables that express a context block, with their values
/// (unconstrained bits 0); `None` when some constrained bit is in no
/// variable.
pub fn configuration(lang: &Language, block: &Block) -> Option<Vec<(String, u32)>> {
    // Masked bits as (global bit index, value).
    let mut bits = Vec::new();
    for (k, &(mask, value)) in block.words.iter().enumerate() {
        for bit in 0..32u32 {
            if mask & (0x8000_0000 >> bit) != 0 {
                let global = block.offset as i64 * 8 + k as i64 * 32 + i64::from(bit);
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
    let mut out: Vec<(String, u32)> = chosen
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
pub fn impose(sample: &mut [u8; 16], fixed: &mut [u8; 16], block: &Block, offset: i32, check: bool) -> bool {
    let mut edits = Vec::new();
    for (k, &(mask, value)) in block.words.iter().enumerate() {
        for i in 0..4 {
            let m = (mask >> (24 - 8 * i)) as u8;
            if m == 0 {
                continue;
            }
            let v = (value >> (24 - 8 * i)) as u8;
            let pos = offset as i64 + i64::from(block.offset) + 4 * k as i64 + i as i64;
            let Ok(pos) = usize::try_from(pos) else { return false };
            if pos >= 16 {
                return false;
            }
            if check && (fixed[pos] & m) != 0 && (sample[pos] & fixed[pos] & m) != (v & fixed[pos] & m) {
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
pub struct Plan {
    pub targets: Vec<Target>,
    /// Configuration → samples as (target index, bytes).
    pub groups: BTreeMap<Vec<(String, u32)>, Vec<(usize, [u8; 16])>>,
    /// Targets whose context block no named variable expresses.
    pub inexpressible: Vec<usize>,
    /// Targets whose constructor has more than 20 operands (kept out of the
    /// oracle streams).
    pub over_20: Vec<usize>,
    /// Targets for which some sample decodes to the targeted constructor.
    pub hit: BTreeSet<usize>,
    /// Targets an earlier pair of the same leaf always wins over (no input
    /// can select them, in Ghidra or here).
    pub shadowed: BTreeSet<usize>,
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
fn fill_sample(
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
        let Some(SymbolKind::Operand(op)) = sla.symbol(operand).map(|s| s.kind) else { continue };
        let Some(table) = op.defining_symbol.filter(|&t| sla.subtable(t).is_some()) else { continue };
        if op.base >= 0 {
            continue;
        }
        let pairs = subtable_pairs.entry(table.index()).or_insert_with(|| leaf_pairs(sla, table));
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
fn prefixes(lang: &Language, targets: &[Target]) -> Vec<(usize, Vec<(String, u32)>, i32)> {
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
        let Some(ctor) = sla.constructor(bk_sla::ConstructorId::new(target.constructor)) else { continue };
        for &operand in sla.operands(ctor) {
            if let Some(SymbolKind::Operand(op)) = sla.symbol(operand).map(|s| s.kind)
                && op.defining_symbol == Some(sla.root())
                && op.base < 0
            {
                out.push((index, config.clone(), op.offset));
            }
        }
    }
    out
}

/// Tries prefix + pair combinations until basilisk's parse contains the
/// pair's constructor.
fn nested_sample(
    lang: &Arc<Language>,
    decoder: &mut Decoder,
    targets: &[Target],
    prefixes: &[(usize, Vec<(String, u32)>, i32)],
    target: &Target,
    rng: &mut Rng,
    contexts: &mut BTreeMap<Vec<(String, u32)>, bk_sleigh::ContextDb>,
) -> Option<(Vec<(String, u32)>, [u8; 16])> {
    let addr = Address::new(lang.default_space(), 0);
    let mut sample = [0u8; 16];
    for _ in 0..EXTENDED_ATTEMPTS {
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
        let db = contexts.entry(config.clone()).or_insert_with(|| start_context(lang, config));
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
pub fn extend_for_coverage(lang: &Arc<Language>, plan: &mut Plan, rng: &mut Rng, attempts: usize) {
    let sla = lang.sla();
    let mut decoder = Decoder::new(Arc::clone(lang));
    let addr = Address::new(lang.default_space(), 0);
    let mut contexts: BTreeMap<Vec<(String, u32)>, bk_sleigh::ContextDb> = BTreeMap::new();
    let mut covered = BTreeSet::new();
    let mut usable = Vec::new();
    for (config, samples) in &plan.groups {
        let db = contexts.entry(config.clone()).or_insert_with(|| start_context(lang, config));
        for (target, sample) in samples {
            if let Ok(parse) = decoder.decode(addr, &SliceBytes::new(0, sample), &*db) {
                covered.extend(parse.constructors().map(|c| c.index()));
            }
            usable.push((config.clone(), *target));
        }
    }
    usable.dedup();
    if usable.is_empty() {
        return;
    }
    let mut subtable_pairs = BTreeMap::new();
    let mut sample = [0u8; 16];
    for _ in 0..attempts {
        let (config, target) = &usable[rng.below(usable.len())];
        let db = &contexts[config];
        fill_sample(sla, &plan.targets[*target], true, &mut subtable_pairs, rng, &mut sample);
        let Ok(parse) = decoder.decode(addr, &SliceBytes::new(0, &sample), db) else { continue };
        if parse.constructors().any(|c| !covered.contains(&c.index())) {
            covered.extend(parse.constructors().map(|c| c.index()));
            plan.groups.entry(config.clone()).or_default().push((*target, sample));
        }
    }
}

/// Builds the samples: `per_pair` for each root leaf pair.
pub fn plan(lang: &Arc<Language>, per_pair: usize, rng: &mut Rng) -> Plan {
    let sla = lang.sla();
    let targets = leaf_pairs(sla, sla.root());
    let mut subtable_pairs: BTreeMap<u32, Vec<Target>> = BTreeMap::new();
    let mut contexts: BTreeMap<Vec<(String, u32)>, bk_sleigh::ContextDb> = BTreeMap::new();
    let mut decoder = Decoder::new(Arc::clone(lang));
    let addr = Address::new(lang.default_space(), 0);
    let mut out = Plan::default();
    let prefixes = prefixes(lang, &targets);
    for (index, target) in targets.iter().enumerate() {
        let config = match &target.context {
            Some(block) if !block.words.is_empty() => match configuration(lang, block) {
                Some(config) => config,
                None => {
                    out.inexpressible.push(index);
                    continue;
                }
            },
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
                fill_sample(sla, target, n % 2 == 1, &mut subtable_pairs, rng, &mut sample);
                let hit = decoder
                    .decode(addr, &SliceBytes::new(0, &sample), &*db)
                    .ok()
                    .and_then(|p| p.root().and_then(|r| r.constructor()))
                    .is_some_and(|c| c.index() == target.constructor);
                if hit {
                    out.hit.insert(index);
                    break;
                }
            }
            if !out.hit.contains(&index) && n == 0 && !prefixes.is_empty() {
                // Reach the pair through a constructor that re-enters the root
                // table, so its context operations set what the pair needs.
                if let Some((config, found)) = nested_sample(lang, &mut decoder, &targets, &prefixes, target, rng, &mut contexts) {
                    out.hit.insert(index);
                    out.groups.entry(config).or_default().push((index, found));
                    continue;
                }
            }
            out.groups.entry(config.clone()).or_default().push((index, sample));
        }
    }
    out.shadowed = shadowed(&targets, sla);
    out.targets = targets;
    out
}

/// Whether every input matching `b` also matches `a` (a's constrained bits
/// are a subset of b's, with equal values).
fn subsumes(a: &Option<Block>, b: &Option<Block>) -> bool {
    let bits = |block: &Option<Block>| -> BTreeMap<i64, (u8, u8)> {
        let mut map = BTreeMap::new();
        if let Some(block) = block {
            for (k, &(mask, value)) in block.words.iter().enumerate() {
                for i in 0..4 {
                    let m = (mask >> (24 - 8 * i)) as u8;
                    if m != 0 {
                        let v = (value >> (24 - 8 * i)) as u8;
                        map.insert(i64::from(block.offset) + 4 * k as i64 + i as i64, (m, v & m));
                    }
                }
            }
        }
        map
    };
    let (a, b) = (bits(a), bits(b));
    a.iter().all(|(pos, &(m, v))| b.get(pos).is_some_and(|&(bm, bv)| bm & m == m && bv & m == v))
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
            if subsumes(&earlier.instruction, &t.instruction) && subsumes(&earlier.context, &t.context) {
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
pub struct Stream {
    pub config: Vec<(String, u32)>,
    pub bytes: Vec<u8>,
    /// (offset in the stream, target index).
    pub starts: Vec<(u64, usize)>,
}

/// Packs each group's samples into streams by basilisk's lengths, cutting
/// after a sample that committed context while fewer than `max_streams`
/// streams exist.
pub fn pack(lang: &Arc<Language>, plan: &Plan, base: u64, max_streams: usize, max_bytes: usize) -> Vec<Stream> {
    let mut streams = Vec::new();
    let space = lang.default_space();
    let mut decoder = Decoder::new(Arc::clone(lang));
    for (config, samples) in &plan.groups {
        let mut current = Stream {
            config: config.clone(),
            bytes: Vec::new(),
            starts: Vec::new(),
        };
        let mut db = start_context(lang, config);
        for (target, sample) in samples {
            if current.bytes.len() + 16 > max_bytes {
                streams.push(std::mem::replace(
                    &mut current,
                    Stream { config: config.clone(), bytes: Vec::new(), starts: Vec::new() },
                ));
                db = start_context(lang, config);
            }
            let pos = current.bytes.len();
            // Decoding at `pos` reads only the sample's own 16 bytes.
            let addr = Address::new(space, base + pos as u64);
            let bytes = SliceBytes::new(base + pos as u64, sample);
            let (len, committed) = match decoder.decode(addr, &bytes, &db) {
                Ok(parse) => {
                    let len = (parse.length() as usize).clamp(1, 16);
                    let committed = !parse.commits().is_empty();
                    let _ = decoder.prepare(addr, &bytes, &mut db);
                    (len, committed)
                }
                Err(_) => (1, false),
            };
            current.starts.push((pos as u64, *target));
            current.bytes.extend_from_slice(&sample[..len]);
            if committed && streams.len() + 1 < max_streams {
                streams.push(std::mem::replace(
                    &mut current,
                    Stream { config: config.clone(), bytes: Vec::new(), starts: Vec::new() },
                ));
                db = start_context(lang, config);
            }
        }
        if !current.bytes.is_empty() {
            streams.push(current);
        }
    }
    streams
}
