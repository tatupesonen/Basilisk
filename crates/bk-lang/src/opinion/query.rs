//! The opinion database and its queries (Ghidra: `QueryOpinionService`).

use std::{collections::HashMap, fmt};

use super::{
    javahash::{JavaHash, JavaHashMap, string_hash},
    model::{Constraint, Opinions},
};
use crate::{id::LanguageCompilerSpecPair, value::java_split};

/// One answer to an opinion query: a language/compiler pair and whether
/// the opinion prefers it.
///
/// A loader offers every result to the user and marks the preferred ones;
/// the first preferred result is the default choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    /// The language and compiler spec.
    pub pair: LanguageCompilerSpecPair,
    /// Whether the matching constraint named this pair's compiler spec.
    pub preferred: bool,
}

impl fmt::Display for QueryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let not = if self.preferred { "" } else { "not " };
        write!(f, "query result: {} ({not}preferred)", self.pair)
    }
}

/// A pair in the database's pair table, with the hash code Ghidra's
/// `QueryResult` has. Equality is by pair alone, as in Ghidra, so the
/// preferred flag of the first of two equal results is the one kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PairKey {
    index: u32,
    hash: i32,
}

impl JavaHash for PairKey {
    fn java_hash(&self) -> i32 {
        self.hash
    }
}

/// `QueryResult.hashCode()`, built from `LanguageCompilerSpecPair`,
/// `CompilerSpecID` and `LanguageID.hashCode()`.
fn query_result_hash(pair: &LanguageCompilerSpecPair) -> i32 {
    let language = 31i32.wrapping_add(string_hash(pair.language_id.as_str()));
    let compiler = 31i32.wrapping_add(string_hash(pair.compiler_spec_id.as_str()));
    let pair_hash = 31i32
        .wrapping_add(compiler)
        .wrapping_mul(31)
        .wrapping_add(language);
    31i32.wrapping_add(pair_hash)
}

type Key = Option<Box<str>>;
/// The results under one (loader, primary, secondary) key: pair → preferred.
type Results = JavaHashMap<PairKey, bool>;
type BySecondary = JavaHashMap<Key, Results>;
type ByPrimary = JavaHashMap<Key, BySecondary>;

fn key(text: Option<&str>) -> Key {
    text.map(Box::from)
}

fn key_hash(text: Option<&str>) -> i32 {
    text.map_or(0, string_hash)
}

/// Every loaded opinion, indexed by loader name, primary key and secondary
/// key.
///
/// Built by feeding it the constraints of each `.opinion` file in the
/// order Ghidra reads them; a [`LanguageRegistry`](crate::LanguageRegistry)
/// does this on first use.
#[derive(Debug, Clone, Default)]
pub struct OpinionDatabase {
    loaders: HashMap<Key, ByPrimary>,
    pairs: Vec<LanguageCompilerSpecPair>,
    pair_keys: HashMap<LanguageCompilerSpecPair, PairKey>,
}

impl OpinionDatabase {
    /// An empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the constraints of one file.
    ///
    /// `matching` returns, for a constraint with inherited attributes
    /// filled in, the language/compiler pairs of every language its
    /// `processor`, `endian`, `size` and `variant` select — all compiler
    /// specs of each, whatever the constraint's own `compilerSpecID`. As in
    /// Ghidra, every constraint element is registered, not only leaves, and
    /// a result is preferred when its compiler spec is the constraint's.
    pub fn add(
        &mut self,
        opinions: &Opinions,
        mut matching: impl FnMut(&Constraint) -> Vec<LanguageCompilerSpecPair>,
    ) {
        for constraint in opinions.resolved() {
            let results = self
                .loaders
                .entry(key(constraint.loader.as_deref()))
                .or_default()
                .get_or_insert_with(key(constraint.primary.as_deref()), JavaHashMap::default)
                .get_or_insert_with(key(constraint.secondary.as_deref()), JavaHashMap::default);
            for pair in matching(&constraint) {
                let preferred =
                    constraint.compiler_spec_id.as_ref() == Some(&pair.compiler_spec_id);
                let next = u32::try_from(self.pairs.len()).unwrap_or(u32::MAX);
                let pair_key = *self.pair_keys.entry(pair).or_insert_with_key(|pair| {
                    self.pairs.push(pair.clone());
                    PairKey {
                        index: next,
                        hash: query_result_hash(pair),
                    }
                });
                results.insert_if_absent(pair_key, preferred);
            }
        }
    }

    /// The language/compiler pairs the opinions give for a file.
    ///
    /// `loader` is the loader's name; `primary` and `secondary` are the
    /// keys the loader derives from the file (for ELF, the machine number
    /// and the `e_flags` value, both as decimal strings).
    ///
    /// Matching follows `QueryOpinionService.query`:
    ///
    /// 1. The primary key selects the constraints whose `primary` equals
    ///    it, or failing that, the first `primary` that is a
    ///    comma-separated list containing it (white space ignored).
    /// 2. Among those, the secondary key selects the constraints whose
    ///    `secondary` equals it; failing that, every constraint whose
    ///    `secondary` is a hexadecimal or binary pattern that the key
    ///    matches ([`secondary_attribute_matches`]); failing that, the
    ///    constraints with no `secondary`.
    ///
    /// The results come in the order Ghidra returns them — the iteration
    /// order of its `HashSet`s.
    #[must_use]
    pub fn query(
        &self,
        loader: &str,
        primary: Option<&str>,
        secondary: Option<&str>,
    ) -> Vec<QueryResult> {
        let Some(by_primary) = self.loaders.get(&key(Some(loader))) else {
            tracing::debug!(loader, primary, secondary, "no opinion for loader");
            return Vec::new();
        };
        let Some(by_secondary) = primary_match(by_primary, primary) else {
            tracing::debug!(loader, primary, secondary, "no opinion for primary key");
            return Vec::new();
        };
        let exact = |wanted: Option<&str>| {
            by_secondary.get_by(key_hash(wanted), |k| k.as_deref() == wanted)
        };
        let masked;
        let results = if let Some(results) = exact(secondary) {
            Some(results)
        } else {
            masked = masked_match(by_secondary, secondary);
            masked.as_ref().or_else(|| exact(None))
        };
        let Some(results) = results else {
            tracing::debug!(loader, primary, secondary, "no opinion for secondary key");
            return Vec::new();
        };
        results
            .iter()
            .filter_map(|(pair_key, preferred)| {
                let pair = self.pairs.get(pair_key.index as usize)?.clone();
                Some(QueryResult {
                    pair,
                    preferred: *preferred,
                })
            })
            .collect()
    }

    /// The names of the loaders that have opinions, in no particular order.
    pub fn loaders(&self) -> impl Iterator<Item = &str> {
        self.loaders.keys().filter_map(|k| k.as_deref())
    }

    /// Whether every stored result set is certain to iterate in Ghidra's
    /// order.
    ///
    /// The order is exact unless nine or more results share one hash bin
    /// of a set with 64 or more bins, where Java switches the bin to a
    /// tree; that takes thousands of results under one key and does not
    /// happen with Ghidra's own files.
    #[must_use]
    pub fn order_is_exact(&self) -> bool {
        self.loaders.values().all(|by_primary| {
            by_primary.order_is_exact()
                && by_primary.iter().all(|(_, by_secondary)| {
                    by_secondary.order_is_exact()
                        && by_secondary
                            .iter()
                            .all(|(_, results)| results.order_is_exact())
                })
        })
    }
}

/// `QueryOpinionService.getPrimaryLoaders`.
fn primary_match<'a>(by_primary: &'a ByPrimary, primary: Option<&str>) -> Option<&'a BySecondary> {
    if let Some(exact) = by_primary.get_by(key_hash(primary), |k| k.as_deref() == primary) {
        return Some(exact);
    }
    // A `primary` attribute may list several values: MIPS has "8,10".
    let primary = primary?;
    by_primary.iter().find_map(|(candidate, by_secondary)| {
        let cleaned: String = candidate
            .as_deref()?
            .chars()
            .filter(|c| !is_java_space(*c))
            .collect();
        java_split(&cleaned, ',')
            .any(|token| token == primary)
            .then_some(by_secondary)
    })
}

/// `QueryOpinionService.getQueryResultWithSecondaryMasking`: the union of
/// the results under every `secondary` pattern the key matches, or `None`
/// when there is none.
fn masked_match(by_secondary: &BySecondary, secondary: Option<&str>) -> Option<Results> {
    let secondary = secondary?;
    let mut union = Results::default();
    for (pattern, results) in by_secondary.iter() {
        if pattern
            .as_deref()
            .is_some_and(|p| secondary_attribute_matches(secondary, p))
        {
            for (pair_key, preferred) in results.iter() {
                union.insert_if_absent(*pair_key, *preferred);
            }
        }
    }
    (union.len() > 0).then_some(union)
}

/// The characters Java's regular expression `\s` matches.
fn is_java_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

/// Whether a loader's secondary key matches a constraint's `secondary`
/// pattern (Ghidra: `QueryOpinionService.secondaryAttributeMatches`).
///
/// `secondary_key` is a signed 32-bit integer in decimal. `constraint` is
/// either `0x` followed by hexadecimal digits, matching when the values
/// are equal as 32-bit patterns, or `0b` followed by up to 32 binary
/// digits (most significant first, shorter patterns padded with zeros on
/// the left) in which a `.` matches either bit. Spaces and `_` in the
/// constraint are ignored and letters may be in either case. Anything else
/// does not match; plain decimal constraints are compared for equality by
/// the query itself, before this is consulted.
#[must_use]
pub fn secondary_attribute_matches(secondary_key: &str, constraint: &str) -> bool {
    let Ok(key) = secondary_key.parse::<i32>() else {
        return false;
    };
    let constraint: String = constraint
        .chars()
        .filter(|c| *c != '_' && !is_java_space(*c))
        .collect::<String>()
        .trim_matches(|c: char| c <= ' ')
        .to_lowercase();
    if let Some(hex) = constraint.strip_prefix("0x") {
        // Java's `Integer.parseUnsignedInt` refuses a minus sign.
        return !hex.starts_with('-')
            && u32::from_str_radix(hex, 16).is_ok_and(|value| value == key as u32);
    }
    let Some(binary) = constraint.strip_prefix("0b") else {
        return false;
    };
    // Compare the first 32 pattern characters against the key's bits, the
    // pattern right-aligned when it is shorter.
    let length = binary.chars().count();
    let padding = 32usize.saturating_sub(length);
    let bit = |i: usize| {
        if (key as u32 >> (31 - i)) & 1 == 1 {
            '1'
        } else {
            '0'
        }
    };
    (0..padding).all(|i| bit(i) == '0')
        && binary
            .chars()
            .take(32)
            .enumerate()
            .all(|(i, c)| c == '.' || c == bit(padding + i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_result_hash_matches_java() {
        // 31 + (31 * (31 + (31 + "gcc".hashCode())) + (31 + "x86:LE:32:default".hashCode()))
        let pair = LanguageCompilerSpecPair::from_strs("x86:LE:32:default", "gcc").unwrap();
        let expected = 31i32.wrapping_add(
            31i32
                .wrapping_mul(31 + 31 + 102_151)
                .wrapping_add(31 + 1_790_962_115),
        );
        assert_eq!(query_result_hash(&pair), expected);
    }

    #[test]
    fn displays_like_ghidra() {
        let pair = LanguageCompilerSpecPair::from_strs("x86:LE:32:default", "gcc").unwrap();
        assert_eq!(
            QueryResult {
                pair: pair.clone(),
                preferred: true
            }
            .to_string(),
            "query result: x86:LE:32:default:gcc (preferred)"
        );
        assert_eq!(
            QueryResult {
                pair,
                preferred: false
            }
            .to_string(),
            "query result: x86:LE:32:default:gcc (not preferred)"
        );
    }
}
