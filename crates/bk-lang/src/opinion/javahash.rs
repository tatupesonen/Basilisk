//! Java's `String.hashCode` and the iteration order of `java.util.HashMap`.
//!
//! Ghidra keeps opinion query results in `HashSet`s and returns them in the
//! set's iteration order, so the order loaders see — and with it which of
//! several preferred results comes first — is a function of Java's hash
//! codes and of `HashMap`'s table layout. No crate reproduces that layout,
//! and matching Ghidra's order is this crate's contract, so the part of
//! `HashMap` that determines it is restated here: hash spreading,
//! power-of-two tables that double at a 0.75 load factor (or when a bin
//! outgrows eight nodes in a table smaller than 64), and insertion order
//! within a bin.

/// `String.hashCode()`: `s[0]*31^(n-1) + … + s[n-1]` over UTF-16 code units.
pub(crate) fn string_hash(text: &str) -> i32 {
    text.encode_utf16().fold(0i32, |h, unit| {
        h.wrapping_mul(31).wrapping_add(i32::from(unit))
    })
}

/// A key with a Java `hashCode()`.
pub(crate) trait JavaHash {
    /// The value Java's `hashCode()` returns for this key.
    fn java_hash(&self) -> i32;
}

impl JavaHash for Option<Box<str>> {
    /// `HashMap` hashes a `null` key to 0 and a string to its hash code.
    fn java_hash(&self) -> i32 {
        self.as_deref().map_or(0, string_hash)
    }
}

const INITIAL_CAPACITY: usize = 16;
const TREEIFY_THRESHOLD: usize = 8;
const MIN_TREEIFY_CAPACITY: usize = 64;

/// A map that iterates in the order `java.util.HashMap` would after the
/// same sequence of insertions.
#[derive(Debug, Clone)]
pub(crate) struct JavaHashMap<K, V> {
    /// Entries in insertion order, with their spread hash.
    entries: Vec<(u32, K, V)>,
    /// The bins: indices into `entries`, in insertion order.
    table: Vec<Vec<u32>>,
    /// Whether Java would have turned a bin into a tree, after which the
    /// order within that bin is no longer insertion order.
    treeified: bool,
}

impl<K, V> Default for JavaHashMap<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            table: Vec::new(),
            treeified: false,
        }
    }
}

impl<K: JavaHash, V> JavaHashMap<K, V> {
    /// `HashMap.hash`: the high half of the hash code folded into the low.
    fn spread(hash: i32) -> u32 {
        let h = hash as u32;
        h ^ (h >> 16)
    }

    fn bin(&self, hash: u32) -> Option<&Vec<u32>> {
        let mask = self.table.len().checked_sub(1)?;
        self.table.get(hash as usize & mask)
    }

    fn position(&self, hash: i32, matches: impl Fn(&K) -> bool) -> Option<usize> {
        let spread = Self::spread(hash);
        self.bin(spread)?.iter().map(|&i| i as usize).find(|&i| {
            self.entries
                .get(i)
                .is_some_and(|(h, k, _)| *h == spread && matches(k))
        })
    }

    /// The value whose key has hash code `hash` and satisfies `matches`.
    pub(crate) fn get_by(&self, hash: i32, matches: impl Fn(&K) -> bool) -> Option<&V> {
        let index = self.position(hash, matches)?;
        self.entries.get(index).map(|(_, _, v)| v)
    }

    fn resize(&mut self) {
        let capacity = (self.table.len() * 2).max(INITIAL_CAPACITY);
        let mut table = vec![Vec::new(); capacity];
        // Java splits each bin preserving relative order, so every bin of
        // the new table holds its entries in insertion order.
        for (index, (hash, _, _)) in self.entries.iter().enumerate() {
            if let Some(bin) = table.get_mut(*hash as usize & (capacity - 1)) {
                bin.push(index as u32);
            }
        }
        self.table = table;
    }

    /// The entries in `HashMap` iteration order: bin by bin.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.table
            .iter()
            .flatten()
            .filter_map(|&i| self.entries.get(i as usize))
            .map(|(_, k, v)| (k, v))
    }

    /// The number of entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the iteration order is certain to be Java's (no bin grew
    /// large enough for Java to turn it into a tree).
    pub(crate) fn order_is_exact(&self) -> bool {
        !self.treeified
    }
}

impl<K: JavaHash + Eq, V> JavaHashMap<K, V> {
    /// The value for `key`, inserting `make()` first if the key is absent
    /// (`HashMap.get` followed by `put` on a miss).
    pub(crate) fn get_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> &mut V {
        let hash = key.java_hash();
        let index = match self.position(hash, |k| *k == key) {
            Some(index) => index,
            None => self.push(hash, key, make()),
        };
        #[expect(clippy::indexing_slicing, reason = "index was just found or pushed")]
        &mut self.entries[index].2
    }

    /// Adds `key` with `value` unless the key is present (`HashSet.add`:
    /// the first of two equal elements stays). Returns whether it was
    /// added.
    pub(crate) fn insert_if_absent(&mut self, key: K, value: V) -> bool {
        let hash = key.java_hash();
        if self.position(hash, |k| *k == key).is_some() {
            return false;
        }
        self.push(hash, key, value);
        true
    }

    /// Appends a new entry as `HashMap.putVal` does and returns its index.
    fn push(&mut self, hash: i32, key: K, value: V) -> usize {
        if self.table.is_empty() {
            self.resize();
        }
        let spread = Self::spread(hash);
        let index = self.entries.len();
        self.entries.push((spread, key, value));
        let mask = self.table.len() - 1;
        let mut overfull = false;
        if let Some(bin) = self.table.get_mut(spread as usize & mask) {
            overfull = bin.len() >= TREEIFY_THRESHOLD;
            bin.push(index as u32);
        }
        if overfull {
            if self.table.len() < MIN_TREEIFY_CAPACITY {
                self.resize();
            } else {
                self.treeified = true;
            }
        }
        // The load factor is 0.75.
        if self.entries.len() * 4 > self.table.len() * 3 {
            self.resize();
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Key(i32);
    impl JavaHash for Key {
        fn java_hash(&self) -> i32 {
            self.0
        }
    }

    fn order(map: &JavaHashMap<Key, ()>) -> Vec<i32> {
        map.iter().map(|(k, ())| k.0).collect()
    }

    fn set(keys: &[i32]) -> JavaHashMap<Key, ()> {
        let mut map = JavaHashMap::default();
        for &k in keys {
            map.insert_if_absent(Key(k), ());
        }
        map
    }

    #[test]
    fn string_hash_matches_java() {
        // Values printed by `"…".hashCode()` on OpenJDK 25.
        assert_eq!(string_hash(""), 0);
        assert_eq!(string_hash("a"), 97);
        assert_eq!(string_hash("gcc"), 102_151);
        assert_eq!(string_hash("default"), 1_544_803_905);
        assert_eq!(string_hash("x86:LE:32:default"), 1_790_962_115);
        assert_eq!(string_hash("windows"), 1_349_493_379);
        // Outside the BMP a character is two UTF-16 code units.
        assert_eq!(string_hash("\u{1F600}"), 1_772_899);
    }

    #[test]
    fn iterates_by_bin_then_insertion_order() {
        // 16 bins: 17 and 1 share bin 1, 33 too; 2 is in bin 2; 16 in bin 0.
        assert_eq!(order(&set(&[33, 2, 17, 16, 1])), vec![16, 33, 17, 1, 2]);
    }

    #[test]
    fn grows_at_three_quarters_full() {
        // Twelve entries fit a 16-bin table; the thirteenth doubles it, so
        // 16 moves from bin 0 to bin 16 and sorts after 12.
        let twelve: Vec<i32> = (5..=16).collect();
        assert_eq!(
            order(&set(&twelve)),
            vec![16, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        let thirteen: Vec<i32> = (5..=17).collect();
        assert_eq!(order(&set(&thirteen)), (5..=17).collect::<Vec<_>>());
    }

    #[test]
    fn spreads_high_bits_into_the_bin_index() {
        // 0x10000 spreads to 0x10001: bin 1, not bin 0.
        assert_eq!(order(&set(&[2, 0x1_0000, 0])), vec![0, 0x1_0000, 2]);
    }

    #[test]
    fn a_ninth_node_in_one_bin_of_a_small_table_doubles_it() {
        // Multiples of 64 share a bin until the table has more than 64
        // bins. The ninth forces 16 -> 32, the tenth 32 -> 64, and the
        // eleventh would make Java build a tree.
        let nine: Vec<i32> = (0..9).map(|i| i * 64).collect();
        let map = set(&nine);
        assert_eq!(map.table.len(), 32);
        assert!(map.order_is_exact());
        let ten: Vec<i32> = (0..10).map(|i| i * 64).collect();
        let map = set(&ten);
        assert_eq!(map.table.len(), 64);
        assert_eq!(order(&map), ten);
        assert!(map.order_is_exact());
        let eleven: Vec<i32> = (0..11).map(|i| i * 64).collect();
        assert!(!set(&eleven).order_is_exact());
    }

    #[test]
    fn first_of_equal_keys_stays() {
        let mut map = JavaHashMap::default();
        assert!(map.insert_if_absent(Key(7), "first"));
        assert!(!map.insert_if_absent(Key(7), "second"));
        assert_eq!(map.get_by(7, |k| k.0 == 7), Some(&"first"));
        assert_eq!(map.len(), 1);
        *map.get_or_insert_with(Key(7), || "third") = "changed";
        *map.get_or_insert_with(Key(8), || "new") = "eight";
        assert_eq!(map.get_by(7, |k| k.0 == 7), Some(&"changed"));
        assert_eq!(map.get_by(8, |k| k.0 == 8), Some(&"eight"));
        assert_eq!(map.get_by(9, |k| k.0 == 9), None);
    }

    #[test]
    fn string_keys_iterate_as_in_java() {
        // Order printed by OpenJDK 25 for a `HashMap<String, Integer>`
        // filled with these keys (null first) in this order.
        let keys = [
            None,
            Some("0b 00.. ..00 .... .... 00.1 0.0. 0000 ...."),
            Some("1"),
            Some("0x55"),
            Some("8,10"),
            Some("3"),
            Some("62"),
            Some("40"),
            Some("183"),
            Some("20"),
            Some("21"),
        ];
        let mut map: JavaHashMap<Option<Box<str>>, usize> = JavaHashMap::default();
        for (i, key) in keys.iter().enumerate() {
            map.insert_if_absent(key.map(Box::from), i);
        }
        let order: Vec<usize> = map.iter().map(|(_, i)| *i).collect();
        assert_eq!(order, vec![0, 2, 5, 1, 4, 6, 7, 8, 9, 3, 10]);
    }

    #[test]
    fn null_key_hashes_to_zero() {
        assert_eq!(None::<Box<str>>.java_hash(), 0);
        assert_eq!(Some(Box::<str>::from("gcc")).java_hash(), 102_151);
    }
}
