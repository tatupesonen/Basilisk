//! The two indexes of a factory, as hash maps keyed by a hash of what the
//! Ghidra comparator compares.
//!
//! Ghidra keeps `set<Datatype*, DatatypeCompare>` and
//! `set<Datatype*, DatatypeNameCompare>`. Its name set is only ever searched,
//! never walked, and its identity set is walked only by the rare operations
//! that list all types (`dependentOrder`, `encodeCoreTypes`,
//! `cacheCoreTypes`), which sort on demand here. Exact searches are hash
//! lookups that compare candidates through the arena, so a lookup needs no
//! throw-away key.

use rustc_hash::FxHashMap;

use crate::ids::TypeId;

/// The ids stored under one hash.
#[derive(Clone, Debug)]
enum Bucket {
    One(TypeId),
    Many(Vec<TypeId>),
}

/// A multimap from a 64-bit hash to type ids.
#[derive(Clone, Debug, Default)]
pub(crate) struct HashIndex {
    map: FxHashMap<u64, Bucket>,
}

impl HashIndex {
    /// The ids stored under `hash`.
    pub(crate) fn candidates(&self, hash: u64) -> &[TypeId] {
        match self.map.get(&hash) {
            None => &[],
            Some(Bucket::One(id)) => std::slice::from_ref(id),
            Some(Bucket::Many(ids)) => ids,
        }
    }

    pub(crate) fn insert(&mut self, hash: u64, id: TypeId) {
        match self.map.get_mut(&hash) {
            None => {
                self.map.insert(hash, Bucket::One(id));
            }
            Some(bucket) => match bucket {
                Bucket::One(first) => *bucket = Bucket::Many(vec![*first, id]),
                Bucket::Many(ids) => ids.push(id),
            },
        }
    }

    pub(crate) fn remove(&mut self, hash: u64, id: TypeId) {
        let Some(bucket) = self.map.get_mut(&hash) else {
            return;
        };
        match bucket {
            Bucket::One(only) => {
                if *only == id {
                    self.map.remove(&hash);
                }
            }
            Bucket::Many(ids) => {
                ids.retain(|&x| x != id);
                match ids.as_slice() {
                    [] => {
                        self.map.remove(&hash);
                    }
                    [only] => *bucket = Bucket::One(*only),
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }
}

/// Hash of a type name for the name index.
pub(crate) fn name_hash(name: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = rustc_hash::FxHasher::default();
    name.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_remove() {
        let mut idx = HashIndex::default();
        let (a, b) = (TypeId::from_raw(1), TypeId::from_raw(2));
        idx.insert(7, a);
        idx.insert(7, b);
        assert_eq!(idx.candidates(7), &[a, b]);
        idx.remove(7, a);
        assert_eq!(idx.candidates(7), &[b]);
        idx.remove(7, b);
        assert_eq!(idx.candidates(7), []);
        idx.remove(9, a);
    }
}
