//! A map from split points to values, with a default before the first
//! split point (Ghidra `partmap`, `CPP/partmap.hh`).

use std::collections::BTreeMap;
use std::ops::Bound;

use bk_core::Address;

/// Values over the address line: the value at an address is that of the
/// last split point at or before it, or the default before the first.
#[derive(Clone, Debug, Default)]
pub(crate) struct PartMap<V> {
    default: V,
    points: BTreeMap<Address, V>,
}

/// Where an address sits between split points ([`PartMap::bounds`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// The split point at or before the address, if any.
    pub(crate) before: Option<Address>,
    /// The first split point after the address, if any.
    pub(crate) after: Option<Address>,
}

impl<V> PartMap<V> {
    pub(crate) fn new(default: V) -> Self {
        Self {
            default,
            points: BTreeMap::new(),
        }
    }

    pub(crate) fn default_value(&self) -> &V {
        &self.default
    }

    pub(crate) fn default_value_mut(&mut self) -> &mut V {
        &mut self.default
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// The value at `point` (Ghidra `getValue`).
    pub(crate) fn get(&self, point: Address) -> &V {
        self.points
            .range(..=point)
            .next_back()
            .map_or(&self.default, |(_, value)| value)
    }

    /// The value at `point` and the split points around it (Ghidra
    /// `bounds`).
    pub(crate) fn bounds(&self, point: Address) -> (&V, Bounds) {
        let before = self.points.range(..=point).next_back();
        let after = self
            .points
            .range((Bound::Excluded(point), Bound::Unbounded))
            .next()
            .map(|(key, _)| *key);
        let bounds = Bounds {
            before: before.map(|(key, _)| *key),
            after,
        };
        (before.map_or(&self.default, |(_, value)| value), bounds)
    }

    /// Introduces a split point at `point` whose value is `copy` of the value
    /// in force there; an existing split point is kept (Ghidra `split`).
    pub(crate) fn split_with(&mut self, point: Address, copy: impl Fn(&V) -> V) {
        if self.points.contains_key(&point) {
            return;
        }
        let value = copy(self.get(point));
        self.points.insert(point, value);
    }

    /// The split points from `first` (inclusive) to `end` (exclusive; to the
    /// end when `None`), in order.
    pub(crate) fn range_mut(
        &mut self,
        first: Address,
        end: Option<Address>,
    ) -> impl Iterator<Item = (&Address, &mut V)> {
        let upper = end.map_or(Bound::Unbounded, Bound::Excluded);
        let lower = Bound::Included(first);
        let empty = end.is_some_and(|end| end <= first);
        self.points
            .range_mut((lower, if empty { Bound::Included(first) } else { upper }))
            .take_while(move |_| !empty)
    }

    /// Removes the split points strictly between `first` and `end` after
    /// splitting at both, and returns the value at `first` (Ghidra
    /// `clearRange`).
    pub(crate) fn clear_range(
        &mut self,
        first: Address,
        end: Address,
        copy: impl Fn(&V) -> V,
    ) -> Option<&mut V> {
        self.split_with(first, &copy);
        self.split_with(end, &copy);
        let doomed: Vec<Address> = self
            .points
            .range((Bound::Excluded(first), Bound::Excluded(end)))
            .map(|(key, _)| *key)
            .collect();
        for key in doomed {
            self.points.remove(&key);
        }
        self.points.get_mut(&first)
    }

    /// The split points in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Address, &V)> {
        self.points.iter()
    }
}

#[cfg(test)]
mod tests {
    use bk_core::SpaceId;

    use super::*;

    fn at(offset: u64) -> Address {
        Address::new(SpaceId::new(1), offset)
    }

    #[test]
    fn matches_the_example_in_partmap_hh() {
        let mut map = PartMap::new(0u32);
        map.split_with(at(5), |v| *v);
        *map.range_mut(at(5), Some(at(6))).next().unwrap().1 = 5;
        map.split_with(at(2), |v| *v);
        *map.range_mut(at(2), Some(at(3))).next().unwrap().1 = 2;
        map.split_with(at(3), |v| *v);
        *map.range_mut(at(3), Some(at(4))).next().unwrap().1 = 3;
        assert_eq!(*map.get(at(6)), 5);
        assert_eq!(*map.get(at(8)), 5);
        assert_eq!(*map.get(at(4)), 3);
        assert_eq!(*map.get(at(1)), 0);
        let from3: Vec<u32> = map.range_mut(at(3), None).map(|(_, v)| *v).collect();
        assert_eq!(from3, [3, 5]);
        let (value, bounds) = map.bounds(at(4));
        assert_eq!(*value, 3);
        assert_eq!(bounds.before, Some(at(3)));
        assert_eq!(bounds.after, Some(at(5)));
        let (value, bounds) = map.bounds(at(0));
        assert_eq!((*value, bounds.before), (0, None));
    }

    #[test]
    fn clear_range_keeps_the_ends() {
        let mut map = PartMap::new(0u32);
        for offset in [2, 4, 6, 8] {
            map.split_with(at(offset), |_| offset as u32);
        }
        let first = map.clear_range(at(3), at(7), |v| *v).unwrap();
        *first = 99;
        let keys: Vec<u64> = map.iter().map(|(k, _)| k.offset()).collect();
        assert_eq!(keys, [2, 3, 7, 8]);
        assert_eq!(*map.get(at(5)), 99);
        assert_eq!(*map.get(at(7)), 6);
        assert!(map.range_mut(at(5), Some(at(5))).next().is_none());
    }
}
