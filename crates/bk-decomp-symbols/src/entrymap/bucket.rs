//! The fragments of one key, in multiset order, without an allocation for
//! the common single fragment.

use std::slice;

/// Fragment ids sharing one `(last, subsort)` key, in multiset order.
#[derive(Clone, Debug, Default)]
pub(super) enum Bucket {
    /// No fragment (only transiently, while a bucket is being filled).
    #[default]
    Empty,
    /// One fragment.
    One(u32),
    /// Two or more fragments.
    Many(Vec<u32>),
}

impl Bucket {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::One(_) => 1,
            Self::Many(ids) => ids.len(),
        }
    }

    pub(super) fn as_slice(&self) -> &[u32] {
        match self {
            Self::Empty => &[],
            Self::One(id) => slice::from_ref(id),
            Self::Many(ids) => ids,
        }
    }

    pub(super) fn get(&self, idx: usize) -> Option<u32> {
        self.as_slice().get(idx).copied()
    }

    pub(super) fn position(&self, id: u32) -> Option<usize> {
        self.as_slice().iter().position(|&x| x == id)
    }

    /// Inserts `id` at `idx` (clamped to the length).
    pub(super) fn insert(&mut self, idx: usize, id: u32) {
        match self {
            Self::Empty => *self = Self::One(id),
            Self::One(old) => {
                let old = *old;
                *self = Self::Many(if idx == 0 {
                    vec![id, old]
                } else {
                    vec![old, id]
                });
            }
            Self::Many(ids) => {
                let idx = idx.min(ids.len());
                ids.insert(idx, id);
            }
        }
    }

    /// Removes and returns the id at `idx`.
    pub(super) fn remove(&mut self, idx: usize) -> Option<u32> {
        match self {
            Self::Empty => None,
            Self::One(id) => {
                if idx != 0 {
                    return None;
                }
                let id = *id;
                *self = Self::Empty;
                Some(id)
            }
            Self::Many(ids) => {
                if idx >= ids.len() {
                    return None;
                }
                let id = ids.remove(idx);
                if let [last] = ids[..] {
                    *self = Self::One(last);
                }
                Some(id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Bucket;

    #[test]
    fn insert_and_remove_keep_order() {
        let mut b = Bucket::default();
        b.insert(0, 1);
        b.insert(0, 2);
        b.insert(9, 3);
        b.insert(1, 4);
        assert_eq!(b.as_slice(), [2, 4, 1, 3]);
        assert_eq!(b.position(1), Some(2));
        assert_eq!(b.remove(1), Some(4));
        assert_eq!(b.remove(7), None);
        assert_eq!(b.remove(0), Some(2));
        assert_eq!(b.remove(1), Some(3));
        assert!(matches!(b, Bucket::One(1)));
        assert_eq!(b.remove(1), None);
        assert_eq!(b.remove(0), Some(1));
        assert_eq!(b.len(), 0);
        assert_eq!(b.get(0), None);
        let mut one = Bucket::One(5);
        one.insert(1, 6);
        assert_eq!(one.as_slice(), [5, 6]);
    }
}
