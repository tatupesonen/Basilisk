//! Short id lists stored inline, spilling into a shared pool.
//!
//! An op's inputs and a varnode's readers are usually at most three ids.
//! [`IdList`] keeps up to three inline (16 bytes) and moves longer lists into
//! a slot of the function's [`Pool`], so the hot structs stay small and the
//! common case allocates nothing. Order is always preserved.

/// The most ids kept inline.
const INLINE: usize = 3;

/// A list of raw ids: inline when it holds at most three, otherwise in a
/// pool slot whose index is `data[0]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IdList {
    len: u32,
    data: [u32; INLINE],
}

/// Spilled lists, with reuse of released slots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Pool {
    slots: Vec<Vec<u32>>,
    free: Vec<u32>,
}

impl Pool {
    fn take_slot(&mut self) -> u32 {
        if let Some(slot) = self.free.pop() {
            return slot;
        }
        self.slots.push(Vec::new());
        (self.slots.len() - 1) as u32
    }

    fn release(&mut self, slot: u32) {
        if let Some(v) = self.slots.get_mut(slot as usize) {
            v.clear();
            self.free.push(slot);
        }
    }

    fn get(&self, slot: u32) -> &[u32] {
        self.slots.get(slot as usize).map_or(&[], Vec::as_slice)
    }

    fn get_mut(&mut self, slot: u32) -> Option<&mut Vec<u32>> {
        self.slots.get_mut(slot as usize)
    }

    /// Bytes held by spilled lists (for the size report).
    pub(crate) fn heap_bytes(&self) -> usize {
        self.slots.iter().map(|v| v.capacity() * 4).sum::<usize>() + self.slots.capacity() * 24
    }
}

impl IdList {
    /// The number of ids.
    pub(crate) const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the list is empty.
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    const fn spilled(&self) -> bool {
        self.len as usize > INLINE
    }

    /// The ids in order.
    pub(crate) fn as_slice<'a>(&'a self, pool: &'a Pool) -> &'a [u32] {
        if self.spilled() {
            pool.get(self.data[0])
        } else {
            self.data.get(..self.len as usize).unwrap_or(&[])
        }
    }

    /// The id at `i`.
    pub(crate) fn get(&self, pool: &Pool, i: usize) -> Option<u32> {
        self.as_slice(pool).get(i).copied()
    }

    fn rebuild(&mut self, pool: &mut Pool, ids: &[u32]) {
        self.clear(pool);
        if ids.len() <= INLINE {
            for (slot, &v) in self.data.iter_mut().zip(ids) {
                *slot = v;
            }
        } else {
            let slot = pool.take_slot();
            if let Some(v) = pool.get_mut(slot) {
                v.extend_from_slice(ids);
            }
            self.data = [slot, 0, 0];
        }
        self.len = ids.len() as u32;
    }

    /// Appends `v`.
    pub(crate) fn push(&mut self, pool: &mut Pool, v: u32) {
        let n = self.len as usize;
        match n.cmp(&INLINE) {
            std::cmp::Ordering::Less => {
                if let Some(slot) = self.data.get_mut(n) {
                    *slot = v;
                }
                self.len += 1;
            }
            std::cmp::Ordering::Equal => {
                let mut ids = self.data.to_vec();
                ids.push(v);
                self.rebuild(pool, &ids);
            }
            std::cmp::Ordering::Greater => {
                if let Some(list) = pool.get_mut(self.data[0]) {
                    list.push(v);
                }
                self.len += 1;
            }
        }
    }

    /// Replaces the id at `i`; out of range does nothing and returns false.
    pub(crate) fn set(&mut self, pool: &mut Pool, i: usize, v: u32) -> bool {
        if i >= self.len as usize {
            return false;
        }
        if self.spilled() {
            if let Some(slot) = pool.get_mut(self.data[0]).and_then(|l| l.get_mut(i)) {
                *slot = v;
                return true;
            }
            false
        } else if let Some(slot) = self.data.get_mut(i) {
            *slot = v;
            true
        } else {
            false
        }
    }

    /// Removes the id at `i`, keeping the order of the rest.
    pub(crate) fn remove(&mut self, pool: &mut Pool, i: usize) -> bool {
        if i >= self.len as usize {
            return false;
        }
        let mut ids = self.as_slice(pool).to_vec();
        ids.remove(i);
        if self.spilled() && ids.len() > INLINE {
            if let Some(list) = pool.get_mut(self.data[0]) {
                list.remove(i);
            }
            self.len -= 1;
        } else {
            self.rebuild(pool, &ids);
        }
        true
    }

    /// Inserts `v` before position `i` (`i == len` appends).
    pub(crate) fn insert(&mut self, pool: &mut Pool, i: usize, v: u32) -> bool {
        if i > self.len as usize {
            return false;
        }
        let mut ids = self.as_slice(pool).to_vec();
        ids.insert(i, v);
        self.rebuild(pool, &ids);
        true
    }

    /// Makes the list `n` copies of `fill`.
    pub(crate) fn reset(&mut self, pool: &mut Pool, n: usize, fill: u32) {
        let ids = vec![fill; n];
        self.rebuild(pool, &ids);
    }

    /// Replaces the list with `ids`.
    pub(crate) fn assign(&mut self, pool: &mut Pool, ids: &[u32]) {
        self.rebuild(pool, ids);
    }

    /// Empties the list, releasing any pool slot.
    pub(crate) fn clear(&mut self, pool: &mut Pool) {
        if self.spilled() {
            pool.release(self.data[0]);
        }
        self.len = 0;
        self.data = [0; INLINE];
    }

    /// The position of the first occurrence of `v`.
    pub(crate) fn position(&self, pool: &Pool, v: u32) -> Option<usize> {
        self.as_slice(pool).iter().position(|&x| x == v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_spill_and_come_back_inline() {
        let mut pool = Pool::default();
        let mut l = IdList::default();
        for v in 0..6 {
            l.push(&mut pool, v);
        }
        assert_eq!(l.as_slice(&pool), [0, 1, 2, 3, 4, 5]);
        assert!(l.remove(&mut pool, 1));
        assert!(l.remove(&mut pool, 1));
        assert_eq!(l.as_slice(&pool), [0, 3, 4, 5]);
        assert!(l.remove(&mut pool, 0));
        assert_eq!(l.as_slice(&pool), [3, 4, 5]);
        assert!(!l.spilled());
        assert!(l.insert(&mut pool, 0, 9));
        assert_eq!(l.as_slice(&pool), [9, 3, 4, 5]);
        assert!(l.set(&mut pool, 3, 7));
        assert_eq!(l.position(&pool, 7), Some(3));
        l.reset(&mut pool, 2, 1);
        assert_eq!(l.as_slice(&pool), [1, 1]);
        assert!(!l.remove(&mut pool, 5));
        assert_eq!(pool.free.len(), 1, "the slot is reused, not leaked");
    }
}
