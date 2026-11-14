//! The per-group consumption state of an assignment (Ghidra's
//! `vector<int4> status`): for each group, the number of slots used, or -1
//! when the group is fully consumed.
//!
//! Lists have a few dozen groups at most, so the state lives inline and an
//! assignment allocates nothing for it (ADR-012); larger lists fall back to
//! the heap.

const INLINE: usize = 48;

/// Consumption state indexed by group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    len: usize,
    inline: [i32; INLINE],
    heap: Vec<i32>,
}

impl Status {
    /// All `groups` groups free (Ghidra `allocateStatus`).
    pub fn new(groups: usize) -> Self {
        let heap = if groups > INLINE {
            vec![0; groups]
        } else {
            Vec::new()
        };
        Self {
            len: groups,
            inline: [0; INLINE],
            heap,
        }
    }

    fn slice(&self) -> &[i32] {
        if self.len > INLINE {
            &self.heap
        } else {
            self.inline.get(..self.len).unwrap_or(&[])
        }
    }

    fn slice_mut(&mut self) -> &mut [i32] {
        if self.len > INLINE {
            &mut self.heap
        } else {
            self.inline.get_mut(..self.len).unwrap_or(&mut [])
        }
    }

    /// The state of a group; a group outside the list reads as consumed.
    pub fn get(&self, group: i32) -> i32 {
        usize::try_from(group)
            .ok()
            .and_then(|g| self.slice().get(g))
            .copied()
            .unwrap_or(-1)
    }

    /// A mutable reference to a group's state, if the group exists.
    pub fn slot(&mut self, group: i32) -> Option<&mut i32> {
        usize::try_from(group)
            .ok()
            .and_then(|g| self.slice_mut().get_mut(g))
    }

    /// Sets a group's state; a group outside the list is ignored.
    pub fn set(&mut self, group: i32, value: i32) {
        if let Some(s) = self.slot(group) {
            *s = value;
        }
    }

    /// Number of groups.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether there are no groups.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The states in group order.
    pub fn as_slice(&self) -> &[i32] {
        self.slice()
    }
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn inline_and_heap_behave_alike() {
        for n in [0usize, 3, 48, 49, 100] {
            let mut s = Status::new(n);
            assert_eq!(s.len(), n);
            assert_eq!(s.get(-1), -1);
            assert_eq!(s.get(n as i32), -1);
            if n > 0 {
                s.set(n as i32 - 1, 7);
                assert_eq!(s.get(n as i32 - 1), 7);
                assert_eq!(s.as_slice().iter().sum::<i32>(), 7);
            }
            s.set(n as i32 + 5, 1);
        }
    }
}
