//! Intrusive doubly linked lists of ops (Ghidra's `std::list<PcodeOp *>`
//! members with iterators stored in the op).
//!
//! Each op has three link pairs: its basic block's op list, the alive/dead
//! list, and the per-opcode list. Links are op indices; removal is O(1) and
//! allocates nothing. A list is a head, a tail and a length.

use crate::ids::{NONE, OpId};

/// Which link pair of an op a list threads through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Thread {
    /// A basic block's op list.
    Block,
    /// `alivelist` / `deadlist`.
    Life,
    /// `storelist`, `loadlist`, `returnlist`, `useroplist`.
    Code,
}

/// The link fields of one op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpLinks {
    links: [[u32; 2]; 3],
    /// The opcode list the op is in (`CodeList` as `u8`, 0 for none).
    pub(crate) code_list: u8,
}

impl Default for OpLinks {
    fn default() -> Self {
        Self {
            links: [[NONE; 2]; 3],
            code_list: 0,
        }
    }
}

const fn t(thread: Thread) -> usize {
    match thread {
        Thread::Block => 0,
        Thread::Life => 1,
        Thread::Code => 2,
    }
}

impl OpLinks {
    /// The previous op on `thread`.
    pub(crate) fn prev(&self, thread: Thread) -> Option<OpId> {
        self.links
            .get(t(thread))
            .and_then(|l| OpId::from_packed(l[0]))
    }

    /// The next op on `thread`.
    pub(crate) fn next(&self, thread: Thread) -> Option<OpId> {
        self.links
            .get(t(thread))
            .and_then(|l| OpId::from_packed(l[1]))
    }

    fn set(&mut self, thread: Thread, prev: u32, next: u32) {
        if let Some(l) = self.links.get_mut(t(thread)) {
            *l = [prev, next];
        }
    }

    fn set_prev(&mut self, thread: Thread, prev: u32) {
        if let Some(l) = self.links.get_mut(t(thread)) {
            l[0] = prev;
        }
    }

    fn set_next(&mut self, thread: Thread, next: u32) {
        if let Some(l) = self.links.get_mut(t(thread)) {
            l[1] = next;
        }
    }
}

/// A list's ends and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ListHead {
    head: u32,
    tail: u32,
    len: u32,
}

impl Default for ListHead {
    fn default() -> Self {
        Self {
            head: NONE,
            tail: NONE,
            len: 0,
        }
    }
}

impl ListHead {
    /// The first op.
    pub(crate) fn first(&self) -> Option<OpId> {
        OpId::from_packed(self.head)
    }

    /// The last op.
    pub(crate) fn last(&self) -> Option<OpId> {
        OpId::from_packed(self.tail)
    }

    /// The number of ops.
    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    /// Inserts `op` before `before` (`None`: at the end). The caller
    /// guarantees `op` is in no list of this thread and `before` is in this
    /// list.
    pub(crate) fn insert_before(
        &mut self,
        links: &mut [OpLinks],
        thread: Thread,
        op: OpId,
        before: Option<OpId>,
    ) {
        let (prev, next) = match before {
            None => (self.tail, NONE),
            Some(b) => (
                links
                    .get(b.index())
                    .and_then(|l| l.prev(thread))
                    .map_or(NONE, OpId::get),
                b.get(),
            ),
        };
        if let Some(l) = links.get_mut(op.index()) {
            l.set(thread, prev, next);
        }
        match OpId::from_packed(prev) {
            Some(p) => {
                if let Some(l) = links.get_mut(p.index()) {
                    l.set_next(thread, op.get());
                }
            }
            None => self.head = op.get(),
        }
        match OpId::from_packed(next) {
            Some(n) => {
                if let Some(l) = links.get_mut(n.index()) {
                    l.set_prev(thread, op.get());
                }
            }
            None => self.tail = op.get(),
        }
        self.len += 1;
    }

    /// Appends `op`.
    pub(crate) fn push_back(&mut self, links: &mut [OpLinks], thread: Thread, op: OpId) {
        self.insert_before(links, thread, op, None);
    }

    /// Unlinks `op`, which the caller guarantees is in this list.
    pub(crate) fn remove(&mut self, links: &mut [OpLinks], thread: Thread, op: OpId) {
        let Some(l) = links.get(op.index()).copied() else {
            return;
        };
        let prev = l.prev(thread);
        let next = l.next(thread);
        match prev {
            Some(p) => {
                if let Some(pl) = links.get_mut(p.index()) {
                    pl.set_next(thread, next.map_or(NONE, OpId::get));
                }
            }
            None => self.head = next.map_or(NONE, OpId::get),
        }
        match next {
            Some(n) => {
                if let Some(nl) = links.get_mut(n.index()) {
                    nl.set_prev(thread, prev.map_or(NONE, OpId::get));
                }
            }
            None => self.tail = prev.map_or(NONE, OpId::get),
        }
        if let Some(ol) = links.get_mut(op.index()) {
            ol.set(thread, NONE, NONE);
        }
        self.len = self.len.saturating_sub(1);
    }

    /// The ops in order, bounded by the list's length (a corrupted link
    /// cannot make the walk endless).
    pub(crate) fn collect(&self, links: &[OpLinks], thread: Thread) -> Vec<OpId> {
        self.iter(links, thread).collect()
    }

    /// The ops in order without allocating, bounded like [`Self::collect`].
    pub(crate) fn iter<'a>(&self, links: &'a [OpLinks], thread: Thread) -> OpIter<'a> {
        OpIter {
            links,
            thread,
            cur: self.first(),
            left: self.len as usize,
        }
    }
}

/// The ops of one intrusive list in order (a borrowed walk; see
/// [`ListHead::iter`]).
#[derive(Clone, Debug)]
pub struct OpIter<'a> {
    links: &'a [OpLinks],
    thread: Thread,
    cur: Option<OpId>,
    left: usize,
}

impl Iterator for OpIter<'_> {
    type Item = OpId;

    fn next(&mut self) -> Option<OpId> {
        if self.left == 0 {
            return None;
        }
        let op = self.cur?;
        self.left -= 1;
        self.cur = self.links.get(op.index()).and_then(|l| l.next(self.thread));
        Some(op)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.left))
    }
}

impl std::iter::FusedIterator for OpIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_remove_keep_order() {
        let mut links = vec![OpLinks::default(); 5];
        let mut h = ListHead::default();
        for i in 0..3 {
            h.push_back(&mut links, Thread::Life, OpId::new(i));
        }
        h.insert_before(&mut links, Thread::Life, OpId::new(3), Some(OpId::new(1)));
        h.insert_before(&mut links, Thread::Life, OpId::new(4), Some(OpId::new(0)));
        let ids = |h: &ListHead, links: &[OpLinks]| {
            h.collect(links, Thread::Life)
                .iter()
                .map(|o| o.get())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&h, &links), [4, 0, 3, 1, 2]);
        h.remove(&mut links, Thread::Life, OpId::new(4));
        h.remove(&mut links, Thread::Life, OpId::new(2));
        h.remove(&mut links, Thread::Life, OpId::new(3));
        assert_eq!(ids(&h, &links), [0, 1]);
        assert_eq!(h.last(), Some(OpId::new(1)));
        assert_eq!(h.len(), 2);
    }
}
