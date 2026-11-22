//! A literal transliteration of Ghidra's `rangemap.hh` over a `Vec`, with
//! libstdc++'s `multiset` insertion algorithm (`_M_insert_equal`,
//! `_M_get_insert_hint_equal_pos`) written out. It is slow and obvious; the
//! property tests require `EntryMap` to agree with it exactly (fragment
//! order, duplicates and record order included).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MFrag {
    pub first: u64,
    pub last: u64,
    pub a: u64,
    pub b: u64,
    pub sub: (u32, u64),
    pub rec: usize,
}

impl MFrag {
    fn key(&self) -> (u64, (u32, u64)) {
        (self.last, self.sub)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Model {
    /// Fragments in multiset order.
    pub tree: Vec<MFrag>,
    /// Record ids in list order.
    pub list: Vec<usize>,
    /// Per record id: (a, b, sub, live).
    pub recs: Vec<(u64, u64, (u32, u64), bool)>,
}

pub const EARLIEST: (u32, u64) = (0, 0);
pub const LATEST: (u32, u64) = (u32::MAX, u64::MAX);

impl Model {
    fn lower_bound(&self, key: (u64, (u32, u64))) -> usize {
        self.tree
            .iter()
            .position(|f| f.key() >= key)
            .unwrap_or(self.tree.len())
    }

    fn upper_bound(&self, key: (u64, (u32, u64))) -> usize {
        self.tree
            .iter()
            .position(|f| f.key() > key)
            .unwrap_or(self.tree.len())
    }

    /// `multiset::insert(t)`: after every equal element. Returns the index.
    fn insert_plain(&mut self, t: MFrag) -> usize {
        let i = self.upper_bound(t.key());
        self.tree.insert(i, t);
        i
    }

    /// `multiset::insert(hint, t)` as libstdc++ does it. Returns the index.
    #[expect(clippy::nonminimal_bool, reason = "written as libstdc++ writes it")]
    fn insert_hint(&mut self, hint: usize, t: MFrag) -> usize {
        let len = self.tree.len();
        let k = t.key();
        let i = if hint == len {
            if len > 0 && !(k < self.tree[len - 1].key()) {
                len
            } else {
                self.upper_bound(k)
            }
        } else if !(self.tree[hint].key() < k) {
            if hint == 0 {
                0
            } else if !(k < self.tree[hint - 1].key()) {
                hint
            } else {
                self.upper_bound(k)
            }
        } else if hint == len - 1 {
            len
        } else if !(self.tree[hint + 1].key() < k) {
            hint + 1
        } else {
            self.lower_bound(k)
        };
        self.tree.insert(i, t);
        i
    }

    fn unzip(&mut self, i: u64, mut iter: usize) {
        let hint_frag = self.tree[iter];
        if hint_frag.last == i {
            return;
        }
        let mut hint = iter;
        let plus1 = i.wrapping_add(1);
        while iter < self.tree.len() && self.tree[iter].first <= i {
            let f = self.tree[iter].first;
            self.tree[iter].first = plus1;
            let copy = MFrag {
                first: f,
                last: i,
                ..self.tree[iter]
            };
            let at = self.insert_hint(hint, copy);
            if at <= hint {
                hint += 1;
            }
            if at <= iter {
                iter += 1;
            }
            iter += 1;
        }
    }

    fn zip(&mut self, i: u64, mut iter: usize) {
        if iter >= self.tree.len() {
            return;
        }
        let f = self.tree[iter].first;
        while iter < self.tree.len() && self.tree[iter].last == i {
            self.tree.remove(iter);
        }
        let plus1 = i.wrapping_add(1);
        while iter < self.tree.len() && self.tree[iter].first == plus1 {
            self.tree[iter].first = f;
            iter += 1;
        }
    }

    pub fn insert(&mut self, a: u64, b: u64, sub: (u32, u64)) -> usize {
        let rec = self.recs.len();
        self.recs.push((a, b, sub, true));
        let mut f = a;
        let mut low = self.lower_bound((f, EARLIEST));
        if low < self.tree.len() && self.tree[low].first < f {
            let before = self.tree.len();
            self.unzip(f.wrapping_sub(1), low);
            // Copies go before `low`'s piece.
            low += self.tree.len() - before;
        }
        let spot = self.lower_bound((b, sub));
        if spot == self.tree.len() {
            self.list.push(rec);
        } else {
            let target = self.tree[spot].rec;
            let at = self.list.iter().position(|&r| r == target).unwrap();
            self.list.insert(at, rec);
        }
        let proto = MFrag {
            first: f,
            last: b,
            a,
            b,
            sub,
            rec,
        };
        while low < self.tree.len() && self.tree[low].first <= b {
            let cur = self.tree[low];
            if f <= cur.last {
                if f < cur.first {
                    let at = self.insert_hint(
                        low,
                        MFrag {
                            first: f,
                            last: cur.first.wrapping_sub(1),
                            ..proto
                        },
                    );
                    if at <= low {
                        low += 1;
                    }
                    f = cur.first;
                }
                if cur.last <= b {
                    let at = self.insert_hint(
                        low,
                        MFrag {
                            first: f,
                            last: cur.last,
                            ..proto
                        },
                    );
                    if at <= low {
                        low += 1;
                    }
                    if cur.last == b {
                        break;
                    }
                    f = cur.last.wrapping_add(1);
                } else {
                    self.unzip(b, low);
                    break;
                }
            }
            low += 1;
        }
        if f <= b {
            self.insert_plain(MFrag {
                first: f,
                last: b,
                ..proto
            });
        }
        rec
    }

    pub fn erase(&mut self, rec: usize) {
        let (a, b, _, live) = self.recs[rec];
        assert!(live);
        let mut leftsew = true;
        let mut rightsew = true;
        let mut leftoverlap = false;
        let mut rightoverlap = false;
        let mut low = self.lower_bound((a, EARLIEST));
        let aminus1 = a.wrapping_sub(1);
        let mut uplow = low;
        while uplow != 0 {
            uplow -= 1;
            if self.tree[uplow].last != aminus1 {
                break;
            }
            if self.tree[uplow].b == aminus1 {
                leftsew = false;
                break;
            }
        }
        loop {
            if self.tree[low].rec == rec {
                self.tree.remove(low);
            } else {
                let fr = self.tree[low];
                if fr.a < a {
                    leftoverlap = true;
                } else if fr.a == a {
                    leftsew = false;
                }
                if b < fr.b {
                    rightoverlap = true;
                } else if fr.b == b {
                    rightsew = false;
                }
                low += 1;
            }
            if !(low < self.tree.len() && self.tree[low].first <= b) {
                break;
            }
        }
        if low < self.tree.len() && self.tree[low].a.wrapping_sub(1) == b {
            rightsew = false;
        }
        if leftsew && leftoverlap {
            let at = self.lower_bound((aminus1, EARLIEST));
            self.zip(aminus1, at);
        }
        if rightsew && rightoverlap {
            let at = self.lower_bound((b, EARLIEST));
            self.zip(b, at);
        }
        // Basilisk's definition of Ghidra's dangling fragments: remove them.
        self.tree.retain(|f| f.rec != rec);
        let at = self.list.iter().position(|&r| r == rec).unwrap();
        self.list.remove(at);
        self.recs[rec].3 = false;
    }

    /// Ghidra `find(p, s1, s2)` as fragment indices.
    pub fn find_sub(&self, p: u64, s1: (u32, u64), s2: (u32, u64)) -> &[MFrag] {
        let i1 = self.lower_bound((p, s1));
        if i1 == self.tree.len() || p < self.tree[i1].first {
            return &[];
        }
        let i2 = self.upper_bound((self.tree[i1].last, s2));
        &self.tree[i1..i2.max(i1)]
    }

    pub fn find_end(&self, p: u64) -> usize {
        let i = self.upper_bound((p, LATEST));
        if i == self.tree.len() || p < self.tree[i].first {
            return i;
        }
        self.upper_bound((self.tree[i].last, LATEST))
    }

    pub fn find_first_after(&self, p: u64) -> Option<usize> {
        let mut i = self.find_end(p);
        while i < self.tree.len() {
            if p < self.tree[i].a {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    pub fn find_last_before(&self, p: u64) -> Option<usize> {
        let mut i = self.lower_bound((p, EARLIEST));
        while i != 0 {
            i -= 1;
            if self.tree[i].b < p {
                return Some(i);
            }
        }
        None
    }

    pub fn find_overlap(&self, p: u64, e: u64) -> Option<usize> {
        let i = self.lower_bound((p, EARLIEST));
        (i < self.tree.len() && self.tree[i].first <= e).then_some(i)
    }
}
