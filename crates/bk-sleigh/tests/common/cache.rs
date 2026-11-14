//! A model of Ghidra's parse cache (`DisassemblyCache`, `sleigh.cc`) as
//! `pcodedump`'s sweep drives it, to tell where the oracle's result
//! depends on the cache's history rather than on the instruction:
//!
//! * a delay-slot lookup reuses the parse object of the instruction being
//!   lifted (or of an earlier delay slot), whose p-code is then built from
//!   another instruction's parse (2-entry caches, languages whose largest
//!   delay slot is one byte or one instruction);
//! * a crossbuild target is not in the cache in the p-code state
//!   ("Could not obtain cached crossbuild instruction"), where basilisk
//!   decodes it on demand.
//!
//! ADR-024 states that basilisk has no address-keyed parse cache.

use bk_sleigh::Language;

use super::sweep::Record;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum State {
    Uninitialized,
    Disassembly,
    Pcode,
}

struct Cache {
    mask: u64,
    objects: Vec<(Option<u64>, State)>,
    table: Vec<usize>,
    next: usize,
}

impl Cache {
    fn new(lang: &Language) -> Self {
        let (size, window) = if lang.max_delay() > 1 || lang.unique_mask() != 0 {
            (8, 256)
        } else {
            (2, 32)
        };
        Self {
            mask: window as u64 - 1,
            objects: vec![(None, State::Uninitialized); size],
            table: vec![0; window],
            next: 0,
        }
    }

    /// `getParserContext`: the object for `addr` and whether it was a hit.
    fn lookup(&mut self, addr: u64) -> (usize, bool) {
        let h = (addr & self.mask) as usize;
        let obj = self.table[h];
        if self.objects[obj].0 == Some(addr) {
            return (obj, true);
        }
        let obj = self.next;
        self.next = (self.next + 1) % self.objects.len();
        self.objects[obj] = (Some(addr), State::Uninitialized);
        self.table[h] = obj;
        (obj, false)
    }

    /// `obtainContext` with a successful resolve.
    fn obtain(&mut self, addr: u64, state: State) -> usize {
        let (obj, _) = self.lookup(addr);
        if self.objects[obj].1 < state {
            self.objects[obj].1 = state;
        }
        obj
    }
}

/// Marks the records whose oracle result depends on the cache's history.
pub(crate) fn mark(lang: &Language, records: &mut [Record]) {
    let mut cache = Cache::new(lang);
    for record in records.iter_mut() {
        if record.constructors.is_empty() {
            // An `E` record: the lookup happened, the resolve failed.
            cache.lookup(record.address);
            continue;
        }
        cache.obtain(record.address, State::Disassembly);
        if let Some(next) = record.next {
            cache.obtain(next, State::Disassembly);
        }
        // oneInstruction.
        let main = cache.obtain(record.address, State::Pcode);
        let mut held = vec![(main, record.address)];
        for &(d, _) in &record.delays {
            held.push((cache.obtain(d, State::Pcode), d));
        }
        let clobbered = |cache: &Cache, held: &[(usize, u64)]| {
            held.iter()
                .any(|&(obj, addr)| cache.objects[obj].0 != Some(addr))
        };
        record.cache_clobbered = clobbered(&cache, &held);
        // The builder's lookups.
        for &(d, next) in &record.delays {
            cache.lookup(d);
            // A delay slot using `inst_next2` decodes the instruction after
            // it while it is built (Ghidra `getN2addr`).
            if let Some(next) = next {
                cache.obtain(next, State::Disassembly);
            }
        }
        for &t in &record.built.cross_targets {
            let (obj, hit) = cache.lookup(t);
            if !hit || cache.objects[obj].1 != State::Pcode {
                record.cross_uncached = true;
            }
        }
        record.cache_clobbered |= clobbered(&cache, &held);
    }
}
