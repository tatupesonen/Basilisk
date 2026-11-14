//! The decoding context: words of context bits per address (inventory
//! section 4).
//!
//! [`ContextDb`] is a port of Ghidra's `ContextInternal`. The decoder reads
//! context through [`ContextSource`] and writes committed changes through
//! [`ContextSink`], so the program model's own store can stand in for it.

mod db;
mod partmap;
mod tracked;

use bk_core::Address;

pub use db::ContextDb;
pub use tracked::TrackedValue;

/// The offsets around an address over which its context is constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OffsetRange {
    /// The first offset with the same context.
    pub first: u64,
    /// The last offset with the same context.
    pub last: u64,
}

/// Where the decoder reads context from.
pub trait ContextSource {
    /// Copies the context words in force at `addr` into `out` (which has the
    /// language's context size) and returns the offsets around `addr` over
    /// which they are constant.
    fn context_at(&self, addr: Address, out: &mut [u32]) -> OffsetRange;
}

/// Where committed context changes (`globalset`) go.
pub trait ContextSink {
    /// The "flowing" set: from `addr` on, until a point where any of these
    /// bits was set explicitly before, set `word`'s bits `mask` to `value`
    /// (Ghidra `setContextChangePoint`).
    fn set_change_point(&mut self, addr: Address, word: usize, mask: u32, value: u32);

    /// Sets `word`'s bits `mask` to `value` over `[first, end)`, or from
    /// `first` to the end of everything when `end` is `None` (Ghidra
    /// `setContextRegion`).
    fn set_region(
        &mut self,
        first: Address,
        end: Option<Address>,
        word: usize,
        mask: u32,
        value: u32,
    );
}

/// A named context variable: a bit range within one context word (Ghidra
/// `ContextBitRange`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ContextVar {
    name: Box<str>,
    word: usize,
    start_bit: u32,
    end_bit: u32,
}

impl ContextVar {
    /// A variable over the bits `start_bit..=end_bit` of the context array,
    /// most significant first (bit 0 is the top bit of word 0). `None` when
    /// the range is empty or straddles two words.
    pub fn new(name: &str, start_bit: u32, end_bit: u32) -> Option<Self> {
        if end_bit < start_bit || start_bit / 32 != end_bit / 32 {
            return None;
        }
        Some(Self {
            name: name.into(),
            word: (start_bit / 32) as usize,
            start_bit,
            end_bit,
        })
    }

    /// The variable's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The index of the word holding the variable.
    pub fn word(&self) -> usize {
        self.word
    }

    /// The first bit over the whole context array, most significant first.
    pub fn start_bit(&self) -> u32 {
        self.start_bit
    }

    /// The last bit over the whole context array.
    pub fn end_bit(&self) -> u32 {
        self.end_bit
    }

    /// The right shift that brings the variable to the bottom of its word.
    pub fn shift(&self) -> u32 {
        31 - self.end_bit % 32
    }

    /// The mask of the variable's value after shifting (not shifted).
    pub fn value_mask(&self) -> u32 {
        u32::MAX >> (31 - (self.end_bit - self.start_bit))
    }

    /// The variable's bits within its word.
    pub fn word_mask(&self) -> u32 {
        self.value_mask() << self.shift()
    }

    /// The variable's value in a context array (0 when the array is too
    /// short).
    pub fn get(&self, words: &[u32]) -> u32 {
        words
            .get(self.word)
            .map_or(0, |word| (word >> self.shift()) & self.value_mask())
    }

    /// Stores `value` (truncated to the variable's width) into a context
    /// array; nothing happens when the array is too short.
    pub fn set(&self, words: &mut [u32], value: u32) {
        if let Some(word) = words.get_mut(self.word) {
            *word = (*word & !self.word_mask()) | ((value & self.value_mask()) << self.shift());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables_pack_most_significant_bit_first() {
        let var = ContextVar::new("TMode", 0, 0).unwrap();
        assert_eq!(
            (var.word(), var.shift(), var.word_mask()),
            (0, 31, 0x8000_0000)
        );
        let var = ContextVar::new("x", 36, 39).unwrap();
        assert_eq!(
            (var.word(), var.shift(), var.word_mask()),
            (1, 24, 0x0f00_0000)
        );
        let mut words = [0u32; 2];
        var.set(&mut words, 0x1f);
        assert_eq!(words, [0, 0x0f00_0000]);
        assert_eq!(var.get(&words), 0xf);
        let full = ContextVar::new("w", 32, 63).unwrap();
        assert_eq!(full.value_mask(), u32::MAX);
        assert!(ContextVar::new("bad", 30, 33).is_none());
        assert!(ContextVar::new("bad", 3, 2).is_none());
        var.set(&mut [0u32; 1], 1);
        assert_eq!(var.get(&[]), 0);
    }
}
