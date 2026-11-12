//! Navigation: the one current location and its history.
//!
//! Ghidra's `NavigationHistoryService`: going somewhere on purpose (go to,
//! following a reference, picking a function) records a history entry;
//! moving the cursor within what is shown does not. Back and forward walk
//! the entries; going somewhere new drops the forward entries. The history
//! keeps 30 entries, Ghidra's default.

use crate::model::{Address, Location};

/// Entries kept, as in Ghidra.
pub const HISTORY_SIZE: usize = 30;

/// Where an entry's function starts, so "previous history function" can
/// skip entries inside the current function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    location: Location,
    function: Option<Address>,
}

/// The current location and the history of locations.
#[derive(Debug, Clone)]
pub struct Navigator {
    entries: Vec<Entry>,
    index: usize,
    /// Incremented on every change, so views can tell when to follow.
    generation: u64,
}

impl Navigator {
    /// A navigator at `start`.
    pub fn new(start: Location) -> Self {
        Self {
            entries: vec![Entry {
                location: start,
                function: None,
            }],
            index: 0,
            generation: 0,
        }
    }

    /// The current location.
    pub fn current(&self) -> Location {
        self.entries
            .get(self.index)
            .map_or(Location::at(Address(0)), |e| e.location)
    }

    /// Changes on every move; views compare it with the value they last saw.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Goes to `location`, recording it in the history.
    pub fn go(&mut self, location: Location) {
        if location == self.current() {
            self.generation += 1;
            return;
        }
        self.entries.truncate(self.index + 1);
        self.entries.push(Entry {
            location,
            function: None,
        });
        if self.entries.len() > HISTORY_SIZE {
            self.entries.remove(0);
        }
        self.index = self.entries.len() - 1;
        self.generation += 1;
    }

    /// Moves the cursor to `location` without a history entry (clicking
    /// around inside the code already shown).
    pub fn move_to(&mut self, location: Location) {
        if let Some(e) = self.entries.get_mut(self.index) {
            if e.location != location {
                e.location = location;
                self.generation += 1;
            }
        }
    }

    /// Records the function of the current entry once it is known.
    pub fn set_function(&mut self, function: Option<Address>) {
        if let Some(e) = self.entries.get_mut(self.index) {
            e.function = function;
        }
    }

    /// Whether there is an entry to go back to.
    pub fn can_back(&self) -> bool {
        self.index > 0
    }

    /// Whether there is an entry to go forward to.
    pub fn can_forward(&self) -> bool {
        self.index + 1 < self.entries.len()
    }

    /// Goes back one entry.
    pub fn back(&mut self) -> bool {
        if self.can_back() {
            self.index -= 1;
            self.generation += 1;
            true
        } else {
            false
        }
    }

    /// Goes forward one entry.
    pub fn forward(&mut self) -> bool {
        if self.can_forward() {
            self.index += 1;
            self.generation += 1;
            true
        } else {
            false
        }
    }

    /// Goes back to the newest entry in a different function.
    pub fn back_function(&mut self) -> bool {
        let here = self.entries.get(self.index).and_then(|e| e.function);
        let target = (0..self.index)
            .rev()
            .find(|i| self.entries.get(*i).is_some_and(|e| e.function != here));
        self.jump(target)
    }

    /// Goes forward to the next entry in a different function.
    pub fn forward_function(&mut self) -> bool {
        let here = self.entries.get(self.index).and_then(|e| e.function);
        let target = (self.index + 1..self.entries.len())
            .find(|i| self.entries.get(*i).is_some_and(|e| e.function != here));
        self.jump(target)
    }

    fn jump(&mut self, target: Option<usize>) -> bool {
        match target {
            Some(i) => {
                self.index = i;
                self.generation += 1;
                true
            }
            None => false,
        }
    }

    /// Forgets every entry but the current one.
    pub fn clear(&mut self) {
        if let Some(e) = self.entries.get(self.index).copied() {
            self.entries = vec![e];
            self.index = 0;
        }
    }

    /// Entries before the current one, newest first (the back button's
    /// drop-down).
    pub fn back_list(&self) -> Vec<Location> {
        self.entries
            .iter()
            .take(self.index)
            .rev()
            .map(|e| e.location)
            .collect()
    }

    /// Entries after the current one, nearest first.
    pub fn forward_list(&self) -> Vec<Location> {
        self.entries
            .iter()
            .skip(self.index + 1)
            .map(|e| e.location)
            .collect()
    }

    /// Goes back `n` entries at once (from the drop-down).
    pub fn back_by(&mut self, n: usize) {
        let i = self.index.saturating_sub(n);
        self.jump(Some(i));
    }

    /// Goes forward `n` entries at once.
    pub fn forward_by(&mut self, n: usize) {
        let i = (self.index + n).min(self.entries.len().saturating_sub(1));
        self.jump(Some(i));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(a: u64) -> Location {
        Location::at(Address(a))
    }

    #[test]
    fn go_back_forward() {
        let mut n = Navigator::new(at(1));
        n.go(at(2));
        n.go(at(3));
        assert!(n.back());
        assert_eq!(n.current(), at(2));
        assert!(n.back());
        assert!(!n.back());
        assert!(n.forward());
        assert_eq!(n.current(), at(2));
        // Going somewhere new drops the forward entries.
        n.go(at(9));
        assert!(!n.can_forward());
        assert_eq!(n.back_list(), vec![at(2), at(1)]);
    }

    #[test]
    fn cursor_moves_do_not_add_history() {
        let mut n = Navigator::new(at(1));
        let g = n.generation();
        n.move_to(at(5));
        assert_eq!(n.current(), at(5));
        assert!(!n.can_back());
        assert!(n.generation() > g);
    }

    #[test]
    fn history_is_bounded() {
        let mut n = Navigator::new(at(0));
        for i in 1..100 {
            n.go(at(i));
        }
        assert_eq!(n.back_list().len(), HISTORY_SIZE - 1);
    }

    #[test]
    fn function_history_skips_entries_in_the_same_function() {
        let mut n = Navigator::new(at(1));
        n.set_function(Some(Address(1)));
        n.go(at(10));
        n.set_function(Some(Address(10)));
        n.go(at(12));
        n.set_function(Some(Address(10)));
        assert!(n.back_function());
        assert_eq!(n.current(), at(1));
        assert!(n.forward_function());
        assert_eq!(n.current(), at(10));
    }

    #[test]
    fn drop_down_jumps() {
        let mut n = Navigator::new(at(1));
        n.go(at(2));
        n.go(at(3));
        n.back_by(2);
        assert_eq!(n.current(), at(1));
        n.forward_by(5);
        assert_eq!(n.current(), at(3));
    }
}
