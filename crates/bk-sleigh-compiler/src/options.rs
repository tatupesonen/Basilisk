//! Options that change what the compiler reports (inventory 9.1).

/// The command-line switches of Ghidra's `sleigh` that this half of the
/// compiler honours. The defaults are Ghidra's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per command-line switch, as Ghidra has them"
)]
pub struct Options {
    /// `-u`: warn about each unnecessary extension or truncation instead of
    /// printing only their count.
    pub warn_unnecessary_pcode: bool,
    /// `-l` clears this: indistinguishable patterns are errors. Used by the
    /// back half; kept here so one value describes a compile.
    pub lenient_conflicts: bool,
    /// `-c`: warn about each constructor with colliding operands.
    pub warn_all_collisions: bool,
    /// `-n`: warn about each NOP constructor.
    pub warn_all_nops: bool,
    /// `-t`: warn about each temporary that is written but not read.
    pub warn_dead_temps: bool,
    /// `-e`: temporaries must be declared with `local`.
    pub enforce_local_key: bool,
    /// `-s` clears this: register names that differ only in case are
    /// errors.
    pub case_insensitive_duplicates: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            warn_unnecessary_pcode: false,
            lenient_conflicts: true,
            warn_all_collisions: false,
            warn_all_nops: false,
            warn_dead_temps: false,
            enforce_local_key: false,
            case_insensitive_duplicates: true,
        }
    }
}

impl Options {
    /// Applies Ghidra's command-line switches (`-u`, `-l`, `-c`, `-n`,
    /// `-t`, `-e`, `-s`); other arguments are ignored. Only the second
    /// character of each argument is examined, as Ghidra does.
    pub fn from_switches<'a>(switches: impl IntoIterator<Item = &'a str>) -> Self {
        let mut options = Self::default();
        for switch in switches {
            let mut chars = switch.chars();
            if chars.next() != Some('-') {
                continue;
            }
            match chars.next() {
                Some('u') => options.warn_unnecessary_pcode = true,
                Some('l') => options.lenient_conflicts = false,
                Some('c') => options.warn_all_collisions = true,
                Some('n') => options.warn_all_nops = true,
                Some('t') => options.warn_dead_temps = true,
                Some('e') => options.enforce_local_key = true,
                Some('s') => options.case_insensitive_duplicates = false,
                _ => {}
            }
        }
        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switches_map_to_options() {
        let options = Options::from_switches(["-l", "-t", "-unused", "x", "-s"]);
        assert!(!options.lenient_conflicts);
        assert!(options.warn_dead_temps);
        assert!(options.warn_unnecessary_pcode);
        assert!(!options.case_insensitive_duplicates);
        assert!(!options.enforce_local_key);
        assert_eq!(Options::from_switches([]), Options::default());
    }
}
