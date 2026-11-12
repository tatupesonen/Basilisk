//! Bounding counts read from a file by what the file can actually hold.
//!
//! These are `ElfHeader.constrainHeaderCount` and `hasHeaderFragment`:
//! every table whose entry count comes from the file (program and section
//! headers, symbols, section-index tables, relocations) goes through them
//! before anything is sized by the count, so no allocation or loop is driven
//! by an unchecked number.

use crate::diag::{DiagnosticKind, Diagnostics};

/// True when Java, which holds the value in a signed `long`, would see it as
/// negative. Ghidra's `<= 0`, `< 0` and ordering checks are reproduced with
/// this where the difference matters.
pub(crate) const fn is_negative(value: u64) -> bool {
    value > i64::MAX as u64
}

/// The largest count of `entry_size`-byte entries Ghidra allows anywhere:
/// what fits a Java array index.
pub(crate) fn hard_limit(entry_size: u64) -> u64 {
    (i32::MAX as u64).checked_div(entry_size).unwrap_or(0)
}

/// Reduces `count` to what fits between `table_offset` and the end of a file
/// of `file_len` bytes, allowing one extra entry that is only partly there,
/// and to `hard_limit`. Reports a reduction as a diagnostic.
pub(crate) fn constrain_count(
    count: u64,
    table_offset: u64,
    entry_size: u64,
    hard_limit: u64,
    file_len: u64,
    what: &str,
    diags: &mut Diagnostics,
) -> u64 {
    let available = file_len.saturating_sub(table_offset);
    let (mut max_possible, remainder) = match entry_size {
        0 => (0, 0),
        size => (available / size, available % size),
    };
    let mut limit_type = "file capacity";
    if max_possible >= hard_limit {
        max_possible = hard_limit;
        limit_type = "hard limit";
    } else if remainder != 0 {
        // The last entry may be truncated; reads past the end yield zeros.
        max_possible += 1;
    }
    if count > max_possible {
        diags.push(
            DiagnosticKind::CountTruncated,
            format!("{what} count {count} exceeds {limit_type} {max_possible}; truncating"),
        );
        return max_possible;
    }
    count
}

/// True — with a diagnostic — when the table's last permitted entry is only
/// partly inside the file.
pub(crate) fn has_fragment(
    count: u64,
    table_offset: u64,
    entry_size: u64,
    hard_limit: u64,
    file_len: u64,
    what: &str,
    diags: &mut Diagnostics,
) -> bool {
    let available = file_len.saturating_sub(table_offset);
    let (complete, remainder) = match entry_size {
        0 => (0, 0),
        size => (available / size, available % size),
    };
    if count.min(hard_limit) > complete && remainder != 0 {
        diags.push(
            DiagnosticKind::PartialEntry,
            format!("{what} has partial entry"),
        );
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(count: u64, offset: u64, size: u64, limit: u64, len: u64) -> (u64, bool, Vec<String>) {
        let mut diags = Diagnostics::default();
        let constrained = constrain_count(count, offset, size, limit, len, "Thing", &mut diags);
        let fragment = has_fragment(count, offset, size, limit, len, "Thing", &mut diags);
        (
            constrained,
            fragment,
            diags.into_vec().into_iter().map(|d| d.message).collect(),
        )
    }

    #[test]
    fn count_that_fits_is_kept() {
        assert_eq!(run(4, 100, 10, 1000, 140), (4, false, vec![]));
        assert_eq!(run(3, 100, 10, 1000, 140), (3, false, vec![]));
        assert_eq!(run(0, 100, 10, 1000, 100), (0, false, vec![]));
    }

    #[test]
    fn count_is_cut_to_file_capacity() {
        let (count, fragment, messages) = run(9, 100, 10, 1000, 140);
        assert_eq!((count, fragment), (4, false));
        assert_eq!(
            messages,
            ["Thing count 9 exceeds file capacity 4; truncating"]
        );
    }

    #[test]
    fn one_partial_entry_is_allowed_and_flagged() {
        // 45 bytes: four whole entries and half of a fifth.
        let (count, fragment, messages) = run(5, 100, 10, 1000, 145);
        assert_eq!((count, fragment), (5, true));
        assert_eq!(messages, ["Thing has partial entry"]);
        let (count, fragment, messages) = run(9, 100, 10, 1000, 145);
        assert_eq!((count, fragment), (5, true));
        assert_eq!(
            messages,
            [
                "Thing count 9 exceeds file capacity 5; truncating",
                "Thing has partial entry"
            ]
        );
        // The partial entry is not wanted: no flag.
        assert_eq!(run(4, 100, 10, 1000, 145), (4, false, vec![]));
    }

    #[test]
    fn hard_limit_applies() {
        let (count, fragment, messages) = run(50, 0, 10, 3, 1000);
        assert_eq!((count, fragment), (3, false));
        assert_eq!(
            messages,
            ["Thing count 50 exceeds hard limit 3; truncating"]
        );
        assert_eq!(run(2, 0, 10, 3, 1000), (2, false, vec![]));
        // A hard limit of zero empties the table.
        assert_eq!(run(1, 0, 10, 0, 1000).0, 0);
    }

    #[test]
    fn degenerate_inputs_do_not_divide_by_zero_or_underflow() {
        assert_eq!(run(5, 0, 0, 10, 100).0, 0);
        assert_eq!(run(5, 200, 10, 10, 100).0, 0, "offset past the end");
        assert_eq!(hard_limit(0), 0);
        assert_eq!(hard_limit(56), u64::from(i32::MAX as u32) / 56);
        assert!(is_negative(u64::MAX) && is_negative(1 << 63) && !is_negative(i64::MAX as u64));
    }
}
