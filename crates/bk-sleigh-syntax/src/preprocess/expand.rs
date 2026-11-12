//! `$(NAME)` expansion.
//!
//! A reference is `$(` followed by a name (`[0-9A-Za-z_]+`) and `)`.
//! Anything else starting with `$(` is left alone. The replacement is the
//! definition's value, inserted textually and not rescanned.

use super::defines::Defines;

/// A piece of an expanded line.
pub(crate) enum LenientPiece<'a> {
    /// Text copied unchanged.
    Text(&'a str),
    /// The value of a reference that stood at byte column `src_col` and was
    /// `src_len` bytes long.
    Value {
        value: &'a str,
        src_col: u32,
        src_len: u32,
    },
    /// A reference to an undefined name; it expands to nothing.
    Unknown {
        name: &'a str,
        src_col: u32,
        src_len: u32,
    },
}

/// A piece of a strictly expanded string.
pub(crate) enum Piece<'a> {
    /// Text copied unchanged.
    Text(&'a str),
    /// The value of a reference.
    Value {
        /// The definition's value.
        value: &'a str,
    },
}

/// Finds the next `$(NAME)` at or after `from`: returns the offsets of the
/// `$` and of the byte after `)`, and the name.
fn next_reference(line: &str, from: usize) -> Option<(usize, usize, &str)> {
    let bytes = line.as_bytes();
    let mut search = from;
    loop {
        let rest = bytes.get(search..)?;
        let start = search + memchr::memmem::find(rest, b"$(")?;
        let name_start = start + 2;
        let name_len = bytes
            .get(name_start..)?
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count();
        let name_end = name_start + name_len;
        if name_len > 0 && bytes.get(name_end) == Some(&b')') {
            return Some((start, name_end + 1, line.get(name_start..name_end)?));
        }
        search = name_start;
    }
}

/// Expands `line`, passing each piece to `emit`. Undefined names are passed
/// on as [`LenientPiece::Unknown`] and expansion continues.
pub(crate) fn expand_lenient<'a>(
    line: &'a str,
    defines: &'a Defines,
    mut emit: impl FnMut(LenientPiece<'a>),
) {
    let mut pos = 0;
    while let Some((start, end, name)) = next_reference(line, pos) {
        emit(LenientPiece::Text(line.get(pos..start).unwrap_or("")));
        let (src_col, src_len) = (start as u32, (end - start) as u32);
        match defines.get(name) {
            Some(value) => emit(LenientPiece::Value {
                value,
                src_col,
                src_len,
            }),
            None => emit(LenientPiece::Unknown {
                name,
                src_col,
                src_len,
            }),
        }
        pos = end;
    }
    emit(LenientPiece::Text(line.get(pos..).unwrap_or("")));
}

/// Expands `text`, stopping at the first undefined name, which is returned.
pub(crate) fn expand<'a>(
    text: &'a str,
    defines: &'a Defines,
    mut emit: impl FnMut(Piece<'a>),
) -> Result<(), &'a str> {
    let mut failed = None;
    expand_lenient(text, defines, |piece| match piece {
        LenientPiece::Text(text) => emit(Piece::Text(text)),
        LenientPiece::Value { value, .. } => emit(Piece::Value { value }),
        LenientPiece::Unknown { name, .. } => {
            failed.get_or_insert(name);
        }
    });
    failed.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(line: &str, defines: &Defines) -> (String, Vec<String>) {
        let mut out = String::new();
        let mut unknown = Vec::new();
        expand_lenient(line, defines, |piece| match piece {
            LenientPiece::Text(t) => out.push_str(t),
            LenientPiece::Value { value, .. } => out.push_str(value),
            LenientPiece::Unknown { name, .. } => unknown.push(name.to_owned()),
        });
        (out, unknown)
    }

    #[test]
    fn references_are_replaced_textually() {
        let d = Defines::new()
            .with("A", "1")
            .with("B_2", "x y")
            .with("E", "");
        assert_eq!(run("r$(A) = $(B_2);", &d).0, "r1 = x y;");
        assert_eq!(run("$(A)$(A)$(E)$(A)", &d).0, "111");
        assert_eq!(run("no references", &d).0, "no references");
        assert_eq!(run("", &d).0, "");
    }

    #[test]
    fn values_are_not_rescanned() {
        let d = Defines::new().with("A", "$(B)").with("B", "b");
        assert_eq!(run("$(A)", &d).0, "$(B)");
    }

    #[test]
    fn malformed_references_are_left_alone() {
        let d = Defines::new().with("A", "1");
        assert_eq!(
            run("$( A) $() $(A $A $(A.B) $", &d),
            ("$( A) $() $(A $A $(A.B) $".into(), vec![])
        );
        // The inner reference of `$($(A))` is the leftmost match.
        assert_eq!(run("$($(A))", &d).0, "$(1)");
    }

    #[test]
    fn unknown_names_expand_to_nothing_and_are_reported() {
        let d = Defines::new().with("A", "1");
        assert_eq!(
            run("x$(NOPE)y$(A)$(NADA)", &d),
            ("xy1".into(), vec!["NOPE".into(), "NADA".into()])
        );
        let mut out = String::new();
        let strict = expand("a/$(NOPE)/$(A)", &d, |p| match p {
            Piece::Text(t) | Piece::Value { value: t } => out.push_str(t),
        });
        assert_eq!(strict, Err("NOPE"));
    }
}
