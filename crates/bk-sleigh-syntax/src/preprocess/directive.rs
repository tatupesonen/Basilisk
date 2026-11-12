//! Recognition of preprocessor directive lines.
//!
//! The forms are those of the regular expressions at the top of Ghidra's
//! `SleighPreprocessor.java`, tried in the same order. A directive line
//! starts with `@` in column one; everything from the first `#` on is a
//! comment (even inside quotes, as in Ghidra).

/// A recognised directive, borrowing from its line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Directive<'a> {
    /// `@include "file"`.
    Include(&'a str),
    /// `@define NAME "value"`, `@define NAME value` or `@define NAME`.
    Define { name: &'a str, value: &'a str },
    /// `@undef NAME`.
    Undef(&'a str),
    /// `@ifdef NAME`.
    Ifdef(&'a str),
    /// `@ifndef NAME`.
    Ifndef(&'a str),
    /// `@if expression`.
    If(&'a str),
    /// `@elif expression`.
    Elif(&'a str),
    /// `@endif`.
    Endif,
    /// `@else`.
    Else,
    /// Starts with `@` but matches no directive form.
    Unrecognized,
}

/// Java's `\s`: space, tab, newline, vertical tab, form feed, carriage return.
pub(crate) const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

fn trim_start(s: &str) -> &str {
    s.trim_start_matches(|c: char| c.is_ascii() && is_space(c as u8))
}

fn trim_end(s: &str) -> &str {
    s.trim_end_matches(|c: char| c.is_ascii() && is_space(c as u8))
}

/// Splits a leading macro name (`[0-9A-Za-z_]+`) off `s`.
fn take_name(s: &str) -> Option<(&str, &str)> {
    let len = s
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if len == 0 {
        None
    } else {
        s.split_at_checked(len)
    }
}

/// Requires at least one whitespace character at the start of `s` and
/// returns what follows the whitespace.
fn after_space(s: &str) -> Option<&str> {
    let rest = trim_start(s);
    (rest.len() < s.len()).then_some(rest)
}

/// A name followed only by whitespace.
fn sole_name(rest: &str) -> Option<&str> {
    let (name, tail) = take_name(after_space(rest)?)?;
    trim_end(tail).is_empty().then_some(name)
}

/// The content of `s` if it is one double-quoted string (to the last quote).
fn quoted(s: &str) -> Option<&str> {
    s.strip_prefix('"')?.strip_suffix('"')
}

/// Classifies `line`, which must start with `@`.
pub(crate) fn parse(line: &str) -> Directive<'_> {
    // Remove any comment, as Ghidra does, before matching.
    let line = line.find('#').and_then(|i| line.get(..i)).unwrap_or(line);
    let Some(body) = line.strip_prefix('@') else {
        return Directive::Unrecognized;
    };
    let word_len = body.bytes().take_while(u8::is_ascii_lowercase).count();
    let Some((word, rest)) = body.split_at_checked(word_len) else {
        return Directive::Unrecognized;
    };
    let parsed = match word {
        "include" => after_space(rest)
            .and_then(|r| quoted(trim_end(r)))
            .map(Directive::Include),
        "define" => parse_define(rest),
        "undef" => sole_name(rest).map(Directive::Undef),
        "ifdef" => sole_name(rest).map(Directive::Ifdef),
        "ifndef" => sole_name(rest).map(Directive::Ifndef),
        "if" => after_space(rest).map(Directive::If),
        "elif" => after_space(rest).map(Directive::Elif),
        "endif" => trim_end(rest).is_empty().then_some(Directive::Endif),
        "else" => trim_end(rest).is_empty().then_some(Directive::Else),
        _ => None,
    };
    parsed.unwrap_or(Directive::Unrecognized)
}

fn parse_define(rest: &str) -> Option<Directive<'_>> {
    let (name, tail) = take_name(after_space(rest)?)?;
    let value = trim_end(tail);
    if value.is_empty() {
        return Some(Directive::Define { name, value: "" });
    }
    let value = after_space(value)?;
    if let Some(inner) = quoted(value) {
        return Some(Directive::Define { name, value: inner });
    }
    // Unquoted: one run of non-whitespace characters.
    (!value.bytes().any(is_space)).then_some(Directive::Define { name, value })
}

#[cfg(test)]
mod tests {
    use super::Directive::{
        Define, Elif, Else, Endif, If, Ifdef, Ifndef, Include, Undef, Unrecognized,
    };
    use super::parse;
    use rstest::rstest;

    #[rstest]
    #[case("@include \"a.sinc\"", Include("a.sinc"))]
    #[case("@include\t \"dir/a b.sinc\"  ", Include("dir/a b.sinc"))]
    #[case("@include \"a\" \"b\"", Include("a\" \"b"))]
    #[case("@include \"a.sinc\" # why", Include("a.sinc"))]
    #[case("@include\"a.sinc\"", Unrecognized)]
    #[case("@include a.sinc", Unrecognized)]
    #[case("@include \"a.sinc", Unrecognized)]
    #[case("@include \"a#b.sinc\"", Unrecognized)]
    #[case("@define FOO \"bar baz\"", Define { name: "FOO", value: "bar baz" })]
    #[case("@define FOO \"\"", Define { name: "FOO", value: "" })]
    #[case("@define FOO \"a\" \"b\"", Define { name: "FOO", value: "a\" \"b" })]
    #[case("@define FOO bar", Define { name: "FOO", value: "bar" })]
    #[case("@define FOO\t\tbar-baz.1  ", Define { name: "FOO", value: "bar-baz.1" })]
    #[case("@define FOO", Define { name: "FOO", value: "" })]
    #[case("@define FOO   ", Define { name: "FOO", value: "" })]
    #[case("@define 9lives 1", Define { name: "9lives", value: "1" })]
    #[case("@define FOO \"a#b\"", Define { name: "FOO", value: "\"a" })]
    #[case("@define FOO \"", Define { name: "FOO", value: "\"" })]
    #[case("@define FOO # just a flag", Define { name: "FOO", value: "" })]
    #[case("@define FOO bar baz", Unrecognized)]
    #[case("@define FOO \"bar baz", Unrecognized)]
    #[case("@define FOO-BAR x", Unrecognized)]
    #[case("@define", Unrecognized)]
    #[case("@define  ", Unrecognized)]
    #[case("@definefoo X", Unrecognized)]
    #[case("@undef FOO", Undef("FOO"))]
    #[case("@undef FOO BAR", Unrecognized)]
    #[case("@undef", Unrecognized)]
    #[case("@ifdef FOO", Ifdef("FOO"))]
    #[case("@ifdef  FOO \t", Ifdef("FOO"))]
    #[case("@ifdef FOO.BAR", Unrecognized)]
    #[case("@ifndef FOO", Ifndef("FOO"))]
    #[case("@if defined(FOO)", If("defined(FOO)"))]
    #[case("@if   FOO == \"x\" # c", If("FOO == \"x\" "))]
    #[case("@if ", If(""))]
    #[case("@if", Unrecognized)]
    #[case("@if(FOO == \"x\")", Unrecognized)]
    #[case("@elif FOO != BAR", Elif("FOO != BAR"))]
    #[case("@elif", Unrecognized)]
    #[case("@endif", Endif)]
    #[case("@endif   # done", Endif)]
    #[case("@endif FOO", Unrecognized)]
    #[case("@endifx", Unrecognized)]
    #[case("@else", Else)]
    #[case("@else\t", Else)]
    #[case("@else if", Unrecognized)]
    #[case("@", Unrecognized)]
    #[case("@Define FOO", Unrecognized)]
    #[case("@ define FOO", Unrecognized)]
    #[case("@pragma once", Unrecognized)]
    fn directive_forms(#[case] line: &str, #[case] expected: super::Directive<'_>) {
        assert_eq!(parse(line), expected, "{line}");
    }
}
