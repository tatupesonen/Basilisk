use super::TokenKind::{
    Ampersand, Assign, Asterisk, BadString, BinInt, BoolAnd, BoolOr, BoolXor, Caret, Colon, Comma,
    CppComment, DecInt, DispChar, Ellipsis, Eof, Equal, Exclaim, FDiv, FEqual, FGreat, FGreatEqual,
    FLess, FLessEqual, FMinus, FMult, FNotEqual, FPlus, Great, GreatEqual, Hash, HexInt, Ident,
    LBrace, LBracket, LParen, Left, Less, LessEqual, Minus, NotEqual, Percent, Pipe, Plus,
    PrefixedDecInt, QString, RBrace, RBracket, RParen, Right, SDiv, SGreat, SGreatEqual, SLess,
    SLessEqual, SRem, SRight, Semi, Slash, SpecAnd, SpecOr, SpecXor, Tilde, Underscore, Unknown,
    UnterminatedString, Whitespace,
};
use super::{Lexer, Mode, TokenKind, string_content};
use crate::intern::{Interner, kw};

fn lex(src: &str, mode: Mode) -> Vec<(TokenKind, &str)> {
    let mut names = Interner::new();
    let mut lexer = Lexer::new(src);
    let mut out = Vec::new();
    loop {
        let token = lexer.next_token(mode, &mut names);
        if token.kind == Eof {
            assert_eq!(token.span.start as usize, src.len());
            return out;
        }
        assert!(!token.span.is_empty(), "empty token at {:?}", token.span);
        let text = &src[token.span.range()];
        if token.kind == Ident {
            assert_eq!(names.resolve(token.ident().unwrap()), text);
        } else {
            assert_eq!(token.ident(), None);
        }
        out.push((token.kind, text));
    }
}

fn kinds(src: &str, mode: Mode) -> Vec<TokenKind> {
    lex(src, mode).into_iter().map(|(k, _)| k).collect()
}

#[test]
fn punctuation_and_operators_of_the_base_lexer() {
    assert_eq!(
        kinds(
            "{ } [ ] ( ) ... : , ! ~ ; = == != < > <= >= || ^^ && | ^ & << >> + - * / %",
            Mode::Base
        ),
        [
            LBrace, RBrace, LBracket, RBracket, LParen, RParen, Ellipsis, Colon, Comma, Exclaim,
            Tilde, Semi, Assign, Equal, NotEqual, Less, Great, LessEqual, GreatEqual, BoolOr,
            BoolXor, BoolAnd, Pipe, Caret, Ampersand, Left, Right, Plus, Minus, Asterisk, Slash,
            Percent
        ]
    );
    assert_eq!(
        kinds("$or $and $xor", Mode::Base),
        [SpecOr, SpecAnd, SpecXor]
    );
    assert_eq!(lex("$orx", Mode::Base), [(SpecOr, "$or"), (Ident, "x")]);
}

#[test]
fn adjacent_operators_split_longest_first() {
    assert_eq!(kinds("<<=", Mode::Base), [Left, Assign]);
    assert_eq!(kinds(">>=", Mode::Base), [Right, Assign]);
    assert_eq!(kinds("===", Mode::Base), [Equal, Assign]);
    assert_eq!(kinds("!==", Mode::Base), [NotEqual, Assign]);
    assert_eq!(kinds("|||", Mode::Base), [BoolOr, Pipe]);
    assert_eq!(kinds("^^^", Mode::Base), [BoolXor, Caret]);
    assert_eq!(kinds("&&&", Mode::Base), [BoolAnd, Ampersand]);
    assert_eq!(kinds("<<<", Mode::Base), [Left, Less]);
    assert_eq!(kinds("a=-1", Mode::Base), [Ident, Assign, Minus, DecInt]);
}

#[test]
fn identifiers_may_contain_dots_and_underscores() {
    assert_eq!(
        lex("abc _x x_ a.b .x x. __ .. a1 A_.9", Mode::Base),
        [
            (Ident, "abc"),
            (Ident, "_x"),
            (Ident, "x_"),
            (Ident, "a.b"),
            (Ident, ".x"),
            (Ident, "x."),
            (Ident, "__"),
            (Ident, ".."),
            (Ident, "a1"),
            (Ident, "A_.9"),
        ]
    );
    // A lone underscore is the wildcard, three dots alone are the ellipsis;
    // attached to more identifier characters they are part of the name.
    assert_eq!(kinds("_ ...", Mode::Base), [Underscore, Ellipsis]);
    assert_eq!(
        lex("...x x... ....", Mode::Base),
        [(Ident, "...x"), (Ident, "x..."), (Ident, "....")]
    );
    assert_eq!(
        kinds("(a)...", Mode::Base),
        [LParen, Ident, RParen, Ellipsis]
    );
}

#[test]
fn keywords_are_identifiers_with_fixed_symbols() {
    let mut names = Interner::new();
    let mut lexer = Lexer::new("define with is if defined");
    let symbols: Vec<_> = (0..5)
        .map(|_| lexer.next_token(Mode::Base, &mut names))
        .map(|t| (t.kind, t.ident().unwrap()))
        .collect();
    assert_eq!(symbols[0], (Ident, kw::DEFINE));
    assert_eq!(symbols[1], (Ident, kw::WITH));
    assert_eq!(symbols[2], (Ident, kw::IS));
    assert_eq!(symbols[3], (Ident, kw::IF));
    assert!(!symbols[4].1.is_keyword());
    assert!(!lexer.next_token(Mode::Base, &mut names).is_word(kw::WITH));
}

#[test]
fn integers_keep_their_radix() {
    assert_eq!(
        lex("0 42 0x1F 0xdeadBEEF 0b101 0n99 007", Mode::Base),
        [
            (DecInt, "0"),
            (DecInt, "42"),
            (HexInt, "0x1F"),
            (HexInt, "0xdeadBEEF"),
            (BinInt, "0b101"),
            (PrefixedDecInt, "0n99"),
            (DecInt, "007"),
        ]
    );
}

#[test]
fn numbers_end_where_their_digits_end() {
    assert_eq!(lex("12ab", Mode::Base), [(DecInt, "12"), (Ident, "ab")]);
    assert_eq!(lex("0x1G", Mode::Base), [(HexInt, "0x1"), (Ident, "G")]);
    assert_eq!(lex("0b12", Mode::Base), [(BinInt, "0b1"), (DecInt, "2")]);
    // A prefix with no digits is a zero followed by an identifier.
    assert_eq!(lex("0xg", Mode::Base), [(DecInt, "0"), (Ident, "xg")]);
    assert_eq!(lex("0b", Mode::Base), [(DecInt, "0"), (Ident, "b")]);
    assert_eq!(lex("0n", Mode::Base), [(DecInt, "0"), (Ident, "n")]);
    assert_eq!(lex("0X10", Mode::Base), [(DecInt, "0"), (Ident, "X10")]);
    assert_eq!(lex("1.5", Mode::Base), [(DecInt, "1"), (Ident, ".5")]);
}

#[test]
fn strings_and_their_escapes() {
    assert_eq!(
        lex(r#""abc" "" "a b""#, Mode::Base),
        [
            (QString, "\"abc\""),
            (QString, "\"\""),
            (QString, "\"a b\"")
        ]
    );
    assert_eq!(
        kinds(
            r#""a\"b" "\\" "\n\t\b\f\r\'" "\u00e9" "\7\77\377""#,
            Mode::Base
        ),
        [QString; 5]
    );
    assert_eq!(
        lex("\"two\nlines\"", Mode::Base),
        [(QString, "\"two\nlines\"")]
    );
    assert_eq!(
        lex("\"# not a comment\" x", Mode::Base),
        [(QString, "\"# not a comment\""), (Ident, "x")]
    );
    assert_eq!(string_content("\"abc\""), "abc");
    assert_eq!(string_content("\"\""), "");
    assert_eq!(string_content("\"open"), "open");
}

#[test]
fn malformed_strings_are_error_tokens() {
    assert_eq!(
        lex(r#""a\qb" x"#, Mode::Base),
        [(BadString, r#""a\qb""#), (Ident, "x")]
    );
    assert_eq!(
        lex(r#""\u12" x"#, Mode::Base),
        [(BadString, r#""\u12""#), (Ident, "x")]
    );
    assert_eq!(
        lex("\"never closed\nx = 1;", Mode::Base),
        [(UnterminatedString, "\"never closed\nx = 1;")]
    );
    assert_eq!(
        lex("\"ends in backslash\\", Mode::Base),
        [(UnterminatedString, "\"ends in backslash\\")]
    );
    assert_eq!(
        lex("\"\\é\" x", Mode::Base),
        [(BadString, "\"\\é\""), (Ident, "x")]
    );
}

#[test]
fn comments_and_whitespace_are_skipped_outside_display() {
    assert_eq!(
        lex("a # comment ; with \" stuff\n b#x\n#y", Mode::Base),
        [(Ident, "a"), (Ident, "b")]
    );
    assert_eq!(
        lex("a\t\r\n  b", Mode::Semantic),
        [(Ident, "a"), (Ident, "b")]
    );
    assert_eq!(kinds("", Mode::Base), []);
    assert_eq!(kinds("  \n# only a comment", Mode::Base), []);
}

#[test]
fn cpp_comments_are_errors() {
    assert_eq!(
        lex("a // not sleigh\nb", Mode::Base),
        [(Ident, "a"), (CppComment, "// not sleigh"), (Ident, "b")]
    );
    assert_eq!(
        lex("a / b", Mode::Base),
        [(Ident, "a"), (Slash, "/"), (Ident, "b")]
    );
    assert_eq!(
        lex("a//b c", Mode::Display),
        [
            (Ident, "a"),
            (CppComment, "//"),
            (Ident, "b"),
            (Whitespace, " "),
            (Ident, "c")
        ]
    );
}

#[test]
fn unknown_characters_are_one_token_each() {
    assert_eq!(
        lex("a @ $ ? ' ` \\", Mode::Base),
        [
            (Ident, "a"),
            (Unknown, "@"),
            (Unknown, "$"),
            (Unknown, "?"),
            (Unknown, "'"),
            (Unknown, "`"),
            (Unknown, "\\")
        ]
    );
    assert_eq!(
        lex("é–x", Mode::Base),
        [(Unknown, "é"), (Unknown, "–"), (Ident, "x")]
    );
    assert_eq!(
        lex("a\u{b}b\u{c}", Mode::Base),
        [
            (Ident, "a"),
            (Unknown, "\u{b}"),
            (Ident, "b"),
            (Unknown, "\u{c}")
        ]
    );
}

#[test]
fn display_mode_keeps_whitespace_and_hash() {
    assert_eq!(
        lex("ADD  op1,#imm\n\t is", Mode::Display),
        [
            (Ident, "ADD"),
            (Whitespace, "  "),
            (Ident, "op1"),
            (Comma, ","),
            (Hash, "#"),
            (Ident, "imm"),
            (Whitespace, "\n\t "),
            (Ident, "is"),
        ]
    );
    assert_eq!(
        kinds("@ $ ? $or", Mode::Display),
        [
            DispChar, Whitespace, DispChar, Whitespace, DispChar, Whitespace, SpecOr
        ]
    );
    assert_eq!(
        lex("\"a b\"^x", Mode::Display),
        [(QString, "\"a b\""), (Caret, "^"), (Ident, "x")]
    );
    assert_eq!(
        lex("[0x10]+1", Mode::Display),
        [
            (LBracket, "["),
            (HexInt, "0x10"),
            (RBracket, "]"),
            (Plus, "+"),
            (DecInt, "1")
        ]
    );
    // No signed or float operators in display mode.
    assert_eq!(
        lex("s< f+", Mode::Display),
        [
            (Ident, "s"),
            (Less, "<"),
            (Whitespace, " "),
            (Ident, "f"),
            (Plus, "+")
        ]
    );
}

#[test]
fn semantic_mode_adds_signed_and_float_operators() {
    assert_eq!(
        kinds(
            "f== f!= f< f> f<= f>= f+ f- f* f/ s< s> s<= s>= s>> s/ s%",
            Mode::Semantic
        ),
        [
            FEqual,
            FNotEqual,
            FLess,
            FGreat,
            FLessEqual,
            FGreatEqual,
            FPlus,
            FMinus,
            FMult,
            FDiv,
            SLess,
            SGreat,
            SLessEqual,
            SGreatEqual,
            SRight,
            SDiv,
            SRem
        ]
    );
    assert_eq!(
        lex("a s< b", Mode::Semantic),
        [(Ident, "a"), (SLess, "s<"), (Ident, "b")]
    );
    assert_eq!(
        lex("as<b", Mode::Semantic),
        [(Ident, "as"), (Less, "<"), (Ident, "b")]
    );
    assert_eq!(
        lex("s <b", Mode::Semantic),
        [(Ident, "s"), (Less, "<"), (Ident, "b")]
    );
    assert_eq!(
        lex("f=1", Mode::Semantic),
        [(Ident, "f"), (Assign, "="), (DecInt, "1")]
    );
    assert_eq!(
        lex("f!x", Mode::Semantic),
        [(Ident, "f"), (Exclaim, "!"), (Ident, "x")]
    );
    assert_eq!(
        lex("s=1 s+1 f%2", Mode::Semantic),
        [
            (Ident, "s"),
            (Assign, "="),
            (DecInt, "1"),
            (Ident, "s"),
            (Plus, "+"),
            (DecInt, "1"),
            (Ident, "f"),
            (Percent, "%"),
            (DecInt, "2")
        ]
    );
    assert_eq!(
        lex("s<<1", Mode::Semantic),
        [(SLess, "s<"), (Less, "<"), (DecInt, "1")]
    );
    assert_eq!(
        lex("s>>=", Mode::Semantic),
        [(SRight, "s>>"), (Assign, "=")]
    );
    // The same text in base mode is an identifier and an ordinary operator.
    assert_eq!(
        lex("s<1 f+2", Mode::Base),
        [
            (Ident, "s"),
            (Less, "<"),
            (DecInt, "1"),
            (Ident, "f"),
            (Plus, "+"),
            (DecInt, "2")
        ]
    );
    assert_eq!(lex("<s>", Mode::Semantic), [(Less, "<"), (SGreat, "s>")]);
}

#[test]
fn seeking_relexes_from_an_offset() {
    let src = "table: s< x";
    let mut names = Interner::new();
    let mut lexer = Lexer::new(src);
    assert_eq!(lexer.next_token(Mode::Base, &mut names).kind, Ident);
    assert_eq!(lexer.next_token(Mode::Base, &mut names).kind, Colon);
    let at = lexer.offset();
    assert_eq!(lexer.next_token(Mode::Base, &mut names).kind, Ident);
    lexer.seek(at);
    assert_eq!(lexer.next_token(Mode::Display, &mut names).kind, Whitespace);
    lexer.seek(at);
    assert_eq!(lexer.next_token(Mode::Semantic, &mut names).kind, SLess);
    lexer.seek(1000);
    assert_eq!(lexer.next_token(Mode::Base, &mut names).kind, Eof);
    let mut multibyte = Lexer::new("é");
    multibyte.seek(1);
    assert_eq!(multibyte.offset(), 0);
}
