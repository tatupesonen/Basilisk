//! The modal lexer.
//!
//! One scanner serves the three modes of Ghidra's ANTLR lexers; the parser
//! says which [`Mode`] applies to each token it asks for. The modes share
//! every token of `BaseLexer.g` and differ only in a few:
//!
//! * [`Mode::Display`] returns whitespace and `#` as tokens and accepts
//!   `@`, `$` and `?`;
//! * [`Mode::Semantic`] adds the `s`- and `f`-prefixed operators.
//!
//! Tokens are matched longest-first, which is what both of Ghidra's lexers
//! do: `s<` beats the identifier `s`, `...` beats `.`, `0x1F` beats `0`.
//! Keywords are not distinguished here: they are identifiers whose
//! [`Symbol`](crate::Symbol) is one of the constants in [`crate::kw`], and
//! the parser decides by position whether one is meant as a keyword.
//!
//! A U+0008 in the text is the preprocessor's mark for the start of an
//! expanded `$(NAME)` value ([`crate::source::EXPANSION_MARK`]). It is
//! skipped in every mode and ends the token before it, as the position
//! markers of Ghidra's preprocessor do.
//!
//! The lexer never fails: invalid input comes back as an error token kind
//! ([`TokenKind::is_error`]) and scanning continues after it.

pub mod literal;
mod token;

pub use token::{Mode, Token, TokenKind};

use crate::intern::{Interner, kw};
use crate::preprocess::expr::escape_len;
use crate::span::Span;

/// Scans tokens from preprocessed text.
#[derive(Clone, Debug)]
pub struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

/// [`crate::source::EXPANSION_MARK`] as a byte.
const EXPANSION_MARK_BYTE: u8 = 8;

const fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'.'
}

const fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
}

const fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

impl<'a> Lexer<'a> {
    /// A lexer at the start of `src`.
    pub fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    /// The offset of the next byte to be scanned.
    pub fn offset(&self) -> u32 {
        self.pos as u32
    }

    /// Continues scanning from `offset` (clamped to the text, and moved
    /// back to a character boundary if it is inside a character).
    pub fn seek(&mut self, offset: u32) {
        let mut pos = (offset as usize).min(self.src.len());
        while !self.src.is_char_boundary(pos) {
            pos -= 1;
        }
        self.pos = pos;
    }

    fn byte(&self, offset: usize) -> Option<u8> {
        self.src.as_bytes().get(self.pos + offset).copied()
    }

    fn rest(&self) -> &'a [u8] {
        self.src.as_bytes().get(self.pos..).unwrap_or(&[])
    }

    fn count_while(&self, from: usize, pred: impl Fn(u8) -> bool) -> usize {
        self.rest()
            .get(from..)
            .unwrap_or(&[])
            .iter()
            .take_while(|b| pred(**b))
            .count()
    }

    fn token(&mut self, kind: TokenKind, len: usize) -> Token {
        let start = self.pos;
        self.pos += len;
        Token {
            kind,
            span: Span::new(start as u32, self.pos as u32),
            symbol: kw::WITH,
        }
    }

    /// Skips whitespace, expansion marks and `#` comments (base and
    /// semantic modes).
    fn skip_trivia(&mut self) {
        loop {
            self.pos += self.count_while(0, |b| is_whitespace(b) || b == EXPANSION_MARK_BYTE);
            if self.byte(0) != Some(b'#') {
                return;
            }
            self.pos += memchr::memchr(b'\n', self.rest()).unwrap_or_else(|| self.rest().len());
        }
    }

    /// Scans the next token in `mode`, interning identifiers in `names`.
    pub fn next_token(&mut self, mode: Mode, names: &mut Interner) -> Token {
        if mode == Mode::Display {
            // Whitespace is a token here; only expansion marks are skipped.
            self.pos += self.count_while(0, |b| b == EXPANSION_MARK_BYTE);
        } else {
            self.skip_trivia();
        }
        let Some(first) = self.byte(0) else {
            return self.token(TokenKind::Eof, 0);
        };
        let second = self.byte(1);
        let pair = |next: u8, two: TokenKind, one: TokenKind| {
            if second == Some(next) {
                (two, 2)
            } else {
                (one, 1)
            }
        };
        let (kind, len) = match first {
            b if is_ident_start(b) => return self.word(mode, names),
            b'0'..=b'9' => self.number(),
            b'"' => self.string(),
            b' ' | b'\t' | b'\r' | b'\n' => {
                (TokenKind::Whitespace, self.count_while(0, is_whitespace))
            }
            b'{' => (TokenKind::LBrace, 1),
            b'}' => (TokenKind::RBrace, 1),
            b'[' => (TokenKind::LBracket, 1),
            b']' => (TokenKind::RBracket, 1),
            b'(' => (TokenKind::LParen, 1),
            b')' => (TokenKind::RParen, 1),
            b':' => (TokenKind::Colon, 1),
            b',' => (TokenKind::Comma, 1),
            b'~' => (TokenKind::Tilde, 1),
            b';' => (TokenKind::Semi, 1),
            b'+' => (TokenKind::Plus, 1),
            b'-' => (TokenKind::Minus, 1),
            b'*' => (TokenKind::Asterisk, 1),
            b'%' => (TokenKind::Percent, 1),
            b'!' => pair(b'=', TokenKind::NotEqual, TokenKind::Exclaim),
            b'=' => pair(b'=', TokenKind::Equal, TokenKind::Assign),
            b'|' => pair(b'|', TokenKind::BoolOr, TokenKind::Pipe),
            b'^' => pair(b'^', TokenKind::BoolXor, TokenKind::Caret),
            b'&' => pair(b'&', TokenKind::BoolAnd, TokenKind::Ampersand),
            b'<' => match second {
                Some(b'<') => (TokenKind::Left, 2),
                Some(b'=') => (TokenKind::LessEqual, 2),
                _ => (TokenKind::Less, 1),
            },
            b'>' => match second {
                Some(b'>') => (TokenKind::Right, 2),
                Some(b'=') => (TokenKind::GreatEqual, 2),
                _ => (TokenKind::Great, 1),
            },
            b'/' if second == Some(b'/') => {
                let len = if mode == Mode::Display {
                    2
                } else {
                    memchr::memchr(b'\n', self.rest()).unwrap_or_else(|| self.rest().len())
                };
                (TokenKind::CppComment, len)
            }
            b'/' => (TokenKind::Slash, 1),
            b'$' if self.rest().starts_with(b"$or") => (TokenKind::SpecOr, 3),
            b'$' if self.rest().starts_with(b"$and") => (TokenKind::SpecAnd, 4),
            b'$' if self.rest().starts_with(b"$xor") => (TokenKind::SpecXor, 4),
            b'$' | b'@' | b'?' if mode == Mode::Display => (TokenKind::DispChar, 1),
            b'#' => (TokenKind::Hash, 1),
            _ => {
                // Consume one whole character so spans stay on boundaries.
                let len = self
                    .src
                    .get(self.pos..)
                    .and_then(|s| s.chars().next())
                    .map_or(1, char::len_utf8);
                (TokenKind::Unknown, len)
            }
        };
        self.token(kind, len)
    }

    /// An identifier, or in semantic mode an `s`/`f` operator.
    fn word(&mut self, mode: Mode, names: &mut Interner) -> Token {
        let len = self.count_while(0, is_ident_continue);
        if len == 1
            && mode == Mode::Semantic
            && let Some((kind, op_len)) = self.prefixed_operator()
        {
            return self.token(kind, op_len);
        }
        let text = self.src.get(self.pos..self.pos + len).unwrap_or("");
        let kind = match text {
            "..." => TokenKind::Ellipsis,
            "_" => TokenKind::Underscore,
            _ => TokenKind::Ident,
        };
        let mut token = self.token(kind, len);
        if kind == TokenKind::Ident {
            token.symbol = names.intern(text);
        }
        token
    }

    /// The signed or floating-point operator starting at a lone `s` or `f`.
    fn prefixed_operator(&self) -> Option<(TokenKind, usize)> {
        let (a, b) = (self.byte(1)?, self.byte(2));
        let found = match (self.byte(0)?, a, b) {
            (b'f', b'=', Some(b'=')) => (TokenKind::FEqual, 3),
            (b'f', b'!', Some(b'=')) => (TokenKind::FNotEqual, 3),
            (b'f', b'<', Some(b'=')) => (TokenKind::FLessEqual, 3),
            (b'f', b'>', Some(b'=')) => (TokenKind::FGreatEqual, 3),
            (b'f', b'<', _) => (TokenKind::FLess, 2),
            (b'f', b'>', _) => (TokenKind::FGreat, 2),
            (b'f', b'+', _) => (TokenKind::FPlus, 2),
            (b'f', b'-', _) => (TokenKind::FMinus, 2),
            (b'f', b'*', _) => (TokenKind::FMult, 2),
            (b'f', b'/', _) => (TokenKind::FDiv, 2),
            (b's', b'<', Some(b'=')) => (TokenKind::SLessEqual, 3),
            (b's', b'>', Some(b'=')) => (TokenKind::SGreatEqual, 3),
            (b's', b'>', Some(b'>')) => (TokenKind::SRight, 3),
            (b's', b'<', _) => (TokenKind::SLess, 2),
            (b's', b'>', _) => (TokenKind::SGreat, 2),
            (b's', b'/', _) => (TokenKind::SDiv, 2),
            (b's', b'%', _) => (TokenKind::SRem, 2),
            _ => return None,
        };
        Some(found)
    }

    /// An integer literal. A prefix without digits (`0x`, `0b`, `0n`) is not
    /// a literal: the `0` stands alone and an identifier follows.
    fn number(&self) -> (TokenKind, usize) {
        if self.byte(0) == Some(b'0') {
            let prefixed = match self.byte(1) {
                Some(b'x') => Some((
                    TokenKind::HexInt,
                    self.count_while(2, |b| b.is_ascii_hexdigit()),
                )),
                Some(b'b') => Some((
                    TokenKind::BinInt,
                    self.count_while(2, |b| matches!(b, b'0' | b'1')),
                )),
                Some(b'n') => Some((
                    TokenKind::PrefixedDecInt,
                    self.count_while(2, |b| b.is_ascii_digit()),
                )),
                _ => None,
            };
            if let Some((kind, digits)) = prefixed
                && digits > 0
            {
                return (kind, 2 + digits);
            }
        }
        (
            TokenKind::DecInt,
            self.count_while(0, |b| b.is_ascii_digit()),
        )
    }

    /// A quoted string. Strings may span lines; a backslash starts one of
    /// the escapes of `BaseLexer.g`.
    fn string(&self) -> (TokenKind, usize) {
        let rest = self.rest();
        let mut i = 1;
        let mut kind = TokenKind::QString;
        loop {
            let Some(found) = memchr::memchr2(b'"', b'\\', rest.get(i..).unwrap_or(&[])) else {
                return (TokenKind::UnterminatedString, rest.len());
            };
            i += found;
            if rest.get(i) == Some(&b'"') {
                return (kind, i + 1);
            }
            let escape = escape_len(rest.get(i + 1..).unwrap_or(&[]));
            if escape == 0 {
                kind = TokenKind::BadString;
                // Skip the backslash and, if it is there, the character it
                // was meant to escape, so `\"`-like typos do not end the
                // string early.
                let next = self
                    .src
                    .get(self.pos + i + 1..)
                    .and_then(|s| s.chars().next())
                    .map_or(0, char::len_utf8);
                i += 1 + next;
            } else {
                i += 1 + escape;
            }
        }
    }
}

/// The content of a string token's text: the part between the quotes,
/// without any expansion marks the preprocessor left in it.
pub fn string_content(token_text: &str) -> std::borrow::Cow<'_, str> {
    let inner = token_text
        .strip_prefix('"')
        .map_or(token_text, |s| s.strip_suffix('"').unwrap_or(s));
    if inner.contains(crate::source::EXPANSION_MARK) {
        std::borrow::Cow::Owned(inner.replace(crate::source::EXPANSION_MARK, ""))
    } else {
        std::borrow::Cow::Borrowed(inner)
    }
}

#[cfg(test)]
mod tests;
