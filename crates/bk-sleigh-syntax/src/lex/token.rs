//! Tokens.

use crate::intern::Symbol;
use crate::span::Span;

/// The lexer mode, chosen by the parser for each token it asks for.
///
/// The modes are those of Ghidra's ANTLR lexers (`BaseLexer.g`,
/// `DisplayLexer.g`, `SemanticLexer.g`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Mode {
    /// Definitions, patterns, context blocks, `with` and `macro` headers.
    Base,
    /// The print pieces between a constructor's `:` and `is`: whitespace is
    /// a token, `#` is a print piece rather than a comment, and `@ $ ?` are
    /// accepted.
    Display,
    /// Inside `{ ... }`: adds the signed (`s<`, `s>>`, ...) and
    /// floating-point (`f+`, `f==`, ...) operators.
    Semantic,
}

/// The kind of a [`Token`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TokenKind {
    /// An identifier, keyword or reserved word; [`Token::ident`] gives its name.
    Ident,
    /// `_` on its own: the wildcard of identifier and value lists.
    Underscore,
    /// A decimal integer: `42`.
    DecInt,
    /// A hexadecimal integer: `0x2A`.
    HexInt,
    /// A binary integer: `0b101010`.
    BinInt,
    /// A decimal integer with the explicit `0n` prefix: `0n42`.
    PrefixedDecInt,
    /// A quoted string, quotes included in the span.
    QString,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `...`
    Ellipsis,
    /// `:`
    Colon,
    /// `,`
    Comma,
    /// `!`
    Exclaim,
    /// `~`
    Tilde,
    /// `;`
    Semi,
    /// `=`
    Assign,
    /// `==`
    Equal,
    /// `!=`
    NotEqual,
    /// `<`
    Less,
    /// `>`
    Great,
    /// `<=`
    LessEqual,
    /// `>=`
    GreatEqual,
    /// `||`
    BoolOr,
    /// `^^`
    BoolXor,
    /// `&&`
    BoolAnd,
    /// `|`
    Pipe,
    /// `^`
    Caret,
    /// `&`
    Ampersand,
    /// `<<`
    Left,
    /// `>>`
    Right,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Asterisk,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `$or`
    SpecOr,
    /// `$and`
    SpecAnd,
    /// `$xor`
    SpecXor,
    /// `f==` (semantic mode)
    FEqual,
    /// `f!=` (semantic mode)
    FNotEqual,
    /// `f<` (semantic mode)
    FLess,
    /// `f>` (semantic mode)
    FGreat,
    /// `f<=` (semantic mode)
    FLessEqual,
    /// `f>=` (semantic mode)
    FGreatEqual,
    /// `f+` (semantic mode)
    FPlus,
    /// `f-` (semantic mode)
    FMinus,
    /// `f*` (semantic mode)
    FMult,
    /// `f/` (semantic mode)
    FDiv,
    /// `s<` (semantic mode)
    SLess,
    /// `s>` (semantic mode)
    SGreat,
    /// `s<=` (semantic mode)
    SLessEqual,
    /// `s>=` (semantic mode)
    SGreatEqual,
    /// `s>>` (semantic mode)
    SRight,
    /// `s/` (semantic mode)
    SDiv,
    /// `s%` (semantic mode)
    SRem,
    /// A run of spaces, tabs and line breaks (display mode only).
    Whitespace,
    /// `@`, `$` or `?` (display mode only).
    DispChar,
    /// `#` (display mode only; elsewhere it starts a comment).
    Hash,
    /// `//`: C++ comments are not SLEIGH. Outside display mode the token
    /// runs to the end of the line.
    CppComment,
    /// A string with an invalid escape sequence.
    BadString,
    /// A string with no closing quote; it runs to the end of the input.
    UnterminatedString,
    /// A character that cannot start any token.
    Unknown,
    /// End of input.
    Eof,
}

impl TokenKind {
    /// Whether the lexer produced this kind to flag invalid input.
    pub const fn is_error(self) -> bool {
        matches!(
            self,
            Self::CppComment | Self::BadString | Self::UnterminatedString | Self::Unknown
        )
    }

    /// Whether this is one of the integer literal kinds.
    pub const fn is_int(self) -> bool {
        matches!(
            self,
            Self::DecInt | Self::HexInt | Self::BinInt | Self::PrefixedDecInt
        )
    }

    /// A short description for error messages: the token's spelling in
    /// backquotes when it has only one, otherwise what it is.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Ident => "identifier",
            Self::Underscore => "`_`",
            Self::DecInt | Self::HexInt | Self::BinInt | Self::PrefixedDecInt => "integer",
            Self::QString => "string",
            Self::LBrace => "`{`",
            Self::RBrace => "`}`",
            Self::LBracket => "`[`",
            Self::RBracket => "`]`",
            Self::LParen => "`(`",
            Self::RParen => "`)`",
            Self::Ellipsis => "`...`",
            Self::Colon => "`:`",
            Self::Comma => "`,`",
            Self::Exclaim => "`!`",
            Self::Tilde => "`~`",
            Self::Semi => "`;`",
            Self::Assign => "`=`",
            Self::Equal => "`==`",
            Self::NotEqual => "`!=`",
            Self::Less => "`<`",
            Self::Great => "`>`",
            Self::LessEqual => "`<=`",
            Self::GreatEqual => "`>=`",
            Self::BoolOr => "`||`",
            Self::BoolXor => "`^^`",
            Self::BoolAnd => "`&&`",
            Self::Pipe => "`|`",
            Self::Caret => "`^`",
            Self::Ampersand => "`&`",
            Self::Left => "`<<`",
            Self::Right => "`>>`",
            Self::Plus => "`+`",
            Self::Minus => "`-`",
            Self::Asterisk => "`*`",
            Self::Slash => "`/`",
            Self::Percent => "`%`",
            Self::SpecOr => "`$or`",
            Self::SpecAnd => "`$and`",
            Self::SpecXor => "`$xor`",
            Self::FEqual => "`f==`",
            Self::FNotEqual => "`f!=`",
            Self::FLess => "`f<`",
            Self::FGreat => "`f>`",
            Self::FLessEqual => "`f<=`",
            Self::FGreatEqual => "`f>=`",
            Self::FPlus => "`f+`",
            Self::FMinus => "`f-`",
            Self::FMult => "`f*`",
            Self::FDiv => "`f/`",
            Self::SLess => "`s<`",
            Self::SGreat => "`s>`",
            Self::SLessEqual => "`s<=`",
            Self::SGreatEqual => "`s>=`",
            Self::SRight => "`s>>`",
            Self::SDiv => "`s/`",
            Self::SRem => "`s%`",
            Self::Whitespace => "whitespace",
            Self::DispChar => "display character",
            Self::Hash => "`#`",
            Self::CppComment => "`//`",
            Self::BadString | Self::UnterminatedString => "malformed string",
            Self::Unknown => "unexpected character",
            Self::Eof => "end of input",
        }
    }
}

/// One token: its kind, where it is, and its name if it is an identifier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// Its extent in the preprocessed text.
    pub span: Span,
    /// The interned name of an [`TokenKind::Ident`]; unspecified otherwise.
    pub(crate) symbol: Symbol,
}

impl Token {
    /// The name, if this is an identifier (keywords included).
    pub fn ident(&self) -> Option<Symbol> {
        (self.kind == TokenKind::Ident).then_some(self.symbol)
    }

    /// Whether this is the identifier `word`.
    pub fn is_word(&self, word: Symbol) -> bool {
        self.kind == TokenKind::Ident && self.symbol == word
    }
}
