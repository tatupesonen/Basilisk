//! The snippet lexer (Ghidra's `PcodeLexer`, `pcodeparse.y` 228–630).
//!
//! It is not the SLEIGH lexer: identifiers may contain `.`, `#` starts a
//! comment to the end of the line, there are no strings, numbers are read
//! the way C++ streams read them with base detection (`0x` hexadecimal, a
//! leading `0` octal), a NUL byte ends the text, and any byte that cannot
//! start a token ends the input for the parser.

use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::BinaryOp;

/// A built-in operator written like a function call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Builtin {
    Abs,
    /// A keyword of the lexer that no grammar rule uses.
    Borrow,
    Carry,
    Ceil,
    Float2Float,
    Floor,
    Int2Float,
    Nan,
    Round,
    SBorrow,
    SCarry,
    Sext,
    Sqrt,
    Trunc,
    Zext,
}

impl Builtin {
    /// The keyword, which is also the name `bk_sleigh_compiler`'s builder
    /// recognises.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Abs => "abs",
            Self::Borrow => "borrow",
            Self::Carry => "carry",
            Self::Ceil => "ceil",
            Self::Float2Float => "float2float",
            Self::Floor => "floor",
            Self::Int2Float => "int2float",
            Self::Nan => "nan",
            Self::Round => "round",
            Self::SBorrow => "sborrow",
            Self::SCarry => "scarry",
            Self::Sext => "sext",
            Self::Sqrt => "sqrt",
            Self::Trunc => "trunc",
            Self::Zext => "zext",
        }
    }

    /// The number of arguments the grammar takes (`None`: no rule).
    pub(crate) const fn arity(self) -> Option<usize> {
        match self {
            Self::Borrow => None,
            Self::Carry | Self::SCarry | Self::SBorrow => Some(2),
            _ => Some(1),
        }
    }
}

/// A statement keyword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Keyword {
    Goto,
    Call,
    Return,
    If,
    Local,
}

/// What a token is, before names are looked up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tok {
    /// An integer that fits in 64 bits.
    Int(u64),
    /// An integer the stream could not read (`BADINTEGER`).
    BadInt,
    /// An identifier that is not a keyword; its text is the span's.
    Name,
    /// A one-character token.
    Punct(u8),
    /// A two- or three-character operator (`==`, `s<=`, `f+`, ...).
    Op(BinaryOp),
    /// A statement keyword.
    Keyword(Keyword),
    /// A built-in operator.
    Builtin(Builtin),
    /// The end of the text (`ENDOFSTREAM`).
    EndOfStream,
    /// What the parser sees after the end, or at a byte that cannot start a
    /// token (Ghidra's token 0).
    Eof,
}

/// A token and where it is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) tok: Tok,
    pub(crate) span: Span,
}

/// The lexer over the bytes of one snippet.
#[derive(Debug)]
pub(crate) struct Lexer<'t> {
    text: &'t [u8],
    pos: usize,
    finished: bool,
    end_sent: bool,
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.'
}

fn span(start: usize, end: usize) -> Span {
    Span::new(
        u32::try_from(start).unwrap_or(u32::MAX),
        u32::try_from(end).unwrap_or(u32::MAX),
    )
}

/// The keyword spelled by an identifier or operator token, if any
/// (`PcodeLexer::idents`).
fn keyword(text: &[u8]) -> Option<Tok> {
    Some(match text {
        b"!=" => Tok::Op(BinaryOp::NotEqual),
        b"&&" => Tok::Op(BinaryOp::BoolAnd),
        b"<<" => Tok::Op(BinaryOp::Left),
        b"<=" => Tok::Op(BinaryOp::LessEqual),
        b"==" => Tok::Op(BinaryOp::Equal),
        b">=" => Tok::Op(BinaryOp::GreatEqual),
        b">>" => Tok::Op(BinaryOp::Right),
        b"^^" => Tok::Op(BinaryOp::BoolXor),
        b"||" => Tok::Op(BinaryOp::BoolOr),
        b"f!=" => Tok::Op(BinaryOp::FNotEqual),
        b"f*" => Tok::Op(BinaryOp::FMult),
        b"f+" => Tok::Op(BinaryOp::FAdd),
        b"f-" => Tok::Op(BinaryOp::FSub),
        b"f/" => Tok::Op(BinaryOp::FDiv),
        b"f<" => Tok::Op(BinaryOp::FLess),
        b"f<=" => Tok::Op(BinaryOp::FLessEqual),
        b"f==" => Tok::Op(BinaryOp::FEqual),
        b"f>" => Tok::Op(BinaryOp::FGreat),
        b"f>=" => Tok::Op(BinaryOp::FGreatEqual),
        b"s%" => Tok::Op(BinaryOp::SRem),
        b"s/" => Tok::Op(BinaryOp::SDiv),
        b"s<" => Tok::Op(BinaryOp::SLess),
        b"s<=" => Tok::Op(BinaryOp::SLessEqual),
        b"s>" => Tok::Op(BinaryOp::SGreat),
        b"s>=" => Tok::Op(BinaryOp::SGreatEqual),
        b"s>>" => Tok::Op(BinaryOp::SRight),
        b"call" => Tok::Keyword(Keyword::Call),
        b"goto" => Tok::Keyword(Keyword::Goto),
        b"if" => Tok::Keyword(Keyword::If),
        b"local" => Tok::Keyword(Keyword::Local),
        b"return" => Tok::Keyword(Keyword::Return),
        b"abs" => Tok::Builtin(Builtin::Abs),
        b"borrow" => Tok::Builtin(Builtin::Borrow),
        b"carry" => Tok::Builtin(Builtin::Carry),
        b"ceil" => Tok::Builtin(Builtin::Ceil),
        b"float2float" => Tok::Builtin(Builtin::Float2Float),
        b"floor" => Tok::Builtin(Builtin::Floor),
        b"int2float" => Tok::Builtin(Builtin::Int2Float),
        b"nan" => Tok::Builtin(Builtin::Nan),
        b"round" => Tok::Builtin(Builtin::Round),
        b"sborrow" => Tok::Builtin(Builtin::SBorrow),
        b"scarry" => Tok::Builtin(Builtin::SCarry),
        b"sext" => Tok::Builtin(Builtin::Sext),
        b"sqrt" => Tok::Builtin(Builtin::Sqrt),
        b"trunc" => Tok::Builtin(Builtin::Trunc),
        b"zext" => Tok::Builtin(Builtin::Zext),
        _ => return None,
    })
}

/// Reads a number token as `istream >> uintb` does with base detection:
/// `0x` and hexadecimal digits, a leading `0` and octal digits (reading
/// stops quietly at the first digit that is not octal), else decimal.
/// `None` where the stream fails: no hexadecimal digit after `0x`, or a
/// value past 64 bits.
pub(crate) fn number_value(text: &[u8]) -> Option<u64> {
    let (digits, radix): (&[u8], u32) = match text {
        [b'0', b'x' | b'X', rest @ ..] => {
            if rest.is_empty() {
                return None;
            }
            (rest, 16)
        }
        [b'0', ..] => (text, 8),
        _ => (text, 10),
    };
    let mut value: u64 = 0;
    for &c in digits {
        let Some(d) = char::from(c).to_digit(radix) else {
            break;
        };
        value = value
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(d))?;
    }
    Some(value)
}

impl<'t> Lexer<'t> {
    /// A lexer over `text`.
    pub(crate) fn new(text: &'t [u8]) -> Self {
        Self {
            text,
            pos: 0,
            finished: false,
            end_sent: false,
        }
    }

    /// The text of a span.
    pub(crate) fn slice(&self, span: Span) -> &'t [u8] {
        self.text.get(span.range()).unwrap_or(&[])
    }

    /// The byte at `i`; 0 past the end (the C++ lexer's look-ahead).
    fn at(&self, i: usize) -> u8 {
        self.text.get(i).copied().unwrap_or(0)
    }

    fn end(&mut self, at: usize) -> Token {
        self.finished = true;
        let tok = if self.end_sent {
            Tok::Eof
        } else {
            self.end_sent = true;
            Tok::EndOfStream
        };
        Token {
            tok,
            span: span(at, at),
        }
    }

    /// The next token.
    pub(crate) fn next_token(&mut self) -> Token {
        if self.finished {
            return self.end(self.pos);
        }
        loop {
            let start = self.pos;
            let c = self.at(start);
            let la1 = self.at(start + 1);
            let la2 = self.at(start + 2);
            let fixed = |len: usize| (start + len, None);
            let (end, tok) = match c {
                0 => return self.end(start),
                b'\n' | b' ' | b'\t' | 0x0b | b'\r' => {
                    self.pos += 1;
                    continue;
                }
                b'#' => {
                    let mut i = start + 1;
                    while !matches!(self.at(i), b'\n' | 0) {
                        i += 1;
                    }
                    self.pos = i;
                    continue;
                }
                b'|' if la1 == b'|' => fixed(2),
                b'&' if la1 == b'&' => fixed(2),
                b'^' if la1 == b'^' => fixed(2),
                b'>' if matches!(la1, b'>' | b'=') => fixed(2),
                b'<' if matches!(la1, b'<' | b'=') => fixed(2),
                b'=' | b'!' if la1 == b'=' => fixed(2),
                b'|' | b'&' | b'^' | b'>' | b'<' | b'=' | b'!' | b'(' | b')' | b',' | b':'
                | b'[' | b']' | b';' | b'+' | b'-' | b'*' | b'/' | b'%' | b'~' => {
                    (start + 1, Some(Tok::Punct(c)))
                }
                b's' if matches!(la1, b'/' | b'%') => fixed(2),
                b's' if la1 == b'<' => fixed(if la2 == b'=' { 3 } else { 2 }),
                b's' if la1 == b'>' => fixed(if matches!(la2, b'>' | b'=') { 3 } else { 2 }),
                b'f' if matches!(la1, b'+' | b'-' | b'*' | b'/') => fixed(2),
                b'f' if matches!(la1, b'=' | b'!') && la2 == b'=' => fixed(3),
                b'f' if matches!(la1, b'<' | b'>') => fixed(if la2 == b'=' { 3 } else { 2 }),
                c if c.is_ascii_alphabetic() || c == b'_' || c == b'.' => {
                    let mut i = start + 1;
                    while is_ident(self.at(i)) {
                        i += 1;
                    }
                    (i, None)
                }
                b'0' if la1 == b'x' => {
                    let mut i = start + 2;
                    while self.at(i).is_ascii_hexdigit() {
                        i += 1;
                    }
                    let tok = number_value(self.text.get(start..i).unwrap_or(&[]))
                        .map_or(Tok::BadInt, Tok::Int);
                    (i, Some(tok))
                }
                b'0'..=b'9' => {
                    let mut i = start + 1;
                    while self.at(i).is_ascii_digit() {
                        i += 1;
                    }
                    let tok = number_value(self.text.get(start..i).unwrap_or(&[]))
                        .map_or(Tok::BadInt, Tok::Int);
                    (i, Some(tok))
                }
                _ => {
                    // An illegal character: token 0, after which the C++
                    // lexer only reports the end.
                    self.pos = start;
                    self.finished = true;
                    self.end_sent = true;
                    return Token {
                        tok: Tok::Eof,
                        span: span(start, start + 1),
                    };
                }
            };
            self.pos = end;
            let sp = span(start, end);
            let tok = tok.unwrap_or_else(|| keyword(self.slice(sp)).unwrap_or(Tok::Name));
            return Token { tok, span: sp };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(text: &str) -> Vec<Tok> {
        let mut lexer = Lexer::new(text.as_bytes());
        let mut out = Vec::new();
        loop {
            let t = lexer.next_token();
            out.push(t.tok);
            if matches!(t.tok, Tok::Eof) || out.len() > 64 {
                return out;
            }
        }
    }

    #[test]
    fn numbers_follow_stream_base_detection() {
        assert_eq!(number_value(b"010"), Some(8));
        assert_eq!(number_value(b"09"), Some(0));
        assert_eq!(number_value(b"0189"), Some(1));
        assert_eq!(number_value(b"0x1F"), Some(31));
        assert_eq!(number_value(b"0x"), None);
        assert_eq!(number_value(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(number_value(b"18446744073709551616"), None);
        assert_eq!(number_value(b"0x10000000000000000"), None);
        assert_eq!(number_value(b"0"), Some(0));
    }

    #[test]
    fn operators_and_identifiers() {
        assert_eq!(
            toks("s<= s< s>> s> f== f! f<x a.b_1 #c\n0x"),
            vec![
                Tok::Op(BinaryOp::SLessEqual),
                Tok::Op(BinaryOp::SLess),
                Tok::Op(BinaryOp::SRight),
                Tok::Op(BinaryOp::SGreat),
                Tok::Op(BinaryOp::FEqual),
                Tok::Name,
                Tok::Punct(b'!'),
                Tok::Op(BinaryOp::FLess),
                Tok::Name,
                Tok::Name,
                Tok::BadInt,
                Tok::EndOfStream,
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn nul_ends_and_illegal_bytes_stop() {
        assert_eq!(toks("a\0b"), vec![Tok::Name, Tok::EndOfStream, Tok::Eof]);
        assert_eq!(toks("a @ b"), vec![Tok::Name, Tok::Eof]);
        assert_eq!(
            toks("goto borrow"),
            vec![
                Tok::Keyword(Keyword::Goto),
                Tok::Builtin(Builtin::Borrow),
                Tok::EndOfStream,
                Tok::Eof
            ]
        );
    }
}
