//! The C declaration lexer (Ghidra `GrammarLexer` and `GrammarToken` in
//! `grammar.y`).
//!
//! The state machine and its line buffer are kept exactly, because error
//! messages print the buffer and a caret under the offending token, and
//! because character constants read their value from wherever the buffer's
//! token start happens to be (a quirk of Ghidra's that is reproduced).

/// Ghidra's buffer size per line (`CParse(glb, 4096)`).
pub const LINE_BUFFER: usize = 4096;

/// A raw token kind (Ghidra `GrammarToken` types).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Raw {
    /// A punctuation character.
    Punct(u8),
    /// A lexical error; the message is in [`Lexer::error`].
    Bad,
    /// End of input.
    Eof,
    /// `...`
    DotDotDot,
    /// `::`
    ScopeRes,
    /// An integer or character constant.
    Number(u64),
    /// An identifier.
    Ident(String),
    /// A string constant.
    Str,
}

/// A token with Ghidra's position (line and column of its start in the
/// line buffer; -1 when unknown).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) raw: Raw,
    pub(crate) line: i32,
    pub(crate) col: i32,
    pub(crate) file: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Start,
    Slash,
    Dot1,
    Dot2,
    Dot3,
    ScopeRes1,
    ScopeRes2,
    Punctuation,
    EndOfLineComment,
    CComment,
    DoubleQuote,
    DoubleQuoteEnd,
    SingleQuote,
    SingleQuoteEnd,
    SingleBackslash,
    Number,
    Identifier,
}

/// What a state transition produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    None,
    Bad,
    Punct(u8),
    DotDotDot,
    ScopeRes,
    Integer,
    CharConst,
    Ident,
    Str,
}

/// The lexer over one input text.
#[derive(Debug)]
pub(crate) struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
    buffer: Vec<u8>,
    bufstart: usize,
    curlineno: i32,
    state: State,
    endoffile: bool,
    /// The last lexical error.
    pub(crate) error: String,
    /// Text of the last token, kept when a newline cleared the buffer
    /// before the token was taken out of it.
    saved: Option<(Vec<u8>, usize)>,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
            buffer: Vec::with_capacity(128),
            bufstart: 0,
            curlineno: 0,
            state: State::Start,
            endoffile: false,
            error: String::new(),
            saved: None,
        }
    }

    /// The current line number of the buffer.
    pub(crate) const fn line(&self) -> i32 {
        self.curlineno
    }

    /// The bytes in the line buffer (for error locations).
    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    fn bump_line(&mut self) {
        // Keep the current token's text, which Ghidra would read from the
        // cleared buffer (past its end, undefined behaviour).
        self.saved = Some((self.buffer.clone(), self.bufstart));
        self.curlineno += 1;
        self.bufstart = 0;
        self.buffer.clear();
    }

    fn set_error(&mut self, msg: &str) {
        msg.clone_into(&mut self.error);
    }

    fn move_state(&mut self, lookahead: u8) -> Out {
        let mut newline = false;
        let signed = lookahead as i8;
        let mut c = lookahead;
        if signed < 32 {
            if matches!(lookahead, 9 | 11 | 12 | 13) {
                c = b' ';
            } else if lookahead == b'\n' {
                newline = true;
                c = b' ';
            } else {
                self.set_error("Illegal character");
                return Out::Bad;
            }
        } else if signed >= 127 {
            self.set_error("Illegal character");
            return Out::Bad;
        }
        let bufend = self.buffer.len();
        let mut res = Out::None;
        let mut syntax = false;
        match self.state {
            State::Start => match c {
                b'/' => self.state = State::Slash,
                b'.' => self.state = State::Dot1,
                b'*' | b',' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b';' | b'=' => {
                    self.state = State::Punctuation;
                    self.bufstart = bufend.saturating_sub(1);
                }
                b':' => self.state = State::ScopeRes1,
                b'-' | b'0'..=b'9' => {
                    self.state = State::Number;
                    self.bufstart = bufend.saturating_sub(1);
                }
                b' ' => {}
                b'"' => {
                    self.state = State::DoubleQuote;
                    self.bufstart = bufend.saturating_sub(1);
                }
                b'\'' => self.state = State::SingleQuote,
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                    self.state = State::Identifier;
                    self.bufstart = bufend.saturating_sub(1);
                }
                _ => {
                    self.set_error("Illegal character");
                    return Out::Bad;
                }
            },
            State::Slash => match c {
                b'*' => self.state = State::CComment,
                b'/' => self.state = State::EndOfLineComment,
                _ => syntax = true,
            },
            State::Dot1 => {
                if c == b'.' {
                    self.state = State::Dot2;
                } else {
                    syntax = true;
                }
            }
            State::Dot2 => {
                if c == b'.' {
                    self.state = State::Dot3;
                } else {
                    syntax = true;
                }
            }
            State::Dot3 => {
                self.state = State::Start;
                res = Out::DotDotDot;
            }
            State::ScopeRes1 => {
                if c == b':' {
                    self.state = State::ScopeRes2;
                } else {
                    self.state = State::Start;
                    res = Out::Punct(b':');
                }
            }
            State::ScopeRes2 => {
                self.state = State::Start;
                res = Out::ScopeRes;
            }
            State::Punctuation => {
                self.state = State::Start;
                res = Out::Punct(self.buffer.get(self.bufstart).copied().unwrap_or(b' '));
            }
            State::EndOfLineComment => {
                if newline {
                    self.state = State::Start;
                }
            }
            State::CComment => {
                if c == b'/' && bufend > 1 && self.buffer.get(bufend - 2) == Some(&b'*') {
                    self.state = State::Start;
                }
            }
            State::DoubleQuote => {
                if c == b'"' {
                    self.state = State::DoubleQuoteEnd;
                }
            }
            State::DoubleQuoteEnd => {
                self.state = State::Start;
                res = Out::Str;
            }
            State::SingleQuote => {
                if c == b'\\' {
                    self.state = State::SingleBackslash;
                } else if c == b'\'' {
                    self.state = State::SingleQuoteEnd;
                }
            }
            State::SingleQuoteEnd => {
                self.state = State::Start;
                res = Out::CharConst;
            }
            State::SingleBackslash => self.state = State::SingleQuote,
            State::Number => {
                if c == b'x' {
                    if bufend.saturating_sub(self.bufstart) != 2
                        || self.buffer.get(self.bufstart) != Some(&b'0')
                    {
                        syntax = true;
                    }
                } else if !(c.is_ascii_alphanumeric() || c == b'_') {
                    self.state = State::Start;
                    res = Out::Integer;
                }
            }
            State::Identifier => {
                if !(c.is_ascii_alphanumeric() || c == b'_') {
                    self.state = State::Start;
                    res = Out::Ident;
                }
            }
        }
        if syntax {
            self.set_error("Syntax error");
            return Out::Bad;
        }
        if newline {
            self.bump_line();
        }
        res
    }

    /// Ghidra `getNextToken`.
    pub(crate) fn next_token(&mut self) -> Token {
        if self.endoffile {
            return Token {
                raw: Raw::Eof,
                line: -1,
                col: -1,
                file: -1,
            };
        }
        self.saved = None;
        let mut out = Out::Bad;
        let mut first = true;
        loop {
            let c = if !first || self.buffer.is_empty() {
                if self.buffer.len() >= LINE_BUFFER {
                    self.set_error("Line too long");
                    out = Out::Bad;
                    break;
                }
                let Some(&c) = self.input.get(self.pos) else {
                    self.endoffile = true;
                    break;
                };
                self.pos += 1;
                self.buffer.push(c);
                c
            } else {
                self.buffer.last().copied().unwrap_or(b' ')
            };
            out = self.move_state(c);
            first = false;
            if out != Out::None {
                break;
            }
        }
        if self.endoffile {
            self.buffer.push(b' ');
            out = self.move_state(b' ');
            if out == Out::None
                && self.state != State::Start
                && self.state != State::EndOfLineComment
            {
                self.set_error("Incomplete token");
                out = Out::Bad;
            }
        }
        self.establish(out)
    }

    /// The text of the token just recognised (without its lookahead).
    fn token_text(&self) -> Vec<u8> {
        let (buf, start) = match &self.saved {
            Some((b, s)) => (b.as_slice(), *s),
            None => (self.buffer.as_slice(), self.bufstart),
        };
        let end = buf.len().saturating_sub(1).max(start);
        buf.get(start..end).unwrap_or_default().to_vec()
    }

    fn establish(&mut self, out: Out) -> Token {
        let raw = match out {
            // A token of type 0 is end of input to bison.
            Out::None => Raw::Eof,
            Out::Bad => Raw::Bad,
            Out::Punct(p) => Raw::Punct(p),
            Out::DotDotDot => Raw::DotDotDot,
            Out::ScopeRes => Raw::ScopeRes,
            Out::Integer => Raw::Number(parse_integer(&self.token_text())),
            Out::CharConst => Raw::Number(char_value(&self.token_text())),
            Out::Ident => Raw::Ident(String::from_utf8_lossy(&self.token_text()).into_owned()),
            Out::Str => Raw::Str,
        };
        Token {
            raw,
            line: self.curlineno,
            col: self.bufstart as i32,
            file: 0,
        }
    }
}

/// Ghidra's character constant value: from the token text as the buffer
/// holds it (`len == 1` gives the byte itself, else an escape after the
/// first byte).
fn char_value(text: &[u8]) -> u64 {
    if text.len() == 1 {
        return text.first().map_or(0, |&b| i64::from(b as i8) as u64);
    }
    match text.get(1).copied() {
        Some(b'n') => 10,
        Some(b'0') => 0,
        Some(b'a') => 7,
        Some(b'b') => 8,
        Some(b't') => 9,
        Some(b'v') => 11,
        Some(b'f') => 12,
        Some(b'r') => 13,
        Some(b) => i64::from(b as i8) as u64,
        None => 0,
    }
}

/// Ghidra's integer token value: `istream >> intb` with the base detected
/// from the prefix (`0x` hex, `0` octal), stopping at the first character
/// that is not a digit; out of range saturates (C++11 `num_get`); no digits
/// gives 0.
pub(crate) fn parse_integer(text: &[u8]) -> u64 {
    let (neg, rest) = match text.split_first() {
        Some((b'-', r)) => (true, r),
        Some((b'+', r)) => (false, r),
        _ => (false, text),
    };
    let (radix, digits) = if rest.len() >= 2
        && rest.first() == Some(&b'0')
        && matches!(rest.get(1), Some(b'x' | b'X'))
    {
        (16u32, rest.get(2..).unwrap_or_default())
    } else if rest.first() == Some(&b'0') {
        (8, rest)
    } else {
        (10, rest)
    };
    let mut val: u128 = 0;
    let mut any = false;
    for &b in digits {
        let Some(d) = char::from(b).to_digit(radix) else {
            break;
        };
        any = true;
        val = val
            .saturating_mul(u128::from(radix))
            .saturating_add(u128::from(d));
    }
    if !any {
        return 0;
    }
    let v: i64 = if neg {
        if val > i64::MAX as u128 + 1 {
            i64::MIN
        } else {
            (val as i128).wrapping_neg() as i64
        }
    } else if val > i64::MAX as u128 {
        i64::MAX
    } else {
        val as i64
    };
    v as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<Raw> {
        let mut lx = Lexer::new(text);
        let mut out = Vec::new();
        loop {
            let t = lx.next_token();
            let stop = matches!(t.raw, Raw::Eof | Raw::Bad);
            out.push(t.raw);
            if stop {
                return out;
            }
        }
    }

    #[test]
    fn basic_tokens() {
        assert_eq!(
            tokens("int4 *a[0x10], ... :: b:3"),
            vec![
                Raw::Ident("int4".into()),
                Raw::Punct(b'*'),
                Raw::Ident("a".into()),
                Raw::Punct(b'['),
                Raw::Number(16),
                Raw::Punct(b']'),
                Raw::Punct(b','),
                Raw::DotDotDot,
                Raw::ScopeRes,
                Raw::Ident("b".into()),
                Raw::Punct(b':'),
                Raw::Number(3),
                Raw::Eof,
            ]
        );
    }

    #[test]
    fn integers() {
        assert_eq!(parse_integer(b"010"), 8);
        assert_eq!(parse_integer(b"-5"), (-5i64) as u64);
        assert_eq!(parse_integer(b"09"), 0);
        assert_eq!(parse_integer(b"12ab"), 12);
        assert_eq!(parse_integer(b"0xffffffffffffffff"), i64::MAX as u64);
        assert_eq!(parse_integer(b"-"), 0);
    }

    #[test]
    fn errors() {
        assert_eq!(tokens("a $"), vec![Raw::Ident("a".into()), Raw::Bad]);
        let mut lx = Lexer::new("1x");
        assert_eq!(lx.next_token().raw, Raw::Bad);
        assert_eq!(lx.error, "Syntax error");
        let mut lx = Lexer::new("/* open");
        assert_eq!(lx.next_token().raw, Raw::Bad);
        assert_eq!(lx.error, "Incomplete token");
        let long = "a".repeat(5000);
        let mut lx = Lexer::new(&long);
        assert_eq!(lx.next_token().raw, Raw::Bad);
        assert_eq!(lx.error, "Line too long");
    }

    #[test]
    fn comments_and_newlines() {
        assert_eq!(
            tokens("a // x\n/* y */ b\n"),
            vec![Raw::Ident("a".into()), Raw::Ident("b".into()), Raw::Eof]
        );
    }
}
