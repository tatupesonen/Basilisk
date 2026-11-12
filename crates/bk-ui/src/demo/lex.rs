//! Splitting the demo's text into tokens: instruction operands as Ghidra
//! prints them, and lines of decompiled C.

/// A piece of an operand string before symbols are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpPiece {
    /// A register name.
    Register(Box<str>),
    /// A scalar.
    Scalar(Box<str>),
    /// A value that may be an address in the program.
    Number { text: Box<str>, value: u64 },
    /// Size keywords (`dword ptr`) and other words.
    Word(Box<str>),
    /// Punctuation and spaces.
    Punct(Box<str>),
}

/// Splits an operand string such as `qword ptr [RBP + -0xd0],RDX`.
pub(crate) fn operands(text: &str) -> Vec<OpPiece> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        let len = if c.is_ascii_alphanumeric() || c == '_' {
            rest.find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
                .unwrap_or(rest.len())
        } else if c == '-' && rest.get(1..3) == Some("0x") {
            1 + rest
                .get(1..)
                .and_then(|r| r.find(|ch: char| !ch.is_ascii_alphanumeric()))
                .unwrap_or(rest.len() - 1)
        } else {
            c.len_utf8()
        };
        let (word, tail) = rest.split_at(len.min(rest.len()));
        rest = tail;
        let first = word.chars().next().unwrap_or(' ');
        if first.is_ascii_digit() || first == '-' && word.len() > 1 {
            let neg = word.starts_with('-');
            let digits = word.trim_start_matches('-');
            let value = digits
                .strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .or_else(|| digits.parse().ok());
            match value {
                Some(v) if !neg && v >= 0x1000 => out.push(OpPiece::Number {
                    text: word.into(),
                    value: v,
                }),
                _ => out.push(OpPiece::Scalar(word.into())),
            }
        } else if first.is_ascii_alphabetic() {
            if word.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit()) {
                out.push(OpPiece::Register(word.into()));
            } else {
                out.push(OpPiece::Word(word.into()));
            }
        } else {
            out.push(OpPiece::Punct(word.into()));
        }
    }
    out
}

/// A lexical class of decompiled C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CClass {
    Ident,
    Number,
    Char,
    String,
    Comment,
    Punct,
    Space,
}

/// Splits one line of C into classed pieces, keeping every character.
pub(crate) fn c_line(line: &str) -> Vec<(CClass, &str)> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b.get(i).copied().unwrap_or(b' ');
        let start = i;
        let class = if c.is_ascii_alphabetic() || c == b'_' {
            while b.get(i).is_some_and(|x| x.is_ascii_alphanumeric() || *x == b'_') {
                i += 1;
            }
            CClass::Ident
        } else if c.is_ascii_digit() {
            while b.get(i).is_some_and(|x| x.is_ascii_alphanumeric()) {
                i += 1;
            }
            CClass::Number
        } else if c == b'"' || c == b'\'' {
            i += 1;
            while let Some(&x) = b.get(i) {
                i += 1;
                if x == b'\\' {
                    i += 1;
                } else if x == c {
                    break;
                }
            }
            if c == b'"' {
                CClass::String
            } else {
                CClass::Char
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i = line
                .get(i + 2..)
                .and_then(|r| r.find("*/"))
                .map_or(b.len(), |p| i + 2 + p + 2);
            CClass::Comment
        } else if c == b' ' {
            while b.get(i) == Some(&b' ') {
                i += 1;
            }
            CClass::Space
        } else if c == b'-' && b.get(i + 1) == Some(&b'>') {
            i += 2;
            CClass::Punct
        } else {
            i += 1;
            CClass::Punct
        };
        let end = i.min(b.len());
        if let Some(s) = line.get(start..end) {
            out.push((class, s));
        }
    }
    out
}

/// C keywords coloured as keywords.
pub(crate) fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "if" | "else"
            | "while"
            | "do"
            | "for"
            | "return"
            | "break"
            | "continue"
            | "switch"
            | "case"
            | "default"
            | "goto"
            | "sizeof"
            | "struct"
            | "const"
    )
}

/// Type names in the demo's C.
pub(crate) fn is_type(w: &str) -> bool {
    matches!(
        w,
        "void"
            | "char"
            | "int"
            | "long"
            | "uint"
            | "ulong"
            | "byte"
            | "undefined"
            | "undefined4"
            | "undefined8"
            | "size_t"
            | "FILE"
            | "config_t"
            | "buffer_t"
            | "rc4_state_t"
            | "pid_t"
            | "time_t"
            | "va_list"
            | "addrinfo"
            | "utsname"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operands_split_into_registers_numbers_and_punctuation() {
        let p = operands("qword ptr [RBP + -0xd0],RDX");
        assert!(p.contains(&OpPiece::Register("RBP".into())));
        assert!(p.contains(&OpPiece::Scalar("-0xd0".into())));
        assert!(p.contains(&OpPiece::Word("qword".into())));
        let call = operands("0x100000c20");
        assert_eq!(
            call,
            vec![OpPiece::Number {
                text: "0x100000c20".into(),
                value: 0x1_0000_0c20
            }]
        );
        assert_eq!(operands("EAX,0x1")[2], OpPiece::Scalar("0x1".into()));
    }

    #[test]
    fn c_lines_keep_every_character() {
        let line = "  if (p->len < 0x10) { /* x */ s = \"a\\\"b\"; c = '\\0'; }";
        let pieces = c_line(line);
        let joined: String = pieces.iter().map(|(_, s)| *s).collect();
        assert_eq!(joined, line);
        assert!(pieces.contains(&(CClass::Comment, "/* x */")));
        assert!(pieces.contains(&(CClass::String, "\"a\\\"b\"")));
        assert!(pieces.contains(&(CClass::Punct, "->")));
        assert!(pieces.contains(&(CClass::Number, "0x10")));
    }
}
