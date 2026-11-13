//! Reads `licd.bkdemo`, the generated demo program (format: the header of
//! that file and `demo/generate.py`).

/// A memory block record.
#[derive(Debug, Clone)]
pub(crate) struct RawSection {
    pub segment: String,
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub flags: String,
}

/// An instruction record.
#[derive(Debug, Clone)]
pub(crate) struct RawInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub line: u32,
}

/// A data record.
#[derive(Debug, Clone)]
pub(crate) struct RawData {
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub datatype: String,
    pub bytes: Vec<u8>,
}

/// Everything in the file, record by record.
#[derive(Debug, Default)]
pub(crate) struct RawProgram {
    pub name: String,
    pub language: String,
    pub format: String,
    pub image_base: u64,
    pub sections: Vec<RawSection>,
    /// (start, end, name)
    pub functions: Vec<(u64, u64, String)>,
    /// (stub address, name, pointer address)
    pub imports: Vec<(u64, String, u64)>,
    pub data: Vec<RawData>,
    /// (address, text)
    pub strings: Vec<(u64, String)>,
    pub insns: Vec<RawInsn>,
    /// (function name, line number, text)
    pub source: Vec<(String, u32, String)>,
    /// (address, kind, text) with kind one of EOL, PRE, PLATE.
    pub comments: Vec<(u64, String, String)>,
}

/// A malformed record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("demo program line {line}: {what}")]
pub struct ParseError {
    /// 1-based line number.
    pub line: usize,
    /// What was wrong.
    pub what: String,
}

fn num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

/// Undoes the file's escapes (`\t`, `\n`, `\\`).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses the whole file.
pub(crate) fn parse(text: &str) -> Result<RawProgram, ParseError> {
    let mut p = RawProgram::default();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let bad = |what: &str| ParseError {
            line: i + 1,
            what: what.to_owned(),
        };
        let field = |n: usize| f.get(n).copied().ok_or_else(|| bad("missing field"));
        let number = |n: usize| field(n).and_then(|s| num(s).ok_or_else(|| bad("bad number")));
        match field(0)? {
            "PROGRAM" => {
                field(1)?.clone_into(&mut p.name);
                field(2)?.clone_into(&mut p.language);
                field(3)?.clone_into(&mut p.format);
                p.image_base = number(4)?;
            }
            "SECTION" => p.sections.push(RawSection {
                segment: field(1)?.to_owned(),
                name: field(2)?.to_owned(),
                start: number(3)?,
                size: number(4)?,
                flags: field(5)?.to_owned(),
            }),
            "FUNC" => p
                .functions
                .push((number(1)?, number(2)?, field(3)?.to_owned())),
            "IMPORT" => p
                .imports
                .push((number(1)?, field(2)?.to_owned(), number(3)?)),
            "DATA" => p.data.push(RawData {
                address: number(1)?,
                size: number(2)?,
                name: field(3)?.to_owned(),
                datatype: field(4)?.to_owned(),
                bytes: hex_bytes(field(5)?).ok_or_else(|| bad("bad bytes"))?,
            }),
            "STRING" => p.strings.push((number(1)?, unescape(field(2)?))),
            "INSN" => p.insns.push(RawInsn {
                address: number(1)?,
                bytes: hex_bytes(field(2)?).ok_or_else(|| bad("bad bytes"))?,
                mnemonic: field(3)?.to_owned(),
                operands: field(4)?.to_owned(),
                line: u32::try_from(number(5)?).map_err(|e| bad(&format!("line number: {e}")))?,
            }),
            "SRC" => p.source.push((
                field(1)?.to_owned(),
                u32::try_from(number(2)?).map_err(|e| bad(&format!("line number: {e}")))?,
                unescape(f.get(3).copied().unwrap_or_default()),
            )),
            kind @ ("EOL" | "PRE" | "PLATE") => {
                p.comments
                    .push((number(1)?, kind.to_owned(), unescape(field(2)?)));
            }
            other => return Err(bad(&format!("unknown record {other:?}"))),
        }
    }
    if p.name.is_empty() {
        return Err(ParseError {
            line: 0,
            what: "no PROGRAM record".into(),
        });
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records_and_escapes() {
        let p = parse(
            "# c\nPROGRAM\tx\tlang\tfmt\t0x1000\nSTRING\t0x1004\ta\\tb\\n\nINSN\t0x1000\t55\tPUSH\tRBP\t3\n",
        )
        .unwrap();
        assert_eq!(p.name, "x");
        assert_eq!(p.strings[0].1, "a\tb\n");
        assert_eq!(p.insns[0].bytes, vec![0x55]);
    }

    #[test]
    fn rejects_bad_records_with_the_line() {
        let e = parse("PROGRAM\tx\tl\tf\t0x0\nINSN\t0xzz\n").unwrap_err();
        assert_eq!(e.line, 2);
        assert!(parse("").is_err());
    }
}
