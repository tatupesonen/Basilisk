//! Basilisk's p-code snippet oracle (`tools/reference/snippetdump.cc`):
//! Ghidra's `PcodeSnippet` compiling the `<pcode>` bodies of compiler and
//! processor specifications, as `PcodeInjectLibrarySleigh::parseInject`
//! does. The record format (version 1) is described in
//! `tools/reference/README.md`.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use super::ToolError;
use super::process::Invocation;
use crate::paths::Tool;

/// Where a record's temporaries start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnippetBase {
    /// Use the carried base and advance it (call fix-ups, injections).
    Continue,
    /// Set the carried base to this value, then continue from it.
    Start(u32),
    /// Use this base; the carried base is untouched (executable p-code).
    Fixed(u32),
}

/// One parameter of a snippet: the name the body uses and its operand index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnippetParameter {
    /// The operand (handle) index.
    pub index: u32,
    /// The name the body uses.
    pub name: String,
}

/// One snippet to compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnippetRecord {
    /// A label the tool echoes back (not interpreted).
    pub source: String,
    /// Where the temporaries start.
    pub base: SnippetBase,
    /// The snippet text.
    pub body: String,
    /// The parameters, added in this order.
    pub params: Vec<SnippetParameter>,
}

/// What the tool reported for one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnippetOutcome {
    /// Compiled, possibly with errors Ghidra ignores.
    Ok {
        /// The temporary base used.
        base: u32,
        /// The carried base afterwards.
        next: u32,
        /// The first error reported, when there was one.
        first_error: Option<String>,
        /// The template as `ConstructTpl::encode` writes it.
        xml: String,
    },
    /// `parseStream` returned false: the first error.
    Rejected {
        /// The temporary base used.
        base: u32,
        /// Ghidra's message.
        message: String,
    },
    /// An exception escaped the compile.
    Exception {
        /// The temporary base used.
        base: u32,
        /// The exception's text.
        message: String,
    },
}

/// Output that is not the documented record format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {reason}")]
pub struct SnippetParseError {
    /// The 1-based line of the output.
    pub line: usize,
    /// What was wrong with it.
    pub reason: String,
}

/// Writes `text` with the format's escapes (`\\`, `\t`, `\n`, `\r`, `\0`).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out
}

/// Reverses [`escape`]; an unknown escape stands for the character after
/// the backslash.
pub fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// The tool's input for `records`: one `S` line each.
pub fn write_records(records: &[SnippetRecord]) -> String {
    let mut input = String::new();
    for r in records {
        input.push_str("S\t");
        input.push_str(&escape(&r.source));
        input.push('\t');
        // Writing to a String cannot fail.
        let _ = match r.base {
            SnippetBase::Continue => write!(input, "continue"),
            SnippetBase::Start(b) => write!(input, "{b:#x}"),
            SnippetBase::Fixed(b) => write!(input, "fixed:{b:#x}"),
        };
        input.push('\t');
        input.push_str(&escape(&r.body));
        for p in &r.params {
            input.push('\t');
            input.push_str(&escape(&format!("{}:{}", p.index, p.name)));
        }
        input.push('\n');
    }
    input
}

/// Parses the tool's output: one outcome per `O` or `F` line, in order. The
/// `H` and `T` lines are checked for shape; the `T` counts must match.
pub fn parse_outcomes(text: &str) -> Result<Vec<SnippetOutcome>, SnippetParseError> {
    let mut out = Vec::new();
    let mut counts = (0_usize, 0_usize);
    let mut trailer = None;
    for (i, line) in text.lines().enumerate() {
        let number = i + 1;
        let bad = |reason: String| SnippetParseError {
            line: number,
            reason,
        };
        let f: Vec<&str> = line.split('\t').collect();
        let field = |n: usize| {
            f.get(n)
                .copied()
                .ok_or_else(|| bad(format!("missing field {n}")))
        };
        let hex = |n: usize| -> Result<u32, SnippetParseError> {
            let text = field(n)?;
            u32::from_str_radix(text.trim_start_matches("0x"), 16)
                .map_err(|e| bad(format!("field {n} {text:?}: {e}")))
        };
        match f.first().copied() {
            Some("O") => {
                counts.0 += 1;
                let first = unescape(field(5)?);
                out.push(SnippetOutcome::Ok {
                    base: hex(2)?,
                    next: hex(3)?,
                    first_error: (field(4)? == "1").then_some(first),
                    xml: unescape(field(6)?),
                });
            }
            Some("F") => {
                counts.1 += 1;
                let base = hex(2)?;
                let message = unescape(field(4)?);
                out.push(match field(3)? {
                    "rejected" => SnippetOutcome::Rejected { base, message },
                    "exception" => SnippetOutcome::Exception { base, message },
                    other => return Err(bad(format!("unknown failure kind {other:?}"))),
                });
            }
            Some("T") => {
                let count = |n: usize| -> Result<usize, SnippetParseError> {
                    field(n)?
                        .parse()
                        .map_err(|e| bad(format!("field {n}: {e}")))
                };
                trailer = Some((number, (count(1)?, count(2)?)));
            }
            Some("H") => {
                if field(1)? != "1" {
                    return Err(bad(format!("record format version {}", field(1)?)));
                }
            }
            _ => return Err(bad(format!("unknown record {line:?}"))),
        }
    }
    match trailer {
        Some((_, found)) if found == counts => Ok(out),
        Some((line, found)) => Err(SnippetParseError {
            line,
            reason: format!("trailer counts {found:?}, records {counts:?}"),
        }),
        None => Err(SnippetParseError {
            line: text.lines().count(),
            reason: "no T line (the tool stopped early)".to_owned(),
        }),
    }
}

/// Runs `bin/snippetdump`. Obtain one with [`crate::ReferenceDir::snippetdump`].
#[derive(Debug, Clone)]
pub struct Snippetdump {
    program: PathBuf,
    root: PathBuf,
    timeout: Duration,
}

impl Snippetdump {
    const DEFAULT_TIMEOUT: Duration = Duration::from_mins(2);

    pub(crate) fn new(program: PathBuf, root: PathBuf) -> Self {
        Self {
            program,
            root,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Replace the time limit of one run.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Find the languages under `root` instead of the reference directory
    /// (a test language written to a temporary directory, for example).
    #[must_use]
    pub fn root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = root.into();
        self
    }

    /// Compile `records` with `language` (a language id) and return one
    /// outcome per record.
    pub fn compile(
        &self,
        language: &str,
        records: &[SnippetRecord],
    ) -> Result<Vec<SnippetOutcome>, ToolError> {
        let text = self.compile_text(language, records)?;
        let outcomes = parse_outcomes(&text)?;
        if outcomes.len() == records.len() {
            Ok(outcomes)
        } else {
            Err(SnippetParseError {
                line: text.lines().count(),
                reason: format!("{} outcomes for {} records", outcomes.len(), records.len()),
            }
            .into())
        }
    }

    /// Like [`Self::compile`], but return the output as the tool printed it.
    pub fn compile_text(
        &self,
        language: &str,
        records: &[SnippetRecord],
    ) -> Result<String, ToolError> {
        if language.is_empty() || language.starts_with('-') {
            return Err(ToolError::Unsupported {
                tool: Tool::Snippetdump,
                reason: format!("{language:?} is not a language id"),
            });
        }
        let mut invocation = Invocation::new(Tool::Snippetdump, &self.program, self.timeout)
            .arg(&self.root)
            .arg(language);
        invocation.stdin = write_records(records).into_bytes();
        Ok(invocation.run()?.require_success(Tool::Snippetdump)?.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_round_trip() {
        let text = "a\\b\tc\nd\re\0f";
        assert_eq!(escape(text), "a\\\\b\\tc\\nd\\re\\0f");
        assert_eq!(unescape(&escape(text)), text);
    }

    #[test]
    fn records_are_written_one_per_line() {
        let records = [
            SnippetRecord {
                source: "a".to_owned(),
                base: SnippetBase::Start(0x10),
                body: "x = 1;\n".to_owned(),
                params: vec![SnippetParameter {
                    index: 0,
                    name: "in1".to_owned(),
                }],
            },
            SnippetRecord {
                source: "b".to_owned(),
                base: SnippetBase::Continue,
                body: String::new(),
                params: Vec::new(),
            },
            SnippetRecord {
                source: "c".to_owned(),
                base: SnippetBase::Fixed(0x2000),
                body: "y".to_owned(),
                params: Vec::new(),
            },
        ];
        assert_eq!(
            write_records(&records),
            "S\ta\t0x10\tx = 1;\\n\t0:in1\nS\tb\tcontinue\t\nS\tc\tfixed:0x2000\ty\n"
        );
    }

    #[test]
    fn outcomes_are_parsed() {
        let text = "H\t1\tx:LE:32:default\t0x10000\t0x10200\n\
                    O\ta\t0x10200\t0x10210\t1\tfirst\\terror\t<x/>\n\
                    O\tb\t0x10210\t0x10210\t0\t\t<y/>\n\
                    F\tc\t0x10210\trejected\tbad\n\
                    F\td\t0x10210\texception\tboom\n\
                    T\t2\t2\n";
        let outcomes = parse_outcomes(text).unwrap();
        assert_eq!(
            outcomes,
            [
                SnippetOutcome::Ok {
                    base: 0x10200,
                    next: 0x10210,
                    first_error: Some("first\terror".to_owned()),
                    xml: "<x/>".to_owned(),
                },
                SnippetOutcome::Ok {
                    base: 0x10210,
                    next: 0x10210,
                    first_error: None,
                    xml: "<y/>".to_owned(),
                },
                SnippetOutcome::Rejected {
                    base: 0x10210,
                    message: "bad".to_owned(),
                },
                SnippetOutcome::Exception {
                    base: 0x10210,
                    message: "boom".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn malformed_output_is_an_error() {
        for text in [
            "O\ta\t0x1\n",
            "O\ta\tzz\t0x1\t0\t\t<x/>\nT\t1\t0\n",
            "F\ta\t0x1\tweird\tm\nT\t0\t1\n",
            "O\ta\t0x1\t0x1\t0\t\t<x/>\n",
            "O\ta\t0x1\t0x1\t0\t\t<x/>\nT\t2\t0\n",
            "H\t2\tx\t0x0\t0x0\nT\t0\t0\n",
            "?\n",
        ] {
            assert!(parse_outcomes(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_missing_tool_is_reported() {
        let tool = Snippetdump::new(
            PathBuf::from("/nonexistent/bin/snippetdump"),
            PathBuf::from("/r"),
        );
        let error = tool.compile("x:LE:32:default", &[]).unwrap_err();
        assert!(
            matches!(
                error,
                ToolError::Missing {
                    tool: Tool::Snippetdump,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(matches!(
            tool.compile("-h", &[]).unwrap_err(),
            ToolError::Unsupported { .. }
        ));
    }
}
