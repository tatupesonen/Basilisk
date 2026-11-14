//! The decompiler's action trace (`docs/features/decomp-oracle.md` 4.9): what
//! `decomp_dbg` and `decomp_bk_dbg` print with `trace address` and `trace
//! enable` (`Funcdata::debugModPrint`, `funcdata.cc`):
//!
//! ```text
//! DEBUG <count>: <action or rule name>
//! <seqnum>: <op before, or **>
//!    <seqnum>: <op after, or **>
//! …
//! <empty line>
//! ```
//!
//! The trace is written into the console's output, between other lines
//! (`Decompiling …`, `Decompilation complete`); [`Trace::extract`] picks the
//! records out of such text and checks each strictly.

use std::fmt::Write as _;

use super::text::{ParseError, ParseErrorKind, parse_u32, shown};

/// The most records one trace may have.
const MAX_RECORDS: usize = 10_000_000;

/// All trace records found in a text, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    /// The records.
    pub records: Vec<TraceRecord>,
}

/// One action or rule application that changed ops in range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRecord {
    /// The running number.
    pub count: u32,
    /// The action or rule.
    pub name: String,
    /// Every op it changed: sequence number as printed, text before, text after.
    pub ops: Vec<TraceOp>,
}

/// One changed op of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceOp {
    /// The op's sequence number as `PcodeOp::printRaw` prints it (`0x001006ca:287`).
    pub seqnum: String,
    /// `PcodeOp::printRaw` before the change; `None` when the op was dead
    /// or had no block (`**`).
    pub before: Option<String>,
    /// `PcodeOp::printRaw` after the change; `None` for `**`.
    pub after: Option<String>,
}

fn op_line(line: &str, indent: &str) -> Option<(String, Option<String>)> {
    let rest = line.strip_prefix(indent)?;
    if rest.starts_with(' ') {
        return None;
    }
    let (seq, text) = rest.split_once(": ")?;
    let ok = !seq.is_empty() && seq.contains(':') && !seq.contains(' ');
    ok.then_some(())?;
    let text = if text == "**" {
        None
    } else {
        Some(text.to_owned())
    };
    Some((seq.to_owned(), text))
}

impl Trace {
    /// Every `DEBUG` record in `text`, which may hold other lines between
    /// records (a console transcript). A record that starts must be complete.
    pub fn extract(text: &str) -> Result<Self, ParseError> {
        let lines: Vec<&str> = text.split('\n').collect();
        let error = |line: usize, kind| ParseError {
            format: "trace",
            line,
            kind,
        };
        let mut records = Vec::new();
        let mut i = 0;
        while let Some(&line) = lines.get(i) {
            let Some(head) = line.strip_prefix("DEBUG ") else {
                i += 1;
                continue;
            };
            let number = i + 1;
            let (count, name) = head
                .split_once(": ")
                .and_then(|(c, n)| Some((parse_u32(c)?, n)))
                .filter(|(_, n)| !n.is_empty() && !n.contains(' '))
                .ok_or_else(|| {
                    error(
                        number,
                        ParseErrorKind::BadField {
                            field: "trace record header",
                            value: shown(line),
                        },
                    )
                })?;
            if records.len() >= MAX_RECORDS {
                return Err(error(
                    number,
                    ParseErrorKind::TooMany {
                        what: "trace records",
                        limit: MAX_RECORDS,
                    },
                ));
            }
            let mut record = TraceRecord {
                count,
                name: name.to_owned(),
                ops: Vec::new(),
            };
            i += 1;
            loop {
                let Some(&before) = lines.get(i) else {
                    return Err(error(
                        i + 1,
                        ParseErrorKind::UnexpectedEnd {
                            expected: "an op line or the empty line ending a trace record",
                        },
                    ));
                };
                if before.is_empty() {
                    i += 1;
                    break;
                }
                let bad = |line: usize, text: &str| {
                    error(
                        line,
                        ParseErrorKind::BadField {
                            field: "trace op line",
                            value: shown(text),
                        },
                    )
                };
                let (seq, before_text) = op_line(before, "").ok_or_else(|| bad(i + 1, before))?;
                let after = lines.get(i + 1).copied().unwrap_or("");
                let (seq2, after_text) = op_line(after, "   ").ok_or_else(|| bad(i + 2, after))?;
                if seq2 != seq {
                    return Err(bad(i + 2, after));
                }
                record.ops.push(TraceOp {
                    seqnum: seq,
                    before: before_text,
                    after: after_text,
                });
                i += 2;
            }
            if record.ops.is_empty() {
                return Err(error(
                    number,
                    ParseErrorKind::Inconsistent {
                        reason: "a trace record without ops".into(),
                    },
                ));
            }
            records.push(record);
        }
        Ok(Self { records })
    }

    /// The records' text, as the console prints them.
    pub fn write(&self) -> String {
        let mut s = String::new();
        for r in &self.records {
            let _ = writeln!(s, "DEBUG {}: {}", r.count, r.name);
            for op in &r.ops {
                let _ = writeln!(s, "{}: {}", op.seqnum, op.before.as_deref().unwrap_or("**"));
                let _ = writeln!(
                    s,
                    "   {}: {}",
                    op.seqnum,
                    op.after.as_deref().unwrap_or("**")
                );
            }
            s.push('\n');
        }
        s
    }

    /// How many records each action or rule has, by name (sorted by name).
    pub fn counts_by_name(&self) -> Vec<(String, usize)> {
        let mut map = std::collections::BTreeMap::new();
        for r in &self.records {
            *map.entry(r.name.clone()).or_insert(0_usize) += 1;
        }
        map.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SAMPLE: &str = "Decompiling f\nDEBUG 0: constbase\n0x001006ca:287: **\n   \
                          0x001006ca:287: DF(0x001006ca:287) = #0x0:1\n\nDEBUG 1: extrapopsetup\n\
                          0x00100708:288: **\n   0x00100708:288: RSP(0x00100708:288) = RSP(free) + #0x8\n\
                          0x001006ef:289: X\n   0x001006ef:289: **\n\nDecompilation complete\n";

    #[test]
    fn records_are_picked_out_of_a_transcript() {
        let trace = Trace::extract(SAMPLE).unwrap();
        assert_eq!(trace.records.len(), 2);
        assert_eq!(trace.records[0].name, "constbase");
        assert_eq!(trace.records[0].ops[0].before, None);
        assert_eq!(
            trace.records[0].ops[0].after.as_deref(),
            Some("DF(0x001006ca:287) = #0x0:1")
        );
        assert_eq!(trace.records[1].ops[1].after, None);
        let written = trace.write();
        assert_eq!(Trace::extract(&written).unwrap(), trace);
        assert!(SAMPLE.contains(written.trim_end_matches('\n')));
        assert_eq!(
            trace.counts_by_name(),
            [("constbase".into(), 1), ("extrapopsetup".into(), 1)]
        );
    }

    #[test]
    fn broken_records_are_errors() {
        for bad in [
            "DEBUG x: name\na: b\n   a: b\n\n",
            "DEBUG 1: name\n0x1:2: a\n   0x1:3: b\n\n",
            "DEBUG 1: name\n0x1:2: a\n",
            "DEBUG 1: name\n\n",
            "DEBUG 1: name\n0x1:2: a\n0x1:2: b\n\n",
        ] {
            assert!(Trace::extract(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Trace::extract("no trace here\n").unwrap(), Trace::default());
    }

    proptest! {
        #[test]
        fn no_input_panics(text in "(DEBUG |[0-9a-fx:* ]|\\n|   ){0,80}") {
            if let Ok(t) = Trace::extract(&text) {
                prop_assert_eq!(Trace::extract(&t.write()).unwrap(), t);
            }
        }
    }
}
