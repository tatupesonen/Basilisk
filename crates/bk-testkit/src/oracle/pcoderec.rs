//! Recorded p-code (format `pcoderec 1`, `docs/features/decomp-oracle.md`
//! 4.8): every answer Ghidra's lifter gave the decompiler during one console
//! run, in call order, written by `bk pcode record`.
//!
//! ```text
//! H → pcoderec → 1 → <language id> → <compiler spec id>
//! X → <address>                                  (context-dependent addresses)
//! I → <address> → <length> → <op count>          (oneInstruction returned; its P records follow)
//! P → <op address> → <opcode> → <output or -> → <inputs…>
//! U → <address> → unimplemented|baddata|error → <length or -> → <message>
//! L → <address> → <length>                       (instructionLength)
//! T → <I count> → <U count> → <L count>
//! ```
//!
//! (`→` stands for one tab.) [`RecordedPcode`] answers by address, as the
//! extension's replay does, and refuses context-dependent addresses.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::graph::OracleAddress;
use super::text::{
    Lines, ParseError, ParseErrorKind, Record, escape, parse_hex_u64, parse_u32, push_display,
    shown, unescape,
};

/// The most records a recording may have.
const MAX_EVENTS: usize = 50_000_000;

/// A varnode as `pcodedump` writes it: `(space,0xOFFSET,SIZE[,NAME])`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecVarnode {
    /// The space's name.
    pub space: String,
    /// The offset; for a `LOAD`/`STORE` space constant, the space's index.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
    /// The register's name, or for a space constant the space's name.
    pub name: Option<String>,
}

impl RecVarnode {
    fn parse(text: &str) -> Option<Self> {
        let body = text.strip_prefix('(')?.strip_suffix(')')?;
        let parts: Vec<&str> = body.split(',').collect();
        let (space, offset, size, name) = match parts.as_slice() {
            [s, o, z] => (*s, *o, *z, None),
            [s, o, z, n] => (*s, *o, *z, Some(*n)),
            _ => return None,
        };
        let token = |t: &str| !t.is_empty() && !t.contains(['(', ')', '\t', ' ']);
        (token(space) && name.is_none_or(token)).then_some(())?;
        Some(Self {
            space: space.to_owned(),
            offset: parse_hex_u64(offset)?,
            size: parse_u32(size)?,
            name: name.map(str::to_owned),
        })
    }

    fn write(&self, out: &mut String) {
        let _ = write!(out, "({},{:#x},{}", self.space, self.offset, self.size);
        if let Some(n) = &self.name {
            out.push(',');
            out.push_str(n);
        }
        out.push(')');
    }
}

/// One p-code op of a recorded instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecOp {
    /// The address the emitter was given.
    pub addr: OracleAddress,
    /// The opcode's name.
    pub opcode: String,
    /// The output.
    pub output: Option<RecVarnode>,
    /// The inputs.
    pub inputs: Vec<RecVarnode>,
}

/// One call of the lifter, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecEvent {
    /// `oneInstruction` returned `length` after emitting `ops`.
    Instruction {
        /// The instruction's address.
        addr: OracleAddress,
        /// What `oneInstruction` returned.
        length: u32,
        /// The ops, in emission order.
        ops: Vec<RecOp>,
    },
    /// `oneInstruction` threw.
    Error {
        /// The instruction's address.
        addr: OracleAddress,
        /// `unimplemented`, `baddata` or `error`.
        kind: String,
        /// `UnimplError::instruction_length`, when there is one.
        length: Option<u32>,
        /// The message.
        message: String,
    },
    /// `instructionLength` returned `length`.
    Length {
        /// The instruction's address.
        addr: OracleAddress,
        /// The length.
        length: u32,
    },
}

impl RecEvent {
    /// The address the call was for.
    pub fn addr(&self) -> &OracleAddress {
        match self {
            Self::Instruction { addr, .. }
            | Self::Error { addr, .. }
            | Self::Length { addr, .. } => addr,
        }
    }
}

/// A whole recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// The language id.
    pub language: String,
    /// The compiler spec id.
    pub compiler: String,
    /// Addresses whose records are not all identical (`X` records).
    pub context_dependent: Vec<OracleAddress>,
    /// Every call, in call order.
    pub events: Vec<RecEvent>,
}

fn addr_at(r: &Record<'_>, i: usize) -> Result<OracleAddress, ParseError> {
    OracleAddress::parse(r.field(i)).ok_or_else(|| r.bad("address", r.field(i)))
}

impl Recording {
    /// Read a recording, checking its counts and that its `X` records name
    /// exactly the addresses whose records differ.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Lines::new("pcoderec", text)?;
        let h = lines.next_line("the header")?;
        if h.tag() != "H" || h.field(1) != "pcoderec" {
            return Err(h.error(ParseErrorKind::UnexpectedRecord {
                expected: "the pcoderec header",
                found: shown(h.text),
            }));
        }
        h.expect("H", 5, "the header")?;
        if h.field(2) != "1" {
            return Err(h.error(ParseErrorKind::UnsupportedVersion {
                version: shown(h.field(2)),
            }));
        }
        let language = unescape(h.field(3)).ok_or_else(|| h.bad("language id", h.field(3)))?;
        let compiler = unescape(h.field(4)).ok_or_else(|| h.bad("compiler spec id", h.field(4)))?;
        let mut context_dependent = Vec::new();
        while lines.peek_tag() == Some("X") {
            let x = lines.next_line("an X record")?;
            x.expect("X", 2, "an X record")?;
            context_dependent.push(addr_at(&x, 1)?);
        }
        let mut events = Vec::new();
        let mut counts = [0_u32; 3];
        loop {
            let r = lines.next_line("a record")?;
            if events.len() >= MAX_EVENTS {
                return Err(r.error(ParseErrorKind::TooMany {
                    what: "records",
                    limit: MAX_EVENTS,
                }));
            }
            match r.tag() {
                "I" => {
                    r.expect("I", 4, "an I record")?;
                    let addr = addr_at(&r, 1)?;
                    let length = r.u32_at(2, "length")?;
                    let count = r.u32_at(3, "op count")?;
                    let mut ops = Vec::new();
                    for _ in 0..count {
                        let p = lines.next_line("a P record")?;
                        if p.tag() != "P" || p.fields.len() < 4 {
                            return Err(p.error(ParseErrorKind::UnexpectedRecord {
                                expected: "a P record",
                                found: shown(p.text),
                            }));
                        }
                        let vn = |i: usize| {
                            RecVarnode::parse(p.field(i))
                                .ok_or_else(|| p.bad("varnode", p.field(i)))
                        };
                        let opcode = p.field(2);
                        if opcode.is_empty()
                            || !opcode
                                .bytes()
                                .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
                        {
                            return Err(p.bad("opcode", opcode));
                        }
                        ops.push(RecOp {
                            addr: addr_at(&p, 1)?,
                            opcode: opcode.to_owned(),
                            output: if p.field(3) == "-" {
                                None
                            } else {
                                Some(vn(3)?)
                            },
                            inputs: (4..p.fields.len()).map(vn).collect::<Result<_, _>>()?,
                        });
                    }
                    counts[0] += 1;
                    events.push(RecEvent::Instruction { addr, length, ops });
                }
                "U" => {
                    r.expect("U", 5, "a U record")?;
                    let kind = r.field(2);
                    if !matches!(kind, "unimplemented" | "baddata" | "error") {
                        return Err(r.bad("error kind", kind));
                    }
                    let length = match r.field(3) {
                        "-" => None,
                        _ => Some(r.u32_at(3, "length")?),
                    };
                    counts[1] += 1;
                    events.push(RecEvent::Error {
                        addr: addr_at(&r, 1)?,
                        kind: kind.to_owned(),
                        length,
                        message: unescape(r.field(4))
                            .ok_or_else(|| r.bad("message", r.field(4)))?,
                    });
                }
                "L" => {
                    r.expect("L", 3, "an L record")?;
                    counts[2] += 1;
                    events.push(RecEvent::Length {
                        addr: addr_at(&r, 1)?,
                        length: r.u32_at(2, "length")?,
                    });
                }
                "T" => {
                    r.expect("T", 4, "the T record")?;
                    for (k, name) in ["I count", "U count", "L count"].into_iter().enumerate() {
                        if r.u32_at(k + 1, name)? != counts.get(k).copied().unwrap_or(0) {
                            return Err(r.bad(name, r.field(k + 1)));
                        }
                    }
                    if lines.peek_tag().is_some() {
                        return Err(lines.error_at(r.number + 1, ParseErrorKind::TrailingText));
                    }
                    break;
                }
                _ => {
                    return Err(r.error(ParseErrorKind::UnexpectedRecord {
                        expected: "an I, U, L or T record",
                        found: shown(r.text),
                    }));
                }
            }
        }
        let recording = Self {
            language,
            compiler,
            context_dependent,
            events,
        };
        let computed: Vec<OracleAddress> = recording.differing_addresses().into_iter().collect();
        if computed != recording.context_dependent {
            return Err(ParseError {
                format: "pcoderec",
                line: 0,
                kind: ParseErrorKind::Inconsistent {
                    reason: format!(
                        "X records name {} addresses, but {} addresses have differing records",
                        recording.context_dependent.len(),
                        computed.len()
                    ),
                },
            });
        }
        Ok(recording)
    }

    /// The addresses whose records are not all identical, in address order.
    pub fn differing_addresses(&self) -> BTreeSet<OracleAddress> {
        let mut first: BTreeMap<(&OracleAddress, u8), &RecEvent> = BTreeMap::new();
        let mut out = BTreeSet::new();
        for e in &self.events {
            let class = u8::from(matches!(e, RecEvent::Length { .. }));
            match first.get(&(e.addr(), class)) {
                Some(prev) if *prev != e => {
                    out.insert(e.addr().clone());
                }
                Some(_) => {}
                None => {
                    first.insert((e.addr(), class), e);
                }
            }
        }
        out
    }

    /// The recording's text; `write(parse(text)) == text`.
    pub fn write(&self) -> String {
        let mut s = format!(
            "H\tpcoderec\t1\t{}\t{}\n",
            escape(&self.language),
            escape(&self.compiler)
        );
        for a in &self.context_dependent {
            let _ = writeln!(s, "X\t{a}");
        }
        let mut counts = [0_u32; 3];
        for e in &self.events {
            match e {
                RecEvent::Instruction { addr, length, ops } => {
                    counts[0] += 1;
                    let _ = writeln!(s, "I\t{addr}\t{length}\t{}", ops.len());
                    for op in ops {
                        let _ = write!(s, "P\t{}\t{}\t", op.addr, op.opcode);
                        match &op.output {
                            Some(v) => v.write(&mut s),
                            None => s.push('-'),
                        }
                        for v in &op.inputs {
                            s.push('\t');
                            v.write(&mut s);
                        }
                        s.push('\n');
                    }
                }
                RecEvent::Error {
                    addr,
                    kind,
                    length,
                    message,
                } => {
                    counts[1] += 1;
                    let _ = write!(s, "U\t{addr}\t{kind}\t");
                    match length {
                        Some(l) => push_display(&mut s, l),
                        None => s.push('-'),
                    }
                    let _ = writeln!(s, "\t{}", escape(message));
                }
                RecEvent::Length { addr, length } => {
                    counts[2] += 1;
                    let _ = writeln!(s, "L\t{addr}\t{length}");
                }
            }
        }
        let _ = writeln!(s, "T\t{}\t{}\t{}", counts[0], counts[1], counts[2]);
        s
    }
}

/// What the lifter answers at one address, from a recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer<'a> {
    /// The ops and the length `oneInstruction` returned.
    Instruction {
        /// The length.
        length: u32,
        /// The ops.
        ops: &'a [RecOp],
    },
    /// The error `oneInstruction` threw.
    Error {
        /// `unimplemented`, `baddata` or `error`.
        kind: &'a str,
        /// The instruction length of an unimplemented instruction.
        length: Option<u32>,
        /// The message.
        message: &'a str,
    },
}

/// Why a recorded answer is not available.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    /// Nothing was recorded at the address.
    #[error("pcode replay: no record for {0}")]
    NoRecord(OracleAddress),
    /// The address's records differ (context dependence).
    #[error("context-dependent records at {0}")]
    ContextDependent(OracleAddress),
}

/// A recording indexed by address, answering as `bk pcode replay` does.
#[derive(Debug, Clone)]
pub struct RecordedPcode {
    recording: Recording,
    instructions: BTreeMap<OracleAddress, usize>,
    lengths: BTreeMap<OracleAddress, u32>,
    dependent: BTreeSet<OracleAddress>,
}

impl RecordedPcode {
    /// Index a recording.
    pub fn new(recording: Recording) -> Self {
        let mut instructions = BTreeMap::new();
        let mut lengths = BTreeMap::new();
        for (i, e) in recording.events.iter().enumerate() {
            match e {
                RecEvent::Length { addr, length } => {
                    lengths.entry(addr.clone()).or_insert(*length);
                }
                _ => {
                    instructions.entry(e.addr().clone()).or_insert(i);
                }
            }
        }
        let dependent = recording.context_dependent.iter().cloned().collect();
        Self {
            recording,
            instructions,
            lengths,
            dependent,
        }
    }

    /// The recording.
    pub fn recording(&self) -> &Recording {
        &self.recording
    }

    /// What `oneInstruction` answers at `addr`.
    pub fn instruction(&self, addr: &OracleAddress) -> Result<Answer<'_>, LookupError> {
        if self.dependent.contains(addr) {
            return Err(LookupError::ContextDependent(addr.clone()));
        }
        let event = self
            .instructions
            .get(addr)
            .and_then(|&i| self.recording.events.get(i))
            .ok_or_else(|| LookupError::NoRecord(addr.clone()))?;
        Ok(match event {
            RecEvent::Instruction { length, ops, .. } => Answer::Instruction {
                length: *length,
                ops,
            },
            RecEvent::Error {
                kind,
                length,
                message,
                ..
            } => Answer::Error {
                kind,
                length: *length,
                message,
            },
            RecEvent::Length { .. } => return Err(LookupError::NoRecord(addr.clone())),
        })
    }

    /// What `instructionLength` answers at `addr`.
    pub fn length(&self, addr: &OracleAddress) -> Result<u32, LookupError> {
        if self.dependent.contains(addr) {
            return Err(LookupError::ContextDependent(addr.clone()));
        }
        self.lengths
            .get(addr)
            .copied()
            .ok_or_else(|| LookupError::NoRecord(addr.clone()))
    }
}

#[cfg(test)]
mod tests;
