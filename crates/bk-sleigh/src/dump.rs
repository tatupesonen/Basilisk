//! `pcodedump`'s linear sweep and record format (format version 1 of
//! `tools/reference/README.md`), written byte for byte as the oracle
//! writes it: the output of `basilisk disasm --format pcodedump` and the
//! basilisk side of the differential test.

use std::fmt::Write as _;

use bk_core::Address;

use crate::context::ContextDb;
use crate::decode::{Decoder, SliceBytes};
use crate::emit::{PcodeCounter, PcodeRecords};
use crate::error::ErrorClass;
use crate::pcode::BuildObserver;

/// The record format version written.
pub const FORMAT_VERSION: u32 = 1;

/// Watches a sweep record by record (and, through [`BuildObserver`], each
/// instruction's build). `()` watches nothing.
pub trait SweepObserver: BuildObserver {
    /// A record was written: `text` is its lines (an `I` record with its
    /// `P` or `U` records, or an `E` record). For an `I` record `decoder`
    /// holds the instruction's parse and delay-slot parses.
    fn record(&mut self, address: u64, text: &str, decoder: Option<&Decoder>) {
        let _ = (address, text, decoder);
    }
}

impl SweepObserver for () {}

/// What a sweep counted (the `T` record and the timing line).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepCounts {
    /// Instructions decoded.
    pub instructions: u64,
    /// `E` and `U` records.
    pub errors: u64,
    /// P-code ops generated.
    pub ops: u64,
}

/// The `pcodedump` record kind of an error class.
pub fn kind(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::BadData => "bad-data",
        ErrorClass::Unimplemented => "unimplemented",
        ErrorClass::Lowlevel => "error",
    }
}

/// Appends `text` with tab, newline, carriage return and backslash escaped.
pub fn escape(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
}

fn hex_bytes(bytes: &[u8], out: &mut String) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// Appends the `H` record.
pub fn write_header(out: &mut String, language: &str, space: &str, base: u64, len: usize) {
    let _ = write!(out, "H\t{FORMAT_VERSION}\t");
    escape(language, out);
    let _ = writeln!(out, "\t{space}\t{base:#x}\t{len}");
}

/// Appends the `T` record.
pub fn write_trailer(out: &mut String, counts: &SweepCounts) {
    let _ = writeln!(out, "T\t{}\t{}", counts.instructions, counts.errors);
}

/// Runs the sweep over `data` placed at `base` in the default code space,
/// appending the records between `H` and `T` to `out` (only counting when
/// `quiet`, as `pcodedump --quiet` does), and returns the counts. The
/// decoder's language decides everything else; `context` is updated by the
/// instructions' commits.
pub fn sweep<O: SweepObserver>(
    decoder: &mut Decoder,
    context: &mut ContextDb,
    base: u64,
    data: &[u8],
    quiet: bool,
    out: &mut String,
    obs: &mut O,
) -> SweepCounts {
    let lang = std::sync::Arc::clone(decoder.language());
    let bytes = SliceBytes::new(base, data);
    let space = lang.default_space();
    let mut counts = SweepCounts::default();
    let mut mnemonic = String::new();
    let mut body = String::new();
    let mut pcode = String::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let offset = base.wrapping_add(pos as u64);
        let addr = Address::new(space, offset);
        let remaining = data.len() - pos;
        let start = out.len();
        let decoded = if quiet {
            decoder
                .decode(addr, &bytes, &*context)
                .map(crate::Parse::length)
        } else {
            mnemonic.clear();
            body.clear();
            decoder
                .decode(addr, &bytes, &*context)
                .map(crate::Parse::length)
                .and_then(|length| {
                    decoder.mnemonic(&mut mnemonic)?;
                    decoder.body(&mut body)?;
                    Ok(length)
                })
        };
        let error = |out: &mut String, len: usize, kind: &str, message: &str| {
            if quiet {
                return;
            }
            let _ = write!(out, "E\t{offset:#x}\t{len}\t");
            hex_bytes(data.get(pos..pos + len).unwrap_or_default(), out);
            let _ = write!(out, "\t{kind}\t");
            escape(message, out);
            out.push('\n');
        };
        let length = match decoded {
            Ok(0) => {
                error(out, 1, "error", "instruction has no length");
                None
            }
            Ok(length) => Some(length as usize),
            Err(e) => {
                error(out, 1, kind(e.class()), &e.to_string());
                None
            }
        };
        let Some(length) = length else {
            counts.errors += 1;
            obs.record(offset, out.get(start..).unwrap_or_default(), None);
            pos += 1;
            continue;
        };
        if length > remaining {
            error(
                out,
                remaining,
                "truncated",
                "instruction extends past the end of the input",
            );
            counts.errors += 1;
            obs.record(offset, out.get(start..).unwrap_or_default(), None);
            break;
        }
        pcode.clear();
        let lifted = if quiet {
            let mut counter = PcodeCounter::default();
            let r = decoder.lift_observed(addr, &bytes, context, &mut counter, obs);
            counts.ops += counter.ops;
            r
        } else {
            let mut records = PcodeRecords::new(&lang, &mut pcode);
            let r = decoder.lift_observed(addr, &bytes, context, &mut records, obs);
            counts.ops += records.count;
            r
        };
        let flow = match &lifted {
            Ok(flow) => *flow as usize,
            Err(e) => e.flow_length().map_or(length, |f| f as usize),
        };
        counts.instructions += 1;
        if !quiet {
            let _ = write!(out, "I\t{offset:#x}\t{length}\t{flow}\t");
            hex_bytes(data.get(pos..pos + length).unwrap_or_default(), out);
            out.push('\t');
            escape(&mnemonic, out);
            out.push('\t');
            escape(&body, out);
            out.push('\n');
            match &lifted {
                Ok(_) => out.push_str(&pcode),
                Err(e) => {
                    let _ = write!(out, "U\t{}\t", kind(e.class()));
                    escape(&e.to_string(), out);
                    out.push('\n');
                }
            }
        }
        if lifted.is_err() {
            counts.errors += 1;
        }
        obs.record(offset, out.get(start..).unwrap_or_default(), Some(decoder));
        pos += length;
    }
    counts
}
