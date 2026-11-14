//! basilisk's side of `pcodedump`'s linear sweep, written in the oracle's
//! record format (`tools/reference/README.md`), without `P` and `U` records.

use std::fmt::Write as _;
use std::sync::Arc;

use bk_core::Address;
use bk_sleigh::{ContextDb, DecodeError, Decoder, ErrorClass, Language, SliceBytes};

/// One instruction or error of a sweep, with what the harness needs to
/// judge differences.
#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub(crate) address: u64,
    pub(crate) line: String,
    /// Constructors of every node, for an `I` record.
    pub(crate) constructors: Vec<u32>,
    pub(crate) root_constructor: Option<u32>,
    /// Ghidra's C++ cannot decode a constructor with more than 20 operands.
    pub(crate) too_many_operands: bool,
    /// A delay-slot instruction folded into this one has more than 20
    /// operands (the oracle's flow length is then the plain length).
    pub(crate) delay_over_20: bool,
    pub(crate) reads_past_window: bool,
    pub(crate) committed: bool,
    pub(crate) uses_next2: bool,
}

/// The sweep's records and the closing `T` line (whose error count has no
/// `U` records, which this part cannot predict).
#[derive(Clone, Debug, Default)]
pub(crate) struct Sweep {
    pub(crate) records: Vec<Record>,
    pub(crate) instructions: u64,
    pub(crate) errors: u64,
}

impl Sweep {
    pub(crate) fn t_line(&self) -> String {
        format!("T\t{}\t{}", self.instructions, self.errors)
    }
}

pub(crate) fn escape(text: &str, out: &mut String) {
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

pub(crate) fn kind(error: &DecodeError) -> &'static str {
    match error.class() {
        ErrorClass::BadData => "bad-data",
        ErrorClass::Unimplemented => "unimplemented",
        ErrorClass::Lowlevel => "error",
    }
}

/// The context `pcodedump` starts from: the `.pspec` defaults, then each
/// `--context` value set over the whole default code space.
pub(crate) fn start_context(lang: &Language, context: &[(String, u32)]) -> ContextDb {
    let mut db = lang.initial_context();
    for (name, value) in context {
        assert!(
            lang.set_context_everywhere(&mut db, name, *value),
            "no context variable {name}"
        );
    }
    db
}

/// Runs the sweep over `data` placed at `base`.
pub(crate) fn sweep(
    lang: &Arc<Language>,
    base: u64,
    data: &[u8],
    context: &[(String, u32)],
) -> Sweep {
    let mut db = start_context(lang, context);
    let mut decoder = Decoder::new(Arc::clone(lang));
    // Fail as Ghidra's C++ does on more than 20 operands, so both sweeps stay
    // in step; basilisk's own decoding of those is checked separately.
    decoder.set_operand_limit(Some(20));
    let bytes = SliceBytes::new(base, data);
    let space = lang.default_space();
    let mut out = Sweep::default();
    let mut mnemonic = String::new();
    let mut body = String::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let offset = base.wrapping_add(pos as u64);
        let addr = Address::new(space, offset);
        let remaining = data.len() - pos;
        mnemonic.clear();
        body.clear();
        let decoded = decoder
            .decode(addr, &bytes, &db)
            .map(bk_sleigh::Parse::length)
            .and_then(|length| {
                decoder.mnemonic(&mut mnemonic)?;
                decoder.body(&mut body)?;
                Ok(length)
            });
        let error_line = |len: usize, kind: &str, message: &str| {
            let mut line = format!("E\t{offset:#x}\t{len}\t");
            hex_bytes(data.get(pos..pos + len).unwrap_or_default(), &mut line);
            line.push('\t');
            line.push_str(kind);
            line.push('\t');
            escape(message, &mut line);
            line
        };
        let plain = |line: String| Record {
            address: offset,
            line,
            constructors: Vec::new(),
            root_constructor: None,
            too_many_operands: false,
            delay_over_20: false,
            reads_past_window: false,
            committed: false,
            uses_next2: false,
        };
        let length = match decoded {
            Ok(length) => length as usize,
            Err(error) => {
                let mut record = plain(error_line(1, kind(&error), &error.to_string()));
                record.reads_past_window = decoder.parse().reads_past_window();
                record.too_many_operands = decoder.parse().max_operands() > 20;
                out.records.push(record);
                out.errors += 1;
                pos += 1;
                continue;
            }
        };
        if length == 0 {
            out.records
                .push(plain(error_line(1, "error", "instruction has no length")));
            out.errors += 1;
            pos += 1;
            continue;
        }
        if length > remaining {
            out.records.push(plain(error_line(
                remaining,
                "truncated",
                "instruction extends past the end of the input",
            )));
            out.errors += 1;
            break;
        }
        let parse = decoder.parse();
        let constructors: Vec<u32> = parse
            .constructors()
            .map(bk_sla::ConstructorId::index)
            .collect();
        let root_constructor = constructors.first().copied();
        let too_many_operands = parse.max_operands() > 20;
        let mut reads_past_window = parse.reads_past_window();
        let committed = !parse.commits().is_empty();
        let uses_next2 = parse.next2().is_some();
        let flow = match decoder.prepare(addr, &bytes, &mut db) {
            Ok(_) if nested_delay_missing(&decoder) => length,
            Ok(prepared) => prepared.flow_length as usize,
            Err(_) => length,
        };
        reads_past_window |= decoder
            .delay_slots()
            .iter()
            .any(bk_sleigh::Parse::reads_past_window);
        let delay_over_20 = decoder.delay_slots().iter().any(|d| d.max_operands() > 20);
        let mut line = format!("I\t{offset:#x}\t{length}\t{flow}\t");
        hex_bytes(data.get(pos..pos + length).unwrap_or_default(), &mut line);
        line.push('\t');
        escape(&mnemonic, &mut line);
        line.push('\t');
        escape(&body, &mut line);
        out.records.push(Record {
            address: offset,
            line,
            constructors,
            root_constructor,
            too_many_operands,
            delay_over_20,
            reads_past_window,
            committed,
            uses_next2,
        });
        out.instructions += 1;
        pos += length;
    }
    out
}

/// Whether p-code generation will fail because a delay-slot instruction has
/// a delay slot of its own whose instructions were not decoded by `prepare`:
/// Ghidra's builder then finds no cached parse ("Could not obtain cached
/// delay slot instruction"), `pcodedump` prints a `U` record and the flow
/// length is the instruction's own length.
pub(crate) fn nested_delay_missing(decoder: &Decoder) -> bool {
    let delays = decoder.delay_slots();
    let decoded: Vec<u64> = std::iter::once(decoder.parse())
        .chain(delays)
        .map(|p| p.address().offset())
        .collect();
    delays.iter().enumerate().any(|(i, d)| {
        if d.delay_slot() == 0 {
            return false;
        }
        // The instructions after `d`, as decoded, must cover its delay bytes.
        let mut at = d.address().offset().wrapping_add(u64::from(d.length()));
        let mut covered = 0u32;
        for later in delays.iter().skip(i + 1) {
            if covered >= d.delay_slot() {
                break;
            }
            if later.address().offset() != at || !decoded.contains(&at) {
                return true;
            }
            covered += later.length();
            at = at.wrapping_add(u64::from(later.length()));
        }
        covered < d.delay_slot()
    })
}
