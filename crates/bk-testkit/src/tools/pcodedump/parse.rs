//! Parser for the text `pcodedump` prints. The format is specified in
//! `tools/reference/README.md`; this is its only reader, and the two change
//! together.

use super::model::{
    DumpError, DumpErrorKind, DumpInstruction, DumpOp, DumpRecord, DumpVarnode, LiftError,
    LiftErrorKind, PcodeDump,
};

/// The format version this parser reads (the second field of the `H` record).
pub(crate) const FORMAT_VERSION: u32 = 1;

/// Why text is not a complete `pcodedump` listing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DumpParseError {
    /// The text does not begin with an `H` record.
    #[error("the listing does not start with an H record")]
    MissingHeader,
    /// The listing was written by a different version of the format.
    #[error("format version {found}, but this parser reads version {FORMAT_VERSION}")]
    UnsupportedVersion {
        /// The version in the header.
        found: String,
    },
    /// A line starts with a record tag the format does not have.
    #[error("line {line}: unknown record {tag:?}")]
    UnknownRecord {
        /// 1-based line number.
        line: usize,
        /// The line's first field.
        tag: String,
    },
    /// A record has too few or too many fields.
    #[error("line {line}: {record} record has {found} fields, expected {expected}")]
    FieldCount {
        /// 1-based line number.
        line: usize,
        /// The record's tag.
        record: char,
        /// How many fields the record should have, tag included.
        expected: &'static str,
        /// How many it has.
        found: usize,
    },
    /// A field is not what its position requires.
    #[error("line {line}: bad {what}: {text:?}")]
    BadField {
        /// 1-based line number.
        line: usize,
        /// Which field.
        what: &'static str,
        /// Its text.
        text: String,
    },
    /// A `P` or `U` record with no instruction before it.
    #[error("line {line}: {record} record does not follow an instruction")]
    Orphan {
        /// 1-based line number.
        line: usize,
        /// The record's tag.
        record: char,
    },
    /// Something follows the `T` record.
    #[error("line {line}: text after the T record")]
    AfterTrailer {
        /// 1-based line number.
        line: usize,
    },
    /// The listing ends without a `T` record: the tool was cut short.
    #[error("the listing has no T record; it is incomplete")]
    MissingTrailer,
    /// The `T` record's counts disagree with the records before it.
    #[error(
        "T record counts {trailer_instructions} instructions and {trailer_errors} errors, but \
         the listing has {instructions} and {errors}"
    )]
    CountMismatch {
        /// Instruction count in the trailer.
        trailer_instructions: u64,
        /// Error count in the trailer.
        trailer_errors: u64,
        /// `I` records in the listing.
        instructions: u64,
        /// `E` and `U` records in the listing.
        errors: u64,
    },
}

/// Parse a complete `pcodedump` listing.
pub fn parse_dump(text: &str) -> Result<PcodeDump, DumpParseError> {
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line));

    let (line, header) = lines.next().ok_or(DumpParseError::MissingHeader)?;
    let fields: Vec<&str> = header.split('\t').collect();
    let [tag, version, language, space, base, byte_count] = fields.as_slice() else {
        return Err(match fields.first() {
            Some(&"H") => field_count(line, 'H', "6", fields.len()),
            _ => DumpParseError::MissingHeader,
        });
    };
    if *tag != "H" {
        return Err(DumpParseError::MissingHeader);
    }
    if version.parse() != Ok(FORMAT_VERSION) {
        return Err(DumpParseError::UnsupportedVersion {
            found: (*version).to_owned(),
        });
    }
    let mut dump = PcodeDump {
        language: unescape(line, "language", language)?,
        space: (*space).to_owned(),
        base: hex(line, "base address", base)?,
        byte_count: decimal(line, "byte count", byte_count)?,
        records: Vec::new(),
    };

    let mut trailer = None;
    let mut lift_errors = 0u64;
    for (line, text) in lines {
        if trailer.is_some() {
            return Err(DumpParseError::AfterTrailer { line });
        }
        let fields: Vec<&str> = text.split('\t').collect();
        match fields.as_slice() {
            ["I", rest @ ..] => {
                let [address, length, flow_length, bytes, mnemonic, body] = rest else {
                    return Err(field_count(line, 'I', "7", fields.len()));
                };
                dump.records.push(DumpRecord::Instruction(DumpInstruction {
                    address: hex(line, "address", address)?,
                    length: decimal(line, "length", length)?,
                    flow_length: decimal(line, "flow length", flow_length)?,
                    bytes: hex_bytes(line, bytes)?,
                    mnemonic: unescape(line, "mnemonic", mnemonic)?,
                    body: unescape(line, "operand text", body)?,
                    pcode: Vec::new(),
                    lift_error: None,
                }));
            }
            ["P", rest @ ..] => {
                let [opcode, output, inputs @ ..] = rest else {
                    return Err(field_count(line, 'P', "at least 3", fields.len()));
                };
                let op = DumpOp {
                    opcode: (*opcode).to_owned(),
                    output: if *output == "-" {
                        None
                    } else {
                        Some(varnode(line, output)?)
                    },
                    inputs: inputs
                        .iter()
                        .map(|input| varnode(line, input))
                        .collect::<Result<_, _>>()?,
                };
                last_instruction(&mut dump, line, 'P')?.pcode.push(op);
            }
            ["U", rest @ ..] => {
                let [kind, message] = rest else {
                    return Err(field_count(line, 'U', "3", fields.len()));
                };
                let error = LiftError {
                    kind: match *kind {
                        "unimplemented" => LiftErrorKind::Unimplemented,
                        "bad-data" => LiftErrorKind::BadData,
                        _ => LiftErrorKind::Other,
                    },
                    message: unescape(line, "message", message)?,
                };
                last_instruction(&mut dump, line, 'U')?.lift_error = Some(error);
                lift_errors += 1;
            }
            ["E", rest @ ..] => {
                let [address, length, bytes, kind, message] = rest else {
                    return Err(field_count(line, 'E', "6", fields.len()));
                };
                dump.records.push(DumpRecord::Error(DumpError {
                    address: hex(line, "address", address)?,
                    length: decimal(line, "length", length)?,
                    bytes: hex_bytes(line, bytes)?,
                    kind: match *kind {
                        "bad-data" => DumpErrorKind::BadData,
                        "truncated" => DumpErrorKind::Truncated,
                        _ => DumpErrorKind::Other,
                    },
                    message: unescape(line, "message", message)?,
                }));
            }
            ["T", rest @ ..] => {
                let [instructions, errors] = rest else {
                    return Err(field_count(line, 'T', "3", fields.len()));
                };
                trailer = Some((
                    decimal::<u64>(line, "instruction count", instructions)?,
                    decimal::<u64>(line, "error count", errors)?,
                ));
            }
            [tag, ..] => {
                return Err(DumpParseError::UnknownRecord {
                    line,
                    tag: (*tag).to_owned(),
                });
            }
            [] => {
                return Err(DumpParseError::UnknownRecord {
                    line,
                    tag: String::new(),
                });
            }
        }
    }

    let (trailer_instructions, trailer_errors) = trailer.ok_or(DumpParseError::MissingTrailer)?;
    let instructions = dump.instructions().count() as u64;
    let errors = dump.errors().count() as u64 + lift_errors;
    if (trailer_instructions, trailer_errors) != (instructions, errors) {
        return Err(DumpParseError::CountMismatch {
            trailer_instructions,
            trailer_errors,
            instructions,
            errors,
        });
    }
    Ok(dump)
}

fn field_count(line: usize, record: char, expected: &'static str, found: usize) -> DumpParseError {
    DumpParseError::FieldCount {
        line,
        record,
        expected,
        found,
    }
}

fn bad(line: usize, what: &'static str, text: &str) -> DumpParseError {
    DumpParseError::BadField {
        line,
        what,
        text: text.to_owned(),
    }
}

/// The instruction a `P` or `U` record belongs to: the record before it.
fn last_instruction(
    dump: &mut PcodeDump,
    line: usize,
    record: char,
) -> Result<&mut DumpInstruction, DumpParseError> {
    match dump.records.last_mut() {
        Some(DumpRecord::Instruction(instruction)) if instruction.lift_error.is_none() => {
            Ok(instruction)
        }
        _ => Err(DumpParseError::Orphan { line, record }),
    }
}

/// A `0x`-prefixed hexadecimal number.
fn hex(line: usize, what: &'static str, text: &str) -> Result<u64, DumpParseError> {
    text.strip_prefix("0x")
        // `from_str_radix` accepts a leading `+`, which the tool never prints.
        .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .ok_or_else(|| bad(line, what, text))
}

/// A decimal number.
fn decimal<T: std::str::FromStr>(
    line: usize,
    what: &'static str,
    text: &str,
) -> Result<T, DumpParseError> {
    // `parse` accepts a leading `+`, which the tool never prints.
    if text.starts_with('+') {
        return Err(bad(line, what, text));
    }
    text.parse().map_err(|_| bad(line, what, text))
}

/// A run of two-digit lower-case hexadecimal bytes.
fn hex_bytes(line: usize, text: &str) -> Result<Vec<u8>, DumpParseError> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(bad(line, "bytes", text));
    }
    pairs
        .iter()
        .map(|&[high, low]| Some(digit(high)? << 4 | digit(low)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| bad(line, "bytes", text))
}

/// Undo the tool's escaping of backslash, tab, line feed and carriage return.
fn unescape(line: usize, what: &'static str, text: &str) -> Result<String, DumpParseError> {
    if !text.contains('\\') {
        return Ok(text.to_owned());
    }
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            plain.push(c);
            continue;
        }
        plain.push(match chars.next() {
            Some('\\') => '\\',
            Some('t') => '\t',
            Some('n') => '\n',
            Some('r') => '\r',
            _ => return Err(bad(line, what, text)),
        });
    }
    Ok(plain)
}

/// `(space,0xOFFSET,SIZE)` or `(space,0xOFFSET,SIZE,NAME)`.
fn varnode(line: usize, text: &str) -> Result<DumpVarnode, DumpParseError> {
    let error = || bad(line, "varnode", text);
    let inner = text
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(error)?;
    let mut parts = inner.splitn(4, ',');
    let (Some(space), Some(offset), Some(size)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(error());
    };
    if space.is_empty() {
        return Err(error());
    }
    Ok(DumpVarnode {
        space: space.to_owned(),
        offset: hex(line, "varnode", offset).map_err(|_| error())?,
        size: decimal(line, "varnode", size).map_err(|_| error())?,
        name: parts.next().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests;
