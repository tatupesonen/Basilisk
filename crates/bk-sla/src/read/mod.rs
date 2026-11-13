//! Reading a compiled language: the container (header and zlib stream), the
//! packed stream and the XML form (`features/sla.md` 4.2).

mod decode;
mod expr;
pub(crate) mod source;
mod table;

use std::path::Path;

use bk_marshal::{Document, PackedDecoder, XmlDecoder};
use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{Location, SlaError};
use crate::ids;
use crate::limits::Limits;
use crate::model::Sla;
pub(crate) use decode::Decoded;
use decode::Reader;
use source::{AnySpace, MarshalSource, PackedCursor, Source};

/// Which decoder reads the packed stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PackedReader {
    /// This crate's own cursor over the bytes (the default, and the fast
    /// path).
    #[default]
    Direct,
    /// `bk-marshal`'s generic `PackedDecoder`, for cross-checking.
    Marshal,
}

impl Sla {
    /// Reads a `.sla` file's bytes: header, inflate, decode, validate.
    pub fn read(bytes: &[u8], limits: &Limits) -> Result<Self, SlaError> {
        let stream = inflate(bytes, limits)?;
        Self::decode_packed(&stream, limits)
    }

    /// Reads a `.sla` file.
    pub fn read_file(path: &Path, limits: &Limits) -> Result<Self, SlaError> {
        let bytes = std::fs::read(path).map_err(|source| SlaError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::read(&bytes, limits)
    }

    /// Decodes and validates an inflated packed stream.
    pub fn decode_packed(stream: &[u8], limits: &Limits) -> Result<Self, SlaError> {
        Self::decode_packed_using(stream, limits, PackedReader::Direct)
    }

    /// Decodes and validates an inflated packed stream with the chosen
    /// decoder. Both give the same model for the same stream.
    pub fn decode_packed_using(
        stream: &[u8],
        limits: &Limits,
        reader: PackedReader,
    ) -> Result<Self, SlaError> {
        check_size(stream.len(), limits)?;
        let decoded = match reader {
            PackedReader::Direct => {
                decode_with(PackedCursor::new(stream, limits.element_depth), limits)?
            }
            PackedReader::Marshal => {
                let spaces = AnySpace;
                let decoder = PackedDecoder::new(stream, &spaces);
                decode_with(
                    MarshalSource::new(decoder, false, limits.element_depth),
                    limits,
                )?
            }
        };
        crate::validate::finish(decoded, limits)
    }

    /// Decodes and validates the XML form that `sleigh -y` writes.
    pub fn decode_xml(text: &str, limits: &Limits) -> Result<Self, SlaError> {
        check_size(text.len(), limits)?;
        let stream_error = |error: bk_marshal::XmlError| SlaError::Stream {
            location: Location::default(),
            error: crate::error::StreamError::Marshal(error.into()),
        };
        let document = Document::parse(text).map_err(stream_error)?;
        let table = ids::id_table().map_err(|error| SlaError::structure("", error.to_string()))?;
        let spaces = AnySpace;
        let decoder = XmlDecoder::new(&document, &table, &spaces);
        let decoded = decode_with(MarshalSource::new(decoder, true, limits.element_depth), limits)?;
        crate::validate::finish(decoded, limits)
    }
}

fn check_size(len: usize, limits: &Limits) -> Result<(), SlaError> {
    if len as u64 > limits.inflated_size {
        return Err(SlaError::Limit {
            location: Location::default(),
            what: "document size",
            limit: limits.inflated_size,
            found: len as u64,
        });
    }
    Ok(())
}

fn decode_with<'a, S: Source<'a>>(src: S, limits: &Limits) -> Result<Decoded, SlaError> {
    let reader = Reader::new(src, limits);
    let (decoded, trailing) = reader.sleigh().map_err(|(fail, location)| fail.at(location))?;
    if let Some(offset) = trailing {
        return Err(SlaError::TrailingData { offset });
    }
    Ok(decoded)
}

/// Checks the header and inflates the zlib stream after it, within the
/// size limit. Bytes after the end of the zlib stream are an error.
pub fn inflate(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, SlaError> {
    let (header, input) = bytes.split_at(bytes.len().min(4));
    if header != ids::HEADER {
        return Err(SlaError::Header {
            found: header.to_vec(),
        });
    }
    let limit = usize::try_from(limits.inflated_size).unwrap_or(usize::MAX);
    let mut inflater = Decompress::new(true);
    // Compressed .sla files inflate about tenfold; start there, within the limit.
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(10).min(limit).max(64));
    loop {
        if out.len() == out.capacity() {
            if out.len() >= limit {
                return Err(SlaError::Limit {
                    location: Location::default(),
                    what: "inflated size",
                    limit: limits.inflated_size,
                    found: out.len() as u64 + 1,
                });
            }
            let more = out.len().max(1 << 16).min(limit - out.len());
            out.reserve_exact(more);
        }
        let consumed = usize::try_from(inflater.total_in()).unwrap_or(usize::MAX);
        let rest = input.get(consumed..).unwrap_or_default();
        let before = (inflater.total_in(), out.len());
        let status = inflater
            .decompress_vec(rest, &mut out, FlushDecompress::None)
            .map_err(|error| SlaError::Compression {
                message: error.to_string(),
            })?;
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if before == (inflater.total_in(), out.len()) && out.len() < out.capacity() {
                    return Err(SlaError::Compression {
                        message: "the stream is truncated".to_owned(),
                    });
                }
            }
        }
    }
    let consumed = usize::try_from(inflater.total_in()).unwrap_or(usize::MAX);
    let trailing = input.len().saturating_sub(consumed);
    if trailing > 0 {
        return Err(SlaError::TrailingBytes { count: trailing });
    }
    Ok(out)
}
