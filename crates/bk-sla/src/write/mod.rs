//! Writing a compiled language: the packed stream, the container and the
//! XML form, exactly as the C++ `encode` methods write them
//! (`features/sla.md` 4.5).

use std::io::Write as _;
use std::path::Path;

use bk_marshal::{EncodeError, Encoder, PackedEncoder, PackedSpace, SpaceRef, XmlEncoder};
use flate2::Compression;
use flate2::write::ZlibEncoder;

use crate::error::SlaError;
use crate::ids::*;
use crate::model::Sla;
use crate::model::handles::SymbolId;
use crate::model::symbol::{SpaceKind, SymbolKind};

mod body;
pub(crate) mod template;

/// Turns a space index into the reference an encoder writes.
pub(crate) trait SpaceNames {
    fn name(&self, index: u32) -> &str;
}

impl SpaceNames for Sla {
    fn name(&self, index: u32) -> &str {
        self.space_name(index).unwrap_or("")
    }
}

pub(crate) fn space_ref<N: SpaceNames + ?Sized>(names: &N, index: u32) -> SpaceRef<'_> {
    SpaceRef {
        name: names.name(index),
        packed: PackedSpace::Index(index),
    }
}

impl Sla {
    /// The inflated packed stream, byte for byte what Ghidra writes.
    pub fn encode_packed(&self) -> Result<Vec<u8>, SlaError> {
        let mut encoder = PackedEncoder::with_buffer(Vec::with_capacity(self.heap_bytes() / 4));
        self.encode(&mut encoder)?;
        Ok(encoder.into_bytes())
    }

    /// The XML text `sleigh -y` writes.
    pub fn encode_xml(&self) -> Result<String, SlaError> {
        let mut encoder = XmlEncoder::new(true);
        self.encode(&mut encoder)?;
        Ok(encoder.into_string())
    }

    /// The file: the header and the packed stream deflated in zlib format
    /// at the default level.
    pub fn write(&self) -> Result<Vec<u8>, SlaError> {
        let stream = self.encode_packed()?;
        let mut out = Vec::with_capacity(stream.len() / 8 + 16);
        out.extend_from_slice(&HEADER);
        let mut zlib = ZlibEncoder::new(out, Compression::default());
        let io = |source| SlaError::Io {
            path: "<memory>".into(),
            source,
        };
        zlib.write_all(&stream).map_err(io)?;
        zlib.finish().map_err(io)
    }

    /// Writes the file to `path` through a temporary file renamed into
    /// place.
    pub fn write_file(&self, path: &Path) -> Result<(), SlaError> {
        let bytes = self.write()?;
        let io = |source| SlaError::Io {
            path: path.to_path_buf(),
            source,
        };
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        let temporary = path.with_file_name(name);
        std::fs::write(&temporary, &bytes).map_err(io)?;
        std::fs::rename(&temporary, path).map_err(|source| {
            let _ = std::fs::remove_file(&temporary);
            io(source)
        })
    }

    /// Writes the document through any encoder (Ghidra `SleighBase::encode`).
    pub fn encode<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        let h = &self.header;
        enc.open_element(ELEM_SLEIGH);
        enc.write_signed(ATTRIB_VERSION, i64::from(FORMAT_VERSION));
        enc.write_bool(ATTRIB_BIGENDIAN, h.big_endian);
        enc.write_signed(ATTRIB_ALIGN, i64::from(h.align));
        enc.write_unsigned(ATTRIB_UNIQBASE, u64::from(h.unique_base));
        if h.max_delay > 0 {
            enc.write_unsigned(ATTRIB_MAXDELAY, u64::from(h.max_delay));
        }
        if h.unique_mask != 0 {
            enc.write_unsigned(ATTRIB_UNIQMASK, u64::from(h.unique_mask));
        }
        if h.num_sections != 0 {
            enc.write_unsigned(ATTRIB_NUMSECTIONS, u64::from(h.num_sections));
        }
        enc.open_element(ELEM_SOURCEFILES);
        for (index, name) in self.source_files().enumerate() {
            enc.open_element(ELEM_SOURCEFILE);
            enc.write_string(ATTRIB_NAME, name)?;
            enc.write_signed(ATTRIB_INDEX, index as i64);
            enc.close_element(ELEM_SOURCEFILE);
        }
        enc.close_element(ELEM_SOURCEFILES);
        enc.open_element(ELEM_SPACES);
        enc.write_string(ATTRIB_DEFAULTSPACE, self.name(self.default_space))?;
        let mut spaces: Vec<_> = self.space_records().iter().collect();
        spaces.sort_by_key(|space| space.index);
        for space in spaces {
            let element = match space.kind {
                SpaceKind::Processor => ELEM_SPACE,
                SpaceKind::Unique => ELEM_SPACE_UNIQUE,
                SpaceKind::Other => ELEM_SPACE_OTHER,
            };
            enc.open_element(element);
            enc.write_string(ATTRIB_NAME, self.text(space.name))?;
            enc.write_signed(ATTRIB_INDEX, i64::from(space.index));
            enc.write_bool(ATTRIB_BIGENDIAN, space.big_endian);
            enc.write_signed(ATTRIB_DELAY, i64::from(space.delay));
            enc.write_signed(ATTRIB_SIZE, i64::from(space.size));
            if space.word_size > 1 {
                enc.write_signed(ATTRIB_WORDSIZE, i64::from(space.word_size));
            }
            enc.write_bool(ATTRIB_PHYSICAL, space.physical);
            enc.close_element(element);
        }
        enc.close_element(ELEM_SPACES);
        self.encode_symbol_table(enc)?;
        enc.close_element(ELEM_SLEIGH);
        Ok(())
    }

    fn encode_symbol_table<E: Encoder>(&self, enc: &mut E) -> Result<(), EncodeError> {
        enc.open_element(ELEM_SYMBOL_TABLE);
        enc.write_signed(ATTRIB_SCOPESIZE, self.scopes().len() as i64);
        enc.write_signed(ATTRIB_SYMBOLSIZE, self.symbols().len() as i64);
        for (id, scope) in self.scopes().iter().enumerate() {
            enc.open_element(ELEM_SCOPE);
            enc.write_unsigned(ATTRIB_ID, id as u64);
            enc.write_unsigned(
                ATTRIB_PARENT,
                scope.parent.map_or(0, |p| u64::from(p.index())),
            );
            enc.close_element(ELEM_SCOPE);
        }
        for (id, symbol) in self.symbols().iter().enumerate() {
            let head = head_element(&symbol.kind);
            enc.open_element(head);
            enc.write_string(ATTRIB_NAME, self.text(symbol.name))?;
            enc.write_unsigned(ATTRIB_ID, id as u64);
            enc.write_unsigned(ATTRIB_SCOPE, u64::from(symbol.scope.index()));
            enc.close_element(head);
        }
        for id in 0..self.symbols().len() {
            self.encode_body(enc, SymbolId::new(id as u32))?;
        }
        enc.close_element(ELEM_SYMBOL_TABLE);
        Ok(())
    }
}

fn head_element(kind: &SymbolKind) -> bk_marshal::ElementId {
    match kind {
        SymbolKind::UserOp { .. } => ELEM_USEROP_HEAD,
        SymbolKind::Value { .. } => ELEM_VALUE_SYM_HEAD,
        SymbolKind::ValueMap { .. } => ELEM_VALUEMAP_SYM_HEAD,
        SymbolKind::Name { .. } => ELEM_NAME_SYM_HEAD,
        SymbolKind::Varnode { .. } => ELEM_VARNODE_SYM_HEAD,
        SymbolKind::Context { .. } => ELEM_CONTEXT_SYM_HEAD,
        SymbolKind::VarnodeList { .. } => ELEM_VARLIST_SYM_HEAD,
        SymbolKind::Operand(_) => ELEM_OPERAND_SYM_HEAD,
        SymbolKind::Start => ELEM_START_SYM_HEAD,
        SymbolKind::End => ELEM_END_SYM_HEAD,
        SymbolKind::Next2 => ELEM_NEXT2_SYM_HEAD,
        SymbolKind::Epsilon => ELEM_EPSILON_SYM_HEAD,
        SymbolKind::Subtable(_) => ELEM_SUBTABLE_SYM_HEAD,
    }
}
