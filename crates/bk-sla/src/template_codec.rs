//! A template outside a language file: writing and reading a lone
//! `construct_tpl` element in both forms (`features/sla.md` 5.2).

use bk_marshal::{Document, PackedDecoder, PackedEncoder, XmlDecoder, XmlEncoder};

use crate::error::{Location, SlaError, StreamError};
use crate::ids;
use crate::limits::Limits;
use crate::model::Sla;
use crate::model::template::Template;
use crate::read::source::{AnySpace, MarshalSource, PackedCursor};
use crate::write::SpaceNames;
use crate::write::template::encode_template;

/// The address spaces a lone template may name: names and indices. The
/// constant space (`const`, index 0) is always present.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceTable {
    entries: Vec<(String, u32)>,
}

impl SpaceTable {
    /// A table holding only the constant space.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a space.
    pub fn insert(&mut self, name: &str, index: u32) {
        self.entries.push((name.to_owned(), index));
    }

    /// The index of the space with the given name.
    pub fn index(&self, name: &str) -> Option<u32> {
        if name == crate::CONSTANT_SPACE_NAME {
            return Some(0);
        }
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|&(_, i)| i)
    }

    /// The name of the space with the given index.
    pub fn name(&self, index: u32) -> Option<&str> {
        if index == 0 {
            return Some(crate::CONSTANT_SPACE_NAME);
        }
        self.entries
            .iter()
            .find(|&&(_, i)| i == index)
            .map(|(n, _)| n.as_str())
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, u32)> {
        self.entries.iter().map(|(n, i)| (n.as_str(), *i))
    }
}

impl SpaceNames for SpaceTable {
    fn name(&self, index: u32) -> &str {
        Self::name(self, index).unwrap_or("")
    }
}

impl Sla {
    /// The spaces of this language as a [`SpaceTable`], for templates that
    /// belong to it.
    pub fn space_table(&self) -> SpaceTable {
        let mut table = SpaceTable::new();
        for space in self.space_records() {
            table.insert(self.text(space.name), space.index);
        }
        table
    }
}

impl Template {
    /// Writes the template as a lone `construct_tpl` in the XML form.
    pub fn encode_xml(&self, spaces: &SpaceTable) -> Result<String, SlaError> {
        let mut encoder = XmlEncoder::new(true);
        encode_template(&mut encoder, spaces, &self.as_ref())?;
        Ok(encoder.into_string())
    }

    /// Writes the template as a lone `construct_tpl` in the packed form.
    pub fn encode_packed(&self, spaces: &SpaceTable) -> Result<Vec<u8>, SlaError> {
        let mut encoder = PackedEncoder::new();
        encode_template(&mut encoder, spaces, &self.as_ref())?;
        Ok(encoder.into_bytes())
    }

    /// Reads a lone `construct_tpl` in the packed form and validates it.
    pub fn decode_packed(
        bytes: &[u8],
        spaces: &SpaceTable,
        limits: &Limits,
    ) -> Result<Self, SlaError> {
        let template = crate::read::decode_template(
            PackedCursor::new(bytes, limits.element_depth),
            limits,
            spaces,
        )?;
        template.validate(spaces, limits)?;
        Ok(template)
    }

    /// Reads a lone `construct_tpl` in the XML form and validates it.
    pub fn decode_xml(text: &str, spaces: &SpaceTable, limits: &Limits) -> Result<Self, SlaError> {
        let document = Document::parse(text).map_err(|error| SlaError::Stream {
            location: Location::default(),
            error: StreamError::Marshal(error.into()),
        })?;
        let table = ids::id_table().map_err(|error| SlaError::structure("", error.to_string()))?;
        let any = AnySpace;
        let decoder = XmlDecoder::new(&document, &table, &any);
        let template = crate::read::decode_template(
            MarshalSource::new(decoder, true, limits.element_depth),
            limits,
            spaces,
        )?;
        template.validate(spaces, limits)?;
        Ok(template)
    }

    /// Reads a lone `construct_tpl` in the packed form through `bk-marshal`'s
    /// generic decoder.
    pub fn decode_packed_marshal(
        bytes: &[u8],
        spaces: &SpaceTable,
        limits: &Limits,
    ) -> Result<Self, SlaError> {
        let any = AnySpace;
        let decoder = PackedDecoder::new(bytes, &any);
        let template = crate::read::decode_template(
            MarshalSource::new(decoder, false, limits.element_depth),
            limits,
            spaces,
        )?;
        template.validate(spaces, limits)?;
        Ok(template)
    }

    /// Checks the template: value ranges, label numbers, space references,
    /// directive shapes. Handle indices are not bounded, since a lone
    /// template has no constructor.
    pub fn validate(&self, spaces: &SpaceTable, limits: &Limits) -> Result<(), SlaError> {
        crate::validate::check_template(
            limits,
            &|index| spaces.name(index).is_some(),
            "construct_tpl",
            &self.as_ref(),
            u32::MAX,
        )
    }
}
