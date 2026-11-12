//! Marshalling of offsets into a space (Ghidra `AddrSpace::encodeAttributes`,
//! `AddrSpace::decodeAttributes` and the `JoinSpace` overrides).
//!
//! An address is written as attributes of whatever element holds it: the
//! space and the offset, with an optional size. A join address is written as
//! its pieces instead (`piece1="register:0x0:4"`, …).

use bk_marshal::ids::{ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_UNKNOWN};
use bk_marshal::xml::number;
use bk_marshal::{Decoder, Encoder, SpaceId};

use super::{Space, SpaceType};
use crate::error::SpaceError;
use crate::ids::{ATTRIB_LOGICALSIZE, ATTRIB_PIECE};
use crate::manager::SpaceManager;
use crate::varnode::VarnodeData;

/// The most pieces one join address can be written with (Ghidra
/// `JoinSpace::MAX_PIECES`). Decoding accepts one more, as Ghidra does.
pub const MAX_JOIN_PIECES: usize = 64;

impl SpaceManager {
    /// Writes `offset` in `space` as the `space` and `offset` attributes of
    /// the current element, or as the pieces of a join (Ghidra
    /// `encodeAttributes(encoder, offset)`).
    pub fn encode_attributes<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        space: SpaceId,
        offset: u64,
    ) -> Result<(), SpaceError> {
        let spc = self.require(space)?;
        if spc.space_type() == SpaceType::Join {
            return self.encode_join_attributes(encoder, spc, offset);
        }
        encoder.write_space(ATTRIB_SPACE, &spc.marshal_ref());
        encoder.write_unsigned(ATTRIB_OFFSET, offset);
        Ok(())
    }

    /// Writes `offset` in `space` and a size (Ghidra
    /// `encodeAttributes(encoder, offset, size)`). A join address ignores the
    /// size: its pieces imply it.
    pub fn encode_attributes_sized<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        space: SpaceId,
        offset: u64,
        size: u32,
    ) -> Result<(), SpaceError> {
        let spc = self.require(space)?;
        if spc.space_type() == SpaceType::Join {
            return self.encode_join_attributes(encoder, spc, offset);
        }
        encoder.write_space(ATTRIB_SPACE, &spc.marshal_ref());
        encoder.write_unsigned(ATTRIB_OFFSET, offset);
        encoder.write_signed(ATTRIB_SIZE, i64::from(size));
        Ok(())
    }

    fn encode_join_attributes<E: Encoder + ?Sized>(
        &self,
        encoder: &mut E,
        join: &Space,
        offset: u64,
    ) -> Result<(), SpaceError> {
        let record = self.find_join(offset)?;
        encoder.write_space(ATTRIB_SPACE, &join.marshal_ref());
        if record.num_pieces() > MAX_JOIN_PIECES {
            return Err(SpaceError::TooManyJoinPieces);
        }
        for (index, piece) in (0u32..).zip(record.pieces()) {
            let space = piece
                .space()
                .and_then(|space| self.space(space))
                .ok_or(SpaceError::InvalidAddress)?;
            let text = format!("{}:{:#x}:{}", space.name(), piece.offset, piece.size);
            encoder.write_string_indexed(ATTRIB_PIECE, index, &text)?;
        }
        if record.num_pieces() == 1 {
            encoder.write_unsigned(ATTRIB_LOGICALSIZE, u64::from(record.unified().size));
        }
        Ok(())
    }

    /// Reads an offset into `space`, and a size, from the attributes of the
    /// current element (Ghidra `decodeAttributes`). The size is 0 when no
    /// `size` attribute is present. Attribute iteration must be at its start.
    ///
    /// For the join space the attributes are the pieces, and the join record
    /// is created if it does not exist yet.
    pub fn decode_attributes<'a, D: Decoder<'a> + ?Sized>(
        &self,
        space: SpaceId,
        decoder: &mut D,
    ) -> Result<(u64, u32), SpaceError> {
        let spc = self.require(space)?;
        if spc.space_type() == SpaceType::Join {
            return self.decode_join_attributes(decoder);
        }
        let mut offset = None;
        let mut size = 0;
        while let Some(attribute) = decoder.next_attribute()? {
            if attribute == ATTRIB_OFFSET {
                offset = Some(decoder.read_unsigned()?);
            } else if attribute == ATTRIB_SIZE {
                size = decoder.read_signed()? as u32;
            }
        }
        let offset = offset.ok_or(SpaceError::MissingOffset)?;
        Ok((offset, size))
    }

    /// Reads the pieces of a join address (Ghidra
    /// `JoinSpace::decodeAttributes`). Every attribute numbered from `piece`
    /// upwards counts as a piece, as in Ghidra; where Ghidra leaves a gap in
    /// the numbering uninitialised, this fails.
    fn decode_join_attributes<'a, D: Decoder<'a> + ?Sized>(
        &self,
        decoder: &mut D,
    ) -> Result<(u64, u32), SpaceError> {
        let mut pieces: Vec<Option<VarnodeData>> = Vec::new();
        let mut logical_size = 0;
        while let Some(mut attribute) = decoder.next_attribute()? {
            if attribute == ATTRIB_LOGICALSIZE {
                logical_size = decoder.read_unsigned()? as u32;
                continue;
            }
            if attribute == ATTRIB_UNKNOWN {
                attribute = decoder.indexed_attribute(ATTRIB_PIECE)?;
            }
            let Some(position) = attribute.get().checked_sub(ATTRIB_PIECE.id()) else {
                continue;
            };
            let position = position as usize;
            if position > MAX_JOIN_PIECES {
                continue;
            }
            let value = decoder.read_string()?;
            let piece = self.parse_join_piece(value)?;
            if pieces.len() <= position {
                pieces.resize(position + 1, None);
            }
            if let Some(slot) = pieces.get_mut(position) {
                *slot = Some(piece);
            }
        }
        let pieces = pieces
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(SpaceError::MalformedJoinPiece)?;
        let record = self.find_add_join(pieces, logical_size)?;
        Ok((record.unified().offset, record.unified().size))
    }

    /// Parses one piece: `space:offset:size`, or a register name.
    fn parse_join_piece(&self, value: &str) -> Result<VarnodeData, SpaceError> {
        let Some((space_name, rest)) = value.split_once(':') else {
            return self.register(value);
        };
        let (offset, size) = rest.split_once(':').ok_or(SpaceError::MalformedJoinPiece)?;
        let space = self
            .space_by_name(space_name)
            .ok_or_else(|| SpaceError::UnknownSpaceName(space_name.to_owned()))?;
        Ok(VarnodeData::new(
            space.id(),
            number::parse_u64(offset),
            number::parse_u32(size),
        ))
    }
}
