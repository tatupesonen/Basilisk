//! Join records for a loaded state.
//!
//! Ghidra keeps one table of join records per architecture
//! (`AddrSpaceManager::splitlist`, `translate.hh:198`–`262`); a record's
//! offset in the join space is handed out in creation order, each record
//! taking the next multiple of 16 bytes (`findAddJoin`,
//! `translate.cc:684`–`728`). A `bkstate` dump of format version 2 does
//! not carry the table, so join varnodes of a loaded state print as
//! `{unlinked:…}`. When the dump carries the table (every record of
//! `splitlist`, in order: the requested format addition), replaying the
//! records through [`SpaceManager::find_add_join`] on the dump's spaces
//! rebuilds the same offsets, which [`install_joins`] checks.

use bk_core::{SpaceManager, VarnodeData};

use super::StateError;

/// One join record as a dump would carry it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRecordDump {
    /// `unified.offset`: the record's offset in the join space.
    pub offset: u64,
    /// `unified.size`: the logical size.
    pub size: u32,
    /// `pieces`, most significant first; a constant-space piece is padding.
    pub pieces: Vec<VarnodeData>,
}

/// Creates the records in `spaces`, in the given (creation) order, and
/// checks that each lands at the offset and size the dump names. `spaces`
/// must not have created join records of its own before.
pub fn install_joins(spaces: &SpaceManager, records: &[JoinRecordDump]) -> Result<(), StateError> {
    for r in records {
        // `findAddJoin` takes a logical size only for a single piece.
        let logical = if r.pieces.len() == 1 { r.size } else { 0 };
        let got = spaces
            .find_add_join(r.pieces.clone(), logical)
            .map_err(|source| StateError::Space {
                name: "join".to_owned(),
                source,
            })?;
        let unified = got.unified();
        if unified.offset != r.offset || unified.size != r.size {
            return Err(StateError::Inconsistent {
                what: "join record",
                detail: format!(
                    "dump has {:#x}:{}, replay gives {:#x}:{}",
                    r.offset, r.size, unified.offset, unified.size
                ),
            });
        }
    }
    Ok(())
}
