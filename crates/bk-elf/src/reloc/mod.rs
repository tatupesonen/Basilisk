//! Relocation tables: `REL`, `RELA`, `RELR` and Android packed relocations.

mod android;
mod rel;
mod relr;
mod table;

// HANDOVER: used by the relocation-table parsing step, which is not written yet.
#[allow(
    unused_imports,
    reason = "handover: its caller (parse::relocs) does not exist yet"
)]
pub(crate) use android::scan as scan_android;
pub use android::{
    AndroidIter, RELOCATION_GROUP_HAS_ADDEND_FLAG, RELOCATION_GROUPED_BY_ADDEND_FLAG,
    RELOCATION_GROUPED_BY_INFO_FLAG, RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG,
};
pub use rel::StandardIter;
pub use relr::RelrIter;
pub use table::{Relocation, RelocationFormat, RelocationIter, RelocationLayout, RelocationTable};
