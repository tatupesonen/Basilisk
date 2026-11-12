//! Relocation tables: `REL`, `RELA`, `RELR` and Android packed relocations.

mod android;
mod rel;
mod relr;
mod table;

pub(crate) use android::scan as scan_android;
pub use android::{
    AndroidIter, RELOCATION_GROUP_HAS_ADDEND_FLAG, RELOCATION_GROUPED_BY_ADDEND_FLAG,
    RELOCATION_GROUPED_BY_INFO_FLAG, RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG,
};
pub use rel::StandardIter;
pub use relr::RelrIter;
pub use table::{Relocation, RelocationFormat, RelocationIter, RelocationLayout, RelocationTable};
