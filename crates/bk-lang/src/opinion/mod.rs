//! Loader opinion files (`.opinion`): which language and compiler a loader
//! should pick for a file, keyed by the loader's name and by values from
//! the file's header.
//!
//! Ghidra reads these in `QueryOpinionServiceHandler` and answers queries
//! in `QueryOpinionService`; [`OpinionDatabase`] reproduces both, down to
//! the order of the results.

mod javahash;
mod model;
mod query;
mod read;

pub use model::{Constraint, ConstraintId, Opinions};
pub use query::{OpinionDatabase, QueryResult, secondary_attribute_matches};
pub use read::{parse, read_file};
