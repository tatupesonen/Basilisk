//! Test support for basilisk: finding Ghidra and the reference tools,
//! running them, and comparing against what they say.
//!
//! basilisk's correctness is measured against Ghidra itself (ADR-007). This
//! crate is what other crates' tests use to do that; it is a
//! dev-dependency only and nothing here ships in the product. It has no
//! counterpart in Ghidra, but it wraps three of Ghidra's native programs —
//! the SLEIGH compiler (`slgh_compile.cc`), the decompiler console
//! (`consolemain.cc`) and the decompiler test runner (`test.cc`,
//! `testfunction.cc`) — and reads the decompiler's data-test files as
//! `testfunction.cc` and `loadimage_xml.cc` do.
//!
//! * [`paths`] — the Ghidra source tree ([`ghidra_dir`]) and the directory
//!   `scripts/build-reference.sh` builds ([`reference_dir`]).
//! * [`skip`] — [`require_ghidra`], [`require_reference`], [`require_tool`]:
//!   run a test when its oracle is present, skip it visibly when not.
//! * [`tools`] — typed wrappers that run `sleigh`, `decomp`, `decomp_test`
//!   and `pcodedump` with a time limit.
//! * [`datatest`] — Ghidra's `<decompilertest>` files as plain data.
//! * [`corpus`] — every language directory, `.slaspec` and data test.
//!
//! A differential test typically reads:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Pcodedump) else {
//!     return Ok(());
//! };
//! let dump = reference.pcodedump().dump("x86:LE:64:default", 0x1000, &[0x55, 0xc3])?;
//! for instruction in dump.instructions() {
//!     // compare with what basilisk decodes at `instruction.address`
//! }
//! # Ok(())
//! # }
//! ```

pub mod corpus;
pub mod datatest;
pub mod paths;
pub mod skip;
pub mod tools;

pub use corpus::{CorpusError, LanguageDir, LanguageFile};
pub use datatest::{DataTest, DataTestError, parse_data_test, read_data_test};
pub use paths::{GhidraDir, ReferenceDir, Tool, ghidra_dir, reference_dir, workspace_root};
pub use skip::{require_ghidra, require_reference, require_tool};
pub use tools::{ToolError, ToolOutput};
