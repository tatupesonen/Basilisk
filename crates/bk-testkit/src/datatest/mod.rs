//! Ghidra's decompiler data tests (`decompile/datatests/*.xml`).
//!
//! Each file is a `<decompilertest>`: a small binary image, a console script
//! that decompiles something from it, and regular expressions the printed
//! output must match a given number of times. Ghidra reads them in
//! `testfunction.cc` (`FunctionTestCollection`) and `loadimage_xml.cc`; this
//! module turns one into plain data ([`DataTest`]) for the oracle wrappers
//! and for basilisk's own decompiler test runner.

mod model;
mod parse;

pub use model::{BinaryImage, ByteChunk, DataTest, ImageSymbol, StringMatch};
pub use parse::{DataTestError, parse_data_test, read_data_test};
