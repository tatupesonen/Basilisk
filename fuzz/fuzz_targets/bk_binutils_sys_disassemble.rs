//! Arbitrary bytes for any architecture binutils knows, through the raw
//! interface of `bk-binutils-sys`: the process must not crash, read or write
//! outside its buffers (run with AddressSanitizer, see fuzz/README.md), or
//! hang (libFuzzer's `-timeout`). The input format is in
//! `crates/bk-binutils-sys/tests/fuzz_input/mod.rs`, shared with the test
//! that replays `fuzz/regressions/bk_binutils_sys_disassemble/`.
//!
//! Environment: `BK_FUZZ_FAMILY=<family>` restricts the run to one BFD
//! architecture family (`i386`, `arm`, ...); `BK_FUZZ_ABORTS=panic` turns a
//! trapped `abort()`/assertion inside binutils into a finding, to discover
//! which are reachable from bytes (by default they are handled errors).

#![no_main]

use std::sync::OnceLock;

use bk_binutils_sys::{ArchInfo, architecture_names, scan_architecture};
use libfuzzer_sys::fuzz_target;

#[path = "../../crates/bk-binutils-sys/tests/fuzz_input/mod.rs"]
mod fuzz_input;

fn architectures() -> &'static [ArchInfo] {
    static ALL: OnceLock<Vec<ArchInfo>> = OnceLock::new();
    ALL.get_or_init(|| {
        let family = std::env::var("BK_FUZZ_FAMILY").ok().filter(|f| !f.is_empty());
        architecture_names()
            .unwrap_or_default()
            .iter()
            .filter_map(|name| scan_architecture(name).ok().flatten())
            .filter(|arch| family.as_deref().is_none_or(|f| arch.family == f))
            .collect()
    })
}

fn aborts_are_findings() -> bool {
    static PANIC: OnceLock<bool> = OnceLock::new();
    *PANIC.get_or_init(|| std::env::var("BK_FUZZ_ABORTS").is_ok_and(|v| v == "panic"))
}

fuzz_target!(|data: &[u8]| {
    if let Err((arch, message)) = fuzz_input::run(data, architectures())
        && aborts_are_findings()
    {
        panic!("binutils aborted on {arch}: {message}");
    }
});
