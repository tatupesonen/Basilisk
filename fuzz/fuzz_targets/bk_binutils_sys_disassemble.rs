//! Arbitrary bytes for any architecture binutils knows, through the raw
//! interface of `bk-binutils-sys`: the process must not crash, read or write
//! outside its buffers (run with AddressSanitizer), or hang (libFuzzer's
//! `-timeout`).
//!
//! Input: two bytes choose the architecture (among every name
//! `bfd_scan_arch` accepts), one byte the byte order and whether an option
//! string follows (its length in the next byte), eight bytes the address,
//! and the rest is disassembled from start to end.
//!
//! Environment: `BK_FUZZ_FAMILY=<family>` restricts the run to one BFD
//! architecture family (`i386`, `arm`, ...); `BK_FUZZ_ABORTS=panic` turns a
//! trapped `abort()`/assertion inside binutils into a finding, to discover
//! which are reachable from bytes (by default they are handled errors).

#![no_main]

use std::sync::OnceLock;

use bk_binutils_sys::{ArchInfo, RawDisassembler, RawError, TEXT_CAPACITY, architecture_names, scan_architecture};
use libfuzzer_sys::fuzz_target;

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

fn check(result: Result<(), RawError>, arch: &ArchInfo) {
    if let Err(RawError::Aborted { message }) = result
        && aborts_are_findings()
    {
        panic!("binutils aborted on {}: {message}", arch.printable_name);
    }
}

fn run(data: &[u8]) -> Option<()> {
    let archs = architectures();
    let (head, rest) = data.split_first_chunk::<3>()?;
    let index = usize::from(u16::from_le_bytes([head[0], head[1]])) % archs.len().max(1);
    let arch = archs.get(index)?;
    let big_endian = head[2] & 1 != 0;
    let (options, rest) = if head[2] & 2 != 0 {
        let (&len, rest) = rest.split_first()?;
        let len = usize::from(len % 48).min(rest.len());
        let (text, rest) = rest.split_at(len);
        (Some(String::from_utf8_lossy(text).into_owned()), rest)
    } else {
        (None, rest)
    };
    let (address, bytes) = rest.split_first_chunk::<8>()?;
    let address = u64::from_le_bytes(*address);

    let mut dis = match RawDisassembler::new(arch.arch, arch.mach, big_endian, options.as_deref()) {
        Ok(dis) => dis,
        Err(e) => {
            check(Err(e), arch);
            return None;
        }
    };
    let mut request = match dis.request(bytes, address) {
        Ok(request) => request,
        Err(e) => {
            check(Err(e), arch);
            return None;
        }
    };
    let mut offset = 0;
    while offset < bytes.len() {
        match request.step(offset) {
            Ok(step) => {
                assert!(step.text.len() < TEXT_CAPACITY);
                offset += usize::try_from(step.length).unwrap_or(0).max(1);
            }
            Err(e) => {
                check(Err(e), arch);
                break;
            }
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(data);
});
