//! How the fuzz target `bk_binutils_sys_disassemble` reads its input, shared
//! with the test that replays saved inputs (`tests/fuzz_regressions.rs`):
//! two bytes choose the architecture among `architectures`, one byte the
//! byte order (bit 0) and whether an option string follows (bit 1; its
//! length in the next byte), eight bytes the address, and the rest is
//! disassembled from start to end.

use bk_binutils_sys::{ArchInfo, RawDisassembler, RawError, TEXT_CAPACITY};

/// Runs one input. A trapped abort inside binutils is returned as `Err`;
/// everything else that binutils reports is an expected outcome.
pub(crate) fn run(data: &[u8], architectures: &[ArchInfo]) -> Result<(), (String, String)> {
    let Some((head, rest)) = data.split_first_chunk::<3>() else {
        return Ok(());
    };
    let index = usize::from(u16::from_le_bytes([head[0], head[1]])) % architectures.len().max(1);
    let Some(arch) = architectures.get(index) else {
        return Ok(());
    };
    let big_endian = head[2] & 1 != 0;
    let (options, rest) = if head[2] & 2 != 0 {
        let Some((&len, rest)) = rest.split_first() else {
            return Ok(());
        };
        let len = usize::from(len % 48).min(rest.len());
        let (text, rest) = rest.split_at(len);
        (Some(String::from_utf8_lossy(text).into_owned()), rest)
    } else {
        (None, rest)
    };
    let Some((address, bytes)) = rest.split_first_chunk::<8>() else {
        return Ok(());
    };
    let address = u64::from_le_bytes(*address);
    let aborted = |e: RawError| match e {
        RawError::Aborted { message } => Err((arch.printable_name.clone(), message)),
        _ => Ok(()),
    };

    let mut dis = match RawDisassembler::new(arch.arch, arch.mach, big_endian, options.as_deref()) {
        Ok(dis) => dis,
        Err(e) => return aborted(e),
    };
    let mut request = match dis.request(bytes, address) {
        Ok(request) => request,
        Err(e) => return aborted(e),
    };
    let mut offset = 0;
    while offset < bytes.len() {
        match request.step(offset) {
            Ok(step) => {
                assert!(step.text.len() < TEXT_CAPACITY);
                offset += usize::try_from(step.length).unwrap_or(0).max(1);
            }
            Err(e) => return aborted(e),
        }
    }
    Ok(())
}
