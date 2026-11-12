//! Tests of the raw interface: what the C shim guarantees to safe Rust.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]
#![cfg(not(windows))]

use bk_binutils_sys::{
    RawDisassembler, RawError, TEXT_CAPACITY, architecture_names, is_available, scan_architecture,
};

fn x86_64() -> RawDisassembler {
    let arch = scan_architecture("i386:x86-64").unwrap().unwrap();
    RawDisassembler::new(arch.arch, arch.mach, false, None).unwrap()
}

/// Disassembles `bytes` from start to end; `(length, text)` per instruction.
fn all(dis: &mut RawDisassembler, bytes: &[u8], address: u64) -> Vec<(i32, String)> {
    let mut request = dis.request(bytes, address).unwrap();
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let step = request.step(offset).unwrap();
        out.push((step.length, String::from_utf8_lossy(step.text).into_owned()));
        if step.length <= 0 {
            break;
        }
        offset += usize::try_from(step.length).unwrap();
    }
    out
}

#[test]
fn binutils_is_built_in() {
    assert!(is_available());
}

#[test]
fn lists_architectures() {
    let names = architecture_names().unwrap();
    assert!(names.len() > 400, "only {} architectures", names.len());
    for expected in [
        "i386:x86-64",
        "aarch64",
        "mips:4000",
        "powerpc:common64",
        "riscv:rv64",
    ] {
        assert!(names.iter().any(|n| n == expected), "{expected} missing");
    }
}

#[test]
fn scans_architecture_names() {
    let arch = scan_architecture("i386:x86-64").unwrap().unwrap();
    assert_eq!(arch.family, "i386");
    assert_eq!(arch.printable_name, "i386:x86-64");
    assert_eq!((arch.bits_per_word, arch.bits_per_address), (64, 64));
    assert_eq!(scan_architecture("no-such-cpu").unwrap(), None);
    assert_eq!(scan_architecture("with\0nul").unwrap(), None);
}

#[test]
fn listed_architectures_scan_except_the_two_binutils_cannot_look_up() {
    // cpu-tic4x.c's scan function accepts "tic4x", "c4x", "4x" and the like,
    // but not the printable names it lists itself.
    let unscannable: Vec<String> = architecture_names()
        .unwrap()
        .into_iter()
        .filter(|name| scan_architecture(name).unwrap().is_none())
        .collect();
    assert_eq!(unscannable, ["tms320c4x", "tms320c3x"]);
    assert_eq!(
        scan_architecture("tic4x").unwrap().unwrap().printable_name,
        "tms320c4x"
    );
}

#[test]
fn disassembles_x86_64() {
    let mut dis = x86_64();
    let got = all(&mut dis, &[0x55, 0x48, 0x89, 0xe5, 0xc3], 0x1000);
    assert_eq!(
        got,
        [
            (1, "push   %rbp".to_owned()),
            (3, "mov    %rsp,%rbp".to_owned()),
            (1, "ret".to_owned())
        ]
    );
}

#[test]
fn reports_instruction_information() {
    // call +0 at 0x1000: target 0x1005.
    let mut dis = x86_64();
    let mut request = dis.request(&[0xe8, 0, 0, 0, 0], 0x1000).unwrap();
    let step = request.step(0).unwrap();
    assert_eq!(step.length, 5);
    assert_eq!(String::from_utf8_lossy(step.text), "call   0x00001005");
}

#[test]
fn a_read_past_the_end_is_refused_and_reported() {
    // "mov $imm32,%eax" cut after two of its five bytes. binutils 2.41's x86
    // disassembler answers a refused read by printing the first byte as data.
    let mut dis = x86_64();
    let mut request = dis.request(&[0xb8, 0x01], 0x2000).unwrap();
    let step = request.step(0).unwrap();
    assert_eq!(
        (step.length, String::from_utf8_lossy(step.text).as_ref()),
        (1, ".byte 0xb8")
    );
    // The refused read is the four-byte immediate, which starts at 0x2001.
    assert_eq!(step.read_fault, Some(0x2001));
    drop(request);

    // AArch64 needs four bytes and has two: the print function fails.
    let arch = scan_architecture("aarch64").unwrap().unwrap();
    let mut dis = RawDisassembler::new(arch.arch, arch.mach, false, None).unwrap();
    let mut request = dis.request(&[0x1f, 0x20], 0x3000).unwrap();
    let step = request.step(0).unwrap();
    assert!(step.length < 0, "length {}", step.length);
    assert_eq!(step.read_fault, Some(0x3000));
}

#[test]
fn an_offset_outside_the_request_is_an_error() {
    let mut dis = x86_64();
    let mut request = dis.request(&[0x90], 0).unwrap();
    assert_eq!(
        request.step(1),
        Err(RawError::OffsetOutOfRange { offset: 1, len: 1 })
    );
    drop(request);
    let mut empty = dis.request(&[], 0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(
        empty.step(0),
        Err(RawError::OffsetOutOfRange { offset: 0, len: 0 })
    );
}

#[test]
fn an_architecture_without_disassembler_is_an_error() {
    // 0 is bfd_arch_unknown.
    let error = RawDisassembler::new(0, 0, false, None).unwrap_err();
    assert_eq!(error, RawError::NoDisassembler { arch: 0, mach: 0 });
    let error = RawDisassembler::new(0xffff, 7, true, None).unwrap_err();
    assert_eq!(
        error,
        RawError::NoDisassembler {
            arch: 0xffff,
            mach: 7
        }
    );
}

#[test]
fn starting_work_inside_an_open_request_is_refused_not_deadlocked() {
    let mut first = x86_64();
    let mut second = x86_64();
    let mut open = first.request(&[0x90, 0xc3], 0).unwrap();
    assert_eq!(
        second.request(&[0x90], 0).unwrap_err(),
        RawError::RequestInProgress
    );
    assert_eq!(
        RawDisassembler::new(0, 0, false, None).unwrap_err(),
        RawError::RequestInProgress
    );
    // Lookups and dropping a disassembler still work.
    assert!(scan_architecture("aarch64").unwrap().is_some());
    assert!(!architecture_names().unwrap().is_empty());
    drop(second);
    // The open request is unaffected.
    assert_eq!(open.step(0).unwrap().text, b"nop");
    assert_eq!(open.step(1).unwrap().text, b"ret");
    drop(open);
    assert_eq!(all(&mut first, &[0xc3], 0), [(1, "ret".to_owned())]);
}

#[test]
fn options_are_applied() {
    let arch = scan_architecture("i386:x86-64").unwrap().unwrap();
    let mut intel = RawDisassembler::new(arch.arch, arch.mach, false, Some("intel")).unwrap();
    assert_eq!(
        all(&mut intel, &[0x48, 0x89, 0xe5], 0),
        [(3, "mov    rbp,rsp".to_owned())]
    );
    let error = RawDisassembler::new(arch.arch, arch.mach, false, Some("a\0b")).unwrap_err();
    assert!(matches!(error, RawError::EmbeddedNul { .. }));
}

#[test]
fn the_callers_bytes_are_never_modified() {
    // C-SKY's disassembler rewrites 32-bit little-endian instructions in the
    // buffer it is given; that buffer must be the request's copy.
    let arch = scan_architecture("csky").unwrap().unwrap();
    let mut dis = RawDisassembler::new(arch.arch, arch.mach, false, None).unwrap();
    let bytes: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let before = bytes.clone();
    let _ = all(&mut dis, &bytes, 0);
    assert_eq!(bytes, before);
}

#[test]
fn text_is_bounded() {
    const { assert!(TEXT_CAPACITY >= 256) };
    let mut dis = x86_64();
    let mut request = dis.request(&[0x90; 64], 0).unwrap();
    for offset in 0..64 {
        let step = request.step(offset).unwrap();
        assert!(step.text.len() < TEXT_CAPACITY);
        assert!(!step.text_truncated);
    }
}

#[test]
fn disassemblers_can_be_used_from_several_threads() {
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            std::thread::spawn(move || {
                let (name, bytes, expected): (&str, &[u8], &str) = if worker % 2 == 0 {
                    ("i386:x86-64", &[0x48, 0x89, 0xe5], "mov    %rsp,%rbp")
                } else {
                    (
                        "aarch64",
                        &[0xfd, 0x7b, 0xbf, 0xa9],
                        "stp\tx29, x30, [sp, #-16]!",
                    )
                };
                let arch = scan_architecture(name).unwrap().unwrap();
                let mut dis = RawDisassembler::new(arch.arch, arch.mach, false, None).unwrap();
                for _ in 0..500 {
                    let got = all(&mut dis, bytes, 0x4000);
                    assert_eq!(got.len(), 1);
                    assert_eq!(got[0].1, expected);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}
