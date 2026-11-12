//! `bk_elf_parse` (the spec's `elf_parse`): parse arbitrary bytes as ELF
//! and read everything on demand.
#![no_main]

#[path = "bk_elf/mod.rs"]
mod elf_target;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    std::hint::black_box(elf_target::elf_parse(data));
});
