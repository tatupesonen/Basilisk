//! Throwaway evaluation: how do `object` and `goblin` behave on ELF files
//! damaged in the ways Ghidra's ElfHeader tolerates?
use object::read::elf::{FileHeader, ProgramHeader as _};
use object::Object;
use std::panic::catch_unwind;

fn w16(b: &mut [u8], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_le_bytes()); }
fn w32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }
fn w64(b: &mut [u8], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_le_bytes()); }
fn r16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) }
fn r32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn r64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

fn object_low(data: &[u8]) -> String {
    type H = object::elf::FileHeader64<object::Endianness>;
    let h = match H::parse(data) { Ok(h) => h, Err(e) => return format!("header ERR: {e}") };
    let e = match h.endian() { Ok(e) => e, Err(e) => return format!("endian ERR: {e}") };
    let mut out = String::new();
    match h.program_headers(e, data) {
        Ok(p) => {
            out += &format!("phdrs={} ", p.len());
            let dynamic = p.iter().find_map(|ph| ph.dynamic(e, data).transpose());
            out += &match dynamic { Some(Ok(d)) => format!("dyn={} ", d.len()), Some(Err(e)) => format!("dyn ERR({e}) "), None => "dyn=none ".into() };
        }
        Err(e) => out += &format!("phdrs ERR({e}) "),
    }
    match h.sections(e, data) {
        Ok(s) => {
            out += &format!("shdrs={} ", s.len());
            match s.symbols(e, data, object::elf::SHT_SYMTAB) { Ok(t) => out += &format!("symtab={} ", t.len()), Err(e) => out += &format!("symtab ERR({e}) ") }
            match s.symbols(e, data, object::elf::SHT_DYNSYM) { Ok(t) => out += &format!("dynsym={} ", t.len()), Err(e) => out += &format!("dynsym ERR({e}) ") }
            let names = s.iter().filter(|sh| s.section_name(e, sh).is_ok()).count();
            out += &format!("named={names} ");
        }
        Err(e) => out += &format!("sections ERR({e}) "),
    }
    out
}

fn object_high(data: &[u8]) -> String {
    match object::File::parse(data) {
        Ok(f) => format!("ok sections={} syms={} dynsyms={}", f.sections().count(), f.symbols().count(), f.dynamic_symbols().count()),
        Err(e) => format!("ERR: {e}"),
    }
}

fn goblin_run(data: &[u8], permissive: bool) -> String {
    let opts = if permissive { goblin::options::ParseOptions::permissive() } else { goblin::options::ParseOptions::strict() };
    match goblin::elf::Elf::parse_with_opts(data, &opts) {
        Ok(e) => format!("ok phdrs={} shdrs={} syms={} dynsyms={} dyn={} libs={:?}", e.program_headers.len(), e.section_headers.len(), e.syms.len(), e.dynsyms.len(), e.dynamic.as_ref().map_or(0, |d| d.dyns.len()), e.libraries),
        Err(e) => format!("ERR: {e}"),
    }
}

fn report(name: &str, data: &[u8]) {
    println!("== {name}");
    let run = |label: &str, f: &dyn Fn() -> String| {
        let f = std::panic::AssertUnwindSafe(f);
        let r = catch_unwind(|| f()).unwrap_or_else(|_| "PANIC".into());
        println!("   {label:<18} {r}");
    };
    run("object low-level", &|| object_low(data));
    run("object File", &|| object_high(data));
    run("goblin strict", &|| goblin_run(data, false));
    run("goblin permissive", &|| goblin_run(data, true));
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let path = std::env::args().nth(1).expect("path to a little-endian ELF64 .so");
    let good = std::fs::read(path).unwrap();
    assert_eq!(&good[..6], b"\x7fELF\x02\x01", "need ELF64 LE");
    let shoff = r64(&good, 0x28) as usize;
    let shnum = r16(&good, 0x3c) as usize;
    let phoff = r64(&good, 0x20) as usize;
    let phnum = r16(&good, 0x38) as usize;
    let sh = |i: usize| shoff + i * 64;
    let find_sh = |ty: u32| (0..shnum).find(|&i| r32(&good, sh(i) + 4) == ty).unwrap();
    report("intact", &good);

    // 1. File truncated in the middle of the section header table.
    report("truncated mid section-header table", &good[..shoff + 64 * (shnum / 2) + 20]);

    // 2. e_phentsize is wrong, sections present (Ghidra: warn, use sections only).
    let mut b = good.clone(); w16(&mut b, 0x36, 57); report("e_phentsize=57", &b);

    // 3. Section headers stripped (Ghidra: finds dynsym through DT_SYMTAB + hash).
    let mut b = good.clone(); w64(&mut b, 0x28, 0); w16(&mut b, 0x3c, 0); w16(&mut b, 0x3e, 0);
    report("section headers stripped", &b);

    // 4. Invalid EI_DATA (Ghidra: warn, assume little-endian).
    let mut b = good.clone(); b[5] = 0; report("EI_DATA=0", &b);

    // 5. .symtab sh_offset outside the file (Ghidra: warn, skip that table only).
    let mut b = good.clone(); let i = find_sh(2); w64(&mut b, sh(i) + 0x18, 0x7fff_0000);
    report(".symtab offset out of file", &b);

    // 6. e_shnum larger than the file can hold (Ghidra: warn, truncate count).
    let mut b = good.clone(); w16(&mut b, 0x3c, (shnum + 500) as u16); report("e_shnum too large", &b);

    // 7. e_phoff outside the file (Ghidra: warn, ignore program headers).
    let mut b = good.clone(); w64(&mut b, 0x20, 0x7fff_0000); report("e_phoff out of file", &b);

    // 8. PT_DYNAMIC p_offset wrong, p_vaddr right (Ghidra: maps p_vaddr through PT_LOAD).
    let mut b = good.clone();
    let d = (0..phnum).map(|i| phoff + i * 56).find(|&o| r32(&good, o) == 2).unwrap();
    w64(&mut b, d + 8, 0x7fff_0000); report("PT_DYNAMIC p_offset bogus", &b);

    // 9. A relocation section whose size runs past the end of the file.
    let mut b = good.clone(); let i = find_sh(4); w64(&mut b, sh(i) + 0x20, 0x7fff_0000);
    report(".rela size past EOF", &b);

    // 10. .dynsym sh_entsize too small (Ghidra: warn, skip that table).
    let mut b = good.clone(); let i = find_sh(11); w64(&mut b, sh(i) + 0x38, 8);
    report(".dynsym sh_entsize=8", &b);

    // 11. e_shstrndx out of range (Ghidra: sections get SECTION<n> names).
    let mut b = good.clone(); w16(&mut b, 0x3e, 0x7000); report("e_shstrndx out of range", &b);

    // 12. Stripped sections AND absurd DT_STRSZ.
    let _ = w32;
}
