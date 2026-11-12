//! Fuzz target bodies for `bk-elf` (target `bk_elf_parse`). Also included by
//! `crates/bk-elf/tests/proptests.rs` and `fuzz_regressions.rs`.

use bk_bin::MemoryProvider;
use bk_elf::ElfFile;

/// The most items of each kind read from one file, so a run stays fast on
/// inputs that declare millions of symbols or relocations.
const LIMIT: usize = 4096;

/// Parses `data` and exercises every on-demand read; returns how many items
/// were read, so that nothing is optimised away.
pub fn elf_parse(data: &[u8]) -> usize {
    let provider = MemoryProvider::new(data);
    let Ok(elf) = ElfFile::parse(&provider) else {
        return 0;
    };
    let mut seen = elf.diagnostics().len();
    for section in elf.sections() {
        seen += elf.section_name(section).len();
        seen += elf.section_data(section).map_or(0, |d| d.len());
        seen += elf.section_notes(section).len();
        seen += elf.version_definitions(section).len();
        seen += elf.version_needs(section).len();
        seen += elf.symbol_versions(section).len();
        if let Some(out) = elf.decompress_section(section) {
            seen += out.data.len();
        }
    }
    seen += elf.program_notes().len();
    seen += elf.dynamic_library_names().map(|n| n.len()).sum::<usize>();
    for table in elf.symbol_tables() {
        for symbol in elf.symbols(table).take(LIMIT) {
            seen += elf.formatted_symbol_name(table, &symbol).len();
            seen += elf.extended_section_index(table, &symbol) as usize & 1;
        }
    }
    for table in elf.relocation_tables() {
        for relocation in elf.relocations(table).take(LIMIT) {
            seen += relocation.symbol_index() as usize & 1;
            seen += relocation.relocation_type() as usize & 1;
        }
    }
    seen += usize::from(elf.abi_tag().is_some());
    seen += usize::from(elf.build_id().is_some());
    seen += usize::from(elf.gnu_property().is_some());
    seen += usize::from(elf.debug_link().is_some());
    seen += usize::from(elf.debug_alt_link().is_some());
    seen += usize::from(elf.comment().is_some());
    seen += elf.image_base() as usize & 1;
    seen
}
