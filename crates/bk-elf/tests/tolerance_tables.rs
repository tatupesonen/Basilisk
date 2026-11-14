//! Ghidra's tolerance rules for the tables found after the headers: the
//! dynamic table, string tables, symbol tables (section-based and through
//! `DT_SYMTAB`) and relocation tables — one damaged fixture per rule, with
//! the diagnostic Ghidra logs (`ElfHeader.parseDynamicTable`,
//! `parseStringTables`, `parseSymbolTables`, `parseDynamicSymbolTable`,
//! `getExtendedSymbolSectionIndexTable`, `parseRelocationTables` and the
//! `ElfRelocationTable` constructor).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

#[allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses part of the support code"
)]
mod common;

use bk_bin::MemoryProvider;
use bk_elf::{DiagnosticKind, ElfFile};
use common::builder::{
    Built, Dyn, ElfBuilder, Enc, Ph, SampleIndex, Section, Segment, Sh, Sym, dt, sample, sht,
};

type Elf = ElfFile<MemoryProvider<Vec<u8>>>;

fn parse(bytes: &[u8]) -> Elf {
    ElfFile::parse(MemoryProvider::new(bytes.to_vec())).unwrap()
}

fn messages(elf: &Elf) -> Vec<&str> {
    elf.diagnostics()
        .iter()
        .map(|d| d.message.as_str())
        .collect()
}

/// The sample, edited, optionally without section headers.
fn variant(enc: Enc, stripped: bool, edit: impl FnOnce(&mut ElfBuilder, &SampleIndex)) -> Built {
    let (mut b, index) = sample(enc);
    b.section_headers = !stripped;
    edit(&mut b, &index);
    b.build()
}

fn tag_of(entry: &Dyn) -> u32 {
    match *entry {
        Dyn::Val(t, _) | Dyn::Addr(t, _) | Dyn::Size(t, _) => t,
    }
}

fn set_dyn(b: &mut ElfBuilder, tag: u32, value: Dyn) {
    for entry in b.dynamic.as_mut().unwrap() {
        if tag_of(entry) == tag {
            *entry = value;
        }
    }
}

fn remove_dyn(b: &mut ElfBuilder, tag: u32) {
    b.dynamic.as_mut().unwrap().retain(|e| tag_of(e) != tag);
}

/// A second `PT_LOAD` at 0x900000 whose file bytes are the last `filesz`
/// bytes of the file (or none).
fn far_segment(b: &mut ElfBuilder, filesz: u64) {
    b.extra_segments.push(Segment {
        p_type: 1,
        offset: 0, // patched by `place_far_segment`
        vaddr: 0x90_0000,
        filesz,
        memsz: 0x1000,
        align: 0x1000,
        ..Segment::default()
    });
}

/// Points the far segment (program header 2) at the end of the file.
fn place_far_segment(built: &mut Built, filesz: u64) {
    let len = built.bytes.len() as u64;
    built.set_ph(2, Ph::Offset, len - filesz);
}

const FAR: u64 = 0x90_0000;

// ---- the dynamic table (rule 20) --------------------------------------------

#[test]
fn dynamic_table_is_located_by_address_not_p_offset() {
    for enc in Enc::ALL {
        let mut built = variant(enc, false, |_, _| {});
        let intact = parse(&built.bytes).dynamic_table().cloned().unwrap();
        built.set_ph(1, Ph::Offset, 0x30);
        let elf = parse(&built.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.dynamic_table(), Some(&intact));
    }
}

#[test]
fn stripped_or_ambiguous_dynamic_segments() {
    for enc in Enc::ALL {
        let mut built = variant(enc, false, |_, _| {});
        built.set_ph(1, Ph::Filesz, 0);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf)[0],
            "ELF Dynamic table appears to have been stripped from binary"
        );
        assert!(elf.dynamic_table().is_none());

        // Two PT_DYNAMIC headers: warned about, then the section is used.
        let mut built = variant(enc, false, |b, _| {
            b.extra_segments.push(Segment {
                p_type: 2,
                vaddr: 0x10000,
                filesz: 8,
                ..Segment::default()
            });
        });
        built.set_ph(1, Ph::Offset, 0x30);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            ["Multiple ELF Dynamic table program headers found"]
        );
        assert_eq!(elf.dynamic_library_names().count(), 2);
    }
}

// ---- string tables (rules 21–23) ----------------------------------------------

#[test]
fn dynamic_string_table_problems() {
    for enc in Enc::ALL {
        let built = variant(enc, false, |b, _| remove_dyn(b, dt::STRTAB));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            ["ELF does not contain a dynamic string table (DT_STRTAB)"]
        );
        assert!(elf.dynamic_string_table().is_none());
        assert!(
            elf.dynamic_library_names()
                .all(|n| n.starts_with("UNK_LIB_NAME_"))
        );

        // Without sections the table can only come from DT_STRTAB/DT_STRSZ.
        let built = variant(enc, true, |b, _| remove_dyn(b, dt::STRSZ));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf)[0],
            "Failed to parse DT_STRTAB, missing dynamic dependency"
        );
        let built = variant(enc, true, |b, _| {
            set_dyn(b, dt::STRTAB, Dyn::Val(dt::STRTAB, 0));
        });
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf)[0],
            "ELF Dynamic String Table of size 54 appears to have been stripped from binary"
        );
        let built = variant(enc, true, |b, _| {
            set_dyn(b, dt::STRTAB, Dyn::Val(dt::STRTAB, FAR));
        });
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf)[0],
            "Failed to locate DT_STRTAB in memory at 0x900000"
        );
        assert_eq!(elf.diagnostics()[0].kind, DiagnosticKind::UnlocatedAddress);
        // The dynamic symbol table is still found, without names.
        let table = elf.dynamic_symbol_table().unwrap();
        assert_eq!(
            messages(&elf)[1],
            format!(
                "String table not found for dynamic symbol table at address 0x{:x}",
                table.address
            )
        );
        let symbol = elf.symbol(table, 1).unwrap();
        assert_eq!(elf.symbol_name(table, &symbol), Ok(None));
        assert_eq!(elf.formatted_symbol_name(table, &symbol), "<no name>");
    }
}

#[test]
fn unreadable_strings() {
    for enc in Enc::ALL {
        let built = variant(enc, false, |b, _| {
            b.dynamic
                .as_mut()
                .unwrap()
                .insert(0, Dyn::Val(dt::NEEDED, 54));
        });
        let elf = parse(&built.bytes);
        let names: Vec<_> = elf.dynamic_library_names().collect();
        assert_eq!(names, ["UNK_LIB_NAME_0", "libc.so.6", "libm.so.6"]);

        let strings = elf.dynamic_string_table().unwrap();
        let error = elf.string(strings, 54).unwrap_err();
        assert_eq!(error.kind, DiagnosticKind::StringRead);
        assert_eq!(
            error.message,
            format!(
                "Failed to read Elf String at offset 0x36 within String Table at offset 0x{:x}",
                strings.file_offset
            )
        );
        assert_eq!(elf.string(strings, 1).unwrap(), "libc.so.6");
    }
}

// ---- symbol tables from sections (rule 24) ----------------------------------------

#[test]
fn unusable_symbol_table_sections_are_skipped() {
    for enc in Enc::ALL {
        let base = variant(enc, false, |_, _| {});
        let symtab = sample(enc).1.symtab;
        let len = base.bytes.len() as u64;
        let cases: [(Sh, u64, String); 3] = [
            (Sh::Offset, len, format!("Symbol table section header '.symtab' has invalid offset value: 0x{len:x}")),
            (Sh::Size, 0, "Symbol table section header '.symtab' has invalid sh_size value (table size): 0x0".into()),
            (Sh::Entsize, 8, "Symbol table section header '.symtab' has unsupported sh_entsize value (table entry size): 0x8".into()),
        ];
        for (field, value, message) in cases {
            let mut built = base.clone();
            built.set_sh(symtab, field, value);
            let elf = parse(&built.bytes);
            assert_eq!(messages(&elf), [message.as_str()]);
            assert_eq!(elf.diagnostics()[0].kind, DiagnosticKind::SymbolTable);
            assert_eq!(elf.symbol_tables().len(), 1, "only .dynsym is left");
        }
    }
}

#[test]
fn symbol_table_size_problems() {
    for enc in Enc::ALL {
        let index = sample(enc).1;
        let entry = enc.sym_size();
        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.symtab, Sh::Size, 5 * entry + 3);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [
                "Symbol table section header '.symtab' has sh_size which is not a multiple of sh_entsize value"
            ]
        );
        let table = elf.symbol_table_for_section(index.symtab).unwrap();
        assert_eq!((table.symbol_count, table.truncated), (5, false));

        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.symtab, Sh::Size, 100_000 * entry);
        let elf = parse(&built.bytes);
        let offset = elf.sections()[index.symtab as usize].sh_offset;
        let available = elf.file_len() - offset;
        let fit = available / entry + u64::from(!available.is_multiple_of(entry));
        assert_eq!(
            messages(&elf)[0],
            format!("Symbol count 100000 exceeds file capacity {fit}; truncating")
        );
        let table = elf.symbol_table_for_section(index.symtab).unwrap();
        assert_eq!(u64::from(table.symbol_count), fit);
        assert!(table.truncated);
        // Every symbol, the partial last one included, decodes.
        assert_eq!(elf.symbols(table).count() as u64, fit);
    }
}

#[test]
fn symbol_table_without_string_table() {
    for enc in Enc::ALL {
        let index = sample(enc).1;
        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.symtab, Sh::Link, 99);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            ["String table not found for symbol table: .symtab"]
        );
        let table = elf.symbol_table_for_section(index.symtab).unwrap();
        assert_eq!(table.string_table, None);
        let symbol = elf.symbol(table, 4).unwrap();
        assert_eq!(elf.symbol_name(table, &symbol), Ok(None));
        // A section symbol with no name is still named after its section.
        let section_symbol = elf.symbol(table, 2).unwrap();
        assert_eq!(
            elf.symbol_name(table, &section_symbol).unwrap().unwrap(),
            ".text"
        );
    }
}

#[test]
fn symbol_name_outside_the_string_table() {
    let enc = Enc::LE64;
    let index = sample(enc).1;
    let built = variant(enc, false, |b, _| {
        // .symtab is the 9th section; replace its third symbol's name offset.
        let symtab = &mut b.sections[index.symtab as usize - 1];
        symtab.data[3 * 24..3 * 24 + 4].copy_from_slice(&5000u32.to_le_bytes());
    });
    let elf = parse(&built.bytes);
    let table = elf.symbol_table_for_section(index.symtab).unwrap();
    let symbol = elf.symbol(table, 3).unwrap();
    let error = elf.symbol_name(table, &symbol).unwrap_err();
    assert_eq!(
        error.message,
        format!(
            "Failed to read Elf String at offset 0x1388 within String Table at offset 0x{:x}",
            elf.sections()[index.strtab as usize].sh_offset
        )
    );
    assert_eq!(elf.formatted_symbol_name(table, &symbol), "<no name>");
}

/// `SHT_SYMTAB_SHNDX`: extended section indexes, and its own checks.
#[test]
fn extended_section_index_tables() {
    for enc in Enc::ALL {
        let make = |size: Option<u64>| {
            let mut b = ElfBuilder::new(enc);
            let mut strings = common::builder::StrTab::default();
            let names = [strings.add("big"), strings.add("small")];
            let strtab = b.strtab(".strtab", &strings, false);
            let symtab = b.symtab(
                ".symtab",
                sht::SYMTAB,
                strtab,
                &[
                    Sym {
                        name: names[0],
                        info: 0x11,
                        shndx: 0xffff,
                        ..Sym::default()
                    },
                    Sym {
                        name: names[1],
                        info: 0x11,
                        shndx: 1,
                        ..Sym::default()
                    },
                ],
            );
            let mut indexes = Vec::new();
            for v in [0u32, 70_000, 0] {
                enc.u32(&mut indexes, v);
            }
            let mut section = Section::new(".symtab_shndx", sht::SYMTAB_SHNDX, indexes)
                .link(symtab)
                .entsize(4)
                .align(4);
            section.size = size;
            let shndx = b.add(section);
            (b.build(), symtab, shndx)
        };
        let (built, symtab, shndx) = make(None);
        let elf = parse(&built.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        let table = elf.symbol_table_for_section(symtab).unwrap();
        let indexes = table.section_index_table.unwrap();
        assert_eq!((indexes.section, indexes.count), (shndx, 3));
        let symbols: Vec<_> = elf.symbols(table).collect();
        assert!(symbols[1].has_extended_section_index());
        assert_eq!(elf.extended_section_index(table, &symbols[1]), 70_000);
        assert_eq!(elf.extended_section_index(table, &symbols[2]), 0);

        let (built, ..) = make(Some(0));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            ["Symbol table section index header '.symtab_shndx' has invalid size: 0x0"]
        );
        let (mut built, _, shndx) = make(None);
        let len = built.bytes.len() as u64;
        built.set_sh(shndx, Sh::Offset, len);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Symbol table section index header '.symtab_shndx' has invalid offset value: 0x{len:x}"
            )]
        );
        // More indexes than symbols: cut to the symbol count.
        let (built, symtab, _) = make(Some(400));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf)[0],
            "Symbol section index count 100 exceeds hard limit 3; truncating"
        );
        assert_eq!(
            elf.symbol_table_for_section(symtab)
                .unwrap()
                .section_index_table
                .unwrap()
                .count,
            3
        );
    }
}

// ---- the dynamic symbol table without sections (rule 24) ------------------------------

#[test]
fn dynamic_symbol_table_problems() {
    for enc in Enc::ALL {
        type Edit = Box<dyn Fn(&mut ElfBuilder, &SampleIndex)>;
        let cases: Vec<(Edit, String)> = vec![
            (
                Box::new(|b, _| remove_dyn(b, dt::SYMTAB)),
                "ELF does not contain a dynamic symbol table (DT_SYMTAB)".into(),
            ),
            (
                Box::new(|b, _| remove_dyn(b, dt::SYMENT)),
                "Failed to parse DT_SYMTAB, missing dynamic dependency".into(),
            ),
            (
                Box::new(|b, _| remove_dyn(b, dt::HASH)),
                "Failed to parse DT_SYMTAB, missing dynamic dependency".into(),
            ),
            (
                Box::new(|b, _| set_dyn(b, dt::SYMTAB, Dyn::Val(dt::SYMTAB, 0))),
                "Failed to process DT_SYMTAB with 0 value".into(),
            ),
            (
                Box::new(|b, _| set_dyn(b, dt::SYMTAB, Dyn::Val(dt::SYMTAB, FAR))),
                "Failed to locate DT_SYMTAB in memory at 0x900000".into(),
            ),
            (
                Box::new(|b, _| set_dyn(b, dt::SYMENT, Dyn::Val(dt::SYMENT, 8))),
                "Dynamic symbol table has unsupported DT_SYMENT value (table entry size): 0x8"
                    .into(),
            ),
            (
                Box::new(|b, _| set_dyn(b, dt::HASH, Dyn::Val(dt::HASH, FAR))),
                "Failed to locate DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH in memory at 0x900000"
                    .into(),
            ),
        ];
        for (edit, message) in cases {
            let built = variant(enc, true, |b, i| edit(b, i));
            let elf = parse(&built.bytes);
            assert!(
                messages(&elf).contains(&message.as_str()),
                "{enc:?}: {:?} lacks {message}",
                messages(&elf)
            );
            assert!(elf.dynamic_symbol_table().is_none());
        }

        // nchain = 0.
        let built = variant(enc, true, |b, i| {
            let hash = &mut b.sections[i.hash as usize - 1].data;
            hash[4..8].fill(0);
        });
        let elf = parse(&built.bytes);
        let address = built.addr(sample(enc).1.dynsym);
        assert_eq!(
            messages(&elf)[0],
            format!(
                "Unable to determine symbol count for dynamic symbol table at address 0x{address:x}"
            )
        );
    }
}

/// Ghidra's `getOffset` throws for a segment with no file bytes; here the
/// table is skipped with a diagnostic.
#[test]
fn dynamic_symbol_table_in_a_segment_without_file_bytes() {
    let built = variant(Enc::LE64, true, |b, _| {
        far_segment(b, 0);
        set_dyn(b, dt::SYMTAB, Dyn::Val(dt::SYMTAB, FAR + 0x10));
    });
    let elf = parse(&built.bytes);
    assert_eq!(
        messages(&elf),
        [
            "Failed to locate DT_SYMTAB in file for address 0x900010: virtualAddress not loaded by this segment"
        ]
    );
}

#[test]
fn dynamic_symbol_table_offset_past_the_end() {
    let mut built = variant(Enc::BE32, true, |b, _| {
        far_segment(b, 8);
        set_dyn(b, dt::SYMTAB, Dyn::Val(dt::SYMTAB, FAR + 0x100));
    });
    place_far_segment(&mut built, 8);
    let elf = parse(&built.bytes);
    let offset = built.bytes.len() as u64 - 8 + 0x100;
    assert_eq!(
        messages(&elf),
        [format!(
            "Dynamic symbol table has invalid DT_SYMTAB value (table offset): 0x{offset:x}"
        )]
    );
}

/// The symbol count from `DT_GNU_XHASH` (`symndx + ngnusyms`) and from a
/// `DT_GNU_HASH` walk, and a walk that leaves the table.
#[test]
fn gnu_hash_tables() {
    for enc in Enc::ALL {
        // DT_GNU_XHASH: ngnusyms = 3, nbuckets = 1, symndx = 2.
        let built = variant(enc, true, |b, i| {
            let mut xhash = Vec::new();
            for v in [3u32, 1, 2, 0] {
                enc.u32(&mut xhash, v);
            }
            let x = b.add(
                Section::new(".gnu.xhash", 0x6fff_fff6, xhash)
                    .alloc()
                    .align(4),
            );
            remove_dyn(b, dt::HASH);
            b.dynamic
                .as_mut()
                .unwrap()
                .push(Dyn::Addr(dt::GNU_XHASH, x));
            let _ = i;
        });
        let elf = parse(&built.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.dynamic_symbol_table().unwrap().symbol_count, 5);

        // DT_GNU_HASH: two buckets starting at 1 and 3; chain ends at 4.
        let gnu = |symbase: u32, chain: &[u32]| {
            variant(enc, true, |b, _| {
                let mut gnu = Vec::new();
                for v in [2u32, symbase, 1, 6] {
                    enc.u32(&mut gnu, v);
                }
                enc.word(&mut gnu, u64::MAX); // bloom
                for v in [1u32, 3].iter().chain(chain) {
                    enc.u32(&mut gnu, *v);
                }
                let g = b.add(Section::new(".gnu.hash", 0x6fff_fff6, gnu).alloc().align(8));
                remove_dyn(b, dt::HASH);
                b.dynamic.as_mut().unwrap().push(Dyn::Addr(dt::GNU_HASH, g));
            })
        };
        let elf = parse(&gnu(1, &[2, 4, 6, 9]).bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.dynamic_symbol_table().unwrap().symbol_count, 5);

        // A symbol base above every bucket puts the chain before the table.
        let elf = parse(&gnu(1000, &[2, 4, 6, 9]).bytes);
        assert_eq!(
            messages(&elf)[0],
            "Error occured while inspecting GNU Hash table"
        );
        assert!(elf.dynamic_symbol_table().is_none());
    }
}

// ---- relocation tables (rule 24) ----------------------------------------------------

fn rel_tags(enc: Enc) -> (u32, u32, u32, &'static str) {
    if enc.is64 {
        (dt::RELA, dt::RELASZ, dt::RELAENT, "RELA")
    } else {
        (dt::REL, dt::RELSZ, dt::RELENT, "REL")
    }
}

#[test]
fn dynamic_relocation_table_problems() {
    for enc in Enc::ALL {
        let (addr, size, ent, name) = rel_tags(enc);
        let built = variant(enc, true, |b, _| set_dyn(b, size, Dyn::Val(size, 0)));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Dynamic relocation table has invalid DT_{name}SZ(0x{size:08x}) (table size): 0x0"
            )]
        );
        assert_eq!(elf.relocation_tables().len(), 2);

        let built = variant(enc, true, |b, _| set_dyn(b, ent, Dyn::Val(ent, 5)));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [
                "Failed to process relocation table: Relocation table has unsupported entry size: 0x5"
            ]
        );

        let built = variant(enc, true, |b, _| set_dyn(b, addr, Dyn::Val(addr, FAR)));
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [format!("Failed to locate DT_{name} in memory at 0x900000")]
        );

        // A missing entry-size or size tag skips the table silently.
        let built = variant(enc, true, |b, _| remove_dyn(b, ent));
        let elf = parse(&built.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        assert_eq!(elf.relocation_tables().len(), 2);

        let mut built = variant(enc, true, |b, _| {
            far_segment(b, 8);
            set_dyn(b, addr, Dyn::Val(addr, FAR + 0x100));
        });
        place_far_segment(&mut built, 8);
        let elf = parse(&built.bytes);
        let offset = built.bytes.len() as u64 - 8 + 0x100;
        assert_eq!(
            messages(&elf),
            [format!(
                "Invalid derived dynamic relocation table file offset: 0x{offset:x}; \
                 DT_{name}(0x{addr:08x}): 0x900100"
            )]
        );
    }
}

/// `DT_JMPREL` with a `DT_PLTREL` that is not `DT_RELA` is a `REL` table.
#[test]
fn plt_relocations_follow_dt_pltrel() {
    let built = variant(Enc::LE64, true, |b, _| {
        set_dyn(b, dt::PLTREL, Dyn::Val(dt::PLTREL, 17));
    });
    let elf = parse(&built.bytes);
    // A RELA table read as REL: 48 bytes of 16-byte entries.
    let plt = &elf.relocation_tables()[1];
    assert!(!plt.has_addend);
    assert_eq!(plt.relocation_count(), Some(3));
}

#[test]
fn section_relocation_table_problems() {
    for enc in Enc::ALL {
        let index = sample(enc).1;
        let rela = if enc.is64 { ".rela" } else { ".rel" };
        // (With a dynamic table, DT_RELA would find the table through the
        // program headers first; an empty section contains no address.)
        let mut built = variant(enc, false, |b, _| b.dynamic = None);
        built.set_sh(index.reladyn, Sh::Size, 0);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [format!(
                "Relocation table section header '{rela}.dyn' has invalid sh_size value (table size): 0x0"
            )]
        );

        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.relplt, Sh::Info, 99);
        let elf = parse(&built.bytes);
        // Reported three times, as in Ghidra: both DT_JMPREL passes reach the
        // section, then the section loop does, and the table is never kept.
        let message = format!(
            "Failed to process relocation table {rela}.plt: invalid linked section index 99"
        );
        assert_eq!(messages(&elf), [message.as_str(); 3]);

        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.relplt, Sh::Link, u64::from(index.text));
        let elf = parse(&built.bytes);
        let message = format!(
            "Failed to process relocation table {rela}.plt: unexpected section type for section index {}",
            index.text
        );
        assert_eq!(messages(&elf), [message.as_str(); 3]);

        // Link 0: `.dynsym` is assumed.
        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.relplt, Sh::Link, 0);
        let elf = parse(&built.bytes);
        assert_eq!(messages(&elf), Vec::<&str>::new());
        let table = elf.relocation_table_for_section(index.relplt).unwrap();
        assert_eq!(
            table.symbol_table,
            elf.symbol_tables().iter().position(|t| t.is_dynamic)
        );
        assert!(!table.is_missing_required_symbol_table());
    }
}

#[test]
fn relocation_tables_past_the_end_of_the_file() {
    for enc in Enc::ALL {
        let index = sample(enc).1;
        let entry = enc.rel_size(enc.is64);
        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.reladyn, Sh::Size, 1000 * entry);
        let elf = parse(&built.bytes);
        let table = elf.relocation_table_for_section(index.reladyn).unwrap();
        let available = elf.file_len() - table.file_offset;
        let fit = available / entry + u64::from(!available.is_multiple_of(entry));
        let mut expected = vec![format!(
            "Relocation Table count 1000 exceeds file capacity {fit}; truncating"
        )];
        if !available.is_multiple_of(entry) {
            expected.push("Relocation Table has partial entry".into());
            expected.push("Truncated ELF Relocation table due to unexpected EOF".into());
        }
        assert_eq!(messages(&elf), expected);
        assert!(table.truncated);
        assert_eq!(table.relocation_count(), Some(available / entry));
        assert_eq!(elf.relocations(table).count() as u64, available / entry);

        let mut built = variant(enc, false, |_, _| {});
        built.set_sh(index.relr, Sh::Size, 1 << 20);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            ["Truncated ELF RELR Relocation table due to unexpected EOF"]
        );
        let table = elf.relocation_table_for_section(index.relr).unwrap();
        assert!(table.truncated);
        // The real words decode first; then whatever follows in the file.
        let first: Vec<u64> = elf.relocations(table).take(4).map(|r| r.r_offset).collect();
        let w = enc.word_size();
        assert_eq!(first, [0x10600, 0x10600 + w, 0x10600 + 3 * w, 0x10800]);
    }
}

#[test]
fn android_tables_that_are_not_aps2() {
    for enc in Enc::ALL {
        let mut b = ElfBuilder::new(enc);
        let bad = b.add(Section::new(
            ".rela.android",
            sht::ANDROID_RELA,
            b"APS1\x02\x00".to_vec(),
        ));
        let gone = b.add(Section::new(
            ".rel.android",
            sht::ANDROID_REL,
            b"APS2".to_vec(),
        ));
        let mut built = b.build();
        let len = built.bytes.len() as u64;
        built.set_sh(gone, Sh::Offset, len - 2);
        let elf = parse(&built.bytes);
        assert_eq!(
            messages(&elf),
            [
                "Failed to process relocation table .rela.android: Unsupported Android relocation table format".to_owned(),
                format!("Failed to process relocation table .rel.android: Android relocation table not found at file offset {}", len - 2),
            ]
        );
        assert!(elf.relocation_table_for_section(bad).is_none());
        assert_eq!(elf.relocation_tables(), []);
    }
}
