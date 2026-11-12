//! A small ELF writer so tests state their input in Rust (spec §6).
//!
//! It lays out: the ELF header, the program headers, every section's data
//! (each aligned), the section-name string table, the section headers. An
//! allocated section's address is `base + file offset`, and one `PT_LOAD`
//! covers the whole file at `base`, so addresses from the dynamic table map
//! back to the right offsets. Tests damage the output with [`Built`]'s
//! patch helpers.
//!
//! Its output is checked against the `object` crate in
//! `tests/builder.rs`, so the builder and the parser are not each other's
//! only reference.

/// Byte order and class of the file being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enc {
    pub is64: bool,
    pub le: bool,
}

impl Enc {
    pub const LE64: Self = Self {
        is64: true,
        le: true,
    };
    pub const BE64: Self = Self {
        is64: true,
        le: false,
    };
    pub const LE32: Self = Self {
        is64: false,
        le: true,
    };
    pub const BE32: Self = Self {
        is64: false,
        le: false,
    };
    pub const ALL: [Self; 4] = [Self::LE64, Self::BE64, Self::LE32, Self::BE32];

    pub fn u16(self, out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        });
    }
    pub fn u32(self, out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        });
    }
    pub fn u64(self, out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        });
    }
    /// An address, offset or other word-sized field.
    pub fn word(self, out: &mut Vec<u8>, v: u64) {
        if self.is64 {
            self.u64(out, v);
        } else {
            self.u32(out, v as u32);
        }
    }
    pub fn word_size(self) -> u64 {
        if self.is64 { 8 } else { 4 }
    }
    pub fn sym_size(self) -> u64 {
        if self.is64 { 24 } else { 16 }
    }
    pub fn rel_size(self, addend: bool) -> u64 {
        self.word_size() * if addend { 3 } else { 2 }
    }
    pub fn dyn_size(self) -> u64 {
        self.word_size() * 2
    }
    /// `r_info` from a symbol index and a type.
    pub fn r_info(self, sym: u32, ty: u32) -> u64 {
        if self.is64 {
            (u64::from(sym) << 32) | u64::from(ty)
        } else {
            (u64::from(sym) << 8) | u64::from(ty & 0xff)
        }
    }
    /// One symbol table entry.
    pub fn sym(self, out: &mut Vec<u8>, s: &Sym) {
        self.u32(out, s.name);
        if self.is64 {
            out.push(s.info);
            out.push(s.other);
            self.u16(out, s.shndx);
            self.u64(out, s.value);
            self.u64(out, s.size);
        } else {
            self.u32(out, s.value as u32);
            self.u32(out, s.size as u32);
            out.push(s.info);
            out.push(s.other);
            self.u16(out, s.shndx);
        }
    }
    /// One `REL` (`addend` None) or `RELA` entry.
    pub fn rel(self, out: &mut Vec<u8>, offset: u64, info: u64, addend: Option<i64>) {
        self.word(out, offset);
        self.word(out, info);
        if let Some(addend) = addend {
            self.word(out, addend as u64);
        }
    }
}

/// A symbol to encode.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sym {
    pub name: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

/// A string table under construction.
#[derive(Debug, Clone)]
pub struct StrTab(pub Vec<u8>);

impl Default for StrTab {
    fn default() -> Self {
        Self(vec![0])
    }
}

impl StrTab {
    /// Appends `s` and returns its offset.
    pub fn add(&mut self, s: &str) -> u32 {
        let offset = self.0.len() as u32;
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        offset
    }
}

/// A section to write. Its index in the file is its position in
/// [`ElfBuilder::sections`] plus one (section 0 is the null section).
#[derive(Debug, Clone, Default)]
pub struct Section {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    /// Address; `None` gives `base + offset` for allocated sections, 0 else.
    pub addr: Option<u64>,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
    pub data: Vec<u8>,
    /// `sh_size` to write instead of the data's length.
    pub size: Option<u64>,
}

impl Section {
    pub fn new(name: &str, sh_type: u32, data: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            sh_type,
            data,
            align: 1,
            ..Self::default()
        }
    }
    pub fn alloc(mut self) -> Self {
        self.flags |= 2;
        self
    }
    pub fn link(mut self, link: u32) -> Self {
        self.link = link;
        self
    }
    pub fn info(mut self, info: u32) -> Self {
        self.info = info;
        self
    }
    pub fn entsize(mut self, entsize: u64) -> Self {
        self.entsize = entsize;
        self
    }
    pub fn align(mut self, align: u64) -> Self {
        self.align = align;
        self
    }
    pub fn flags(mut self, flags: u64) -> Self {
        self.flags |= flags;
        self
    }
}

/// A dynamic table entry; addresses and sizes of sections are filled in
/// once the layout is known.
#[derive(Debug, Clone, Copy)]
pub enum Dyn {
    Val(u32, u64),
    /// The address of the section with this index.
    Addr(u32, u32),
    /// The size of the section with this index.
    Size(u32, u32),
}

/// A program header written as given.
#[derive(Debug, Clone, Copy, Default)]
pub struct Segment {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// The ELF writer.
#[derive(Debug, Clone)]
pub struct ElfBuilder {
    pub enc: Enc,
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub flags: u32,
    pub osabi: u8,
    /// Address of file offset 0.
    pub base: u64,
    pub sections: Vec<Section>,
    /// Entries of a `.dynamic` section (added after the other sections) and
    /// a `PT_DYNAMIC` header; `DT_NULL` is appended.
    pub dynamic: Option<Vec<Dyn>>,
    /// `sh_link` of `.dynamic`: its string table.
    pub dynamic_strtab: u32,
    /// Write one `PT_LOAD` over the whole file.
    pub load_segment: bool,
    pub extra_segments: Vec<Segment>,
    /// Write the section header table.
    pub section_headers: bool,
}

/// The written file and where its parts are.
#[derive(Debug, Clone)]
pub struct Built {
    pub bytes: Vec<u8>,
    pub enc: Enc,
    /// File offset of each section's data, by section index (0 for the null section).
    pub offsets: Vec<u64>,
    pub phoff: u64,
    pub shoff: u64,
    /// Index of the section-name string table.
    pub shstrndx: u32,
    pub base: u64,
}

/// Section types used by tests.
pub mod sht {
    pub const PROGBITS: u32 = 1;
    pub const SYMTAB: u32 = 2;
    pub const STRTAB: u32 = 3;
    pub const RELA: u32 = 4;
    pub const HASH: u32 = 5;
    pub const DYNAMIC: u32 = 6;
    pub const NOTE: u32 = 7;
    pub const NOBITS: u32 = 8;
    pub const REL: u32 = 9;
    pub const DYNSYM: u32 = 11;
    pub const SYMTAB_SHNDX: u32 = 18;
    pub const RELR: u32 = 19;
    pub const ANDROID_REL: u32 = 0x6000_0001;
    pub const ANDROID_RELA: u32 = 0x6000_0002;
    pub const GNU_VERDEF: u32 = 0x6fff_fffd;
    pub const GNU_VERNEED: u32 = 0x6fff_fffe;
    pub const GNU_VERSYM: u32 = 0x6fff_ffff;
}

impl ElfBuilder {
    pub fn new(enc: Enc) -> Self {
        Self {
            enc,
            e_type: 3,
            machine: if enc.is64 { 62 } else { 3 },
            entry: 0,
            flags: 0,
            osabi: 0,
            base: 0x10000,
            sections: Vec::new(),
            dynamic: None,
            dynamic_strtab: 0,
            load_segment: true,
            extra_segments: Vec::new(),
            section_headers: true,
        }
    }

    /// Adds a section and returns its index.
    pub fn add(&mut self, section: Section) -> u32 {
        self.sections.push(section);
        self.sections.len() as u32
    }

    /// The index the next added section will get.
    pub fn next_index(&self) -> u32 {
        self.sections.len() as u32 + 1
    }

    /// The index `.dynamic` will get (it follows the added sections).
    pub fn dynamic_index(&self) -> u32 {
        self.next_index()
    }

    /// Adds a string table section with `strings`; returns its index.
    pub fn strtab(&mut self, name: &str, strings: &StrTab, alloc: bool) -> u32 {
        let section = Section::new(name, sht::STRTAB, strings.0.clone());
        self.add(if alloc { section.alloc() } else { section })
    }

    /// Adds a symbol table section (the null symbol is prepended); returns
    /// its index.
    pub fn symtab(&mut self, name: &str, sh_type: u32, strtab: u32, symbols: &[Sym]) -> u32 {
        let enc = self.enc;
        let mut data = Vec::new();
        enc.sym(&mut data, &Sym::default());
        let mut first_global = 1;
        for (i, s) in symbols.iter().enumerate() {
            enc.sym(&mut data, s);
            if s.info >> 4 == 0 {
                first_global = i as u32 + 2;
            }
        }
        let section = Section::new(name, sh_type, data)
            .link(strtab)
            .info(first_global)
            .entsize(enc.sym_size())
            .align(enc.word_size());
        self.add(if sh_type == sht::DYNSYM {
            section.alloc()
        } else {
            section
        })
    }

    /// Writes the file.
    pub fn build(&self) -> Built {
        let enc = self.enc;
        let mut sections = self.sections.clone();
        let dynamic_index = self.dynamic.as_ref().map(|entries| {
            let len = (entries.len() as u64 + 1) * enc.dyn_size();
            sections.push(
                Section::new(".dynamic", sht::DYNAMIC, vec![0; len as usize])
                    .alloc()
                    .flags(1)
                    .entsize(enc.dyn_size())
                    .align(enc.word_size())
                    .link(self.dynamic_strtab),
            );
            sections.len() as u32
        });
        let mut shstrtab = StrTab::default();
        let names: Vec<u32> = sections.iter().map(|s| shstrtab.add(&s.name)).collect();
        let shstrtab_name = shstrtab.add(".shstrtab");
        let shstrndx = sections.len() as u32 + 1;

        let ehsize: u64 = if enc.is64 { 64 } else { 52 };
        let phentsize: u64 = if enc.is64 { 56 } else { 32 };
        let shentsize: u64 = if enc.is64 { 64 } else { 40 };
        let phnum = u64::from(self.load_segment)
            + u64::from(dynamic_index.is_some())
            + self.extra_segments.len() as u64;
        let phoff = if phnum > 0 { ehsize } else { 0 };
        let mut offset = ehsize + phnum * phentsize;
        let mut offsets = vec![0u64];
        for s in &sections {
            offset = offset.next_multiple_of(s.align.max(1));
            offsets.push(offset);
            if s.sh_type != sht::NOBITS {
                offset += s.data.len() as u64;
            }
        }
        let shstrtab_offset = offset;
        offset += shstrtab.0.len() as u64;
        let shoff = offset.next_multiple_of(8);
        let shnum = sections.len() as u64 + 2;
        let file_len = if self.section_headers {
            shoff + shnum * shentsize
        } else {
            shoff
        };
        let addrs: Vec<u64> = sections
            .iter()
            .enumerate()
            .map(|(i, s)| {
                s.addr.unwrap_or(if s.flags & 2 != 0 {
                    self.base + offsets[i + 1]
                } else {
                    0
                })
            })
            .collect();
        let addr = |i: u32| -> u64 { addrs[i as usize - 1] };

        if let (Some(entries), Some(index)) = (&self.dynamic, dynamic_index) {
            let mut data = Vec::new();
            for entry in entries {
                let (tag, value) = match *entry {
                    Dyn::Val(tag, value) => (tag, value),
                    Dyn::Addr(tag, i) => (tag, addr(i)),
                    Dyn::Size(tag, i) => (tag, sections[i as usize - 1].data.len() as u64),
                };
                enc.word(&mut data, u64::from(tag));
                enc.word(&mut data, value);
            }
            enc.word(&mut data, 0);
            enc.word(&mut data, 0);
            sections[index as usize - 1].data = data;
        }

        let mut out = Vec::with_capacity(file_len as usize);
        out.extend_from_slice(b"\x7fELF");
        out.push(if enc.is64 { 2 } else { 1 });
        out.push(if enc.le { 1 } else { 2 });
        out.push(1);
        out.push(self.osabi);
        out.extend_from_slice(&[0; 8]);
        enc.u16(&mut out, self.e_type);
        enc.u16(&mut out, self.machine);
        enc.u32(&mut out, 1);
        enc.word(&mut out, self.entry);
        enc.word(&mut out, phoff);
        enc.word(&mut out, if self.section_headers { shoff } else { 0 });
        enc.u32(&mut out, self.flags);
        enc.u16(&mut out, ehsize as u16);
        enc.u16(&mut out, phentsize as u16);
        enc.u16(&mut out, phnum as u16);
        enc.u16(&mut out, shentsize as u16);
        enc.u16(
            &mut out,
            if self.section_headers {
                shnum as u16
            } else {
                0
            },
        );
        enc.u16(
            &mut out,
            if self.section_headers {
                shstrndx as u16
            } else {
                0
            },
        );

        let mut segments = Vec::new();
        if self.load_segment {
            segments.push(Segment {
                p_type: 1,
                flags: 7,
                offset: 0,
                vaddr: self.base,
                filesz: file_len,
                memsz: file_len,
                align: 0x1000,
            });
        }
        if let Some(index) = dynamic_index {
            let len = sections[index as usize - 1].data.len() as u64;
            segments.push(Segment {
                p_type: 2,
                flags: 6,
                offset: offsets[index as usize],
                vaddr: addr(index),
                filesz: len,
                memsz: len,
                align: enc.word_size(),
            });
        }
        segments.extend_from_slice(&self.extra_segments);
        for s in &segments {
            enc.u32(&mut out, s.p_type);
            if enc.is64 {
                enc.u32(&mut out, s.flags);
                for v in [s.offset, s.vaddr, s.vaddr, s.filesz, s.memsz, s.align] {
                    enc.u64(&mut out, v);
                }
            } else {
                for v in [s.offset, s.vaddr, s.vaddr, s.filesz, s.memsz] {
                    enc.u32(&mut out, v as u32);
                }
                enc.u32(&mut out, s.flags);
                enc.u32(&mut out, s.align as u32);
            }
        }
        for (i, s) in sections.iter().enumerate() {
            out.resize(offsets[i + 1] as usize, 0);
            if s.sh_type != sht::NOBITS {
                out.extend_from_slice(&s.data);
            }
        }
        out.resize(shstrtab_offset as usize, 0);
        out.extend_from_slice(&shstrtab.0);
        if self.section_headers {
            out.resize(shoff as usize, 0);
            out.extend_from_slice(&vec![0; shentsize as usize]);
            let write = |out: &mut Vec<u8>, h: [u64; 10]| {
                enc.u32(out, h[0] as u32);
                enc.u32(out, h[1] as u32);
                enc.word(out, h[2]);
                enc.word(out, h[3]);
                enc.word(out, h[4]);
                enc.word(out, h[5]);
                enc.u32(out, h[6] as u32);
                enc.u32(out, h[7] as u32);
                enc.word(out, h[8]);
                enc.word(out, h[9]);
            };
            for (i, s) in sections.iter().enumerate() {
                let index = i as u32 + 1;
                let size = s.size.unwrap_or(s.data.len() as u64);
                write(
                    &mut out,
                    [
                        u64::from(names[i]),
                        u64::from(s.sh_type),
                        s.flags,
                        addr(index),
                        offsets[i + 1],
                        size,
                        u64::from(s.link),
                        u64::from(s.info),
                        s.align,
                        s.entsize,
                    ],
                );
            }
            write(
                &mut out,
                [
                    u64::from(shstrtab_name),
                    u64::from(sht::STRTAB),
                    0,
                    0,
                    shstrtab_offset,
                    shstrtab.0.len() as u64,
                    0,
                    0,
                    1,
                    0,
                ],
            );
        }
        out.resize(file_len as usize, 0);
        offsets.push(shstrtab_offset);
        Built {
            bytes: out,
            enc,
            offsets,
            phoff,
            shoff,
            shstrndx,
            base: self.base,
        }
    }
}

/// ELF header fields that tests patch.
#[derive(Debug, Clone, Copy)]
pub enum Field {
    Phoff,
    Shoff,
    Phentsize,
    Phnum,
    Shentsize,
    Shnum,
    Shstrndx,
}

/// Section header fields that tests patch.
#[derive(Debug, Clone, Copy)]
pub enum Sh {
    Name,
    Type,
    Flags,
    Addr,
    Offset,
    Size,
    Link,
    Info,
    Addralign,
    Entsize,
}

/// Program header fields that tests patch.
#[derive(Debug, Clone, Copy)]
pub enum Ph {
    Type,
    Offset,
    Vaddr,
    Filesz,
    Memsz,
}

impl Built {
    fn put(&mut self, offset: u64, size: u64, value: u64) {
        let at = offset as usize;
        let bytes = match (size, self.enc.le) {
            (2, true) => (value as u16).to_le_bytes().to_vec(),
            (2, false) => (value as u16).to_be_bytes().to_vec(),
            (4, true) => (value as u32).to_le_bytes().to_vec(),
            (4, false) => (value as u32).to_be_bytes().to_vec(),
            (8, true) => value.to_le_bytes().to_vec(),
            (8, false) => value.to_be_bytes().to_vec(),
            _ => unreachable!(),
        };
        self.bytes[at..at + bytes.len()].copy_from_slice(&bytes);
    }

    /// Writes `size` bytes of `value` at `offset` in the file's byte order.
    pub fn patch(&mut self, offset: u64, size: u64, value: u64) {
        self.put(offset, size, value);
    }

    /// Sets an ELF header field.
    pub fn set(&mut self, field: Field, value: u64) {
        let w = self.enc.word_size();
        let (offset, size) = match (field, self.enc.is64) {
            (Field::Phoff, true) => (32, w),
            (Field::Phoff, false) => (28, w),
            (Field::Shoff, true) => (40, w),
            (Field::Shoff, false) => (32, w),
            (Field::Phentsize, true) => (54, 2),
            (Field::Phentsize, false) => (42, 2),
            (Field::Phnum, true) => (56, 2),
            (Field::Phnum, false) => (44, 2),
            (Field::Shentsize, true) => (58, 2),
            (Field::Shentsize, false) => (46, 2),
            (Field::Shnum, true) => (60, 2),
            (Field::Shnum, false) => (48, 2),
            (Field::Shstrndx, true) => (62, 2),
            (Field::Shstrndx, false) => (50, 2),
        };
        self.put(offset, size, value);
    }

    /// Sets a field of section header `index`.
    pub fn set_sh(&mut self, index: u32, field: Sh, value: u64) {
        let (w, is64) = (self.enc.word_size(), self.enc.is64);
        let entsize: u64 = if is64 { 64 } else { 40 };
        let (at, size) = match field {
            Sh::Name => (0, 4),
            Sh::Type => (4, 4),
            Sh::Flags => (8, w),
            Sh::Addr => (8 + w, w),
            Sh::Offset => (8 + 2 * w, w),
            Sh::Size => (8 + 3 * w, w),
            Sh::Link => (8 + 4 * w, 4),
            Sh::Info => (12 + 4 * w, 4),
            Sh::Addralign => (16 + 4 * w, w),
            Sh::Entsize => (16 + 5 * w, w),
        };
        self.put(self.shoff + u64::from(index) * entsize + at, size, value);
    }

    /// Sets a field of program header `index`.
    pub fn set_ph(&mut self, index: u32, field: Ph, value: u64) {
        let is64 = self.enc.is64;
        let entsize: u64 = if is64 { 56 } else { 32 };
        let (at, size) = match (field, is64) {
            (Ph::Type, _) => (0, 4),
            (Ph::Offset, true) => (8, 8),
            (Ph::Vaddr, true) => (16, 8),
            (Ph::Filesz, true) => (32, 8),
            (Ph::Memsz, true) => (40, 8),
            (Ph::Offset, false) => (4, 4),
            (Ph::Vaddr, false) => (8, 4),
            (Ph::Filesz, false) => (16, 4),
            (Ph::Memsz, false) => (20, 4),
        };
        self.put(self.phoff + u64::from(index) * entsize + at, size, value);
    }

    /// The address of section `index` (allocated sections only).
    pub fn addr(&self, index: u32) -> u64 {
        self.base + self.offsets[index as usize]
    }
}

/// Section indexes of [`sample`].
#[derive(Debug, Clone, Copy)]
pub struct SampleIndex {
    pub text: u32,
    pub dynstr: u32,
    pub dynsym: u32,
    pub hash: u32,
    pub reladyn: u32,
    pub relplt: u32,
    pub relr: u32,
    pub strtab: u32,
    pub symtab: u32,
    pub dynamic: u32,
}

/// Dynamic tags used by [`sample`].
pub mod dt {
    pub const NEEDED: u32 = 1;
    pub const PLTRELSZ: u32 = 2;
    pub const HASH: u32 = 4;
    pub const STRTAB: u32 = 5;
    pub const SYMTAB: u32 = 6;
    pub const RELA: u32 = 7;
    pub const RELASZ: u32 = 8;
    pub const RELAENT: u32 = 9;
    pub const STRSZ: u32 = 10;
    pub const SYMENT: u32 = 11;
    pub const REL: u32 = 17;
    pub const RELSZ: u32 = 18;
    pub const RELENT: u32 = 19;
    pub const PLTREL: u32 = 20;
    pub const JMPREL: u32 = 23;
    pub const RELRSZ: u32 = 35;
    pub const RELR: u32 = 36;
    pub const RELRENT: u32 = 37;
    pub const GNU_HASH: u32 = 0x6fff_fef5;
    pub const GNU_XHASH: u32 = 0x6fff_fef4;
}

/// A shared object with everything the parser locates: dynamic symbols
/// sized by `DT_HASH`, dynamic strings, `DT_NEEDED`, `REL`/`RELA`
/// relocations through `DT_REL(A)` and `DT_JMPREL`, a `RELR` table, and a
/// `.symtab`. 64-bit files use `RELA`, 32-bit ones `REL`.
pub fn sample(enc: Enc) -> (ElfBuilder, SampleIndex) {
    let mut b = ElfBuilder::new(enc);
    let rela = enc.is64;
    let text = b.add(
        Section::new(".text", sht::PROGBITS, vec![0xc3; 64])
            .alloc()
            .flags(4)
            .align(16),
    );
    let mut dynstr = StrTab::default();
    let libc = dynstr.add("libc.so.6");
    let libm = dynstr.add("libm.so.6");
    let names: Vec<u32> = ["puts", "malloc", "exported", "data_object"]
        .iter()
        .map(|n| dynstr.add(n))
        .collect();
    let dynstr_index = b.strtab(".dynstr", &dynstr, true);
    let dynsyms = [
        Sym {
            name: names[0],
            info: 0x12,
            ..Sym::default()
        },
        Sym {
            name: names[1],
            info: 0x12,
            ..Sym::default()
        },
        Sym {
            name: names[2],
            info: 0x12,
            value: 0x10100,
            size: 16,
            shndx: text as u16,
            ..Sym::default()
        },
        Sym {
            name: names[3],
            info: 0x11,
            value: 0x10200,
            size: 8,
            shndx: text as u16,
            other: 2,
            ..Sym::default()
        },
    ];
    let dynsym = b.symtab(".dynsym", sht::DYNSYM, dynstr_index, &dynsyms);
    let nsyms = dynsyms.len() as u32 + 1;
    let mut hash = Vec::new();
    for v in [1, nsyms, 0]
        .into_iter()
        .chain(std::iter::repeat_n(0, nsyms as usize))
    {
        enc.u32(&mut hash, v);
    }
    let hash_index = b.add(
        Section::new(".hash", sht::HASH, hash)
            .alloc()
            .link(dynsym)
            .entsize(4)
            .align(4),
    );

    let rel_type = if rela { sht::RELA } else { sht::REL };
    let relative = 8; // R_X86_64_RELATIVE / R_386_RELATIVE
    let mut reladyn = Vec::new();
    for i in 0..3u64 {
        let addend = rela.then_some(0x10100 + i as i64);
        enc.rel(
            &mut reladyn,
            0x10400 + i * enc.word_size(),
            enc.r_info(0, relative),
            addend,
        );
    }
    enc.rel(&mut reladyn, 0x10480, enc.r_info(4, 1), rela.then_some(-4));
    let reladyn_index = b.add(
        Section::new(
            if rela { ".rela.dyn" } else { ".rel.dyn" },
            rel_type,
            reladyn,
        )
        .alloc()
        .link(dynsym)
        .entsize(enc.rel_size(rela))
        .align(enc.word_size()),
    );
    let mut relplt = Vec::new();
    for (i, sym) in [1u32, 2].into_iter().enumerate() {
        enc.rel(
            &mut relplt,
            0x10500 + i as u64 * enc.word_size(),
            enc.r_info(sym, 7),
            rela.then_some(0),
        );
    }
    let relplt_index = b.add(
        Section::new(
            if rela { ".rela.plt" } else { ".rel.plt" },
            rel_type,
            relplt,
        )
        .alloc()
        .link(dynsym)
        .info(text)
        .entsize(enc.rel_size(rela))
        .align(enc.word_size()),
    );
    // RELR: an address, a bitmap selecting slots 0 and 2 after it, an address.
    let mut relr = Vec::new();
    enc.word(&mut relr, 0x10600);
    enc.word(&mut relr, 0b1011);
    enc.word(&mut relr, 0x10800);
    let relr_index = b.add(
        Section::new(".relr.dyn", sht::RELR, relr)
            .alloc()
            .entsize(enc.word_size())
            .align(enc.word_size()),
    );

    let mut strtab = StrTab::default();
    let file = strtab.add("sample.c");
    let local = strtab.add("local_function");
    let global = strtab.add("exported");
    let strtab_index = b.strtab(".strtab", &strtab, false);
    let symtab = b.symtab(
        ".symtab",
        sht::SYMTAB,
        strtab_index,
        &[
            Sym {
                name: file,
                info: 0x04,
                shndx: 0xfff1,
                ..Sym::default()
            },
            Sym {
                name: 0,
                info: 0x03,
                shndx: text as u16,
                value: 0x10000,
                ..Sym::default()
            },
            Sym {
                name: local,
                info: 0x02,
                shndx: text as u16,
                value: 0x10120,
                size: 4,
                ..Sym::default()
            },
            Sym {
                name: global,
                info: 0x12,
                shndx: text as u16,
                value: 0x10100,
                size: 16,
                ..Sym::default()
            },
        ],
    );
    let dynamic = b.dynamic_index();
    b.dynamic_strtab = dynstr_index;
    let (rel_tag, relsz, relent) = if rela {
        (dt::RELA, dt::RELASZ, dt::RELAENT)
    } else {
        (dt::REL, dt::RELSZ, dt::RELENT)
    };
    b.dynamic = Some(vec![
        Dyn::Val(dt::NEEDED, u64::from(libc)),
        Dyn::Val(dt::NEEDED, u64::from(libm)),
        Dyn::Addr(dt::HASH, hash_index),
        Dyn::Addr(dt::STRTAB, dynstr_index),
        Dyn::Addr(dt::SYMTAB, dynsym),
        Dyn::Size(dt::STRSZ, dynstr_index),
        Dyn::Val(dt::SYMENT, enc.sym_size()),
        Dyn::Addr(rel_tag, reladyn_index),
        Dyn::Size(relsz, reladyn_index),
        Dyn::Val(relent, enc.rel_size(rela)),
        Dyn::Addr(dt::JMPREL, relplt_index),
        Dyn::Size(dt::PLTRELSZ, relplt_index),
        Dyn::Val(dt::PLTREL, u64::from(rel_tag)),
        Dyn::Addr(dt::RELR, relr_index),
        Dyn::Size(dt::RELRSZ, relr_index),
        Dyn::Val(dt::RELRENT, enc.word_size()),
    ]);
    (
        b,
        SampleIndex {
            text,
            dynstr: dynstr_index,
            dynsym,
            hash: hash_index,
            reladyn: reladyn_index,
            relplt: relplt_index,
            relr: relr_index,
            strtab: strtab_index,
            symtab,
            dynamic,
        },
    )
}
