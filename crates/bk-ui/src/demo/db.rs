//! The demo program's in-memory database, built once from the parsed file
//! and edited by commands.

use std::collections::{BTreeMap, HashMap};

use super::lex::{self, OpPiece};
use super::parse::{RawProgram, RawSection};
use crate::model::{CommentKind, RefKind, SymbolKind};

/// What a code unit is.
#[derive(Debug, Clone)]
pub(crate) enum UnitKind {
    Insn {
        bytes: Box<[u8]>,
        mnemonic: Box<str>,
        operands: Vec<OpPiece>,
        /// Source line of licd.c (0 = none).
        line: u32,
    },
    Data {
        bytes: Box<[u8]>,
        datatype: Box<str>,
        /// The value as displayed, with the address it points to.
        value: Box<str>,
        target: Option<u64>,
    },
}

/// An instruction or data item.
#[derive(Debug, Clone)]
pub(crate) struct Unit {
    pub address: u64,
    pub size: u64,
    pub kind: UnitKind,
    /// Index of the section starting at this unit.
    pub section_start: Option<usize>,
}

/// A variable of a function.
#[derive(Debug, Clone)]
pub(crate) struct Var {
    pub name: Box<str>,
    pub datatype: Box<str>,
    pub is_param: bool,
    /// Storage for the listing (`EDI:4`, `Stack[-0x28]:8`); None for
    /// register temporaries the listing does not show.
    pub storage: Option<Box<str>>,
}

/// A function.
#[derive(Debug, Clone)]
pub(crate) struct Func {
    pub entry: u64,
    pub end: u64,
    pub is_thunk: bool,
    /// The C signature line from the source (with the original name).
    pub signature: Box<str>,
    pub original_name: Box<str>,
    pub vars: Vec<Var>,
    /// (licd.c line number, text) of its body.
    pub source: Vec<(u32, Box<str>)>,
}

/// A name at an address.
#[derive(Debug, Clone)]
pub(crate) struct Name {
    pub name: Box<str>,
    pub kind: SymbolKind,
}

/// A reference from `from` (to the address it is filed under).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Xref {
    pub from: u64,
    pub kind: RefKind,
}

/// The whole demo program.
#[derive(Debug, Clone)]
pub(crate) struct Db {
    pub name: String,
    pub language: String,
    pub format: String,
    pub image_base: u64,
    pub sections: Vec<RawSection>,
    pub units: Vec<Unit>,
    pub funcs: Vec<Func>,
    pub names: BTreeMap<u64, Name>,
    pub xrefs: HashMap<u64, Vec<Xref>>,
    pub comments: HashMap<(u64, CommentKind), String>,
    /// Renamed variables: (function entry, index) → name.
    pub var_names: HashMap<(u64, u32), String>,
    /// Strings: address → text.
    pub strings: BTreeMap<u64, Box<str>>,
    /// First row of each unit, plus the total at the end.
    pub row_starts: Vec<u64>,
    /// Identifiers of the C source (original names) → symbol address.
    pub ident_index: HashMap<Box<str>, (u64, SymbolKind)>,
    /// String text → address.
    pub string_index: HashMap<Box<str>, u64>,
}

const PARAM_REGS: [[&str; 4]; 6] = [
    ["RDI", "EDI", "DI", "DIL"],
    ["RSI", "ESI", "SI", "SIL"],
    ["RDX", "EDX", "DX", "DL"],
    ["RCX", "ECX", "CX", "CL"],
    ["R8", "R8D", "R8W", "R8B"],
    ["R9", "R9D", "R9W", "R9B"],
];

fn type_size(t: &str) -> u32 {
    if t.contains('*') {
        return 8;
    }
    match t {
        "char" | "byte" | "undefined" => 1,
        "int" | "uint" | "undefined4" | "pid_t" => 4,
        _ => 8,
    }
}

fn reg_for(i: usize, size: u32) -> String {
    let col = match size {
        8 => 0,
        4 => 1,
        2 => 2,
        _ => 3,
    };
    PARAM_REGS
        .get(i)
        .and_then(|r| r.get(col))
        .map_or_else(|| format!("Stack[{:#x}]", 8 * (i + 1)), |r| (*r).to_owned())
}

/// Splits `type name` / `type *name` / `type name [n]` into (type, name).
fn split_decl(decl: &str) -> Option<(String, String)> {
    let decl = decl.trim().trim_end_matches(';').trim();
    let (decl, array) = match decl.find(" [") {
        Some(p) => (decl.get(..p)?, decl.get(p..).unwrap_or_default().trim()),
        None => (decl, ""),
    };
    let split = decl.rfind(|c: char| c == ' ' || c == '*')?;
    let name = decl.get(split + 1..)?.trim();
    let mut ty = decl.get(..=split)?.trim().to_owned();
    if !array.is_empty() {
        ty = format!("{ty} {array}");
    }
    if name.is_empty() || ty.is_empty() {
        return None;
    }
    Some((ty, name.to_owned()))
}

/// Parameters and stack locals of a function from its C text.
fn variables(signature: &str, body: &[(u32, Box<str>)]) -> Vec<Var> {
    let mut vars = Vec::new();
    let params = signature
        .find('(')
        .and_then(|p| signature.get(p + 1..signature.rfind(')').unwrap_or(signature.len())))
        .unwrap_or_default();
    let mut reg = 0;
    for p in params.split(',') {
        if p.trim() == "void" || p.trim() == "..." || p.trim().is_empty() {
            continue;
        }
        if let Some((ty, name)) = split_decl(p) {
            let size = type_size(&ty);
            vars.push(Var {
                storage: Some(format!("{}:{size}", reg_for(reg, size)).into()),
                name: name.into(),
                datatype: ty.into(),
                is_param: true,
            });
            reg += 1;
        }
    }
    // Declarations: from the line after "{" to the first blank line.
    for (_, line) in body.iter().skip(2) {
        if line.trim().is_empty() || !line.trim_end().ends_with(';') {
            break;
        }
        if let Some((ty, name)) = split_decl(line) {
            let storage = name.strip_prefix("local_").and_then(|off| {
                u64::from_str_radix(off, 16)
                    .ok()
                    .map(|o| format!("Stack[-{o:#x}]:{}", type_size(&ty)).into())
            });
            vars.push(Var {
                name: name.into(),
                datatype: ty.into(),
                is_param: false,
                storage,
            });
        }
    }
    vars
}

fn data_value(d: &super::parse::RawData) -> (String, Option<u64>) {
    if d.datatype == "pointer" {
        let mut v = [0u8; 8];
        for (dst, src) in v.iter_mut().zip(d.bytes.iter()) {
            *dst = *src;
        }
        let a = u64::from_le_bytes(v);
        return (format!("{a:08x}"), (a != 0).then_some(a));
    }
    if d.bytes.is_empty() || d.bytes.iter().all(|b| *b == 0) && d.datatype.contains('[') {
        return ("??".into(), None);
    }
    if d.datatype == "char[65]" {
        let s: String = d.bytes.iter().take_while(|b| **b != 0).map(|b| char::from(*b)).collect();
        return (format!("\"{s}\""), None);
    }
    let mut v = [0u8; 8];
    for (dst, src) in v.iter_mut().zip(d.bytes.iter().take(8)) {
        *dst = *src;
    }
    (format!("{:#x}", u64::from_le_bytes(v)), None)
}

/// C-escapes a string for display in the listing.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out
}

/// Ghidra's automatic string label: `s_` + the text's first characters with
/// spaces as `_`, then the address.
pub(crate) fn string_label(text: &str, address: u64) -> String {
    let body: String = text
        .chars()
        .take(20)
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect();
    format!("s_{body}_{address:08x}")
}

impl Db {
    /// Builds the database from the parsed file.
    pub(crate) fn build(raw: RawProgram) -> Self {
        let mut names = BTreeMap::new();
        let mut funcs = Vec::new();
        let src_by_fn = {
            let mut m: HashMap<&str, Vec<(u32, Box<str>)>> = HashMap::new();
            for (f, n, text) in &raw.source {
                m.entry(f.as_str()).or_default().push((*n, text.as_str().into()));
            }
            m
        };
        for (start, end, name) in &raw.functions {
            let source = src_by_fn.get(name.as_str()).cloned().unwrap_or_default();
            let signature: Box<str> = source.first().map_or_else(
                || format!("undefined {name}(void)").into(),
                |(_, s)| s.clone(),
            );
            let vars = variables(&signature, &source);
            names.insert(
                *start,
                Name {
                    name: name.as_str().into(),
                    kind: SymbolKind::Function,
                },
            );
            funcs.push(Func {
                entry: *start,
                end: *end,
                is_thunk: false,
                signature,
                original_name: name.as_str().into(),
                vars,
                source,
            });
        }
        for (stub, name, ptr) in &raw.imports {
            names.insert(
                *stub,
                Name {
                    name: name.as_str().into(),
                    kind: SymbolKind::Import,
                },
            );
            names.insert(
                *ptr,
                Name {
                    name: format!("PTR_{name}").into(),
                    kind: SymbolKind::Data,
                },
            );
            funcs.push(Func {
                entry: *stub,
                end: stub + 6,
                is_thunk: true,
                signature: format!("thunk undefined {name}()").into(),
                original_name: name.as_str().into(),
                vars: Vec::new(),
                source: Vec::new(),
            });
        }
        funcs.sort_by_key(|f| f.entry);

        let mut units = Vec::new();
        for i in &raw.insns {
            units.push(Unit {
                address: i.address,
                size: i.bytes.len() as u64,
                kind: UnitKind::Insn {
                    bytes: i.bytes.clone().into(),
                    mnemonic: i.mnemonic.as_str().into(),
                    operands: lex::operands(&i.operands),
                    line: i.line,
                },
                section_start: None,
            });
        }
        for d in &raw.data {
            let (value, target) = data_value(d);
            names.insert(
                d.address,
                Name {
                    name: d.name.as_str().into(),
                    kind: SymbolKind::Data,
                },
            );
            units.push(Unit {
                address: d.address,
                size: d.size.max(1),
                kind: UnitKind::Data {
                    bytes: d.bytes.clone().into(),
                    datatype: d.datatype.replace("pointer", "addr").into(),
                    value: value.into(),
                    target,
                },
                section_start: None,
            });
        }
        for (stub, name, ptr) in &raw.imports {
            if *ptr != 0 {
                units.push(Unit {
                    address: *ptr,
                    size: 8,
                    kind: UnitKind::Data {
                        bytes: Box::new([]),
                        datatype: "addr".into(),
                        value: format!("->{name}").into(),
                        target: Some(*stub),
                    },
                    section_start: None,
                });
            }
        }
        let mut strings = BTreeMap::new();
        for (a, s) in &raw.strings {
            names.insert(
                *a,
                Name {
                    name: string_label(s, *a).into(),
                    kind: SymbolKind::String,
                },
            );
            strings.insert(*a, s.as_str().into());
            units.push(Unit {
                address: *a,
                size: s.len() as u64 + 1,
                kind: UnitKind::Data {
                    bytes: s.bytes().chain(std::iter::once(0)).take(8).collect(),
                    datatype: "ds".into(),
                    value: format!("\"{}\"", escape(s)).into(),
                    target: None,
                },
                section_start: None,
            });
        }
        units.sort_by_key(|u| u.address);
        units.dedup_by_key(|u| u.address);
        for (si, s) in raw.sections.iter().enumerate() {
            if let Some(u) = units
                .iter_mut()
                .find(|u| u.address >= s.start && u.address < s.start + s.size)
            {
                u.section_start = Some(si);
            }
        }

        let mut db = Self {
            name: raw.name,
            language: raw.language,
            format: raw.format,
            image_base: raw.image_base,
            sections: raw.sections,
            units,
            funcs,
            names,
            xrefs: HashMap::new(),
            comments: HashMap::new(),
            var_names: HashMap::new(),
            strings,
            row_starts: Vec::new(),
            ident_index: HashMap::new(),
            string_index: HashMap::new(),
        };
        db.build_indexes();
        db.build_references();
        for (a, kind, text) in raw.comments {
            let k = match kind.as_str() {
                "EOL" => CommentKind::Eol,
                "PRE" => CommentKind::Pre,
                _ => CommentKind::Plate,
            };
            db.comments.insert((a, k), text);
        }
        db.relayout();
        db
    }

    fn build_indexes(&mut self) {
        for f in &self.funcs {
            let kind = if f.is_thunk {
                SymbolKind::Import
            } else {
                SymbolKind::Function
            };
            self.ident_index
                .insert(f.original_name.clone(), (f.entry, kind));
        }
        for (a, n) in &self.names {
            if n.kind == SymbolKind::Data {
                self.ident_index.insert(n.name.clone(), (*a, SymbolKind::Data));
                // `stderr` and `optarg` are read through their GOT entries.
                if let Some(base) = n.name.strip_prefix("PTR_") {
                    let c_name = if base == "stderrp" { "stderr" } else { base };
                    self.ident_index
                        .entry(c_name.into())
                        .or_insert((*a, SymbolKind::Data));
                }
            }
        }
        for (a, s) in &self.strings {
            self.string_index.entry(s.clone()).or_insert(*a);
        }
    }

    /// Whether `a` is inside a memory block.
    pub(crate) fn in_memory(&self, a: u64) -> bool {
        self.sections
            .iter()
            .any(|s| s.start <= a && a < s.start.saturating_add(s.size))
    }

    /// Cross-references and `LAB_` labels from instruction operands.
    fn build_references(&mut self) {
        let mut refs: HashMap<u64, Vec<Xref>> = HashMap::new();
        for u in &self.units {
            match &u.kind {
                UnitKind::Insn {
                    mnemonic, operands, ..
                } => {
                    let mut in_brackets = false;
                    let mut first_operand = true;
                    for p in operands {
                        match p {
                            OpPiece::Punct(s) if &**s == "[" => in_brackets = true,
                            OpPiece::Punct(s) if &**s == "]" => in_brackets = false,
                            OpPiece::Punct(s) if &**s == "," => first_operand = false,
                            OpPiece::Number { value, .. } if self.in_memory(*value) => {
                                let kind = if &**mnemonic == "CALL" {
                                    RefKind::Call
                                } else if mnemonic.starts_with('J') && !in_brackets {
                                    RefKind::Jump
                                } else if &**mnemonic == "LEA" {
                                    RefKind::Pointer
                                } else if first_operand && &**mnemonic == "MOV" {
                                    RefKind::Write
                                } else {
                                    RefKind::Read
                                };
                                refs.entry(*value).or_default().push(Xref {
                                    from: u.address,
                                    kind,
                                });
                            }
                            _ => {}
                        }
                    }
                }
                UnitKind::Data {
                    target: Some(t), ..
                } => refs.entry(*t).or_default().push(Xref {
                    from: u.address,
                    kind: RefKind::Pointer,
                }),
                UnitKind::Data { .. } => {}
            }
        }
        for (to, list) in &mut refs {
            list.sort_by_key(|x| x.from);
            let is_jump_target = list.iter().any(|x| x.kind == RefKind::Jump);
            if is_jump_target && !self.names.contains_key(to) {
                self.names.insert(
                    *to,
                    Name {
                        name: format!("LAB_{to:08x}").into(),
                        kind: SymbolKind::Label,
                    },
                );
            }
        }
        self.xrefs = refs;
    }

    /// The function whose body contains `a`.
    pub(crate) fn func_containing(&self, a: u64) -> Option<&Func> {
        let i = self.funcs.partition_point(|f| f.entry <= a);
        self.funcs
            .get(i.checked_sub(1)?)
            .filter(|f| a < f.end)
    }

    /// The current name of a function (after renames).
    pub(crate) fn func_name<'a>(&'a self, f: &'a Func) -> &'a str {
        self.names
            .get(&f.entry)
            .map_or(&*f.original_name, |n| &*n.name)
    }

    /// The current name of the function starting at `a` (or its label).
    pub(crate) fn func_name_at(&self, a: u64) -> &str {
        self.names.get(&a).map_or("", |n| &*n.name)
    }

    /// The display name of a variable (after renames).
    pub(crate) fn var_name<'a>(&'a self, f: &'a Func, index: u32) -> Option<&'a str> {
        if let Some(n) = self.var_names.get(&(f.entry, index)) {
            return Some(n);
        }
        f.vars.get(index as usize).map(|v| &*v.name)
    }

    /// Name shown for an address operand: its label, or Ghidra's default
    /// (`FUN_`, `LAB_`, `DAT_`).
    pub(crate) fn label_for(&self, a: u64) -> (String, SymbolKind) {
        if let Some(n) = self.names.get(&a) {
            return (n.name.to_string(), n.kind);
        }
        match self.func_containing(a) {
            Some(f) if f.entry == a => (format!("FUN_{a:08x}"), SymbolKind::Function),
            Some(_) => (format!("LAB_{a:08x}"), SymbolKind::Label),
            None => (format!("DAT_{a:08x}"), SymbolKind::Data),
        }
    }

    /// Recomputes the row numbering after an edit that changes row counts.
    pub(crate) fn relayout(&mut self) {
        let mut starts = Vec::with_capacity(self.units.len() + 1);
        let mut row = 0u64;
        for u in &self.units {
            starts.push(row);
            row += super::rows::unit_row_count(self, u) as u64;
        }
        starts.push(row);
        self.row_starts = starts;
    }

    /// Index of the unit holding `row`.
    pub(crate) fn unit_at_row(&self, row: u64) -> Option<usize> {
        let i = self.row_starts.partition_point(|s| *s <= row);
        let i = i.checked_sub(1)?;
        (i < self.units.len()).then_some(i)
    }

    /// Index of the unit containing `a`, or of the next unit after it.
    pub(crate) fn unit_for_address(&self, a: u64) -> Option<usize> {
        let i = self.units.partition_point(|u| u.address <= a);
        if let Some(prev) = i.checked_sub(1).and_then(|p| self.units.get(p)) {
            if a < prev.address + prev.size {
                return Some(i - 1);
            }
        }
        (i < self.units.len()).then_some(i)
    }

    /// Total number of listing rows.
    pub(crate) fn total_rows(&self) -> u64 {
        self.row_starts.last().copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_split_into_type_and_name() {
        assert_eq!(
            split_decl("  char local_218 [512];"),
            Some(("char [512]".into(), "local_218".into()))
        );
        assert_eq!(
            split_decl("char *param_2"),
            Some(("char *".into(), "param_2".into()))
        );
        assert_eq!(split_decl("FILE *__stream;"), Some(("FILE *".into(), "__stream".into())));
    }

    #[test]
    fn parameters_get_sysv_registers() {
        let v = variables("int f(int param_1,char *param_2)", &[]);
        assert_eq!(v[0].storage.as_deref(), Some("EDI:4"));
        assert_eq!(v[1].storage.as_deref(), Some("RSI:8"));
    }

    #[test]
    fn string_labels_follow_ghidra() {
        assert_eq!(string_label("cannot open %s", 0x1d14), "s_cannot_open_%s_00001d14");
    }
}
