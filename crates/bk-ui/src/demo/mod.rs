//! The demo data source: a real program, shown before the program model
//! exists.
//!
//! `licd` is a small licence daemon (`demo/licd.c`) compiled for x86-64
//! macOS. Its disassembly comes from Ghidra's own decoder and its
//! "decompiled" C is the source, written in Ghidra's output style and
//! mapped to instructions through the DWARF line table, so listing and
//! decompiler cross-highlight exactly (`demo/generate.py`,
//! `demo/README.md`). [`synthetic::SyntheticProgram`] is the other
//! implementation: a generated listing of any size for the scrolling test.

mod db;
mod decompile;
mod lex;
mod parse;
mod rows;
pub mod synthetic;

use fuzzy_matcher::FuzzyMatcher as _;
use fuzzy_matcher::skim::SkimMatcherV2;
use parking_lot::RwLock;

use self::db::{Db, UnitKind};
pub use self::parse::ParseError;
use crate::model::{
    Address, Command, CommentKind, DecompiledFunction, FunctionColumn, FunctionInfo, ListingRow,
    MemoryBlock, Page, ProgramInfo, ProgramSource, Reference, RowIndex, RowSpan, SearchHit,
    SearchQuery, SortOrder, SourceError, SourceResult, StringColumn, StringInfo, Symbol,
    SymbolCategory, SymbolKind, TableQuery,
};

/// The generated demo program (see `demo/README.md`).
const LICD: &str = include_str!("../../demo/licd.bkdemo");

/// The library every import of the demo comes from.
const LIBRARY: &str = "libSystem.B.dylib";

/// A program held in memory, read from the demo file.
#[derive(Debug)]
pub struct DemoProgram {
    info: ProgramInfo,
    db: RwLock<Db>,
}

impl DemoProgram {
    /// The `licd` demo program.
    pub fn licd() -> Result<Self, ParseError> {
        Self::from_text(LICD)
    }

    /// A program from demo-format text.
    pub fn from_text(text: &str) -> Result<Self, ParseError> {
        let db = Db::build(parse::parse(text)?);
        let entry = db
            .funcs
            .iter()
            .find(|f| &*f.original_name == "main")
            .or_else(|| db.funcs.first())
            .map_or(Address(db.image_base), |f| Address(f.entry));
        let info = ProgramInfo {
            name: db.name.clone(),
            language: db.language.clone(),
            format: db.format.clone(),
            image_base: Address(db.image_base),
            entry,
        };
        Ok(Self {
            info,
            db: RwLock::new(db),
        })
    }
}

fn page<T>(rows: Vec<T>, offset: u64, limit: u32) -> Page<T> {
    let total = rows.len() as u64;
    let rows = rows
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(limit as usize)
        .collect();
    Page { rows, total }
}

fn order<T>(mut v: Vec<T>, o: SortOrder, key: impl FnMut(&T, &T) -> std::cmp::Ordering) -> Vec<T> {
    v.sort_by(key);
    if o == SortOrder::Descending {
        v.reverse();
    }
    v
}

/// Checks a symbol or variable name typed by the user.
fn check_name(name: &str) -> SourceResult<()> {
    let bad = |reason| {
        Err(SourceError::InvalidName {
            name: name.to_owned(),
            reason,
        })
    };
    if name.is_empty() {
        return bad("a name cannot be empty");
    }
    if name.len() > 200 {
        return bad("a name is at most 200 characters");
    }
    if name.chars().any(char::is_whitespace) {
        return bad("a name cannot contain spaces");
    }
    Ok(())
}

impl ProgramSource for DemoProgram {
    fn info(&self) -> ProgramInfo {
        self.info.clone()
    }

    fn listing_len(&self) -> SourceResult<u64> {
        Ok(self.db.read().total_rows())
    }

    fn listing_rows(&self, start: RowIndex, count: u32) -> SourceResult<Vec<ListingRow>> {
        let db = self.db.read();
        let mut out = Vec::with_capacity(count as usize);
        let Some(mut i) = db.unit_at_row(start.0) else {
            return Ok(out);
        };
        let mut skip = start.0 - db.row_starts.get(i).copied().unwrap_or(0);
        while out.len() < count as usize && i < db.units.len() {
            let rows = rows::unit_rows(&db, i);
            let need = count as usize - out.len();
            out.extend(rows.into_iter().skip(skip as usize).take(need));
            skip = 0;
            i += 1;
        }
        Ok(out)
    }

    fn rows_for_address(&self, address: Address) -> SourceResult<RowSpan> {
        let db = self.db.read();
        let i = db
            .unit_for_address(address.0)
            .ok_or(SourceError::NoSuchAddress(address))?;
        let first = db.row_starts.get(i).copied().unwrap_or(0);
        let rows = rows::unit_rows(&db, i);
        let unit = rows.iter().position(ListingRow::is_unit).unwrap_or(0) as u64;
        Ok(RowSpan {
            first: RowIndex(first),
            unit: RowIndex(first + unit),
        })
    }

    fn memory_blocks(&self) -> SourceResult<Vec<MemoryBlock>> {
        let db = self.db.read();
        Ok(db
            .sections
            .iter()
            .map(|s| MemoryBlock {
                name: s.name.as_str().into(),
                parent: s.segment.as_str().into(),
                start: Address(s.start),
                size: s.size,
                permissions: s.flags.as_str().into(),
            })
            .collect())
    }

    fn functions(&self, q: &TableQuery<FunctionColumn>) -> SourceResult<Page<FunctionInfo>> {
        let db = self.db.read();
        let filter = q.filter.to_lowercase();
        let rows: Vec<FunctionInfo> = db
            .funcs
            .iter()
            .map(|f| function_info(&db, f))
            .filter(|f| filter.is_empty() || f.name.to_lowercase().contains(&filter))
            .collect();
        let rows = order(rows, q.order, |a, b| match q.sort {
            FunctionColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            FunctionColumn::Location => a.entry.cmp(&b.entry),
            FunctionColumn::Size => a.size.cmp(&b.size).then(a.entry.cmp(&b.entry)),
            FunctionColumn::References => {
                a.references.cmp(&b.references).then(a.entry.cmp(&b.entry))
            }
        });
        Ok(page(rows, q.offset, q.limit))
    }

    fn function_containing(&self, address: Address) -> SourceResult<Option<FunctionInfo>> {
        let db = self.db.read();
        Ok(db.func_containing(address.0).map(|f| function_info(&db, f)))
    }

    fn decompile(&self, address: Address) -> SourceResult<DecompiledFunction> {
        let db = self.db.read();
        let f = db
            .func_containing(address.0)
            .ok_or(SourceError::NoFunction(address))?;
        Ok(decompile::decompile(&db, f))
    }

    fn symbols(
        &self,
        category: SymbolCategory,
        filter: &str,
        limit: u32,
    ) -> SourceResult<Page<Symbol>> {
        let db = self.db.read();
        let filter = filter.to_lowercase();
        let mut out = Vec::new();
        let mut push = |name: &str, address: u64, kind: SymbolKind, namespace: &str| {
            if filter.is_empty() || name.to_lowercase().contains(&filter) {
                out.push(Symbol {
                    name: name.into(),
                    address: Address(address),
                    kind,
                    namespace: namespace.into(),
                });
            }
        };
        match category {
            SymbolCategory::Imports => {
                for f in db.funcs.iter().filter(|f| f.is_thunk) {
                    push(db.func_name(f), f.entry, SymbolKind::Import, LIBRARY);
                }
            }
            SymbolCategory::Exports => {
                push(
                    db.func_name_at(self.info.entry.0),
                    self.info.entry.0,
                    SymbolKind::Function,
                    "",
                );
            }
            SymbolCategory::Functions => {
                for f in db.funcs.iter().filter(|f| !f.is_thunk) {
                    push(db.func_name(f), f.entry, SymbolKind::Function, "");
                }
            }
            SymbolCategory::Labels => {
                for (a, n) in &db.names {
                    if matches!(n.kind, SymbolKind::Data | SymbolKind::Label)
                        && !n.name.starts_with("LAB_")
                    {
                        push(&n.name, *a, n.kind, "");
                    }
                }
            }
            SymbolCategory::Classes | SymbolCategory::Namespaces => {}
        }
        out.sort_by_key(|a| a.name.to_lowercase());
        Ok(page(out, 0, limit))
    }

    fn lookup(&self, query: &str, limit: u32) -> SourceResult<Vec<Symbol>> {
        let db = self.db.read();
        let matcher = SkimMatcherV2::default();
        let mut scored: Vec<(i64, Symbol)> = Vec::new();
        for (a, n) in &db.names {
            if let Some(score) = matcher.fuzzy_match(&n.name, query) {
                // Functions first among equals: they are what people jump to.
                let bonus = match n.kind {
                    SymbolKind::Function => 20,
                    SymbolKind::Import | SymbolKind::Data => 10,
                    _ => 0,
                };
                let namespace = if n.kind == SymbolKind::Import {
                    LIBRARY
                } else {
                    ""
                };
                scored.push((
                    score + bonus,
                    Symbol {
                        name: n.name.clone(),
                        address: Address(*a),
                        kind: n.kind,
                        namespace: namespace.into(),
                    },
                ));
            }
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.name.len().cmp(&b.1.name.len())));
        Ok(scored
            .into_iter()
            .take(limit as usize)
            .map(|(_, s)| s)
            .collect())
    }

    fn references_to(&self, address: Address, limit: u32) -> SourceResult<Page<Reference>> {
        let db = self.db.read();
        let refs = db
            .xrefs
            .get(&address.0)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let rows = refs
            .iter()
            .map(|x| Reference {
                from: Address(x.from),
                to: address,
                from_function: db.func_containing(x.from).map(|f| db.func_name(f).into()),
                code: db
                    .unit_for_address(x.from)
                    .map(|i| rows::unit_text(&db, i))
                    .unwrap_or_default()
                    .into(),
                kind: x.kind,
            })
            .collect();
        Ok(page(rows, 0, limit))
    }

    fn strings(&self, q: &TableQuery<StringColumn>) -> SourceResult<Page<StringInfo>> {
        let db = self.db.read();
        let filter = q.filter.to_lowercase();
        let rows: Vec<StringInfo> = db
            .strings
            .iter()
            .filter(|(_, s)| filter.is_empty() || s.to_lowercase().contains(&filter))
            .map(|(a, s)| StringInfo {
                address: Address(*a),
                value: db::escape(s).into(),
                length: s.len() as u32 + 1,
                datatype: "ds".into(),
            })
            .collect();
        let rows = order(rows, q.order, |a, b| match q.sort {
            StringColumn::Location => a.address.cmp(&b.address),
            StringColumn::Value => a.value.cmp(&b.value),
            StringColumn::Length => a.length.cmp(&b.length).then(a.address.cmp(&b.address)),
        });
        Ok(page(rows, q.offset, q.limit))
    }

    fn search(&self, query: &SearchQuery, limit: u32) -> SourceResult<Page<SearchHit>> {
        let db = self.db.read();
        let mut hits = Vec::new();
        for (i, u) in db.units.iter().enumerate() {
            let found = match query {
                SearchQuery::Text(t) => {
                    let t = t.to_lowercase();
                    let mut text = rows::unit_text(&db, i).to_lowercase();
                    if let Some(n) = db.names.get(&u.address) {
                        text.push(' ');
                        text.push_str(&n.name.to_lowercase());
                    }
                    for k in CommentKind::ALL {
                        if let Some(c) = db.comments.get(&(u.address, k)) {
                            text.push(' ');
                            text.push_str(&c.to_lowercase());
                        }
                    }
                    !t.is_empty() && text.contains(&t)
                }
                SearchQuery::Bytes(b) => {
                    let bytes = match &u.kind {
                        UnitKind::Insn { bytes, .. } | UnitKind::Data { bytes, .. } => bytes,
                    };
                    !b.is_empty() && bytes.windows(b.len()).any(|w| w == b.as_slice())
                }
            };
            if found {
                hits.push(SearchHit {
                    address: Address(u.address),
                    preview: rows::unit_text(&db, i).into(),
                });
            }
        }
        Ok(page(hits, 0, limit))
    }

    fn comments(&self, address: Address) -> SourceResult<Vec<(CommentKind, String)>> {
        let db = self.db.read();
        Ok(CommentKind::ALL
            .iter()
            .filter_map(|k| db.comments.get(&(address.0, *k)).map(|c| (*k, c.clone())))
            .collect())
    }

    fn apply(&self, command: &Command) -> SourceResult<()> {
        let mut db = self.db.write();
        match command {
            Command::RenameSymbol { address, name } => {
                check_name(name)?;
                let kind = match db.label_for(address.0).1 {
                    // A new name on a plain address becomes a label.
                    SymbolKind::Data
                        if !db.names.contains_key(&address.0)
                            && db.func_containing(address.0).is_some() =>
                    {
                        SymbolKind::Label
                    }
                    k => k,
                };
                if db.unit_for_address(address.0).is_none() {
                    return Err(SourceError::NoSuchAddress(*address));
                }
                db.names.insert(
                    address.0,
                    db::Name {
                        name: name.as_str().into(),
                        kind,
                    },
                );
            }
            Command::RemoveLabel { address } => {
                let removable = db
                    .names
                    .get(&address.0)
                    .is_some_and(|n| n.kind == SymbolKind::Label);
                if !removable {
                    return Err(SourceError::Rejected(format!("no label at {address}")));
                }
                db.names.remove(&address.0);
            }
            Command::RenameVariable {
                function,
                index,
                name,
            } => {
                check_name(name)?;
                let f = db
                    .func_containing(function.0)
                    .ok_or(SourceError::NoFunction(*function))?;
                if *index as usize >= f.vars.len() {
                    return Err(SourceError::Rejected(format!("no variable {index}")));
                }
                let entry = f.entry;
                db.var_names.insert((entry, *index), name.clone());
            }
            Command::SetComment {
                address,
                kind,
                text,
            } => {
                if db.unit_for_address(address.0).is_none() {
                    return Err(SourceError::NoSuchAddress(*address));
                }
                if text.trim().is_empty() {
                    db.comments.remove(&(address.0, *kind));
                } else {
                    db.comments.insert((address.0, *kind), text.clone());
                }
            }
        }
        db.relayout();
        Ok(())
    }
}

fn function_info(db: &Db, f: &db::Func) -> FunctionInfo {
    let name: Box<str> = db.func_name(f).into();
    FunctionInfo {
        entry: Address(f.entry),
        signature: f.signature.replacen(&*f.original_name, &name, 1).into(),
        name,
        size: f.end - f.entry,
        references: db.xrefs.get(&f.entry).map_or(0, Vec::len) as u32,
        is_thunk: f.is_thunk,
    }
}

#[cfg(test)]
mod tests;
