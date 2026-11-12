//! A generated program of any size, for the scrolling performance test
//! and for checking that no view depends on a program being small.
//!
//! Every function has the same shape — a six-row header and
//! [`INSNS_PER_FUNCTION`] four-byte instructions — so rows and addresses
//! convert to each other arithmetically, as a real program store's index
//! would let them.

use crate::model::{
    Address, AddressRange, Command, DecompLine, DecompiledFunction, FunctionColumn, FunctionInfo,
    ListingRow, MemoryBlock, Page, ProgramInfo, ProgramSource, RefKind, Reference, Referent,
    RowContent, RowIndex, RowSpan, SearchHit, SearchQuery, SortOrder, SourceError, SourceResult,
    StringColumn, StringInfo, Symbol, SymbolCategory, SymbolKind, TableQuery, Token, TokenKind,
    XrefEntry,
};

/// Instructions in each generated function.
pub const INSNS_PER_FUNCTION: u64 = 100;
const HEADER_ROWS: u64 = 6;
const ROWS_PER_FUNCTION: u64 = HEADER_ROWS + INSNS_PER_FUNCTION;
const FUNCTION_STRIDE: u64 = 0x200;
const BASE: u64 = 0x0040_0000;

/// A generated program with at least the requested number of listing rows.
#[derive(Debug, Clone)]
pub struct SyntheticProgram {
    functions: u64,
}

impl SyntheticProgram {
    /// A program with at least `rows` listing rows.
    pub fn with_rows(rows: u64) -> Self {
        Self {
            functions: rows.div_ceil(ROWS_PER_FUNCTION).max(1),
        }
    }

    fn entry(k: u64) -> u64 {
        BASE + k * FUNCTION_STRIDE
    }

    fn name(k: u64) -> String {
        format!("FUN_{:08x}", Self::entry(k))
    }

    fn info_of(&self, k: u64) -> FunctionInfo {
        FunctionInfo {
            entry: Address(Self::entry(k)),
            name: Self::name(k).into(),
            signature: format!("undefined8 {}(long param_1)", Self::name(k)).into(),
            size: INSNS_PER_FUNCTION * 4,
            references: u32::from(k > 0),
            is_thunk: false,
        }
    }

    fn insn(&self, k: u64, j: u64) -> RowContent {
        let callee = (k * 7 + j) % self.functions;
        let fun = |text: String, a: u64| {
            Token::with_referent(text, TokenKind::Function, Referent::Address(Address(a)))
        };
        let reg = |r: &str| Token::with_referent(r, TokenKind::Register, Referent::Register(r.into()));
        let p = |s: &str| Token::new(s, TokenKind::Punctuation);
        let (mnemonic, operands, bytes): (&str, Vec<Token>, &[u8]) = match j % 6 {
            0 => ("PUSH", vec![reg("RBP")], &[0x55]),
            1 => ("MOV", vec![reg("RBP"), p(","), reg("RSP")], &[0x48, 0x89, 0xe5]),
            2 => (
                "MOV",
                vec![
                    reg("EAX"),
                    p(","),
                    Token::new("dword ptr ", TokenKind::Plain),
                    p("["),
                    reg("RBP"),
                    p(" + "),
                    Token::new(format!("-{:#x}", 4 + (j % 8) * 4), TokenKind::Immediate),
                    p("]"),
                ],
                &[0x8b, 0x45, 0xfc],
            ),
            3 => (
                "ADD",
                vec![reg("EAX"), p(","), Token::new(format!("{:#x}", j), TokenKind::Immediate)],
                &[0x83, 0xc0, 0x01],
            ),
            4 => (
                "CALL",
                vec![fun(Self::name(callee), Self::entry(callee))],
                &[0xe8, 0x00, 0x00, 0x00],
            ),
            _ => ("TEST", vec![reg("EAX"), p(","), reg("EAX")], &[0x85, 0xc0]),
        };
        RowContent::Instruction {
            bytes: bytes.into(),
            mnemonic: Token::new(mnemonic, TokenKind::Mnemonic),
            operands,
            comment: None,
        }
    }

    fn row(&self, r: u64) -> Option<ListingRow> {
        let k = r / ROWS_PER_FUNCTION;
        if k >= self.functions {
            return None;
        }
        let i = r % ROWS_PER_FUNCTION;
        let entry = Self::entry(k);
        let (address, content) = match i {
            0 => (entry, RowContent::Blank),
            1 | 3 => (entry, RowContent::PlateBorder),
            2 => (entry, RowContent::Plate("FUNCTION".into())),
            4 => (
                entry,
                RowContent::Signature(vec![
                    Token::new("undefined8", TokenKind::Type),
                    Token::new(" ", TokenKind::Plain),
                    Token::with_referent(Self::name(k), TokenKind::Function, Referent::Address(Address(entry))),
                    Token::new("(long param_1)", TokenKind::Punctuation),
                ]),
            ),
            5 => (
                entry,
                RowContent::Label {
                    name: Token::with_referent(Self::name(k), TokenKind::Function, Referent::Address(Address(entry))),
                    xref_count: u32::from(k > 0),
                    first_xref: (k > 0).then(|| XrefEntry {
                        from: Address(Self::entry(k - 1) + 16),
                        from_function: Some(Self::name(k - 1).into()),
                        kind: RefKind::Call,
                    }),
                },
            ),
            _ => {
                let j = i - HEADER_ROWS;
                (entry + j * 4, self.insn(k, j))
            }
        };
        Some(ListingRow {
            address: Address(address),
            content,
        })
    }
}

impl ProgramSource for SyntheticProgram {
    fn info(&self) -> ProgramInfo {
        ProgramInfo {
            name: format!("synthetic-{}", self.functions * ROWS_PER_FUNCTION),
            language: "x86:LE:64:default".into(),
            format: "Synthetic".into(),
            image_base: Address(BASE),
            entry: Address(BASE),
        }
    }

    fn listing_len(&self) -> SourceResult<u64> {
        Ok(self.functions * ROWS_PER_FUNCTION)
    }

    fn listing_rows(&self, start: RowIndex, count: u32) -> SourceResult<Vec<ListingRow>> {
        Ok((start.0..start.0.saturating_add(u64::from(count)))
            .map_while(|r| self.row(r))
            .collect())
    }

    fn rows_for_address(&self, address: Address) -> SourceResult<RowSpan> {
        let off = address
            .0
            .checked_sub(BASE)
            .ok_or(SourceError::NoSuchAddress(address))?;
        let mut k = off / FUNCTION_STRIDE;
        let mut j = (off % FUNCTION_STRIDE) / 4;
        if j >= INSNS_PER_FUNCTION {
            k += 1;
            j = 0;
        }
        if k >= self.functions {
            return Err(SourceError::NoSuchAddress(address));
        }
        let unit = k * ROWS_PER_FUNCTION + HEADER_ROWS + j;
        let first = if j == 0 { k * ROWS_PER_FUNCTION } else { unit };
        Ok(RowSpan {
            first: RowIndex(first),
            unit: RowIndex(unit),
        })
    }

    fn memory_blocks(&self) -> SourceResult<Vec<MemoryBlock>> {
        Ok(vec![MemoryBlock {
            name: ".text".into(),
            parent: "ram".into(),
            start: Address(BASE),
            size: self.functions * FUNCTION_STRIDE,
            permissions: "r-x".into(),
        }])
    }

    fn functions(&self, q: &TableQuery<FunctionColumn>) -> SourceResult<Page<FunctionInfo>> {
        // Names, addresses and sizes all grow together, so every sort is
        // the address order; filtering scans names (fast enough at 100k).
        let desc = q.order == SortOrder::Descending;
        let index = |n: u64| if desc { self.functions - 1 - n } else { n };
        if q.filter.is_empty() {
            let rows = (q.offset..(q.offset + u64::from(q.limit)).min(self.functions))
                .map(|n| self.info_of(index(n)))
                .collect();
            return Ok(Page {
                rows,
                total: self.functions,
            });
        }
        let f = q.filter.to_lowercase();
        let matching: Vec<u64> = (0..self.functions)
            .map(index)
            .filter(|k| Self::name(*k).to_lowercase().contains(&f))
            .collect();
        Ok(Page {
            total: matching.len() as u64,
            rows: matching
                .iter()
                .skip(q.offset as usize)
                .take(q.limit as usize)
                .map(|k| self.info_of(*k))
                .collect(),
        })
    }

    fn function_containing(&self, address: Address) -> SourceResult<Option<FunctionInfo>> {
        let Some(off) = address.0.checked_sub(BASE) else {
            return Ok(None);
        };
        let k = off / FUNCTION_STRIDE;
        let inside = off % FUNCTION_STRIDE < INSNS_PER_FUNCTION * 4;
        Ok((k < self.functions && inside).then(|| self.info_of(k)))
    }

    fn decompile(&self, address: Address) -> SourceResult<DecompiledFunction> {
        let f = self
            .function_containing(address)?
            .ok_or(SourceError::NoFunction(address))?;
        let e = f.entry.0;
        let line = |text: &str, from: u64, to: u64| DecompLine {
            indent: u16::from(text.starts_with("  ")),
            tokens: vec![Token::new(text.trim_start(), TokenKind::Plain)],
            ranges: if to > from {
                vec![AddressRange {
                    start: Address(e + from),
                    end: Address(e + to),
                }]
            } else {
                Vec::new()
            },
        };
        Ok(DecompiledFunction {
            entry: f.entry,
            name: f.name.clone(),
            signature: f.signature.clone(),
            lines: vec![
                line(&f.signature, 0, 8),
                line("{", 0, 0),
                line("  return param_1 + 1;", 8, INSNS_PER_FUNCTION * 4),
                line("}", 0, 0),
            ],
            variables: Vec::new(),
        })
    }

    fn symbols(&self, category: SymbolCategory, filter: &str, limit: u32) -> SourceResult<Page<Symbol>> {
        if category != SymbolCategory::Functions {
            return Ok(Page {
                rows: Vec::new(),
                total: 0,
            });
        }
        let page = self.functions(&TableQuery {
            filter: filter.to_owned(),
            sort: FunctionColumn::Location,
            order: SortOrder::Ascending,
            offset: 0,
            limit,
        })?;
        Ok(Page {
            total: page.total,
            rows: page
                .rows
                .into_iter()
                .map(|f| Symbol {
                    name: f.name,
                    address: f.entry,
                    kind: SymbolKind::Function,
                    namespace: "".into(),
                })
                .collect(),
        })
    }

    fn lookup(&self, query: &str, limit: u32) -> SourceResult<Vec<Symbol>> {
        Ok(self.symbols(SymbolCategory::Functions, query, limit)?.rows)
    }

    fn references_to(&self, address: Address, _limit: u32) -> SourceResult<Page<Reference>> {
        let rows = match self.function_containing(address)? {
            Some(f) if f.entry == address && f.entry.0 > BASE => vec![Reference {
                from: Address(f.entry.0 - FUNCTION_STRIDE + 16),
                to: address,
                from_function: Some(Self::name((f.entry.0 - BASE) / FUNCTION_STRIDE - 1).into()),
                code: format!("CALL {}", f.name).into(),
                kind: RefKind::Call,
            }],
            _ => Vec::new(),
        };
        Ok(Page {
            total: rows.len() as u64,
            rows,
        })
    }

    fn strings(&self, _q: &TableQuery<StringColumn>) -> SourceResult<Page<StringInfo>> {
        Ok(Page {
            rows: Vec::new(),
            total: 0,
        })
    }

    fn search(&self, _q: &SearchQuery, _limit: u32) -> SourceResult<Page<SearchHit>> {
        Ok(Page {
            rows: Vec::new(),
            total: 0,
        })
    }

    fn comments(&self, _address: Address) -> SourceResult<Vec<(crate::model::CommentKind, String)>> {
        Ok(Vec::new())
    }

    fn apply(&self, _command: &Command) -> SourceResult<()> {
        Err(SourceError::Rejected("the synthetic program is read-only".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_million_rows_map_to_addresses_and_back() {
        let p = SyntheticProgram::with_rows(10_000_000);
        let len = p.listing_len().unwrap();
        assert!(len >= 10_000_000);
        let last = p.listing_rows(RowIndex(len - 3), 10).unwrap();
        assert_eq!(last.len(), 3);
        for r in [0, 7, 5_000_123, len - 1] {
            let row = &p.listing_rows(RowIndex(r), 1).unwrap()[0];
            let span = p.rows_for_address(row.address).unwrap();
            assert!(span.first.0 <= r && (row.is_unit() == (span.unit.0 == r)));
        }
    }

    #[test]
    fn function_pages_are_served_by_window() {
        let p = SyntheticProgram::with_rows(10_000_000);
        let q = TableQuery {
            filter: String::new(),
            sort: FunctionColumn::Location,
            order: SortOrder::Descending,
            offset: 10,
            limit: 5,
        };
        let page = p.functions(&q).unwrap();
        assert_eq!(page.rows.len(), 5);
        assert!(page.total > 90_000);
        assert!(page.rows[0].entry > page.rows[1].entry);
    }
}
