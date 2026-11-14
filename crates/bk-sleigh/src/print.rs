//! Disassembly text (Ghidra `Constructor::printMnemonic`, `printBody`,
//! `print`, and each symbol's `print`; inventory section 6).
//!
//! Numbers are written as `0x…` or `-0x…` in lower-case hexadecimal of the
//! 64-bit value; nothing depends on a locale or uses floating point.

use std::fmt::Write as _;

use bk_sla::{PrintPiece, SymbolKind};

use crate::decode::expr::{Env, Point};
use crate::decode::resolve::env;
use crate::decode::tree::Parse;
use crate::error::DecodeError;
use crate::language::Language;
use crate::language::tables::OpDef;

impl Language {
    /// Appends the mnemonic of a decoded instruction to `out` (Ghidra
    /// `printMnemonic` of the root constructor).
    pub fn mnemonic(&self, parse: &Parse, out: &mut String) -> Result<(), DecodeError> {
        Printer {
            env: env(self, parse, Some(parse.naddr)),
            out,
        }
        .mnemonic(0)
    }

    /// Appends the operand text of a decoded instruction to `out` (Ghidra
    /// `printBody` of the root constructor).
    pub fn body(&self, parse: &Parse, out: &mut String) -> Result<(), DecodeError> {
        Printer {
            env: env(self, parse, Some(parse.naddr)),
            out,
        }
        .body(0)
    }
}

struct Printer<'a, 'o> {
    env: Env<'a>,
    out: &'o mut String,
}

/// Writes a signed value as Ghidra does: `0x…`, or `-0x…` of the negation.
pub(crate) fn hex(out: &mut String, value: i64) {
    if value >= 0 {
        let _ = write!(out, "{value:#x}");
    } else {
        let _ = write!(out, "-{:#x}", value.unsigned_abs());
    }
}

impl<'a> Printer<'a, '_> {
    fn model(&self, what: &'static str) -> DecodeError {
        self.env.model(what)
    }

    /// The constructor at node `n`, its print pieces and its `first`.
    fn pieces(&self, n: u32) -> Result<(&'a [PrintPiece], i32, Option<u32>), DecodeError> {
        let sla: &'a bk_sla::Sla = self.env.sla;
        let node = self
            .env
            .parse
            .nodes
            .get(n as usize)
            .ok_or_else(|| self.model("node"))?;
        let id = node
            .constructor()
            .ok_or_else(|| self.model("node constructor"))?;
        let ctor = sla
            .constructor(id)
            .ok_or_else(|| self.model("constructor"))?;
        let flow = self
            .env
            .lang
            .tables
            .ctor(id)
            .and_then(|info| info.flow_through);
        Ok((sla.print_pieces(ctor), ctor.first, flow))
    }

    fn child(&self, n: u32, index: u32) -> Result<u32, DecodeError> {
        self.env
            .parse
            .nodes
            .get(n as usize)
            .and_then(|node| node.child(index))
            .ok_or_else(|| self.model("operand node"))
    }

    fn mnemonic(&mut self, n: u32) -> Result<(), DecodeError> {
        let (pieces, first, flow) = self.pieces(n)?;
        if let Some(index) = flow {
            return self.mnemonic(self.child(n, index)?);
        }
        let end = usize::try_from(first).map_or(pieces.len(), |f| f.min(pieces.len()));
        self.pieces_out(n, pieces.get(..end).unwrap_or_default())
    }

    fn body(&mut self, n: u32) -> Result<(), DecodeError> {
        let (pieces, first, flow) = self.pieces(n)?;
        if let Some(index) = flow {
            return self.body(self.child(n, index)?);
        }
        let Ok(first) = usize::try_from(first) else {
            return Ok(());
        };
        self.pieces_out(n, pieces.get(first + 1..).unwrap_or_default())
    }

    /// Ghidra `Constructor::print`: every piece.
    fn all(&mut self, n: u32) -> Result<(), DecodeError> {
        let (pieces, _, _) = self.pieces(n)?;
        self.pieces_out(n, pieces)
    }

    fn pieces_out(&mut self, n: u32, pieces: &[PrintPiece]) -> Result<(), DecodeError> {
        for piece in pieces {
            match *piece {
                PrintPiece::Text(text) => self.out.push_str(self.env.sla.text(text)),
                PrintPiece::Operand(index) => self.operand(n, index.max(0) as u32)?,
            }
        }
        Ok(())
    }

    /// Ghidra `OperandSymbol::print`.
    fn operand(&mut self, n: u32, index: u32) -> Result<(), DecodeError> {
        let node = self
            .env
            .parse
            .nodes
            .get(n as usize)
            .ok_or_else(|| self.model("node"))?;
        let id = node
            .constructor()
            .ok_or_else(|| self.model("node constructor"))?;
        let info = self
            .env
            .lang
            .tables
            .ctor(id)
            .ok_or_else(|| self.model("constructor"))?;
        let op = *self
            .env
            .lang
            .tables
            .op(info, index)
            .ok_or_else(|| self.model("operand"))?;
        let child = self.child(n, index)?;
        let point = Point::Node(child);
        let sla = self.env.sla;
        match op.def {
            OpDef::Subtable(_) => self.all(child)?,
            OpDef::Expr(expr) | OpDef::Value(expr) => hex(self.out, self.env.eval(expr, point, 0)?),
            OpDef::Table {
                symbol, expr, kind, ..
            } => {
                let value = self.env.eval(expr, point, 0)?;
                let slot = value as u32 as usize;
                let missing = || DecodeError::NoTableEntry {
                    address: self.env.parse.addr,
                    at: self.env.lang.raw_text(self.env.parse.addr),
                    table: kind,
                };
                match sla.symbol(symbol).map(|s| s.kind) {
                    Some(SymbolKind::ValueMap { table, .. }) => {
                        let entry = sla
                            .value_table(table)
                            .get(slot)
                            .copied()
                            .ok_or_else(missing)?;
                        hex(self.out, entry);
                    }
                    Some(SymbolKind::Name { table, .. }) => {
                        let name = sla
                            .name_table(table)
                            .get(slot)
                            .copied()
                            .ok_or_else(missing)?;
                        // An unusable entry prints as Ghidra's mark for it.
                        self.out.push_str(name.map_or("\t", |name| sla.text(name)));
                    }
                    Some(SymbolKind::VarnodeList { table, .. }) => {
                        let entries = sla.varnode_table(table);
                        let entry = entries.get(slot).ok_or(DecodeError::VarnodeListRange {
                            address: self.env.parse.addr,
                        })?;
                        let register = entry.ok_or_else(missing)?;
                        self.out.push_str(sla.symbol_name(register));
                    }
                    _ => return Err(self.model("table symbol")),
                }
            }
            OpDef::Varnode { symbol, .. } => self.out.push_str(sla.symbol_name(symbol)),
            OpDef::Start => {
                let _ = write!(self.out, "{:#x}", self.env.parse.addr.offset());
            }
            OpDef::End => {
                let _ = write!(
                    self.out,
                    "{:#x}",
                    self.env.naddr.unwrap_or(self.env.parse.addr).offset()
                );
            }
            OpDef::Next2 => {
                let next2 = self.env.parse.next2.ok_or(DecodeError::Next2Unavailable {
                    address: self.env.parse.addr,
                })?;
                let _ = write!(self.out, "{:#x}", next2.offset());
            }
            OpDef::Zero => self.out.push('0'),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_print_as_ghidra_prints_them() {
        let mut s = String::new();
        for value in [0, 0x1f, -1, -0x80, i64::MIN, i64::MAX] {
            hex(&mut s, value);
            s.push(' ');
        }
        assert_eq!(
            s,
            "0x0 0x1f -0x1 -0x80 -0x8000000000000000 0x7fffffffffffffff "
        );
    }
}
