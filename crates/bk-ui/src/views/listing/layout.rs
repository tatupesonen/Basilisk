//! Turning a listing row into text: Ghidra's field columns, colours and
//! the x-span of every token (for clicks, hover and highlights).
//!
//! Each row becomes one `Galley`, built once when its page arrives and
//! reused every frame until the page, the theme or the density changes.

use std::sync::Arc;

use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontFamily, FontId, Galley};

use crate::design::Tokens;
use crate::design::syntax;
use crate::model::{
    Address, ListingRow, Referent, RowContent, Token, TokenKind, XrefEntry,
};

/// Bytes shown in the bytes field before "…" (Ghidra wraps them onto more
/// lines; one row per instruction keeps every row the same height).
pub(crate) const MAX_BYTES: usize = 6;

/// Width of a plate comment box in characters.
const PLATE_WIDTH: usize = 58;

/// Field columns in characters, as Ghidra lays out its default format.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Columns {
    pub address: usize,
    pub bytes: usize,
    pub label: usize,
    pub mnemonic: usize,
    pub operands: usize,
    pub comment: usize,
    pub var_type: usize,
    pub var_storage: usize,
    pub var_name: usize,
    pub xref: usize,
    pub xref_entry: usize,
}

impl Columns {
    /// Columns for addresses of `digits` hex digits.
    pub(crate) fn new(digits: usize) -> Self {
        let address = 0;
        let bytes = address + digits + 2;
        let mnemonic = bytes + MAX_BYTES * 3 + 1;
        let operands = mnemonic + 10;
        let label = bytes + 6;
        Self {
            address,
            bytes,
            label,
            mnemonic,
            operands,
            comment: operands + 30,
            var_type: bytes - 2,
            var_storage: label + 6,
            var_name: label + 22,
            xref: operands + 14,
            xref_entry: operands + 24,
        }
    }
}

/// Where one token sits in a laid-out row.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Span {
    /// Left edge, in pixels from the text origin.
    pub x0: f32,
    /// Right edge.
    pub x1: f32,
    /// The token.
    pub token: Token,
}

/// A row ready to paint.
#[derive(Debug, Clone)]
pub(crate) struct RowLayout {
    pub galley: Arc<Galley>,
    pub spans: Vec<Span>,
}

impl RowLayout {
    /// The token under x (pixels from the text origin).
    pub(crate) fn token_at(&self, x: f32) -> Option<usize> {
        self.spans.iter().position(|s| x >= s.x0 && x < s.x1)
    }
}

struct Builder<'a> {
    job: LayoutJob,
    col: usize,
    cw: f32,
    t: &'a Tokens,
    spans: Vec<Span>,
}

impl Builder<'_> {
    fn font(&self, family: FontFamily) -> FontId {
        FontId::new(self.t.metrics.code_size, family)
    }

    fn to(&mut self, col: usize) {
        if col > self.col {
            let pad = (col - self.col) as f32 * self.cw;
            self.job.append(
                "",
                pad,
                TextFormat::simple(self.font(FontFamily::Monospace), Color32::TRANSPARENT),
            );
            self.col = col;
        } else if self.col > 0 && col <= self.col {
            self.text(" ", Color32::TRANSPARENT);
        }
    }

    fn text_in(&mut self, s: &str, color: Color32, family: FontFamily) {
        self.job
            .append(s, 0.0, TextFormat::simple(self.font(family), color));
        self.col += s.chars().count();
    }

    fn text(&mut self, s: &str, color: Color32) {
        self.text_in(s, color, FontFamily::Monospace);
    }

    fn token(&mut self, tok: &Token, defining: bool) {
        let x0 = self.col as f32 * self.cw;
        let color = syntax::color(&self.t.syntax, tok.kind);
        self.text_in(&tok.text, color, syntax::family(tok.kind, defining));
        let x1 = self.col as f32 * self.cw;
        if !matches!(tok.kind, TokenKind::Punctuation) || tok.referent.is_some() {
            self.spans.push(Span {
                x0,
                x1,
                token: tok.clone(),
            });
        }
    }

    fn xref(&mut self, x: &XrefEntry) {
        let text = match &x.from_function {
            Some(f) => format!("{f}:{}({})", x.from, x.kind.tag()),
            None => format!("{}({})", x.from, x.kind.tag()),
        };
        let tok = Token::with_referent(text, TokenKind::Address, Referent::Address(x.from));
        let x0 = self.col as f32 * self.cw;
        self.text(&tok.text, self.t.palette.text_secondary);
        let x1 = self.col as f32 * self.cw;
        self.spans.push(Span { x0, x1, token: tok });
    }
}

/// Formats bytes Ghidra-style (`48 89 e5`), truncated to [`MAX_BYTES`].
pub(crate) fn bytes_text(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(MAX_BYTES * 3);
    let shown = if bytes.len() > MAX_BYTES {
        MAX_BYTES - 1
    } else {
        bytes.len()
    };
    for (i, b) in bytes.iter().take(shown).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > MAX_BYTES {
        s.push_str(" …");
    }
    s
}

/// Lays out one row.
pub(crate) fn layout(
    row: &ListingRow,
    cols: &Columns,
    t: &Tokens,
    cw: f32,
    painter: &egui::Painter,
) -> RowLayout {
    let mut b = Builder {
        job: LayoutJob::default(),
        col: 0,
        cw,
        t,
        spans: Vec::new(),
    };
    b.job.wrap.max_width = f32::INFINITY;
    let s = t.syntax;
    let p = t.palette;
    match &row.content {
        RowContent::Blank => {}
        RowContent::PlateBorder => {
            b.to(cols.label);
            b.text(&"*".repeat(PLATE_WIDTH), s.comment);
        }
        RowContent::Plate(text) => {
            b.to(cols.label);
            let inner = PLATE_WIDTH - 4;
            let body: String = text.chars().take(inner).collect();
            let n = body.chars().count();
            // Ghidra centres the default "FUNCTION" titles and left-aligns
            // user comments.
            let centred = matches!(&**text, "FUNCTION" | "THUNK FUNCTION");
            let (l, r) = if centred {
                ((inner - n) / 2, inner - n - (inner - n) / 2)
            } else {
                (0, inner - n)
            };
            b.text(
                &format!("* {}{}{} *", " ".repeat(l), body, " ".repeat(r)),
                s.comment,
            );
        }
        RowContent::Signature(tokens) => {
            b.to(cols.label);
            for tok in tokens {
                b.token(tok, true);
            }
        }
        RowContent::Variable {
            datatype,
            storage,
            name,
        } => {
            b.to(cols.var_type);
            b.text(datatype, s.datatype);
            b.to(cols.var_storage);
            b.text(storage, s.address);
            b.to(cols.var_name);
            b.token(name, false);
        }
        RowContent::Label {
            name,
            xref_count,
            first_xref,
        } => {
            b.to(cols.label);
            b.token(name, true);
            if let Some(x) = first_xref {
                b.to(cols.xref);
                b.text(&format!("XREF[{xref_count}]:"), p.text_muted);
                b.to(cols.xref_entry);
                b.xref(x);
            }
        }
        RowContent::Xref(x) => {
            b.to(cols.xref_entry);
            b.xref(x);
        }
        RowContent::XrefMore(n) => {
            b.to(cols.xref_entry);
            b.text(&format!("[{n} more]"), p.text_muted);
        }
        RowContent::PreComment(text) | RowContent::PostComment(text) => {
            b.to(cols.label);
            b.text(text, s.comment);
        }
        RowContent::Section { name, range } => {
            b.to(cols.label);
            b.text(&format!("// {name}"), s.comment);
            b.to(cols.operands);
            b.text(range, s.comment);
        }
        RowContent::Instruction {
            bytes,
            mnemonic,
            operands,
            comment,
        } => {
            b.to(cols.address);
            b.text(&row.address.to_string(), s.address);
            b.to(cols.bytes);
            b.text(&bytes_text(bytes), s.bytes);
            b.to(cols.mnemonic);
            b.token(mnemonic, false);
            b.to(cols.operands);
            for tok in operands {
                b.token(tok, false);
            }
            if let Some(c) = comment {
                b.to(cols.comment);
                b.text(c, s.comment);
            }
        }
        RowContent::Data {
            bytes,
            datatype,
            value,
            comment,
        } => {
            b.to(cols.address);
            b.text(&row.address.to_string(), s.address);
            b.to(cols.bytes);
            b.text(&bytes_text(bytes), s.bytes);
            b.to(cols.mnemonic);
            b.token(datatype, false);
            b.to(cols.operands);
            for tok in value {
                b.token(tok, false);
            }
            if let Some(c) = comment {
                b.to(cols.comment);
                b.text(c, s.comment);
            }
        }
    }
    let spans = b.spans;
    RowLayout {
        galley: painter.layout_job(b.job),
        spans,
    }
}

/// Plain text of a row, for Copy.
pub(crate) fn row_text(row: &ListingRow) -> String {
    let mut s = String::new();
    match &row.content {
        RowContent::Instruction {
            bytes,
            mnemonic,
            operands,
            comment,
        } => {
            s.push_str(&format!("{}  {:<20}{:<10} ", row.address, bytes_text(bytes), mnemonic.text));
            for o in operands {
                s.push_str(&o.text);
            }
            if let Some(c) = comment {
                s.push_str("  ");
                s.push_str(c);
            }
        }
        _ => {
            for tok in row.tokens() {
                s.push_str(&tok.text);
            }
        }
    }
    s
}

/// The number of hex digits needed for addresses up to `max`.
pub(crate) fn address_digits(max: Address) -> usize {
    let bits = 64 - max.0.leading_zeros() as usize;
    bits.div_ceil(4).max(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_spaced_and_truncated() {
        assert_eq!(bytes_text(&[0x48, 0x89, 0xe5]), "48 89 e5");
        assert_eq!(bytes_text(&[1, 2, 3, 4, 5, 6, 7]), "01 02 03 04 05 …");
        assert_eq!(bytes_text(&[1, 2, 3, 4, 5, 6]), "01 02 03 04 05 06");
    }

    #[test]
    fn columns_leave_room_for_each_field() {
        let c = Columns::new(9);
        assert!(c.bytes > c.address + 9);
        assert!(c.mnemonic >= c.bytes + MAX_BYTES * 3);
        assert!(c.operands > c.mnemonic + 7);
        assert_eq!(address_digits(Address(0x1_0000_0650)), 9);
        assert_eq!(address_digits(Address(0x401000)), 8);
    }
}
