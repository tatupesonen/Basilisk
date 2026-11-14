//! Display sections (`constructprint` of `slghparse.y` 275-289;
//! `Constructor::addSyntax`, `addOperand`, `removeTrailingSpace`).

use bk_sleigh_syntax::ast::DisplayPiece;

use super::{Compiler, CtorData, Piece};
use crate::ids::CtorId;

/// `Constructor::addSyntax`: adjacent text joins, white space collapses to
/// one `" "` piece, and the first white-space piece is remembered.
pub(crate) fn add_syntax(ctor: &mut CtorData, text: &str) {
    if text.is_empty() {
        return;
    }
    let text = if text.bytes().all(|b| b == b' ') { " " } else { text };
    if ctor.first == -1 && text == " " {
        ctor.first = ctor.print.len() as i32;
    }
    match ctor.print.last_mut() {
        None => ctor.print.push(Piece::Text(text.to_owned())),
        Some(Piece::Text(last)) if last == " " && text == " " => {}
        Some(Piece::Text(last)) if last != " " && text != " " => last.push_str(text),
        Some(_) => ctor.print.push(Piece::Text(text.to_owned())),
    }
}

/// `Constructor::removeTrailingSpace`.
pub(crate) fn remove_trailing_space(ctor: &mut CtorData) {
    if matches!(ctor.print.last(), Some(Piece::Text(t)) if t == " ") {
        ctor.print.pop();
    }
}

impl Compiler<'_> {
    /// The display section of constructor `ctor`. Returns false when the
    /// constructor must be abandoned.
    pub(crate) fn display(&mut self, ctor: CtorId, pieces: &[DisplayPiece], in_root: bool) -> bool {
        let mut first = true;
        for piece in pieces {
            if first && matches!(piece, DisplayPiece::Whitespace(_)) {
                continue;
            }
            match piece {
                DisplayPiece::Ident(ident) if first && in_root => {
                    let text = self.text(ident.name).to_owned();
                    if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                        add_syntax(c, &text);
                    }
                }
                DisplayPiece::Ident(ident) => {
                    let index = self.ctors.get(ctor.slot()).map_or(0, |c| c.operands.len() as u32);
                    let op = self.new_operand(ident.name, index, Some(ctor), ident.span);
                    if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                        c.operands.push(op);
                        c.print.push(Piece::Operand(index));
                    }
                }
                DisplayPiece::Whitespace(_) => {
                    if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                        add_syntax(c, " ");
                    }
                }
                DisplayPiece::Concat(span) => {
                    if first && !in_root {
                        self.diags.error(Some(*span), "Unexpected '^' at start of print pieces");
                        return false;
                    }
                }
                DisplayPiece::Literal { text, .. } => {
                    let text = self.text(*text).to_owned();
                    if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                        add_syntax(c, &text);
                    }
                }
                DisplayPiece::Quoted(s) => {
                    let text = self.text(s.value).to_owned();
                    if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                        add_syntax(c, &text);
                    }
                }
            }
            first = false;
        }
        true
    }
}
