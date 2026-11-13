//! Token kinds to colours and faces, one mapping for both code views.

use egui::{Color32, FontFamily};

use super::tokens::SyntaxPalette;
use super::typography;
use crate::model::TokenKind;

/// The colour of a token kind.
pub fn color(s: &SyntaxPalette, kind: TokenKind) -> Color32 {
    match kind {
        TokenKind::Mnemonic => s.mnemonic,
        TokenKind::Register => s.register,
        TokenKind::Immediate | TokenKind::Constant => s.number,
        TokenKind::Address | TokenKind::Label => s.label,
        TokenKind::Function | TokenKind::Import => s.function,
        TokenKind::Global => s.global,
        TokenKind::Variable | TokenKind::Field => s.variable,
        TokenKind::Parameter => s.parameter,
        TokenKind::Keyword => s.keyword,
        TokenKind::Type => s.datatype,
        TokenKind::String => s.string,
        TokenKind::Comment => s.comment,
        _ => s.punctuation,
    }
}

/// The face of a token kind: semibold for definitions that anchor the eye
/// (function names), regular otherwise.
pub fn family(kind: TokenKind, defining: bool) -> FontFamily {
    if defining && kind == TokenKind::Function {
        typography::code_strong_family()
    } else {
        FontFamily::Monospace
    }
}
