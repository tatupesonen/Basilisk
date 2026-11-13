//! Tokens: the unit of text in the listing and the decompiler.
//!
//! Ghidra's listing fields and the decompiler's `ClangToken` classes both
//! know what kind of thing each piece of text is and what it refers to.
//! [`Token`] carries the same information, so a view can colour it, find
//! its other uses and navigate to its target without parsing text.

use super::location::Address;

/// What a token is, which decides its colour and how it behaves.
///
/// One set for both views, so a function name is the same colour in the
/// listing and in the decompiler (Ghidra's `ClangFuncNameToken`,
/// `ClangVariableToken`, `ClangTypeToken`, … and the listing's mnemonic,
/// register, scalar and label operand representations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenKind {
    /// Instruction mnemonic (`MOV`, `CALL`).
    Mnemonic,
    /// Processor register (`RAX`, `RBP`).
    Register,
    /// Immediate or scalar operand (`0x10`).
    Immediate,
    /// A raw address with no symbol (`100000c20`).
    Address,
    /// A code or data label (`LAB_100000700`, `s_usage_100001d00`).
    Label,
    /// A function name.
    Function,
    /// An imported (external) function name.
    Import,
    /// A global variable or other data symbol.
    Global,
    /// A local variable in the decompiler.
    Variable,
    /// A function parameter in the decompiler.
    Parameter,
    /// A C keyword (`if`, `return`).
    Keyword,
    /// A data type name (`int`, `config_t`).
    Type,
    /// A constant in decompiled C (`0x3c`, `'\0'`).
    Constant,
    /// A string literal.
    String,
    /// A comment.
    Comment,
    /// A structure field name.
    Field,
    /// Operators and punctuation (`,`, `[`, `+`, `;`).
    Punctuation,
    /// Anything else.
    Plain,
}

/// What a token refers to, which is what navigation and "find other uses"
/// act on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Referent {
    /// A location in the program (a function, label or data item).
    Address(Address),
    /// A variable or parameter of the function starting at `function`.
    Variable {
        /// Entry address of the function that owns the variable.
        function: Address,
        /// Index of the variable in that function (parameters first).
        index: u32,
    },
    /// A register, by name.
    Register(Box<str>),
    /// A data type, by name.
    Type(Box<str>),
}

impl Referent {
    /// The address this referent leads to, if it is navigable.
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(a) => Some(*a),
            _ => None,
        }
    }
}

/// One piece of text with its kind and, when it has one, its referent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The text as displayed.
    pub text: Box<str>,
    /// What kind of token this is.
    pub kind: TokenKind,
    /// What it refers to.
    pub referent: Option<Referent>,
}

impl Token {
    /// A token with no referent.
    pub fn new(text: impl Into<Box<str>>, kind: TokenKind) -> Self {
        Self {
            text: text.into(),
            kind,
            referent: None,
        }
    }

    /// A token that refers to something.
    pub fn with_referent(text: impl Into<Box<str>>, kind: TokenKind, referent: Referent) -> Self {
        Self {
            text: text.into(),
            kind,
            referent: Some(referent),
        }
    }

    /// Whether this token and `other` are "the same thing" for highlighting:
    /// the same referent, or the same text when neither has one (Ghidra's
    /// middle-click highlight matches text in the listing and variables in
    /// the decompiler).
    pub fn matches(&self, other: &Self) -> bool {
        match (&self.referent, &other.referent) {
            (Some(a), Some(b)) => a == b,
            (None, None) => {
                self.text == other.text
                    && !matches!(self.kind, TokenKind::Punctuation | TokenKind::Plain)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_match_by_referent_before_text() {
        let a = Token::with_referent("main", TokenKind::Function, Referent::Address(Address(1)));
        let b = Token::with_referent("FUN_1", TokenKind::Function, Referent::Address(Address(1)));
        let c = Token::new("main", TokenKind::Function);
        assert!(a.matches(&b));
        assert!(!a.matches(&c));
        assert!(c.matches(&Token::new("main", TokenKind::Label)));
        assert!(
            !Token::new(",", TokenKind::Punctuation)
                .matches(&Token::new(",", TokenKind::Punctuation))
        );
    }
}
