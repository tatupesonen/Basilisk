//! String interning for identifiers, string literals and print pieces.
//!
//! Every name in the syntax tree is a [`Symbol`], a `u32` index into the
//! [`Interner`] that was used while parsing. Comparing two names is an
//! integer comparison, and parsing allocates once per *distinct* string,
//! not once per token.
//!
//! SLEIGH's keywords are interned first, in a fixed order, so the parser can
//! test for a keyword by comparing against the constants in [`kw`]. Keywords
//! are contextual (`SleighParser.g`, rule `key_as_id`): the lexer never
//! treats them specially.

use rustc_hash::FxBuildHasher;
use string_interner::backend::StringBackend;
use string_interner::symbol::SymbolU32;
use string_interner::{StringInterner, Symbol as _};

/// An interned string. Resolve it with [`Interner::resolve`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Symbol(u32);

impl Symbol {
    /// The index of this symbol in its interner.
    pub const fn index(self) -> u32 {
        self.0
    }

    /// Whether this is one of the words `SleighParser.g` lists under
    /// `key_as_id`: keywords that may also be used as ordinary identifiers
    /// (except where the grammar asks for a strict identifier).
    pub const fn is_keyword(self) -> bool {
        self.0 >= kw::FIRST_KEY.0 && self.0 <= kw::LAST_KEY.0
    }

    /// Whether this is `with`, the one word reserved in every lexer mode.
    pub const fn is_reserved(self) -> bool {
        self.0 == kw::WITH.0
    }
}

macro_rules! keywords {
    ($($index:literal $name:ident $text:literal,)*) => {
        /// Pre-interned keyword symbols.
        pub mod kw {
            use super::Symbol;
            $(
                #[doc = concat!("The word `", $text, "`.")]
                pub const $name: Symbol = Symbol($index);
            )*
            /// First of the keywords usable as identifiers.
            pub const FIRST_KEY: Symbol = ALIGNMENT;
            /// Last of the keywords usable as identifiers.
            pub const LAST_KEY: Symbol = WORDSIZE;
        }

        /// Keyword texts in symbol order.
        const KEYWORDS: &[&str] = &[$($text,)*];
    };
}

keywords! {
    0 WITH "with",
    1 IS "is",
    2 IF "if",
    3 ALIGNMENT "alignment",
    4 ATTACH "attach",
    5 BIG "big",
    6 BITRANGE "bitrange",
    7 BUILD "build",
    8 CALL "call",
    9 CONTEXT "context",
    10 CROSSBUILD "crossbuild",
    11 DEC "dec",
    12 DEFAULT "default",
    13 DEFINE "define",
    14 ENDIAN "endian",
    15 EXPORT "export",
    16 GOTO "goto",
    17 HEX "hex",
    18 LITTLE "little",
    19 LOCAL "local",
    20 MACRO "macro",
    21 NAMES "names",
    22 NOFLOW "noflow",
    23 OFFSET "offset",
    24 PCODEOP "pcodeop",
    25 RETURN "return",
    26 SIGNED "signed",
    27 SIZE "size",
    28 SPACE "space",
    29 TOKEN "token",
    30 TYPE "type",
    31 UNIMPL "unimpl",
    32 VALUES "values",
    33 VARIABLES "variables",
    34 WORDSIZE "wordsize",
}

/// The table of interned strings for one parse.
///
/// A thin wrapper over the `string-interner` crate (one contiguous string
/// buffer, symbols handed out as consecutive indices) hashed with
/// `rustc-hash`; the wrapper pins the keyword symbols and keeps the
/// dependency out of the public API.
#[derive(Clone, Debug)]
pub struct Interner {
    strings: StringInterner<StringBackend<SymbolU32>, FxBuildHasher>,
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    /// An interner holding only the keywords.
    pub fn new() -> Self {
        let mut interner = Self {
            strings: StringInterner::with_hasher(FxBuildHasher),
        };
        for word in KEYWORDS {
            interner.strings.get_or_intern_static(word);
        }
        interner
    }

    /// The symbol for `text`, adding it if it is new.
    pub fn intern(&mut self, text: &str) -> Symbol {
        Symbol(self.strings.get_or_intern(text).to_usize() as u32)
    }

    /// The symbol for `text` if it has been interned.
    pub fn get(&self, text: &str) -> Option<Symbol> {
        self.strings.get(text).map(|s| Symbol(s.to_usize() as u32))
    }

    /// The text of `symbol`; empty for a symbol from another interner.
    pub fn resolve(&self, symbol: Symbol) -> &str {
        SymbolU32::try_from_usize(symbol.0 as usize)
            .and_then(|s| self.strings.resolve(s))
            .unwrap_or("")
    }

    /// Number of distinct strings, keywords included.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether the interner is empty (it never is: keywords are always present).
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_have_their_constant_symbols() {
        let interner = Interner::new();
        assert_eq!(interner.resolve(kw::WITH), "with");
        assert_eq!(interner.resolve(kw::IS), "is");
        assert_eq!(interner.resolve(kw::IF), "if");
        assert_eq!(interner.resolve(kw::DEFINE), "define");
        assert_eq!(interner.resolve(kw::UNIMPL), "unimpl");
        assert_eq!(interner.resolve(kw::WORDSIZE), "wordsize");
        assert_eq!(interner.len(), KEYWORDS.len());
        for (i, word) in KEYWORDS.iter().enumerate() {
            let sym = interner.get(word).unwrap();
            assert_eq!(sym.index() as usize, i, "{word}");
            assert_eq!(sym.is_keyword(), i >= 3, "{word}");
        }
        assert!(kw::WITH.is_reserved());
        assert!(!kw::IS.is_keyword());
    }

    #[test]
    fn interning_is_idempotent_and_resolves() {
        let mut interner = Interner::new();
        let a = interner.intern("EAX");
        let b = interner.intern("EBX");
        assert_ne!(a, b);
        assert_eq!(interner.intern("EAX"), a);
        assert_eq!(interner.resolve(a), "EAX");
        assert_eq!(interner.resolve(b), "EBX");
        assert_eq!(interner.get("ECX"), None);
        assert!(!a.is_keyword());
    }

    #[test]
    fn long_and_similar_strings_stay_distinct() {
        let mut interner = Interner::new();
        let names: Vec<String> = (0..2000).map(|i| format!("register_name_{i:05}")).collect();
        let syms: Vec<Symbol> = names.iter().map(|n| interner.intern(n)).collect();
        for (name, sym) in names.iter().zip(&syms) {
            assert_eq!(interner.resolve(*sym), name);
            assert_eq!(interner.get(name), Some(*sym));
        }
    }

    #[test]
    fn foreign_symbol_resolves_to_empty() {
        let mut big = Interner::new();
        let sym = big.intern("only_here");
        assert_eq!(Interner::new().resolve(sym), "");
    }
}
