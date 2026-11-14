//! A pattern with the tokens it spans and its ellipses (`TokenPattern`,
//! inventory 10 a.1, a.3, a.4): what equations build and what alignment of
//! operands is decided by.

use super::algebra::Pattern;
use super::block::Block;
use super::disjoint::Disjoint;

/// A token: its index in definition order and its size in bytes. Tokens
/// are the same token when their indices are equal (Ghidra compares
/// pointers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tok {
    /// Definition order.
    pub index: u32,
    /// Size in bytes.
    pub size: u32,
}

/// Why two patterns cannot be combined (Ghidra's `SleighError`s of
/// `TokenPattern`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CombineError {
    /// "Right/left ellipsis".
    RightLeftEllipsis,
    /// "Left/right ellipsis".
    LeftRightEllipsis,
    /// "Mismatched pattern sizes -- A != B".
    MismatchedSizes(usize, usize),
    /// "Pattern size cannot vary (missing '...'?)".
    SizeCannotVary,
    /// "Mismatched tokens when combining patterns -- A != B" (Basilisk
    /// names the tokens; Ghidra prints two pointers).
    MismatchedTokens(Tok, Tok),
    /// "Interior ellipsis in pattern".
    InteriorEllipsis,
    /// "Double ellipsis in pattern".
    DoubleEllipsis,
    /// "Right/left ellipsis in commonSubPattern".
    CommonRightLeftEllipsis,
}

impl CombineError {
    /// Ghidra's text, with token names from `name`.
    pub fn message(&self, name: impl Fn(Tok) -> String) -> String {
        match self {
            Self::RightLeftEllipsis => "Right/left ellipsis".to_owned(),
            Self::LeftRightEllipsis => "Left/right ellipsis".to_owned(),
            Self::MismatchedSizes(a, b) => format!("Mismatched pattern sizes -- {a} != {b}"),
            Self::SizeCannotVary => "Pattern size cannot vary (missing '...'?)".to_owned(),
            Self::MismatchedTokens(a, b) => format!(
                "Mismatched tokens when combining patterns -- {} != {}",
                name(*a),
                name(*b)
            ),
            Self::InteriorEllipsis => "Interior ellipsis in pattern".to_owned(),
            Self::DoubleEllipsis => "Double ellipsis in pattern".to_owned(),
            Self::CommonRightLeftEllipsis => "Right/left ellipsis in commonSubPattern".to_owned(),
        }
    }
}

/// A pattern over a list of tokens. The pattern is always simplified, as
/// every stored `TokenPattern` is in Ghidra (copies go through
/// `simplifyClone`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenPattern {
    /// The bit pattern.
    pub pattern: Pattern,
    /// The tokens, in order.
    pub tokens: Vec<Tok>,
    /// `...` before.
    pub left_ellipsis: bool,
    /// `...` after.
    pub right_ellipsis: bool,
}

/// Token lists and ellipses of a combination, and the shift between the
/// operands (`resolveTokens`).
struct Resolved {
    tokens: Vec<Tok>,
    left: bool,
    right: bool,
    sa: i32,
}

fn size_sum<'a>(tokens: impl Iterator<Item = &'a Tok>) -> i32 {
    tokens.fold(0_i32, |acc, t| acc.wrapping_add(t.size as i32))
}

fn resolve(a: &TokenPattern, b: &TokenPattern) -> Result<Resolved, CombineError> {
    let (len1, len2) = (a.tokens.len(), b.tokens.len());
    let min = len1.min(len2);
    if min == 0 {
        let plain = |t: &TokenPattern| t.tokens.is_empty() && !t.left_ellipsis && !t.right_ellipsis;
        let take = |t: &TokenPattern| Resolved {
            tokens: t.tokens.clone(),
            left: t.left_ellipsis,
            right: t.right_ellipsis,
            sa: 0,
        };
        if plain(a) {
            return Ok(take(b));
        }
        if plain(b) {
            return Ok(take(a));
        }
    }
    let (mut left, mut right, mut reverse) = (false, false, false);
    // The size checks shared by every branch where one side has an ellipsis
    // and the other has none.
    let check = |len: usize| {
        if len != min {
            Err(CombineError::MismatchedSizes(len, min))
        } else if len1 == len2 {
            Err(CombineError::SizeCannotVary)
        } else {
            Ok(())
        }
    };
    if a.left_ellipsis {
        reverse = true;
        if b.right_ellipsis {
            return Err(CombineError::RightLeftEllipsis);
        } else if b.left_ellipsis {
            left = true;
        } else {
            check(len1)?;
        }
    } else if a.right_ellipsis {
        if b.left_ellipsis {
            return Err(CombineError::LeftRightEllipsis);
        } else if b.right_ellipsis {
            right = true;
        } else {
            check(len1)?;
        }
    } else if b.left_ellipsis {
        reverse = true;
        check(len2)?;
    } else if b.right_ellipsis {
        check(len2)?;
    } else if len2 != len1 {
        return Err(CombineError::MismatchedSizes(len2, len1));
    }
    let mut sa = 0_i32;
    if reverse {
        for (x, y) in a.tokens.iter().rev().zip(b.tokens.iter().rev()) {
            if x != y {
                return Err(CombineError::MismatchedTokens(*x, *y));
            }
        }
        let longer = if len1 <= len2 { &b.tokens } else { &a.tokens };
        sa = size_sum(longer.iter().rev().skip(min));
        if len1 < len2 {
            sa = sa.wrapping_neg();
        }
    } else {
        for (x, y) in a.tokens.iter().zip(&b.tokens) {
            if x != y {
                return Err(CombineError::MismatchedTokens(*x, *y));
            }
        }
    }
    let tokens = if len1 <= len2 {
        b.tokens.clone()
    } else {
        a.tokens.clone()
    };
    Ok(Resolved {
        tokens,
        left,
        right,
        sa,
    })
}

impl TokenPattern {
    /// The always-true (`true`) or always-false pattern over no tokens.
    pub const fn constant(value: bool) -> Self {
        Self {
            pattern: if value { Pattern::TRUE } else { Pattern::FALSE },
            tokens: Vec::new(),
            left_ellipsis: false,
            right_ellipsis: false,
        }
    }

    /// The true pattern over one token (`TokenPattern(Token*)`).
    pub fn token(tok: Tok) -> Self {
        Self {
            tokens: vec![tok],
            ..Self::constant(true)
        }
    }

    /// A token field `bitstart..=bitend` of `tok` holding `value`.
    pub fn field(tok: Tok, big_endian: bool, bitstart: i32, bitend: i32, value: i64) -> Self {
        let block = if big_endian {
            Block::big(tok.size as i32, bitstart, bitend, value)
        } else {
            Block::little(bitstart, bitend, value)
        };
        Self {
            pattern: Pattern::One(Disjoint::Instruction(block)),
            tokens: vec![tok],
            left_ellipsis: false,
            right_ellipsis: false,
        }
    }

    /// Context bits `start..=end` (most significant bit first) holding
    /// `value`.
    pub fn context(value: i64, start: i32, end: i32) -> Self {
        let size = end / 8 + 1;
        let block = Block::big(size, size * 8 - 1 - end, size * 8 - 1 - start, value);
        Self {
            pattern: Pattern::One(Disjoint::Context(block)),
            ..Self::constant(true)
        }
    }

    fn with(resolved: Resolved, pattern: &Pattern) -> Self {
        Self {
            pattern: pattern.simplified(),
            tokens: resolved.tokens,
            left_ellipsis: resolved.left,
            right_ellipsis: resolved.right,
        }
    }

    /// `doAnd`.
    pub fn and(&self, other: &Self) -> Result<Self, CombineError> {
        let r = resolve(self, other)?;
        let pattern = self.pattern.and(&other.pattern, r.sa);
        Ok(Self::with(r, &pattern))
    }

    /// `doOr`.
    pub fn or(&self, other: &Self) -> Result<Self, CombineError> {
        let r = resolve(self, other)?;
        let pattern = self.pattern.or(&other.pattern, r.sa);
        Ok(Self::with(r, &pattern))
    }

    /// `doCat`: `other` follows this pattern.
    pub fn cat(&self, other: &Self) -> Result<Self, CombineError> {
        let mut left = self.left_ellipsis;
        let mut right = self.right_ellipsis;
        let mut tokens = self.tokens.clone();
        let sa = if self.right_ellipsis || other.left_ellipsis {
            if self.right_ellipsis && !other.pattern.always_instruction_true() {
                return Err(CombineError::InteriorEllipsis);
            }
            if other.left_ellipsis {
                if !self.pattern.always_instruction_true() {
                    return Err(CombineError::InteriorEllipsis);
                }
                left = true;
            }
            0
        } else {
            let sa = size_sum(self.tokens.iter());
            tokens.extend_from_slice(&other.tokens);
            right = other.right_ellipsis;
            sa
        };
        if left && right {
            return Err(CombineError::DoubleEllipsis);
        }
        let pattern = self.pattern.and(&other.pattern, sa);
        Ok(Self {
            pattern: pattern.simplified(),
            tokens,
            left_ellipsis: left,
            right_ellipsis: right,
        })
    }

    /// `commonSubPattern`: what both patterns have in common.
    pub fn common(&self, other: &Self) -> Result<Self, CombineError> {
        let reverse = self.left_ellipsis || other.left_ellipsis;
        if reverse && (self.right_ellipsis || other.right_ellipsis) {
            return Err(CombineError::CommonRightLeftEllipsis);
        }
        let mut left = self.left_ellipsis || other.left_ellipsis;
        let mut right = self.right_ellipsis || other.right_ellipsis;
        let max = self.tokens.len().max(other.tokens.len());
        let tokens: Vec<Tok> = if reverse {
            let mut common: Vec<Tok> = self
                .tokens
                .iter()
                .rev()
                .zip(other.tokens.iter().rev())
                .take_while(|(x, y)| x == y)
                .map(|(x, _)| *x)
                .collect();
            common.reverse();
            if common.len() < max {
                left = true;
            }
            common
        } else {
            let common: Vec<Tok> = self
                .tokens
                .iter()
                .zip(&other.tokens)
                .take_while(|(x, y)| x == y)
                .map(|(x, _)| *x)
                .collect();
            if common.len() < max {
                right = true;
            }
            common
        };
        Ok(Self {
            pattern: self.pattern.common(&other.pattern, 0).simplified(),
            tokens,
            left_ellipsis: left,
            right_ellipsis: right,
        })
    }

    /// Either ellipsis.
    pub const fn has_ellipsis(&self) -> bool {
        self.left_ellipsis || self.right_ellipsis
    }

    /// The sum of the token sizes (`getMinimumLength`).
    pub fn minimum_length(&self) -> i32 {
        size_sum(self.tokens.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: Tok = Tok { index: 0, size: 1 };
    const T2: Tok = Tok { index: 1, size: 2 };

    fn ellipsis(mut t: TokenPattern, left: bool) -> TokenPattern {
        if left {
            t.left_ellipsis = true;
        } else {
            t.right_ellipsis = true;
        }
        t
    }

    #[test]
    fn resolve_tokens_cases() {
        let a = TokenPattern::field(T1, true, 0, 3, 5);
        let b = TokenPattern::field(T1, true, 4, 7, 2);
        let ab = a.and(&b).unwrap();
        assert_eq!(ab.tokens, [T1]);
        // Different tokens.
        let c = TokenPattern::field(T2, true, 0, 3, 1);
        assert_eq!(
            a.and(&c),
            Err(CombineError::MismatchedTokens(T1, T2))
        );
        // Different lengths without an ellipsis.
        let ac = a.cat(&TokenPattern::token(T2)).unwrap();
        assert_eq!(ac.tokens, [T1, T2]);
        assert_eq!(a.and(&ac), Err(CombineError::MismatchedSizes(2, 1)));
        // Left ellipsis aligns on the right; the shift is the extra bytes.
        let left = ellipsis(TokenPattern::field(T2, true, 0, 3, 1), true);
        let r = left.and(&ac).unwrap();
        assert_eq!(r.tokens, [T1, T2]);
        assert!(!r.left_ellipsis);
        // The T2 field lands at byte offset 1 (after the 1-byte T1).
        let block = r.pattern.disjuncts()[0].block(false).unwrap().clone();
        assert_eq!((block.mask(20, 4), block.value(20, 4)), (0xf, 1));
        assert_eq!((block.mask(4, 4), block.value(4, 4)), (0xf, 5));
        // Same length with an ellipsis on one side.
        let same = ellipsis(TokenPattern::field(T1, true, 0, 3, 1), false);
        assert_eq!(same.and(&a), Err(CombineError::SizeCannotVary));
        // Opposite ellipses.
        let l = ellipsis(TokenPattern::token(T1), true);
        let r2 = ellipsis(TokenPattern::token(T1), false);
        assert_eq!(l.and(&r2), Err(CombineError::RightLeftEllipsis));
        assert_eq!(r2.and(&l), Err(CombineError::LeftRightEllipsis));
        assert_eq!(l.common(&r2), Err(CombineError::CommonRightLeftEllipsis));
    }

    #[test]
    fn cat_offsets_and_ellipsis_errors() {
        let a = TokenPattern::field(T2, true, 0, 7, 0xff);
        let b = TokenPattern::field(T1, true, 0, 7, 0x12);
        let ab = a.cat(&b).unwrap();
        assert_eq!(ab.minimum_length(), 3);
        let block = ab.pattern.disjuncts()[0].block(false).unwrap().clone();
        assert_eq!((block.offset, block.nonzero), (1, 2));
        let r = ellipsis(a.clone(), false);
        assert_eq!(r.cat(&b), Err(CombineError::InteriorEllipsis));
        let l = ellipsis(b.clone(), true);
        assert_eq!(a.cat(&l), Err(CombineError::InteriorEllipsis));
        let ctx = TokenPattern::context(1, 0, 0);
        let r_then_ctx = r.cat(&ctx).unwrap();
        assert!(r_then_ctx.right_ellipsis);
        let l_true = ellipsis(TokenPattern::constant(true), true);
        assert_eq!(r.cat(&l_true), Err(CombineError::InteriorEllipsis));
        let r_ctx = ellipsis(ctx, false);
        assert_eq!(r_ctx.cat(&l_true), Err(CombineError::DoubleEllipsis));
    }

    #[test]
    fn common_keeps_shared_prefix() {
        let a = TokenPattern::field(T1, true, 0, 7, 1)
            .cat(&TokenPattern::token(T2))
            .unwrap();
        let b = TokenPattern::field(T1, true, 0, 7, 3);
        let c = a.common(&b).unwrap();
        assert_eq!(c.tokens, [T1]);
        assert!(c.right_ellipsis);
        assert_eq!(
            c.pattern,
            Pattern::One(Disjoint::Instruction(Block::word(0, 0xfd00_0000, 0x0100_0000)))
        );
    }

    #[test]
    fn context_pattern_bits() {
        let c = TokenPattern::context(0b101, 8, 10);
        let block = c.pattern.disjuncts()[0].block(true).unwrap().clone();
        assert_eq!(block, Block::word(1, 0xe000_0000, 0xa000_0000));
    }
}
