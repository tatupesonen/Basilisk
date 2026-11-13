//! Where a name or a type came from (ADR-025, item 3f).
//!
//! Ghidra records this for symbols as `SourceType` (`DEFAULT`, `ANALYSIS`,
//! `AI`, `IMPORTED`, `USER_DEFINED`) and uses its priority to decide which
//! of two sources may overwrite the other. basilisk keeps finer kinds — an
//! import, a library signature and debug information are told apart — and
//! carries the value on types as well as names, across the program trait in
//! both directions.

/// Who supplied a name or a type.
///
/// Kinds are compared by [`trust`](Self::trust), not by their order here:
/// several kinds share a rank, as `ANALYSIS` and `AI` do in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Provenance {
    /// Nobody: a generated placeholder such as `FUN_00401000` or
    /// `undefined4` (Ghidra's `DEFAULT`).
    #[default]
    Default,
    /// Derived by analysis or by the decompiler (Ghidra's `ANALYSIS`).
    Analysis,
    /// Proposed by a language model through the plugin interface
    /// (Ghidra's `AI`); never applied without the user's opt-in.
    Model,
    /// Read from the imported file: its symbol tables, exports and imports
    /// (Ghidra's `IMPORTED`).
    Imported,
    /// Matched from a library signature or a type archive.
    LibrarySignature,
    /// Read from debug information (DWARF, PDB, …).
    DebugInfo,
    /// Entered by the user (Ghidra's `USER_DEFINED`).
    User,
}

impl Provenance {
    /// The rank used to decide which of two sources wins: a higher rank may
    /// replace a lower one. It follows Ghidra's `SourceType` priority,
    /// `DEFAULT` < `ANALYSIS` = `AI` < `IMPORTED` < `USER_DEFINED`, with
    /// library signatures and debug information ranked with imports.
    #[must_use]
    pub const fn trust(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::Analysis | Self::Model => 1,
            Self::Imported | Self::LibrarySignature | Self::DebugInfo => 2,
            Self::User => 3,
        }
    }

    /// The provenance to keep when `self` and `other` describe the same
    /// thing: the one of higher [`trust`](Self::trust), and `self` when
    /// they rank equally.
    #[must_use]
    pub const fn or_more_trusted(self, other: Self) -> Self {
        if other.trust() > self.trust() {
            other
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Provenance;

    const ALL: [Provenance; 7] = [
        Provenance::Default,
        Provenance::Analysis,
        Provenance::Model,
        Provenance::Imported,
        Provenance::LibrarySignature,
        Provenance::DebugInfo,
        Provenance::User,
    ];

    #[test]
    fn trust_follows_ghidras_source_type_priority() {
        let ranks = ALL.map(Provenance::trust);
        assert_eq!(ranks, [0, 1, 1, 2, 2, 2, 3]);
    }

    #[test]
    fn the_default_is_the_least_trusted() {
        assert_eq!(Provenance::default(), Provenance::Default);
        assert!(
            ALL.iter()
                .all(|p| p.trust() >= Provenance::default().trust())
        );
    }

    #[test]
    fn the_more_trusted_of_two_is_kept_and_ties_keep_the_first() {
        for a in ALL {
            for b in ALL {
                let kept = a.or_more_trusted(b);
                assert!(kept.trust() >= a.trust() && kept.trust() >= b.trust());
                if a.trust() >= b.trust() {
                    assert_eq!(kept, a);
                } else {
                    assert_eq!(kept, b);
                }
            }
        }
    }
}
