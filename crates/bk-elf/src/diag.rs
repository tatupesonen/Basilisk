//! Diagnostics: what Ghidra reports through its message log while it
//! carries on parsing a damaged file.

/// What a [`Diagnostic`] is about. Tests and callers match on this; the
/// message carries the details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// `e_ident[EI_DATA]` is neither little- nor big-endian; little-endian
    /// headers were assumed.
    InvalidDataEncoding,
    /// `e_phoff` or `e_shoff` is outside the file; that table is ignored.
    InvalidTableOffset,
    /// `e_shnum` lies in the reserved range; treated as 0.
    InvalidSectionCount,
    /// An extended count (`PN_XNUM`, `e_shnum` = 0) could not be read from
    /// section 0, or its value is unusable.
    InvalidExtendedCount,
    /// `e_phentsize` or `e_shentsize` is not the size the class requires;
    /// that table is ignored.
    UnsupportedEntrySize,
    /// A table has more entries than the file can hold; the count was
    /// reduced.
    CountTruncated,
    /// The last entry of a table is only partly inside the file.
    PartialEntry,
    /// The prelink trailer could not be read.
    Prelink,
    /// The dynamic table is absent, stripped or ambiguous.
    DynamicTable,
    /// A required dynamic entry (`DT_STRTAB`, `DT_STRSZ`, `DT_SYMTAB`, …) is
    /// missing or zero.
    MissingDynamicEntry,
    /// An address from the dynamic table is not inside any loaded segment,
    /// or cannot be turned into a file offset.
    UnlocatedAddress,
    /// A string table could not be established.
    StringTable,
    /// A string could not be read from a string table.
    StringRead,
    /// A symbol table header has an unusable offset, size or entry size;
    /// the table is skipped.
    SymbolTable,
    /// The extended section index table (`SHT_SYMTAB_SHNDX`) of a symbol
    /// table is unusable.
    SectionIndexTable,
    /// The symbol hash table needed to size the dynamic symbol table could
    /// not be walked.
    HashTable,
    /// A relocation table has an unusable size, entry size or link; the
    /// table is skipped.
    RelocationTable,
    /// A relocation table ends early; the relocations before the cut are kept.
    RelocationTableTruncated,
    /// A compressed section's header is invalid or its algorithm is not
    /// supported; the section is treated as not compressed.
    Compression,
}

/// One problem found in a file that did not stop it from being parsed.
///
/// The messages are Ghidra's (what `ElfHeader` passes to its error
/// consumer), so a log produced from them reads the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// What the problem is about.
    pub kind: DiagnosticKind,
    /// The message, with offsets and values.
    pub message: String,
}

impl Diagnostic {
    /// Creates a diagnostic.
    pub fn new(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Collects diagnostics while a file is parsed.
#[derive(Debug, Default)]
pub(crate) struct Diagnostics {
    items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub(crate) fn push(&mut self, kind: DiagnosticKind, message: impl Into<String>) {
        let diagnostic = Diagnostic::new(kind, message);
        tracing::debug!(target: "bk_elf", kind = ?diagnostic.kind, "{}", diagnostic.message);
        self.items.push(diagnostic);
    }

    pub(crate) fn into_vec(self) -> Vec<Diagnostic> {
        self.items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_in_order() {
        let mut diags = Diagnostics::default();
        diags.push(DiagnosticKind::PartialEntry, "Symbol has partial entry");
        diags.push(DiagnosticKind::CountTruncated, String::from("truncating"));
        let items = diags.into_vec();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0],
            Diagnostic::new(DiagnosticKind::PartialEntry, "Symbol has partial entry")
        );
        assert_eq!(items[1].to_string(), "truncating");
    }
}
