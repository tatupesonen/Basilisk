//! Typed arena ids and the marshalling ids this crate reads and writes.
//!
//! Names and numbers of the element and attribute ids are Ghidra's
//! (`database.cc` 23–43, `comment.cc`, `stringmanage.cc`, `cpool.cc`,
//! `loadimage_xml.cc`, `globalcontext.cc`, `override.cc`, and the few of
//! `architecture.cc` the symbol filling reads).

use bk_marshal::{AttributeId, ElementId, IdTable};

macro_rules! arena_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) u32);

        impl $name {
            /// The arena index.
            pub const fn index(self) -> u32 {
                self.0
            }
        }
    };
}

arena_id!(
    /// A scope in a [`Database`](crate::Database): an index into its scope
    /// arena. Ghidra's 64-bit scope id is a separate field.
    ScopeId
);
arena_id!(
    /// A symbol in a [`Database`](crate::Database). Ghidra's 64-bit symbol id
    /// is a separate field.
    SymbolId
);
arena_id!(
    /// A symbol entry (storage location) in a [`Database`](crate::Database).
    EntryId
);

macro_rules! ids {
    ($kind:ident, $list:ident: $($(#[$doc:meta])* $name:ident = ($text:literal, $num:literal);)*) => {
        $($(#[$doc])* pub const $name: $kind = $kind::new($text, $num);)*
        /// Every id of this kind the crate defines.
        pub static $list: &[$kind] = &[$($name),*];
    };
}

ids!(AttributeId, ATTRIBUTES:
    /// `cat` (database.cc).
    ATTRIB_CAT = ("cat", 61);
    /// `field` (database.cc).
    ATTRIB_FIELD = ("field", 62);
    /// `merge` (database.cc).
    ATTRIB_MERGE = ("merge", 63);
    /// `scopeidbyname` (database.cc).
    ATTRIB_SCOPEIDBYNAME = ("scopeidbyname", 64);
    /// `volatile` (database.cc).
    ATTRIB_VOLATILE = ("volatile", 65);
    /// `trunc` (stringmanage.cc).
    ATTRIB_TRUNC = ("trunc", 69);
    /// `a` (cpool.cc).
    ATTRIB_A = ("a", 80);
    /// `b` (cpool.cc).
    ATTRIB_B = ("b", 81);
    /// `length` (cpool.cc).
    ATTRIB_LENGTH = ("length", 82);
    /// `tag` (cpool.cc).
    ATTRIB_TAG = ("tag", 83);
    /// `label` (jumptable.cc; read for display names).
    ATTRIB_LABEL = ("label", 131);
    /// `arch` (`loadimage_xml.cc`).
    ATTRIB_ARCH = ("arch", 135);
    /// `addrtied` (varmap.cc; written by union facets).
    ATTRIB_ADDRTIED = ("addrtied", 30);
    /// `address` (architecture.cc; `<default_symbols>`).
    ATTRIB_ADDRESS = ("address", 148);
    /// `vector_lane_sizes` (architecture.cc).
    ATTRIB_VECTOR_LANE_SIZES = ("vector_lane_sizes", 130);
);

ids!(ElementId, ELEMENTS:
    /// `<collision>` (database.cc).
    ELEM_COLLISION = ("collision", 67);
    /// `<db>` (database.cc).
    ELEM_DB = ("db", 68);
    /// `<equatesymbol>` (database.cc).
    ELEM_EQUATESYMBOL = ("equatesymbol", 69);
    /// `<externrefsymbol>` (database.cc).
    ELEM_EXTERNREFSYMBOL = ("externrefsymbol", 70);
    /// `<facetsymbol>` (database.cc).
    ELEM_FACETSYMBOL = ("facetsymbol", 71);
    /// `<functionshell>` (database.cc).
    ELEM_FUNCTIONSHELL = ("functionshell", 72);
    /// `<hash>` (database.cc).
    ELEM_HASH = ("hash", 73);
    /// `<hole>` (database.cc).
    ELEM_HOLE = ("hole", 74);
    /// `<labelsym>` (database.cc).
    ELEM_LABELSYM = ("labelsym", 75);
    /// `<mapsym>` (database.cc).
    ELEM_MAPSYM = ("mapsym", 76);
    /// `<parent>` (database.cc).
    ELEM_PARENT = ("parent", 77);
    /// `<property_changepoint>` (database.cc).
    ELEM_PROPERTY_CHANGEPOINT = ("property_changepoint", 78);
    /// `<rangeequalssymbols>` (database.cc).
    ELEM_RANGEEQUALSSYMBOLS = ("rangeequalssymbols", 79);
    /// `<scope>` (database.cc).
    ELEM_SCOPE = ("scope", 80);
    /// `<symbollist>` (database.cc).
    ELEM_SYMBOLLIST = ("symbollist", 81);
    /// `<bytes>` (stringmanage.cc).
    ELEM_BYTES = ("bytes", 83);
    /// `<string>` (stringmanage.cc).
    ELEM_STRING = ("string", 84);
    /// `<stringmanage>` (stringmanage.cc).
    ELEM_STRINGMANAGE = ("stringmanage", 85);
    /// `<comment>` (comment.cc).
    ELEM_COMMENT = ("comment", 86);
    /// `<commentdb>` (comment.cc).
    ELEM_COMMENTDB = ("commentdb", 87);
    /// `<text>` (comment.cc).
    ELEM_TEXT = ("text", 88);
    /// `<constantpool>` (cpool.cc).
    ELEM_CONSTANTPOOL = ("constantpool", 109);
    /// `<cpoolrec>` (cpool.cc).
    ELEM_CPOOLREC = ("cpoolrec", 110);
    /// `<ref>` (cpool.cc).
    ELEM_REF = ("ref", 111);
    /// `<token>` (cpool.cc).
    ELEM_TOKEN = ("token", 112);
    /// `<context_data>` (globalcontext.cc).
    ELEM_CONTEXT_DATA = ("context_data", 120);
    /// `<context_points>` (globalcontext.cc).
    ELEM_CONTEXT_POINTS = ("context_points", 121);
    /// `<context_pointset>` (globalcontext.cc).
    ELEM_CONTEXT_POINTSET = ("context_pointset", 122);
    /// `<context_set>` (globalcontext.cc).
    ELEM_CONTEXT_SET = ("context_set", 123);
    /// `<set>` (globalcontext.cc).
    ELEM_SET = ("set", 124);
    /// `<tracked_pointset>` (globalcontext.cc).
    ELEM_TRACKED_POINTSET = ("tracked_pointset", 125);
    /// `<tracked_set>` (globalcontext.cc).
    ELEM_TRACKED_SET = ("tracked_set", 126);
    /// `<deadcodedelay>` (override.cc).
    ELEM_DEADCODEDELAY = ("deadcodedelay", 218);
    /// `<flow>` (override.cc).
    ELEM_FLOW = ("flow", 219);
    /// `<forcegoto>` (override.cc).
    ELEM_FORCEGOTO = ("forcegoto", 220);
    /// `<calldest>` (override.cc).
    ELEM_CALLDEST = ("calldest", 221);
    /// `<multistagejump>` (override.cc).
    ELEM_MULTISTAGEJUMP = ("multistagejump", 222);
    /// `<override>` (override.cc).
    ELEM_OVERRIDE = ("override", 223);
    /// `<protooverride>` (override.cc).
    ELEM_PROTOOVERRIDE = ("protooverride", 224);
    /// `<binaryimage>` (`loadimage_xml.cc`).
    ELEM_BINARYIMAGE = ("binaryimage", 230);
    /// `<bytechunk>` (`loadimage_xml.cc`).
    ELEM_BYTECHUNK = ("bytechunk", 231);
    /// `<function>` (fspec.cc / funcdata.cc; decoded by D07).
    ELEM_FUNCTION = ("function", 116);
    /// `<flowoverridelist>` (architecture.cc).
    ELEM_FLOWOVERRIDELIST = ("flowoverridelist", 140);
    /// `<default_symbols>` (architecture.cc).
    ELEM_DEFAULT_SYMBOLS = ("default_symbols", 136);
    /// `<global>` (architecture.cc).
    ELEM_GLOBAL = ("global", 142);
    /// `<incidentalcopy>` (architecture.cc).
    ELEM_INCIDENTALCOPY = ("incidentalcopy", 143);
    /// `<readonly>` (architecture.cc).
    ELEM_READONLY = ("readonly", 151);
    /// `<register_data>` (architecture.cc).
    ELEM_REGISTER_DATA = ("register_data", 152);
    /// `<volatile>` (architecture.cc).
    ELEM_VOLATILE = ("volatile", 159);
);

/// An id table with `marshal.cc`'s ids, `bk-core`'s, `bk-decomp-types`'s,
/// `bk-cspec`'s and this crate's: every element this crate reads.
pub fn id_table() -> IdTable {
    // The slices hold no conflicting names (checked by a test), so the
    // fallback is never taken.
    IdTable::new(
        &[
            bk_marshal::ids::ATTRIBUTES,
            bk_core::ids::ATTRIBUTES,
            bk_decomp_types::xml::ids::ATTRIBUTES,
            ATTRIBUTES,
        ],
        &[
            bk_marshal::ids::ELEMENTS,
            bk_core::ids::ELEMENTS,
            bk_decomp_types::xml::ids::ELEMENTS,
            ELEMENTS,
        ],
    )
    .unwrap_or_else(|_| IdTable::marshal_only())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_do_not_conflict() {
        let table = bk_marshal::IdTable::new(
            &[
                bk_marshal::ids::ATTRIBUTES,
                bk_core::ids::ATTRIBUTES,
                bk_decomp_types::xml::ids::ATTRIBUTES,
                super::ATTRIBUTES,
            ],
            &[
                bk_marshal::ids::ELEMENTS,
                bk_core::ids::ELEMENTS,
                bk_decomp_types::xml::ids::ELEMENTS,
                super::ELEMENTS,
            ],
        );
        assert!(table.is_ok(), "{table:?}");
    }
}
