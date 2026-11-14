//! Element and attribute ids this crate reads and writes, with Ghidra's
//! names and numbers (`fspec.cc`, `modelrules.cc`, `pcodeinject.cc`,
//! `architecture.cc`, `userop.cc`, `type.cc`), and the id table used to
//! decode `.cspec` documents.
//!
//! The ids of `marshal.cc` come from `bk-marshal` and those of `address.cc`,
//! `space.cc` and `translate.cc` from `bk-core`.

use std::sync::OnceLock;

use bk_marshal::{AttributeId, ElementId, IdTable};

macro_rules! ids {
    ($kind:ident, $list:ident: $($name:ident = $text:literal, $num:literal;)*) => {
        $(
            #[doc = concat!("Marshalling id `", $text, "`.")]
            pub const $name: $kind = $kind::new($text, $num);
        )*
        /// Every id of this kind defined here.
        pub static $list: &[$kind] = &[$($name),*];
    };
}

ids! { AttributeId, ATTRIBUTES:
    // fspec.cc
    ATTRIB_CUSTOM = "custom", 114;
    ATTRIB_DOTDOTDOT = "dotdotdot", 115;
    ATTRIB_EXTENSION = "extension", 116;
    ATTRIB_HASTHIS = "hasthis", 117;
    ATTRIB_INLINE = "inline", 118;
    ATTRIB_KILLEDBYCALL = "killedbycall", 119;
    ATTRIB_MAXSIZE = "maxsize", 120;
    ATTRIB_MINSIZE = "minsize", 121;
    ATTRIB_MODELLOCK = "modellock", 122;
    ATTRIB_NORETURN = "noreturn", 123;
    ATTRIB_POINTERMAX = "pointermax", 124;
    ATTRIB_SEPARATEFLOAT = "separatefloat", 125;
    ATTRIB_STACKSHIFT = "stackshift", 126;
    ATTRIB_STRATEGY = "strategy", 127;
    ATTRIB_THISBEFORERETPOINTER = "thisbeforeretpointer", 128;
    ATTRIB_VOIDLOCK = "voidlock", 129;
    // modelrules.cc
    ATTRIB_SIZES = "sizes", 151;
    ATTRIB_BACKFILL = "backfill", 152;
    ATTRIB_MAX_PRIMITIVES = "maxprimitives", 153;
    ATTRIB_REVERSESIGNIF = "reversesignif", 154;
    ATTRIB_MATCHSIZE = "matchsize", 155;
    ATTRIB_AFTER_BYTES = "afterbytes", 156;
    ATTRIB_AFTER_STORAGE = "afterstorage", 157;
    ATTRIB_FILL_ALTERNATE = "fillalternate", 158;
    ATTRIB_MINELEMENTS = "minelements", 159;
    ATTRIB_MAXELEMENTS = "maxelements", 160;
    // pcodeinject.cc
    ATTRIB_DYNAMIC = "dynamic", 70;
    ATTRIB_INCIDENTALCOPY = "incidentalcopy", 71;
    ATTRIB_INJECT = "inject", 72;
    ATTRIB_PARAMSHIFT = "paramshift", 73;
    ATTRIB_TARGETOP = "targetop", 74;
    // architecture.cc
    ATTRIB_ADJUSTVMA = "adjustvma", 103;
    ATTRIB_ENABLE = "enable", 104;
    ATTRIB_GROUP = "group", 105;
    ATTRIB_GROWTH = "growth", 106;
    ATTRIB_KEY = "key", 107;
    ATTRIB_LOADERSYMBOLS = "loadersymbols", 108;
    ATTRIB_PARENT = "parent", 109;
    ATTRIB_REGISTER = "register", 110;
    ATTRIB_REVERSEJUSTIFY = "reversejustify", 111;
    ATTRIB_SIGNEXT = "signext", 112;
    ATTRIB_STYLE = "style", 113;
    // userop.cc
    ATTRIB_FARPOINTER = "farpointer", 85;
    ATTRIB_INPUTOP = "inputop", 86;
    ATTRIB_OUTPUTOP = "outputop", 87;
    ATTRIB_USEROP = "userop", 88;
    // space.cc, address.cc (as bk-core)
    ATTRIB_DELAY = "delay", 91;
    ATTRIB_FIRST = "first", 27;
    ATTRIB_LAST = "last", 28;
    // op.cc
    ATTRIB_A = "a", 80;
    ATTRIB_B = "b", 81;
    // basilisk's own (ADR-025 3f); written only in basilisk's encoder mode
    ATTRIB_PROVENANCE = "bk_provenance", 400;
}

ids! { ElementId, ELEMENTS:
    // fspec.cc
    ELEM_GROUP = "group", 160;
    ELEM_INTERNALLIST = "internallist", 161;
    ELEM_KILLEDBYCALL = "killedbycall", 162;
    ELEM_LIKELYTRASH = "likelytrash", 163;
    ELEM_LOCALRANGE = "localrange", 164;
    ELEM_MODEL = "model", 165;
    ELEM_PARAM = "param", 166;
    ELEM_PARAMRANGE = "paramrange", 167;
    ELEM_PENTRY = "pentry", 168;
    ELEM_PROTOTYPE = "prototype", 169;
    ELEM_RESOLVEPROTOTYPE = "resolveprototype", 170;
    ELEM_RETPARAM = "retparam", 171;
    ELEM_RETURNSYM = "returnsym", 172;
    ELEM_UNAFFECTED = "unaffected", 173;
    ELEM_INTERNAL_STORAGE = "internal_storage", 286;
    ELEM_SHARESTACK = "sharestack", 291;
    // modelrules.cc
    ELEM_DATATYPE = "datatype", 273;
    ELEM_CONSUME = "consume", 274;
    ELEM_CONSUME_EXTRA = "consume_extra", 275;
    ELEM_CONVERT_TO_PTR = "convert_to_ptr", 276;
    ELEM_GOTO_STACK = "goto_stack", 277;
    ELEM_JOIN = "join", 278;
    ELEM_DATATYPE_AT = "datatype_at", 279;
    ELEM_POSITION = "position", 280;
    ELEM_VARARGS = "varargs", 281;
    ELEM_HIDDEN_RETURN = "hidden_return", 282;
    ELEM_JOIN_PER_PRIMITIVE = "join_per_primitive", 283;
    ELEM_JOIN_DUAL_CLASS = "join_dual_class", 285;
    ELEM_EXTRA_STACK = "extra_stack", 287;
    ELEM_CONSUME_REMAINING = "consume_remaining", 288;
    // pcodeinject.cc
    ELEM_ADDR_PCODE = "addr_pcode", 89;
    ELEM_BODY = "body", 90;
    ELEM_CALLFIXUP = "callfixup", 91;
    ELEM_CALLOTHERFIXUP = "callotherfixup", 92;
    ELEM_CASE_PCODE = "case_pcode", 93;
    ELEM_CONTEXT = "context", 94;
    ELEM_DEFAULT_PCODE = "default_pcode", 95;
    ELEM_INJECT = "inject", 96;
    ELEM_INJECTDEBUG = "injectdebug", 97;
    ELEM_INST = "inst", 98;
    ELEM_PAYLOAD = "payload", 99;
    ELEM_PCODE = "pcode", 100;
    ELEM_SIZE_PCODE = "size_pcode", 101;
    // architecture.cc
    ELEM_AGGRESSIVETRIM = "aggressivetrim", 131;
    ELEM_COMPILER_SPEC = "compiler_spec", 132;
    ELEM_DATA_SPACE = "data_space", 133;
    ELEM_DEFAULT_MEMORY_BLOCKS = "default_memory_blocks", 134;
    ELEM_DEFAULT_PROTO = "default_proto", 135;
    ELEM_DEFAULT_SYMBOLS = "default_symbols", 136;
    ELEM_EVAL_CALLED_PROTOTYPE = "eval_called_prototype", 137;
    ELEM_EVAL_CURRENT_PROTOTYPE = "eval_current_prototype", 138;
    ELEM_EXPERIMENTAL_RULES = "experimental_rules", 139;
    ELEM_FLOWOVERRIDELIST = "flowoverridelist", 140;
    ELEM_FUNCPTR = "funcptr", 141;
    ELEM_GLOBAL = "global", 142;
    ELEM_INCIDENTALCOPY = "incidentalcopy", 143;
    ELEM_INFERPTRBOUNDS = "inferptrbounds", 144;
    ELEM_MODELALIAS = "modelalias", 145;
    ELEM_NOHIGHPTR = "nohighptr", 146;
    ELEM_PROCESSOR_SPEC = "processor_spec", 147;
    ELEM_PROGRAMCOUNTER = "programcounter", 148;
    ELEM_PROPERTIES = "properties", 149;
    ELEM_PROPERTY = "property", 150;
    ELEM_READONLY = "readonly", 151;
    ELEM_REGISTER_DATA = "register_data", 152;
    ELEM_RULE = "rule", 153;
    ELEM_SAVE_STATE = "save_state", 154;
    ELEM_SEGMENTED_ADDRESS = "segmented_address", 155;
    ELEM_SPACEBASE = "spacebase", 156;
    ELEM_SPECEXTENSIONS = "specextensions", 157;
    ELEM_STACKPOINTER = "stackpointer", 158;
    ELEM_VOLATILE = "volatile", 159;
    // userop.cc, globalcontext.cc, type.cc, varmap.cc
    ELEM_CONSTRESOLVE = "constresolve", 127;
    ELEM_JUMPASSIST = "jumpassist", 128;
    ELEM_SEGMENTOP = "segmentop", 129;
    ELEM_CONTEXT_DATA = "context_data", 120;
    ELEM_DATA_ORGANIZATION = "data_organization", 42;
    ELEM_ENUM = "enum", 48;
    ELEM_DEADCODEDELAY = "deadcodedelay", 218;
    ELEM_PREFERSPLIT = "prefersplit", 225;
}

/// The id table for `.cspec` documents and prototype XML: the ids of
/// `bk-marshal`, `bk-core` and this crate.
pub fn id_table() -> &'static IdTable {
    static TABLE: OnceLock<IdTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        IdTable::new(
            &[
                bk_marshal::ids::ATTRIBUTES,
                bk_core::ids::ATTRIBUTES,
                ATTRIBUTES,
            ],
            &[bk_marshal::ids::ELEMENTS, bk_core::ids::ELEMENTS, ELEMENTS],
        )
        .unwrap_or_else(|_| IdTable::marshal_only())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_no_conflicts() {
        IdTable::new(
            &[
                bk_marshal::ids::ATTRIBUTES,
                bk_core::ids::ATTRIBUTES,
                ATTRIBUTES,
            ],
            &[bk_marshal::ids::ELEMENTS, bk_core::ids::ELEMENTS, ELEMENTS],
        )
        .unwrap();
        let t = id_table();
        assert_eq!(t.element("pentry"), ELEM_PENTRY.code());
        assert_eq!(t.attribute("piece1"), t.unknown_attribute());
        assert_eq!(t.element("nonsense"), t.unknown_element());
    }
}
