//! The element and attribute ids of the `.sla` format scope.
//!
//! Ghidra: `slaformat.hh`/`slaformat.cc`. The `.sla` file numbers its
//! elements and attributes in their own scope (`FORMAT_SCOPE`, 1),
//! independently of the default marshalling scope of `bk-marshal`. The packed
//! form writes these numbers; the XML form (`sleigh -y`) writes the names.
//! Attribute id 1 is reserved (Ghidra's `ATTRIB_CONTEXT = 1` comment).

use bk_marshal::{AttrCode, AttributeId, ElemCode, ElementId, IdTable, IdTableError};

/// The format version this crate reads and writes (`FORMAT_VERSION`).
pub const FORMAT_VERSION: u8 = 4;

/// The four bytes a `.sla` file starts with: `s`, `l`, `a` and the version.
pub const HEADER: [u8; 4] = [b's', b'l', b'a', FORMAT_VERSION];

/// The code an unregistered attribute name maps to in the XML form. It is
/// outside the format scope's numbers.
pub const UNKNOWN_ATTRIBUTE: AttrCode = AttrCode::new(0xffff);
/// The code an unregistered element name maps to in the XML form.
pub const UNKNOWN_ELEMENT: ElemCode = ElemCode::new(0xffff);

/// Format attribute `val`.
pub const ATTRIB_VAL: AttributeId = AttributeId::new("val", 2);
/// Format attribute `id`.
pub const ATTRIB_ID: AttributeId = AttributeId::new("id", 3);
/// Format attribute `space`.
pub const ATTRIB_SPACE: AttributeId = AttributeId::new("space", 4);
/// Format attribute `s`.
pub const ATTRIB_S: AttributeId = AttributeId::new("s", 5);
/// Format attribute `off`.
pub const ATTRIB_OFF: AttributeId = AttributeId::new("off", 6);
/// Format attribute `code`.
pub const ATTRIB_CODE: AttributeId = AttributeId::new("code", 7);
/// Format attribute `mask`.
pub const ATTRIB_MASK: AttributeId = AttributeId::new("mask", 8);
/// Format attribute `index`.
pub const ATTRIB_INDEX: AttributeId = AttributeId::new("index", 9);
/// Format attribute `nonzero`.
pub const ATTRIB_NONZERO: AttributeId = AttributeId::new("nonzero", 10);
/// Format attribute `piece`.
pub const ATTRIB_PIECE: AttributeId = AttributeId::new("piece", 11);
/// Format attribute `name`.
pub const ATTRIB_NAME: AttributeId = AttributeId::new("name", 12);
/// Format attribute `scope`.
pub const ATTRIB_SCOPE: AttributeId = AttributeId::new("scope", 13);
/// Format attribute `startbit`.
pub const ATTRIB_STARTBIT: AttributeId = AttributeId::new("startbit", 14);
/// Format attribute `size`.
pub const ATTRIB_SIZE: AttributeId = AttributeId::new("size", 15);
/// Format attribute `table`.
pub const ATTRIB_TABLE: AttributeId = AttributeId::new("table", 16);
/// Format attribute `ct`.
pub const ATTRIB_CT: AttributeId = AttributeId::new("ct", 17);
/// Format attribute `minlen`.
pub const ATTRIB_MINLEN: AttributeId = AttributeId::new("minlen", 18);
/// Format attribute `base`.
pub const ATTRIB_BASE: AttributeId = AttributeId::new("base", 19);
/// Format attribute `number`.
pub const ATTRIB_NUMBER: AttributeId = AttributeId::new("number", 20);
/// Format attribute `context`.
pub const ATTRIB_CONTEXT: AttributeId = AttributeId::new("context", 21);
/// Format attribute `parent`.
pub const ATTRIB_PARENT: AttributeId = AttributeId::new("parent", 22);
/// Format attribute `subsym`.
pub const ATTRIB_SUBSYM: AttributeId = AttributeId::new("subsym", 23);
/// Format attribute `line`.
pub const ATTRIB_LINE: AttributeId = AttributeId::new("line", 24);
/// Format attribute `source`.
pub const ATTRIB_SOURCE: AttributeId = AttributeId::new("source", 25);
/// Format attribute `length`.
pub const ATTRIB_LENGTH: AttributeId = AttributeId::new("length", 26);
/// Format attribute `first`.
pub const ATTRIB_FIRST: AttributeId = AttributeId::new("first", 27);
/// Format attribute `plus`.
pub const ATTRIB_PLUS: AttributeId = AttributeId::new("plus", 28);
/// Format attribute `shift`.
pub const ATTRIB_SHIFT: AttributeId = AttributeId::new("shift", 29);
/// Format attribute `endbit`.
pub const ATTRIB_ENDBIT: AttributeId = AttributeId::new("endbit", 30);
/// Format attribute `signbit`.
pub const ATTRIB_SIGNBIT: AttributeId = AttributeId::new("signbit", 31);
/// Format attribute `endbyte`.
pub const ATTRIB_ENDBYTE: AttributeId = AttributeId::new("endbyte", 32);
/// Format attribute `startbyte`.
pub const ATTRIB_STARTBYTE: AttributeId = AttributeId::new("startbyte", 33);
/// Format attribute `version`.
pub const ATTRIB_VERSION: AttributeId = AttributeId::new("version", 34);
/// Format attribute `bigendian`.
pub const ATTRIB_BIGENDIAN: AttributeId = AttributeId::new("bigendian", 35);
/// Format attribute `align`.
pub const ATTRIB_ALIGN: AttributeId = AttributeId::new("align", 36);
/// Format attribute `uniqbase`.
pub const ATTRIB_UNIQBASE: AttributeId = AttributeId::new("uniqbase", 37);
/// Format attribute `maxdelay`.
pub const ATTRIB_MAXDELAY: AttributeId = AttributeId::new("maxdelay", 38);
/// Format attribute `uniqmask`.
pub const ATTRIB_UNIQMASK: AttributeId = AttributeId::new("uniqmask", 39);
/// Format attribute `numsections`.
pub const ATTRIB_NUMSECTIONS: AttributeId = AttributeId::new("numsections", 40);
/// Format attribute `defaultspace`.
pub const ATTRIB_DEFAULTSPACE: AttributeId = AttributeId::new("defaultspace", 41);
/// Format attribute `delay`.
pub const ATTRIB_DELAY: AttributeId = AttributeId::new("delay", 42);
/// Format attribute `wordsize`.
pub const ATTRIB_WORDSIZE: AttributeId = AttributeId::new("wordsize", 43);
/// Format attribute `physical`.
pub const ATTRIB_PHYSICAL: AttributeId = AttributeId::new("physical", 44);
/// Format attribute `scopesize`.
pub const ATTRIB_SCOPESIZE: AttributeId = AttributeId::new("scopesize", 45);
/// Format attribute `symbolsize`.
pub const ATTRIB_SYMBOLSIZE: AttributeId = AttributeId::new("symbolsize", 46);
/// Format attribute `varnode`.
pub const ATTRIB_VARNODE: AttributeId = AttributeId::new("varnode", 47);
/// Format attribute `low`.
pub const ATTRIB_LOW: AttributeId = AttributeId::new("low", 48);
/// Format attribute `high`.
pub const ATTRIB_HIGH: AttributeId = AttributeId::new("high", 49);
/// Format attribute `flow`.
pub const ATTRIB_FLOW: AttributeId = AttributeId::new("flow", 50);
/// Format attribute `contain`.
pub const ATTRIB_CONTAIN: AttributeId = AttributeId::new("contain", 51);
/// Format attribute `i`.
pub const ATTRIB_I: AttributeId = AttributeId::new("i", 52);
/// Format attribute `numct`.
pub const ATTRIB_NUMCT: AttributeId = AttributeId::new("numct", 53);
/// Format attribute `section`.
pub const ATTRIB_SECTION: AttributeId = AttributeId::new("section", 54);
/// Format attribute `labels`.
pub const ATTRIB_LABELS: AttributeId = AttributeId::new("labels", 55);

/// Format element `<const_real>`.
pub const ELEM_CONST_REAL: ElementId = ElementId::new("const_real", 1);
/// Format element `<varnode_tpl>`.
pub const ELEM_VARNODE_TPL: ElementId = ElementId::new("varnode_tpl", 2);
/// Format element `<const_spaceid>`.
pub const ELEM_CONST_SPACEID: ElementId = ElementId::new("const_spaceid", 3);
/// Format element `<const_handle>`.
pub const ELEM_CONST_HANDLE: ElementId = ElementId::new("const_handle", 4);
/// Format element `<op_tpl>`.
pub const ELEM_OP_TPL: ElementId = ElementId::new("op_tpl", 5);
/// Format element `<mask_word>`.
pub const ELEM_MASK_WORD: ElementId = ElementId::new("mask_word", 6);
/// Format element `<pat_block>`.
pub const ELEM_PAT_BLOCK: ElementId = ElementId::new("pat_block", 7);
/// Format element `<print>`.
pub const ELEM_PRINT: ElementId = ElementId::new("print", 8);
/// Format element `<pair>`.
pub const ELEM_PAIR: ElementId = ElementId::new("pair", 9);
/// Format element `<context_pat>`.
pub const ELEM_CONTEXT_PAT: ElementId = ElementId::new("context_pat", 10);
/// Format element `<null>`.
pub const ELEM_NULL: ElementId = ElementId::new("null", 11);
/// Format element `<operand_exp>`.
pub const ELEM_OPERAND_EXP: ElementId = ElementId::new("operand_exp", 12);
/// Format element `<operand_sym>`.
pub const ELEM_OPERAND_SYM: ElementId = ElementId::new("operand_sym", 13);
/// Format element `<operand_sym_head>`.
pub const ELEM_OPERAND_SYM_HEAD: ElementId = ElementId::new("operand_sym_head", 14);
/// Format element `<oper>`.
pub const ELEM_OPER: ElementId = ElementId::new("oper", 15);
/// Format element `<decision>`.
pub const ELEM_DECISION: ElementId = ElementId::new("decision", 16);
/// Format element `<opprint>`.
pub const ELEM_OPPRINT: ElementId = ElementId::new("opprint", 17);
/// Format element `<instruct_pat>`.
pub const ELEM_INSTRUCT_PAT: ElementId = ElementId::new("instruct_pat", 18);
/// Format element `<combine_pat>`.
pub const ELEM_COMBINE_PAT: ElementId = ElementId::new("combine_pat", 19);
/// Format element `<constructor>`.
pub const ELEM_CONSTRUCTOR: ElementId = ElementId::new("constructor", 20);
/// Format element `<construct_tpl>`.
pub const ELEM_CONSTRUCT_TPL: ElementId = ElementId::new("construct_tpl", 21);
/// Format element `<scope>`.
pub const ELEM_SCOPE: ElementId = ElementId::new("scope", 22);
/// Format element `<varnode_sym>`.
pub const ELEM_VARNODE_SYM: ElementId = ElementId::new("varnode_sym", 23);
/// Format element `<varnode_sym_head>`.
pub const ELEM_VARNODE_SYM_HEAD: ElementId = ElementId::new("varnode_sym_head", 24);
/// Format element `<userop>`.
pub const ELEM_USEROP: ElementId = ElementId::new("userop", 25);
/// Format element `<userop_head>`.
pub const ELEM_USEROP_HEAD: ElementId = ElementId::new("userop_head", 26);
/// Format element `<tokenfield>`.
pub const ELEM_TOKENFIELD: ElementId = ElementId::new("tokenfield", 27);
/// Format element `<var>`.
pub const ELEM_VAR: ElementId = ElementId::new("var", 28);
/// Format element `<contextfield>`.
pub const ELEM_CONTEXTFIELD: ElementId = ElementId::new("contextfield", 29);
/// Format element `<handle_tpl>`.
pub const ELEM_HANDLE_TPL: ElementId = ElementId::new("handle_tpl", 30);
/// Format element `<const_relative>`.
pub const ELEM_CONST_RELATIVE: ElementId = ElementId::new("const_relative", 31);
/// Format element `<context_op>`.
pub const ELEM_CONTEXT_OP: ElementId = ElementId::new("context_op", 32);
/// Format element `<sleigh>`.
pub const ELEM_SLEIGH: ElementId = ElementId::new("sleigh", 33);
/// Format element `<spaces>`.
pub const ELEM_SPACES: ElementId = ElementId::new("spaces", 34);
/// Format element `<sourcefiles>`.
pub const ELEM_SOURCEFILES: ElementId = ElementId::new("sourcefiles", 35);
/// Format element `<sourcefile>`.
pub const ELEM_SOURCEFILE: ElementId = ElementId::new("sourcefile", 36);
/// Format element `<space>`.
pub const ELEM_SPACE: ElementId = ElementId::new("space", 37);
/// Format element `<symbol_table>`.
pub const ELEM_SYMBOL_TABLE: ElementId = ElementId::new("symbol_table", 38);
/// Format element `<value_sym>`.
pub const ELEM_VALUE_SYM: ElementId = ElementId::new("value_sym", 39);
/// Format element `<value_sym_head>`.
pub const ELEM_VALUE_SYM_HEAD: ElementId = ElementId::new("value_sym_head", 40);
/// Format element `<context_sym>`.
pub const ELEM_CONTEXT_SYM: ElementId = ElementId::new("context_sym", 41);
/// Format element `<context_sym_head>`.
pub const ELEM_CONTEXT_SYM_HEAD: ElementId = ElementId::new("context_sym_head", 42);
/// Format element `<end_sym>`.
pub const ELEM_END_SYM: ElementId = ElementId::new("end_sym", 43);
/// Format element `<end_sym_head>`.
pub const ELEM_END_SYM_HEAD: ElementId = ElementId::new("end_sym_head", 44);
/// Format element `<space_other>`.
pub const ELEM_SPACE_OTHER: ElementId = ElementId::new("space_other", 45);
/// Format element `<space_unique>`.
pub const ELEM_SPACE_UNIQUE: ElementId = ElementId::new("space_unique", 46);
/// Format element `<and_exp>`.
pub const ELEM_AND_EXP: ElementId = ElementId::new("and_exp", 47);
/// Format element `<div_exp>`.
pub const ELEM_DIV_EXP: ElementId = ElementId::new("div_exp", 48);
/// Format element `<lshift_exp>`.
pub const ELEM_LSHIFT_EXP: ElementId = ElementId::new("lshift_exp", 49);
/// Format element `<minus_exp>`.
pub const ELEM_MINUS_EXP: ElementId = ElementId::new("minus_exp", 50);
/// Format element `<mult_exp>`.
pub const ELEM_MULT_EXP: ElementId = ElementId::new("mult_exp", 51);
/// Format element `<not_exp>`.
pub const ELEM_NOT_EXP: ElementId = ElementId::new("not_exp", 52);
/// Format element `<or_exp>`.
pub const ELEM_OR_EXP: ElementId = ElementId::new("or_exp", 53);
/// Format element `<plus_exp>`.
pub const ELEM_PLUS_EXP: ElementId = ElementId::new("plus_exp", 54);
/// Format element `<rshift_exp>`.
pub const ELEM_RSHIFT_EXP: ElementId = ElementId::new("rshift_exp", 55);
/// Format element `<sub_exp>`.
pub const ELEM_SUB_EXP: ElementId = ElementId::new("sub_exp", 56);
/// Format element `<xor_exp>`.
pub const ELEM_XOR_EXP: ElementId = ElementId::new("xor_exp", 57);
/// Format element `<intb>`.
pub const ELEM_INTB: ElementId = ElementId::new("intb", 58);
/// Format element `<end_exp>`.
pub const ELEM_END_EXP: ElementId = ElementId::new("end_exp", 59);
/// Format element `<next2_exp>`.
pub const ELEM_NEXT2_EXP: ElementId = ElementId::new("next2_exp", 60);
/// Format element `<start_exp>`.
pub const ELEM_START_EXP: ElementId = ElementId::new("start_exp", 61);
/// Format element `<epsilon_sym>`.
pub const ELEM_EPSILON_SYM: ElementId = ElementId::new("epsilon_sym", 62);
/// Format element `<epsilon_sym_head>`.
pub const ELEM_EPSILON_SYM_HEAD: ElementId = ElementId::new("epsilon_sym_head", 63);
/// Format element `<name_sym>`.
pub const ELEM_NAME_SYM: ElementId = ElementId::new("name_sym", 64);
/// Format element `<name_sym_head>`.
pub const ELEM_NAME_SYM_HEAD: ElementId = ElementId::new("name_sym_head", 65);
/// Format element `<nametab>`.
pub const ELEM_NAMETAB: ElementId = ElementId::new("nametab", 66);
/// Format element `<next2_sym>`.
pub const ELEM_NEXT2_SYM: ElementId = ElementId::new("next2_sym", 67);
/// Format element `<next2_sym_head>`.
pub const ELEM_NEXT2_SYM_HEAD: ElementId = ElementId::new("next2_sym_head", 68);
/// Format element `<start_sym>`.
pub const ELEM_START_SYM: ElementId = ElementId::new("start_sym", 69);
/// Format element `<start_sym_head>`.
pub const ELEM_START_SYM_HEAD: ElementId = ElementId::new("start_sym_head", 70);
/// Format element `<subtable_sym>`.
pub const ELEM_SUBTABLE_SYM: ElementId = ElementId::new("subtable_sym", 71);
/// Format element `<subtable_sym_head>`.
pub const ELEM_SUBTABLE_SYM_HEAD: ElementId = ElementId::new("subtable_sym_head", 72);
/// Format element `<valuemap_sym>`.
pub const ELEM_VALUEMAP_SYM: ElementId = ElementId::new("valuemap_sym", 73);
/// Format element `<valuemap_sym_head>`.
pub const ELEM_VALUEMAP_SYM_HEAD: ElementId = ElementId::new("valuemap_sym_head", 74);
/// Format element `<valuetab>`.
pub const ELEM_VALUETAB: ElementId = ElementId::new("valuetab", 75);
/// Format element `<varlist_sym>`.
pub const ELEM_VARLIST_SYM: ElementId = ElementId::new("varlist_sym", 76);
/// Format element `<varlist_sym_head>`.
pub const ELEM_VARLIST_SYM_HEAD: ElementId = ElementId::new("varlist_sym_head", 77);
/// Format element `<or_pat>`.
pub const ELEM_OR_PAT: ElementId = ElementId::new("or_pat", 78);
/// Format element `<commit>`.
pub const ELEM_COMMIT: ElementId = ElementId::new("commit", 79);
/// Format element `<const_start>`.
pub const ELEM_CONST_START: ElementId = ElementId::new("const_start", 80);
/// Format element `<const_next>`.
pub const ELEM_CONST_NEXT: ElementId = ElementId::new("const_next", 81);
/// Format element `<const_next2>`.
pub const ELEM_CONST_NEXT2: ElementId = ElementId::new("const_next2", 82);
/// Format element `<const_curspace>`.
pub const ELEM_CONST_CURSPACE: ElementId = ElementId::new("const_curspace", 83);
/// Format element `<const_curspace_size>`.
pub const ELEM_CONST_CURSPACE_SIZE: ElementId = ElementId::new("const_curspace_size", 84);
/// Format element `<const_flowref>`.
pub const ELEM_CONST_FLOWREF: ElementId = ElementId::new("const_flowref", 85);
/// Format element `<const_flowref_size>`.
pub const ELEM_CONST_FLOWREF_SIZE: ElementId = ElementId::new("const_flowref_size", 86);
/// Format element `<const_flowdest>`.
pub const ELEM_CONST_FLOWDEST: ElementId = ElementId::new("const_flowdest", 87);
/// Format element `<const_flowdest_size>`.
pub const ELEM_CONST_FLOWDEST_SIZE: ElementId = ElementId::new("const_flowdest_size", 88);

/// Every attribute of the format scope, in id order.
pub const ATTRIBUTES: &[AttributeId] = &[
    ATTRIB_VAL,
    ATTRIB_ID,
    ATTRIB_SPACE,
    ATTRIB_S,
    ATTRIB_OFF,
    ATTRIB_CODE,
    ATTRIB_MASK,
    ATTRIB_INDEX,
    ATTRIB_NONZERO,
    ATTRIB_PIECE,
    ATTRIB_NAME,
    ATTRIB_SCOPE,
    ATTRIB_STARTBIT,
    ATTRIB_SIZE,
    ATTRIB_TABLE,
    ATTRIB_CT,
    ATTRIB_MINLEN,
    ATTRIB_BASE,
    ATTRIB_NUMBER,
    ATTRIB_CONTEXT,
    ATTRIB_PARENT,
    ATTRIB_SUBSYM,
    ATTRIB_LINE,
    ATTRIB_SOURCE,
    ATTRIB_LENGTH,
    ATTRIB_FIRST,
    ATTRIB_PLUS,
    ATTRIB_SHIFT,
    ATTRIB_ENDBIT,
    ATTRIB_SIGNBIT,
    ATTRIB_ENDBYTE,
    ATTRIB_STARTBYTE,
    ATTRIB_VERSION,
    ATTRIB_BIGENDIAN,
    ATTRIB_ALIGN,
    ATTRIB_UNIQBASE,
    ATTRIB_MAXDELAY,
    ATTRIB_UNIQMASK,
    ATTRIB_NUMSECTIONS,
    ATTRIB_DEFAULTSPACE,
    ATTRIB_DELAY,
    ATTRIB_WORDSIZE,
    ATTRIB_PHYSICAL,
    ATTRIB_SCOPESIZE,
    ATTRIB_SYMBOLSIZE,
    ATTRIB_VARNODE,
    ATTRIB_LOW,
    ATTRIB_HIGH,
    ATTRIB_FLOW,
    ATTRIB_CONTAIN,
    ATTRIB_I,
    ATTRIB_NUMCT,
    ATTRIB_SECTION,
    ATTRIB_LABELS,
];

/// Every element of the format scope, in id order.
pub const ELEMENTS: &[ElementId] = &[
    ELEM_CONST_REAL,
    ELEM_VARNODE_TPL,
    ELEM_CONST_SPACEID,
    ELEM_CONST_HANDLE,
    ELEM_OP_TPL,
    ELEM_MASK_WORD,
    ELEM_PAT_BLOCK,
    ELEM_PRINT,
    ELEM_PAIR,
    ELEM_CONTEXT_PAT,
    ELEM_NULL,
    ELEM_OPERAND_EXP,
    ELEM_OPERAND_SYM,
    ELEM_OPERAND_SYM_HEAD,
    ELEM_OPER,
    ELEM_DECISION,
    ELEM_OPPRINT,
    ELEM_INSTRUCT_PAT,
    ELEM_COMBINE_PAT,
    ELEM_CONSTRUCTOR,
    ELEM_CONSTRUCT_TPL,
    ELEM_SCOPE,
    ELEM_VARNODE_SYM,
    ELEM_VARNODE_SYM_HEAD,
    ELEM_USEROP,
    ELEM_USEROP_HEAD,
    ELEM_TOKENFIELD,
    ELEM_VAR,
    ELEM_CONTEXTFIELD,
    ELEM_HANDLE_TPL,
    ELEM_CONST_RELATIVE,
    ELEM_CONTEXT_OP,
    ELEM_SLEIGH,
    ELEM_SPACES,
    ELEM_SOURCEFILES,
    ELEM_SOURCEFILE,
    ELEM_SPACE,
    ELEM_SYMBOL_TABLE,
    ELEM_VALUE_SYM,
    ELEM_VALUE_SYM_HEAD,
    ELEM_CONTEXT_SYM,
    ELEM_CONTEXT_SYM_HEAD,
    ELEM_END_SYM,
    ELEM_END_SYM_HEAD,
    ELEM_SPACE_OTHER,
    ELEM_SPACE_UNIQUE,
    ELEM_AND_EXP,
    ELEM_DIV_EXP,
    ELEM_LSHIFT_EXP,
    ELEM_MINUS_EXP,
    ELEM_MULT_EXP,
    ELEM_NOT_EXP,
    ELEM_OR_EXP,
    ELEM_PLUS_EXP,
    ELEM_RSHIFT_EXP,
    ELEM_SUB_EXP,
    ELEM_XOR_EXP,
    ELEM_INTB,
    ELEM_END_EXP,
    ELEM_NEXT2_EXP,
    ELEM_START_EXP,
    ELEM_EPSILON_SYM,
    ELEM_EPSILON_SYM_HEAD,
    ELEM_NAME_SYM,
    ELEM_NAME_SYM_HEAD,
    ELEM_NAMETAB,
    ELEM_NEXT2_SYM,
    ELEM_NEXT2_SYM_HEAD,
    ELEM_START_SYM,
    ELEM_START_SYM_HEAD,
    ELEM_SUBTABLE_SYM,
    ELEM_SUBTABLE_SYM_HEAD,
    ELEM_VALUEMAP_SYM,
    ELEM_VALUEMAP_SYM_HEAD,
    ELEM_VALUETAB,
    ELEM_VARLIST_SYM,
    ELEM_VARLIST_SYM_HEAD,
    ELEM_OR_PAT,
    ELEM_COMMIT,
    ELEM_CONST_START,
    ELEM_CONST_NEXT,
    ELEM_CONST_NEXT2,
    ELEM_CONST_CURSPACE,
    ELEM_CONST_CURSPACE_SIZE,
    ELEM_CONST_FLOWREF,
    ELEM_CONST_FLOWREF_SIZE,
    ELEM_CONST_FLOWDEST,
    ELEM_CONST_FLOWDEST_SIZE,
];

/// The name table of the format scope, for reading the XML form.
///
/// Names that are not registered map to [`UNKNOWN_ATTRIBUTE`] and
/// [`UNKNOWN_ELEMENT`].
pub fn id_table() -> Result<IdTable, IdTableError> {
    Ok(IdTable::new(&[ATTRIBUTES], &[ELEMENTS])?.with_unknown(UNKNOWN_ATTRIBUTE, UNKNOWN_ELEMENT))
}

/// The name of a format-scope element id, for messages.
pub fn element_name(id: u32) -> Option<&'static str> {
    usize::try_from(id)
        .ok()
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| ELEMENTS.get(index))
        .map(ElementId::name)
}

/// The name of a format-scope attribute id, for messages.
pub fn attribute_name(id: u32) -> Option<&'static str> {
    usize::try_from(id)
        .ok()
        .and_then(|index| index.checked_sub(2))
        .and_then(|index| ATTRIBUTES.get(index))
        .map(AttributeId::name)
}

/// Attribute ids as plain numbers, for `match` patterns.
#[expect(dead_code, reason = "the complete table; not every id is matched on")]
pub(crate) mod a {
    pub(crate) const VAL: u32 = 2;
    pub(crate) const ID: u32 = 3;
    pub(crate) const SPACE: u32 = 4;
    pub(crate) const S: u32 = 5;
    pub(crate) const OFF: u32 = 6;
    pub(crate) const CODE: u32 = 7;
    pub(crate) const MASK: u32 = 8;
    pub(crate) const INDEX: u32 = 9;
    pub(crate) const NONZERO: u32 = 10;
    pub(crate) const PIECE: u32 = 11;
    pub(crate) const NAME: u32 = 12;
    pub(crate) const SCOPE: u32 = 13;
    pub(crate) const STARTBIT: u32 = 14;
    pub(crate) const SIZE: u32 = 15;
    pub(crate) const TABLE: u32 = 16;
    pub(crate) const CT: u32 = 17;
    pub(crate) const MINLEN: u32 = 18;
    pub(crate) const BASE: u32 = 19;
    pub(crate) const NUMBER: u32 = 20;
    pub(crate) const CONTEXT: u32 = 21;
    pub(crate) const PARENT: u32 = 22;
    pub(crate) const SUBSYM: u32 = 23;
    pub(crate) const LINE: u32 = 24;
    pub(crate) const SOURCE: u32 = 25;
    pub(crate) const LENGTH: u32 = 26;
    pub(crate) const FIRST: u32 = 27;
    pub(crate) const PLUS: u32 = 28;
    pub(crate) const SHIFT: u32 = 29;
    pub(crate) const ENDBIT: u32 = 30;
    pub(crate) const SIGNBIT: u32 = 31;
    pub(crate) const ENDBYTE: u32 = 32;
    pub(crate) const STARTBYTE: u32 = 33;
    pub(crate) const VERSION: u32 = 34;
    pub(crate) const BIGENDIAN: u32 = 35;
    pub(crate) const ALIGN: u32 = 36;
    pub(crate) const UNIQBASE: u32 = 37;
    pub(crate) const MAXDELAY: u32 = 38;
    pub(crate) const UNIQMASK: u32 = 39;
    pub(crate) const NUMSECTIONS: u32 = 40;
    pub(crate) const DEFAULTSPACE: u32 = 41;
    pub(crate) const DELAY: u32 = 42;
    pub(crate) const WORDSIZE: u32 = 43;
    pub(crate) const PHYSICAL: u32 = 44;
    pub(crate) const SCOPESIZE: u32 = 45;
    pub(crate) const SYMBOLSIZE: u32 = 46;
    pub(crate) const VARNODE: u32 = 47;
    pub(crate) const LOW: u32 = 48;
    pub(crate) const HIGH: u32 = 49;
    pub(crate) const FLOW: u32 = 50;
    pub(crate) const CONTAIN: u32 = 51;
    pub(crate) const I: u32 = 52;
    pub(crate) const NUMCT: u32 = 53;
    pub(crate) const SECTION: u32 = 54;
    pub(crate) const LABELS: u32 = 55;
}

/// Element ids as plain numbers, for `match` patterns.
#[expect(dead_code, reason = "the complete table; not every id is matched on")]
pub(crate) mod e {
    pub(crate) const CONST_REAL: u32 = 1;
    pub(crate) const VARNODE_TPL: u32 = 2;
    pub(crate) const CONST_SPACEID: u32 = 3;
    pub(crate) const CONST_HANDLE: u32 = 4;
    pub(crate) const OP_TPL: u32 = 5;
    pub(crate) const MASK_WORD: u32 = 6;
    pub(crate) const PAT_BLOCK: u32 = 7;
    pub(crate) const PRINT: u32 = 8;
    pub(crate) const PAIR: u32 = 9;
    pub(crate) const CONTEXT_PAT: u32 = 10;
    pub(crate) const NULL: u32 = 11;
    pub(crate) const OPERAND_EXP: u32 = 12;
    pub(crate) const OPERAND_SYM: u32 = 13;
    pub(crate) const OPERAND_SYM_HEAD: u32 = 14;
    pub(crate) const OPER: u32 = 15;
    pub(crate) const DECISION: u32 = 16;
    pub(crate) const OPPRINT: u32 = 17;
    pub(crate) const INSTRUCT_PAT: u32 = 18;
    pub(crate) const COMBINE_PAT: u32 = 19;
    pub(crate) const CONSTRUCTOR: u32 = 20;
    pub(crate) const CONSTRUCT_TPL: u32 = 21;
    pub(crate) const SCOPE: u32 = 22;
    pub(crate) const VARNODE_SYM: u32 = 23;
    pub(crate) const VARNODE_SYM_HEAD: u32 = 24;
    pub(crate) const USEROP: u32 = 25;
    pub(crate) const USEROP_HEAD: u32 = 26;
    pub(crate) const TOKENFIELD: u32 = 27;
    pub(crate) const VAR: u32 = 28;
    pub(crate) const CONTEXTFIELD: u32 = 29;
    pub(crate) const HANDLE_TPL: u32 = 30;
    pub(crate) const CONST_RELATIVE: u32 = 31;
    pub(crate) const CONTEXT_OP: u32 = 32;
    pub(crate) const SLEIGH: u32 = 33;
    pub(crate) const SPACES: u32 = 34;
    pub(crate) const SOURCEFILES: u32 = 35;
    pub(crate) const SOURCEFILE: u32 = 36;
    pub(crate) const SPACE: u32 = 37;
    pub(crate) const SYMBOL_TABLE: u32 = 38;
    pub(crate) const VALUE_SYM: u32 = 39;
    pub(crate) const VALUE_SYM_HEAD: u32 = 40;
    pub(crate) const CONTEXT_SYM: u32 = 41;
    pub(crate) const CONTEXT_SYM_HEAD: u32 = 42;
    pub(crate) const END_SYM: u32 = 43;
    pub(crate) const END_SYM_HEAD: u32 = 44;
    pub(crate) const SPACE_OTHER: u32 = 45;
    pub(crate) const SPACE_UNIQUE: u32 = 46;
    pub(crate) const AND_EXP: u32 = 47;
    pub(crate) const DIV_EXP: u32 = 48;
    pub(crate) const LSHIFT_EXP: u32 = 49;
    pub(crate) const MINUS_EXP: u32 = 50;
    pub(crate) const MULT_EXP: u32 = 51;
    pub(crate) const NOT_EXP: u32 = 52;
    pub(crate) const OR_EXP: u32 = 53;
    pub(crate) const PLUS_EXP: u32 = 54;
    pub(crate) const RSHIFT_EXP: u32 = 55;
    pub(crate) const SUB_EXP: u32 = 56;
    pub(crate) const XOR_EXP: u32 = 57;
    pub(crate) const INTB: u32 = 58;
    pub(crate) const END_EXP: u32 = 59;
    pub(crate) const NEXT2_EXP: u32 = 60;
    pub(crate) const START_EXP: u32 = 61;
    pub(crate) const EPSILON_SYM: u32 = 62;
    pub(crate) const EPSILON_SYM_HEAD: u32 = 63;
    pub(crate) const NAME_SYM: u32 = 64;
    pub(crate) const NAME_SYM_HEAD: u32 = 65;
    pub(crate) const NAMETAB: u32 = 66;
    pub(crate) const NEXT2_SYM: u32 = 67;
    pub(crate) const NEXT2_SYM_HEAD: u32 = 68;
    pub(crate) const START_SYM: u32 = 69;
    pub(crate) const START_SYM_HEAD: u32 = 70;
    pub(crate) const SUBTABLE_SYM: u32 = 71;
    pub(crate) const SUBTABLE_SYM_HEAD: u32 = 72;
    pub(crate) const VALUEMAP_SYM: u32 = 73;
    pub(crate) const VALUEMAP_SYM_HEAD: u32 = 74;
    pub(crate) const VALUETAB: u32 = 75;
    pub(crate) const VARLIST_SYM: u32 = 76;
    pub(crate) const VARLIST_SYM_HEAD: u32 = 77;
    pub(crate) const OR_PAT: u32 = 78;
    pub(crate) const COMMIT: u32 = 79;
    pub(crate) const CONST_START: u32 = 80;
    pub(crate) const CONST_NEXT: u32 = 81;
    pub(crate) const CONST_NEXT2: u32 = 82;
    pub(crate) const CONST_CURSPACE: u32 = 83;
    pub(crate) const CONST_CURSPACE_SIZE: u32 = 84;
    pub(crate) const CONST_FLOWREF: u32 = 85;
    pub(crate) const CONST_FLOWREF_SIZE: u32 = 86;
    pub(crate) const CONST_FLOWDEST: u32 = 87;
    pub(crate) const CONST_FLOWDEST_SIZE: u32 = 88;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_dense_and_in_order() {
        for (position, id) in ATTRIBUTES.iter().enumerate() {
            assert_eq!(id.id() as usize, position + 2, "{}", id.name());
            assert_eq!(attribute_name(id.id()), Some(id.name()));
        }
        for (position, id) in ELEMENTS.iter().enumerate() {
            assert_eq!(id.id() as usize, position + 1, "{}", id.name());
            assert_eq!(element_name(id.id()), Some(id.name()));
        }
        assert_eq!(ATTRIBUTES.len(), 54);
        assert_eq!(ELEMENTS.len(), 88);
        assert_eq!(element_name(0), None);
        assert_eq!(element_name(89), None);
        assert_eq!(attribute_name(1), None);
    }

    #[test]
    fn table_maps_names_both_ways() {
        let table = id_table().unwrap();
        assert_eq!(
            table.element("const_flowdest_size"),
            ELEM_CONST_FLOWDEST_SIZE.code()
        );
        assert_eq!(table.attribute("labels"), ATTRIB_LABELS.code());
        assert_eq!(table.attribute("bogus"), UNKNOWN_ATTRIBUTE);
        assert_eq!(table.element("bogus"), UNKNOWN_ELEMENT);
        assert_eq!(table.element_count(), 88);
        assert_eq!(table.attribute_count(), 54);
    }
}
