//! The grammar of the three file types, as data.
//!
//! These tables restate Ghidra's RELAX NG schemas
//! (`Ghidra/Framework/SoftwareModeling/data/languages/language_definitions.rxg`,
//! `processor_spec.rxg`, `format_opinions.rxg` and the shared
//! `language_common.rxg`): every element, its attributes with their
//! requiredness and value type, and its children with their cardinality and
//! order. The readers check each element they visit against its entry here,
//! so the tables are what "strict mode" means. A test walks the `.rxg`
//! files and asserts that they and these tables describe the same grammar.

/// The values an attribute may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrType {
    /// Any text.
    Text,
    /// The schema's `boolean_type`: `true`, `false`, `yes`, `no`, `1`, `0`.
    Boolean,
    /// The schema's `endian_type`: `big` or `little`.
    Endian,
    /// The schema's `symbol_type`: `code` or `code_ptr`.
    SymbolType,
}

impl AttrType {
    /// The name of the schema definition this type restates, if any.
    #[must_use]
    pub const fn schema_name(self) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::Boolean => Some("boolean_type"),
            Self::Endian => Some("endian_type"),
            Self::SymbolType => Some("symbol_type"),
        }
    }

    /// Describes the allowed values when `value` is not one of them.
    pub(crate) fn rejects(self, value: &str) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::Boolean => (!crate::value::is_schema_boolean(value))
                .then_some("one of true, false, yes, no, 1, 0"),
            Self::Endian => (!matches!(value, "big" | "little")).then_some("big or little"),
            Self::SymbolType => {
                (!matches!(value, "code" | "code_ptr")).then_some("code or code_ptr")
            }
        }
    }
}

/// One attribute of an element.
#[derive(Debug, Clone, Copy)]
pub struct AttrDef {
    /// The attribute's name.
    pub name: &'static str,
    /// Whether the schema requires it.
    pub required: bool,
    /// The values it may take.
    pub ty: AttrType,
}

/// How many times a child element may occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Card {
    /// Exactly once.
    One,
    /// At most once.
    Optional,
    /// Any number of times.
    ZeroOrMore,
    /// At least once.
    OneOrMore,
}

impl Card {
    /// Whether a second occurrence is a violation.
    #[must_use]
    pub const fn at_most_one(self) -> bool {
        matches!(self, Self::One | Self::Optional)
    }

    /// Whether absence is a violation.
    #[must_use]
    pub const fn at_least_one(self) -> bool {
        matches!(self, Self::One | Self::OneOrMore)
    }
}

/// One child element of an element.
#[derive(Debug, Clone, Copy)]
pub struct ChildDef {
    /// The child's own definition.
    pub def: &'static ElementDef,
    /// How many times it may occur.
    pub card: Card,
    /// Its place in the parent's content: children must appear in
    /// non-decreasing `group` order, and children sharing a group may be
    /// interleaved freely.
    pub group: u8,
}

/// The definition of one element in one context.
#[derive(Debug)]
pub struct ElementDef {
    /// The element's name.
    pub name: &'static str,
    /// Its attributes.
    pub attrs: &'static [AttrDef],
    /// Its child elements.
    pub children: &'static [ChildDef],
    /// Whether it holds text rather than elements.
    pub text: bool,
}

impl ElementDef {
    /// The definition of the attribute called `name`.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&'static AttrDef> {
        self.attrs.iter().find(|a| a.name == name)
    }

    /// The index in [`children`](Self::children) of the child called `name`.
    #[must_use]
    pub fn child_index(&self, name: &str) -> Option<usize> {
        self.children.iter().position(|c| c.def.name == name)
    }
}

/// The largest number of distinct children any element has.
pub(crate) const MAX_CHILDREN: usize = 16;

const fn req(name: &'static str) -> AttrDef {
    AttrDef {
        name,
        required: true,
        ty: AttrType::Text,
    }
}

const fn opt(name: &'static str) -> AttrDef {
    AttrDef {
        name,
        required: false,
        ty: AttrType::Text,
    }
}

const fn typed(name: &'static str, required: bool, ty: AttrType) -> AttrDef {
    AttrDef { name, required, ty }
}

const fn child(def: &'static ElementDef, card: Card, group: u8) -> ChildDef {
    ChildDef { def, card, group }
}

const fn leaf(name: &'static str, attrs: &'static [AttrDef]) -> ElementDef {
    ElementDef {
        name,
        attrs,
        children: &[],
        text: false,
    }
}

const fn text(name: &'static str) -> ElementDef {
    ElementDef {
        name,
        attrs: &[],
        children: &[],
        text: true,
    }
}

const fn parent(name: &'static str, children: &'static [ChildDef]) -> ElementDef {
    ElementDef {
        name,
        attrs: &[],
        children,
        text: false,
    }
}

// ---------------------------------------------------------------- .ldefs

/// `<language_definitions>`, the root of a `.ldefs` file.
pub static LANGUAGE_DEFINITIONS: ElementDef = parent(
    "language_definitions",
    &[child(&LANGUAGE, Card::ZeroOrMore, 0)],
);

pub(crate) static LANGUAGE: ElementDef = ElementDef {
    name: "language",
    attrs: &[
        typed("hidden", false, AttrType::Boolean),
        typed("deprecated", false, AttrType::Boolean),
        req("processor"),
        typed("endian", true, AttrType::Endian),
        typed("instructionEndian", false, AttrType::Endian),
        req("size"),
        req("variant"),
        req("version"),
        req("slafile"),
        req("processorspec"),
        opt("manualindexfile"),
        req("id"),
    ],
    children: &[
        child(&DESCRIPTION, Card::One, 0),
        child(&TRUNCATE_SPACE, Card::Optional, 1),
        child(&COMPILER, Card::OneOrMore, 2),
        child(&EXTERNAL_NAME, Card::ZeroOrMore, 3),
    ],
    text: false,
};

pub(crate) static DESCRIPTION: ElementDef = text("description");
pub(crate) static TRUNCATE_SPACE: ElementDef = leaf("truncate_space", &[req("space"), req("size")]);
pub(crate) static COMPILER: ElementDef = leaf("compiler", &[req("name"), req("spec"), req("id")]);
pub(crate) static EXTERNAL_NAME: ElementDef = leaf("external_name", &[req("tool"), req("name")]);

// -------------------------------------------------------------- .opinion

/// `<opinions>`, the root of a `.opinion` file.
pub static OPINIONS: ElementDef = parent("opinions", &[child(&CONSTRAINT, Card::ZeroOrMore, 0)]);

pub(crate) static CONSTRAINT: ElementDef = ElementDef {
    name: "constraint",
    attrs: &[
        opt("loader"),
        opt("primary"),
        opt("secondary"),
        opt("processor"),
        opt("endian"),
        opt("size"),
        opt("variant"),
        opt("compilerSpecID"),
    ],
    children: &[child(&CONSTRAINT, Card::ZeroOrMore, 0)],
    text: false,
};

// ---------------------------------------------------------------- .pspec

/// `<processor_spec>`, the root of a `.pspec` file.
pub static PROCESSOR_SPEC: ElementDef = parent(
    "processor_spec",
    &[
        child(&PROPERTIES, Card::Optional, 0),
        child(&PROGRAMCOUNTER, Card::Optional, 0),
        child(&DATA_SPACE, Card::Optional, 0),
        child(&INFERPTRBOUNDS, Card::ZeroOrMore, 0),
        child(&SEGMENTED_ADDRESS, Card::Optional, 0),
        child(&SEGMENTOP, Card::ZeroOrMore, 0),
        child(&CONTEXT_DATA, Card::Optional, 0),
        child(&VOLATILE, Card::Optional, 0),
        child(&INCIDENTALCOPY, Card::Optional, 0),
        child(&JUMPASSIST, Card::ZeroOrMore, 0),
        child(&REGISTER_DATA, Card::Optional, 0),
        child(&DEFAULT_SYMBOLS, Card::Optional, 0),
        child(&DEFAULT_MEMORY_BLOCKS, Card::Optional, 0),
    ],
);

pub(crate) static PROPERTIES: ElementDef =
    parent("properties", &[child(&PROPERTY, Card::ZeroOrMore, 0)]);
pub(crate) static PROPERTY: ElementDef = leaf("property", &[req("key"), req("value")]);
pub(crate) static PROGRAMCOUNTER: ElementDef = leaf("programcounter", &[req("register")]);
pub(crate) static DATA_SPACE: ElementDef = leaf("data_space", &[req("space"), opt("ptr_wordsize")]);
pub(crate) static INFERPTRBOUNDS: ElementDef =
    parent("inferptrbounds", &[child(&RANGE, Card::OneOrMore, 0)]);
pub(crate) static RANGE: ElementDef = leaf("range", RANGE_ATTRS);
const RANGE_ATTRS: &[AttrDef] = &[req("space"), opt("first"), opt("last")];
pub(crate) static SEGMENTED_ADDRESS: ElementDef =
    leaf("segmented_address", &[req("space"), opt("type")]);

pub(crate) static SEGMENTOP: ElementDef = ElementDef {
    name: "segmentop",
    attrs: &[req("space"), opt("userop"), opt("farpointer")],
    children: &[
        child(&PCODE, Card::One, 0),
        child(&CONSTRESOLVE, Card::Optional, 1),
    ],
    text: false,
};
pub(crate) static CONSTRESOLVE: ElementDef = parent("constresolve", VARNODE_TAGS);
/// The schema's `varnode_tags_type`: a `<register>` or a `<varnode>`.
const VARNODE_TAGS: &[ChildDef] = &[
    child(&TAG_REGISTER, Card::Optional, 0),
    child(&VARNODE, Card::Optional, 0),
];
pub(crate) static TAG_REGISTER: ElementDef = leaf("register", &[req("name")]);
pub(crate) static VARNODE: ElementDef =
    leaf("varnode", &[req("space"), req("offset"), req("size")]);

/// The schema's `pcode_type`, shared by `<pcode>` and the four
/// `<jumpassist>` children.
const PCODE_ATTRS: &[AttrDef] = &[opt("paramshift"), opt("dynamic"), opt("incidentalcopy")];
const PCODE_CHILDREN: &[ChildDef] = &[
    child(&INPUT, Card::ZeroOrMore, 0),
    child(&OUTPUT, Card::ZeroOrMore, 0),
    child(&BODY, Card::Optional, 1),
];
const fn pcode(name: &'static str) -> ElementDef {
    ElementDef {
        name,
        attrs: PCODE_ATTRS,
        children: PCODE_CHILDREN,
        text: false,
    }
}
pub(crate) static PCODE: ElementDef = pcode("pcode");
pub(crate) static CASE_PCODE: ElementDef = pcode("case_pcode");
pub(crate) static ADDR_PCODE: ElementDef = pcode("addr_pcode");
pub(crate) static DEFAULT_PCODE: ElementDef = pcode("default_pcode");
pub(crate) static SIZE_PCODE: ElementDef = pcode("size_pcode");
pub(crate) static INPUT: ElementDef = leaf("input", INJECT_PARAMETER);
pub(crate) static OUTPUT: ElementDef = leaf("output", INJECT_PARAMETER);
const INJECT_PARAMETER: &[AttrDef] = &[req("name"), opt("size")];
pub(crate) static BODY: ElementDef = text("body");

pub(crate) static CONTEXT_DATA: ElementDef = parent(
    "context_data",
    &[
        child(&CONTEXT_SET, Card::ZeroOrMore, 0),
        child(&TRACKED_SET, Card::ZeroOrMore, 0),
    ],
);
const SET_CHILDREN: &[ChildDef] = &[child(&SET, Card::OneOrMore, 0)];
pub(crate) static CONTEXT_SET: ElementDef = ElementDef {
    name: "context_set",
    attrs: RANGE_ATTRS,
    children: SET_CHILDREN,
    text: false,
};
pub(crate) static TRACKED_SET: ElementDef = ElementDef {
    name: "tracked_set",
    attrs: RANGE_ATTRS,
    children: SET_CHILDREN,
    text: false,
};
pub(crate) static SET: ElementDef = leaf("set", &[req("name"), req("val"), opt("description")]);

pub(crate) static VOLATILE: ElementDef = ElementDef {
    name: "volatile",
    attrs: &[req("inputop"), req("outputop"), opt("format")],
    // The schema's `memory_tags_type`: `<register>` or `<range>`, repeated.
    children: &[
        child(&TAG_REGISTER, Card::ZeroOrMore, 0),
        child(&RANGE, Card::ZeroOrMore, 0),
    ],
    text: false,
};
pub(crate) static INCIDENTALCOPY: ElementDef = parent(
    "incidentalcopy",
    &[
        child(&TAG_REGISTER, Card::ZeroOrMore, 0),
        child(&VARNODE, Card::ZeroOrMore, 0),
    ],
);

pub(crate) static JUMPASSIST: ElementDef = ElementDef {
    name: "jumpassist",
    attrs: &[req("name")],
    children: &[
        child(&CASE_PCODE, Card::Optional, 0),
        child(&ADDR_PCODE, Card::Optional, 0),
        child(&DEFAULT_PCODE, Card::Optional, 0),
        child(&SIZE_PCODE, Card::Optional, 0),
    ],
    text: false,
};

pub(crate) static REGISTER_DATA: ElementDef =
    parent("register_data", &[child(&REGISTER, Card::OneOrMore, 0)]);
pub(crate) static REGISTER: ElementDef = leaf(
    "register",
    &[
        req("name"),
        opt("rename"),
        opt("alias"),
        opt("group"),
        typed("hidden", false, AttrType::Boolean),
        typed("volatile", false, AttrType::Boolean),
        opt("vector_lane_sizes"),
    ],
);

pub(crate) static DEFAULT_SYMBOLS: ElementDef =
    parent("default_symbols", &[child(&SYMBOL, Card::OneOrMore, 0)]);
pub(crate) static SYMBOL: ElementDef = leaf(
    "symbol",
    &[
        req("name"),
        req("address"),
        typed("volatile", false, AttrType::Boolean),
        opt("size"),
        typed("entry", false, AttrType::Boolean),
        typed("type", false, AttrType::SymbolType),
        opt("description"),
    ],
);

pub(crate) static DEFAULT_MEMORY_BLOCKS: ElementDef = parent(
    "default_memory_blocks",
    &[child(&MEMORY_BLOCK, Card::OneOrMore, 0)],
);
pub(crate) static MEMORY_BLOCK: ElementDef = leaf(
    "memory_block",
    &[
        req("name"),
        req("start_address"),
        req("length"),
        opt("bit_mapped_address"),
        opt("byte_mapped_address"),
        typed("initialized", false, AttrType::Boolean),
        opt("mode"),
        typed("overlay", false, AttrType::Boolean),
    ],
);

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(def: &'static ElementDef, seen: &mut Vec<*const ElementDef>) {
        if seen.contains(&std::ptr::from_ref(def)) {
            return;
        }
        seen.push(std::ptr::from_ref(def));
        assert!(
            def.children.len() <= MAX_CHILDREN,
            "<{}> has too many children",
            def.name
        );
        assert!(
            !def.text || def.children.is_empty(),
            "<{}> mixes text and elements",
            def.name
        );
        for (i, a) in def.attrs.iter().enumerate() {
            assert_eq!(
                def.attrs.iter().position(|b| b.name == a.name),
                Some(i),
                "{}",
                a.name
            );
        }
        for (i, c) in def.children.iter().enumerate() {
            assert_eq!(
                def.child_index(c.def.name),
                Some(i),
                "duplicate child {}",
                c.def.name
            );
            walk(c.def, seen);
        }
    }

    #[test]
    fn tables_are_well_formed() {
        for root in [&LANGUAGE_DEFINITIONS, &OPINIONS, &PROCESSOR_SPEC] {
            walk(root, &mut Vec::new());
        }
    }

    #[test]
    fn attribute_types_reject_other_values() {
        assert_eq!(AttrType::Text.rejects("anything"), None);
        assert_eq!(AttrType::Boolean.rejects("yes"), None);
        assert!(AttrType::Boolean.rejects("y").is_some());
        assert_eq!(AttrType::Endian.rejects("little"), None);
        assert!(AttrType::Endian.rejects("LE").is_some());
        assert_eq!(AttrType::SymbolType.rejects("code_ptr"), None);
        assert!(AttrType::SymbolType.rejects("data").is_some());
    }
}
