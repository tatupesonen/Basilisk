//! `<segmentop>` and `<jumpassist>`: p-code snippets the decompiler
//! injects, kept as source text with their declared parameters.

use roxmltree::Node;

use super::model::VarnodeTag;
use crate::{
    error::{ParseError, ParseErrorKind},
    reader::{Reader, children_named, text_of},
    schema::{
        ADDR_PCODE, BODY, CASE_PCODE, CONSTRESOLVE, DEFAULT_PCODE, ElementDef, INPUT, JUMPASSIST,
        OUTPUT, PCODE, SEGMENTOP, SIZE_PCODE, TAG_REGISTER, VARNODE,
    },
    value::{decode_bool, decode_i32, decode_u64},
};

/// A named parameter of a p-code snippet (`<input>` or `<output>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectParameter {
    /// The name the snippet's body uses.
    pub name: String,
    /// The size in bytes; 0 when the file gives none.
    pub size: u32,
}

/// A p-code snippet (the schema's `pcode_type`): SLEIGH semantic
/// statements with declared inputs and outputs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PcodeInject {
    /// How many parameters the snippet shifts the call's parameters by.
    pub param_shift: i32,
    /// Whether the p-code is generated at run time instead of from `body`.
    pub dynamic: bool,
    /// Whether the snippet's copies are incidental.
    pub incidental_copy: bool,
    /// The declared inputs, in file order.
    pub inputs: Vec<InjectParameter>,
    /// The declared outputs, in file order.
    pub outputs: Vec<InjectParameter>,
    /// The SLEIGH source of the snippet, exactly as written.
    pub body: Option<String>,
}

/// `<segmentop>`: how a segment and an offset combine into an address in
/// a segmented space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentOp {
    /// The segmented address space's name.
    pub space: String,
    /// The SLEIGH user-op this implements; `segment` when absent.
    pub userop: Option<String>,
    /// The `farpointer` attribute: `None` when absent, otherwise its value
    /// decoded as a boolean. Ghidra's two readers disagree on a value of
    /// `no`: Java decodes the value (false), the decompiler only checks
    /// that the attribute is present (true).
    pub far_pointer: Option<bool>,
    /// The p-code computing the address.
    pub pcode: PcodeInject,
    /// Where the segment value comes from when it is not known from
    /// context.
    pub const_resolve: Option<VarnodeTag>,
}

impl SegmentOp {
    /// The user-op name: [`userop`](Self::userop) or `segment`.
    #[must_use]
    pub fn userop_name(&self) -> &str {
        self.userop.as_deref().unwrap_or("segment")
    }

    /// The name Ghidra registers the p-code payload under:
    /// `<userop>_pcode`.
    #[must_use]
    pub fn payload_name(&self) -> String {
        format!("{}_pcode", self.userop_name())
    }
}

/// Which of the four snippets of a `<jumpassist>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JumpAssistPcode {
    /// `<case_pcode>`: the case value for a table index.
    Case,
    /// `<addr_pcode>`: the destination address for a table index.
    Addr,
    /// `<default_pcode>`: the default destination.
    Default,
    /// `<size_pcode>`: the number of table entries.
    Size,
}

impl JumpAssistPcode {
    /// The suffix of the payload's name.
    #[must_use]
    pub const fn payload_suffix(self) -> &'static str {
        match self {
            Self::Case => "_index2case",
            Self::Addr => "_index2addr",
            Self::Default => "_defaultaddr",
            Self::Size => "_calcsize",
        }
    }
}

/// `<jumpassist>`: p-code that lets the decompiler recover a jump table
/// from a user-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpAssist {
    /// The user-op's name.
    pub name: String,
    /// `<case_pcode>`.
    pub case_pcode: Option<PcodeInject>,
    /// `<addr_pcode>`; the decompiler requires it.
    pub addr_pcode: Option<PcodeInject>,
    /// `<default_pcode>`; the decompiler requires it.
    pub default_pcode: Option<PcodeInject>,
    /// `<size_pcode>`.
    pub size_pcode: Option<PcodeInject>,
}

impl JumpAssist {
    /// The snippet of the given kind.
    #[must_use]
    pub fn pcode(&self, which: JumpAssistPcode) -> Option<&PcodeInject> {
        match which {
            JumpAssistPcode::Case => self.case_pcode.as_ref(),
            JumpAssistPcode::Addr => self.addr_pcode.as_ref(),
            JumpAssistPcode::Default => self.default_pcode.as_ref(),
            JumpAssistPcode::Size => self.size_pcode.as_ref(),
        }
    }

    /// The name Ghidra registers a snippet's payload under, such as
    /// `switchAssist_index2addr`.
    #[must_use]
    pub fn payload_name(&self, which: JumpAssistPcode) -> String {
        format!("{}{}", self.name, which.payload_suffix())
    }
}

const INT: &str = "an integer (decimal, 0x hexadecimal or 0 octal)";

fn parameter(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    def: &'static ElementDef,
) -> Result<InjectParameter, ParseError> {
    r.check(node, def)?;
    let size = r.decode(node, def, "size", "a non-negative size in bytes", |s| {
        decode_i32(s).and_then(|v| u32::try_from(v).ok())
    })?;
    Ok(InjectParameter {
        name: r.required(node, def, "name")?.to_owned(),
        size: size.unwrap_or(0),
    })
}

/// Reads an element of the schema's `pcode_type`.
fn pcode(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    def: &'static ElementDef,
) -> Result<PcodeInject, ParseError> {
    r.check(node, def)?;
    let flag = |name: &str| node.attribute(name).and_then(decode_bool).unwrap_or(false);
    let mut inject = PcodeInject {
        param_shift: r
            .decode(node, def, "paramshift", INT, decode_i32)?
            .unwrap_or(0),
        dynamic: flag("dynamic"),
        incidental_copy: flag("incidentalcopy"),
        ..PcodeInject::default()
    };
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "input" => inject.inputs.push(parameter(r, child, &INPUT)?),
            "output" => inject.outputs.push(parameter(r, child, &OUTPUT)?),
            "body" => {
                r.check(child, &BODY)?;
                inject.body = Some(text_of(child));
            }
            _ => {}
        }
    }
    Ok(inject)
}

/// Reads the `<register>` or `<varnode>` children of `node`.
pub(crate) fn varnode_tags(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    tags: &mut Vec<VarnodeTag>,
) -> Result<(), ParseError> {
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "register" => {
                r.check(child, &TAG_REGISTER)?;
                tags.push(VarnodeTag::Register(
                    r.required(child, &TAG_REGISTER, "name")?.to_owned(),
                ));
            }
            "varnode" => {
                let def = &VARNODE;
                r.check(child, def)?;
                let number = |r: &Reader<'_, '_>, name: &'static str| {
                    let text = r.required(child, def, name)?;
                    decode_u64(text).ok_or_else(|| r.invalid(child, def, name, text, INT))
                };
                tags.push(VarnodeTag::Varnode {
                    space: r.required(child, def, "space")?.to_owned(),
                    offset: number(r, "offset")?,
                    size: number(r, "size")?,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Reads a `<segmentop>` element.
pub(crate) fn segment_op(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
) -> Result<SegmentOp, ParseError> {
    let def = &SEGMENTOP;
    r.check(node, def)?;
    let Some(pcode_node) = children_named(node, PCODE.name).next() else {
        return Err(r.fatal(
            node,
            ParseErrorKind::Rejected {
                element: def.name,
                message: "missing <pcode> child".to_owned(),
            },
        ));
    };
    let mut const_resolve = Vec::new();
    for resolve in children_named(node, CONSTRESOLVE.name) {
        r.check(resolve, &CONSTRESOLVE)?;
        varnode_tags(r, resolve, &mut const_resolve)?;
        if const_resolve.len() != 1 {
            r.rule(
                resolve,
                &CONSTRESOLVE,
                "exactly one <register> or <varnode> is required",
            )?;
        }
    }
    Ok(SegmentOp {
        space: r.required(node, def, "space")?.to_owned(),
        userop: node.attribute("userop").map(str::to_owned),
        far_pointer: node
            .attribute("farpointer")
            .map(|value| decode_bool(value).unwrap_or(false)),
        pcode: pcode(r, pcode_node, &PCODE)?,
        const_resolve: const_resolve.into_iter().next(),
    })
}

/// Reads a `<jumpassist>` element.
pub(crate) fn jump_assist(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
) -> Result<JumpAssist, ParseError> {
    let def = &JUMPASSIST;
    r.check(node, def)?;
    let mut assist = JumpAssist {
        name: r.required(node, def, "name")?.to_owned(),
        case_pcode: None,
        addr_pcode: None,
        default_pcode: None,
        size_pcode: None,
    };
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "case_pcode" => assist.case_pcode = Some(pcode(r, child, &CASE_PCODE)?),
            "addr_pcode" => assist.addr_pcode = Some(pcode(r, child, &ADDR_PCODE)?),
            "default_pcode" => assist.default_pcode = Some(pcode(r, child, &DEFAULT_PCODE)?),
            "size_pcode" => assist.size_pcode = Some(pcode(r, child, &SIZE_PCODE)?),
            _ => {}
        }
    }
    Ok(assist)
}
