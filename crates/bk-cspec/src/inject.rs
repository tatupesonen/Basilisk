//! Declarations of injection payloads and user-op fix-ups, uncompiled
//! (Ghidra `InjectPayload`, `InjectParameter`, `PcodeInjectLibrary`'s name
//! tables and `decodeInject`, `InjectPayloadSleigh::decode`,
//! `InjectPayloadCallfixup::decode`, `InjectPayloadCallother::decode`,
//! `ExecutablePcodeSleigh::decode`, `SegmentOp::decode`,
//! `JumpAssistOp::decode`). Compiling and running the bodies is D18's.

use std::collections::BTreeMap;

use bk_core::{SpaceId, SpaceManager, VarnodeData};
use bk_marshal::Decoder;
use bk_marshal::ids::{
    ATTRIB_CONTENT, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE, ELEM_INPUT, ELEM_OUTPUT, ELEM_TARGET,
};

use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_DYNAMIC, ATTRIB_FARPOINTER, ATTRIB_INCIDENTALCOPY, ATTRIB_INJECT, ATTRIB_PARAMSHIFT,
    ATTRIB_TARGETOP, ATTRIB_USEROP, ELEM_ADDR_PCODE, ELEM_BODY, ELEM_CALLFIXUP,
    ELEM_CALLOTHERFIXUP, ELEM_CASE_PCODE, ELEM_CONSTRESOLVE, ELEM_DEFAULT_PCODE, ELEM_JUMPASSIST,
    ELEM_PCODE, ELEM_SEGMENTOP, ELEM_SIZE_PCODE,
};

/// The kind of a payload (Ghidra's `InjectPayload` types, with their
/// numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum InjectKind {
    /// Replaces a call (`CALLFIXUP_TYPE`).
    CallFixup = 1,
    /// Replaces a user-defined op (`CALLOTHERFIXUP_TYPE`).
    CallOtherFixup = 2,
    /// Patches data-flow at the call boundary (`CALLMECHANISM_TYPE`).
    CallMechanism = 3,
    /// A stand-alone p-code script (`EXECUTABLEPCODE_TYPE`).
    ExecutablePcode = 4,
}

/// A named input or output of a payload (Ghidra `InjectParameter`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectParameter {
    /// The name used in the body.
    pub name: String,
    /// Index across inputs then outputs.
    pub index: i32,
    /// Size in bytes (0 when not given).
    pub size: u32,
}

/// One payload declaration (Ghidra `InjectPayload` without its compiled
/// template).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectPayload {
    /// The kind.
    pub kind: InjectKind,
    /// The registered name.
    pub name: String,
    /// Description of where it was declared, for messages.
    pub source: String,
    /// Inputs.
    pub inputs: Vec<InjectParameter>,
    /// Outputs.
    pub outputs: Vec<InjectParameter>,
    /// Parameters shifted in the original call.
    pub paramshift: i32,
    /// Injected copies are incidental.
    pub incidental_copy: bool,
    /// The p-code is generated dynamically.
    pub dynamic: bool,
    /// The SLEIGH p-code text of the `<body>`, verbatim.
    pub body: String,
    /// Symbol names a call fix-up applies to (`<target>`).
    pub targets: Vec<String>,
}

impl InjectPayload {
    fn new(kind: InjectKind, name: &str, source: &str) -> Self {
        Self {
            kind,
            name: name.to_owned(),
            source: source.to_owned(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            paramshift: 0,
            incidental_copy: false,
            dynamic: false,
            body: String::new(),
            targets: Vec::new(),
        }
    }

    /// Ghidra `decodePayloadAttributes`.
    fn decode_attributes(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        self.paramshift = 0;
        self.dynamic = false;
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_PARAMSHIFT {
                self.paramshift = dec.read_signed()? as i32;
            } else if attr == ATTRIB_DYNAMIC {
                self.dynamic = dec.read_bool()?;
            } else if attr == ATTRIB_INCIDENTALCOPY {
                self.incidental_copy = dec.read_bool()?;
            } else if attr == ATTRIB_INJECT {
                if dec.read_string()? == "uponentry" {
                    self.name.push_str("@@inject_uponentry");
                } else {
                    self.name.push_str("@@inject_uponreturn");
                }
            }
        }
        Ok(())
    }

    /// Ghidra `decodePayloadParams` and `orderParameters`.
    fn decode_params(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        while let Some(peek) = dec.peek_element() {
            let is_input = peek == ELEM_INPUT;
            if !is_input && peek != ELEM_OUTPUT {
                break;
            }
            let elem = dec
                .open_element()?
                .ok_or_else(|| CspecError::new("Missing parameter"))?;
            let (mut name, mut size) = (String::new(), 0u32);
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_NAME {
                    dec.read_string()?.clone_into(&mut name);
                } else if attr == ATTRIB_SIZE {
                    size = dec.read_unsigned()? as u32;
                }
            }
            dec.close_element(elem)?;
            if name.is_empty() {
                return Err(CspecError::new("Missing inject parameter name"));
            }
            let p = InjectParameter {
                name,
                index: 0,
                size,
            };
            if is_input {
                self.inputs.push(p);
            } else {
                self.outputs.push(p);
            }
        }
        for (i, p) in self
            .inputs
            .iter_mut()
            .chain(self.outputs.iter_mut())
            .enumerate()
        {
            p.index = i as i32;
        }
        Ok(())
    }

    /// Ghidra `InjectPayloadSleigh::decodeBody`.
    fn decode_body(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        if let Some(peek) = dec.peek_element() {
            if peek != ELEM_BODY {
                // Ghidra opens the element and leaves it open, so closing
                // the enclosing element fails.
                return Err(CspecError::new("Unexpected element in <pcode>"));
            }
            let elem = dec.open_element_expecting(ELEM_BODY)?;
            dec.read_string_attr(ATTRIB_CONTENT)?
                .clone_into(&mut self.body);
            dec.close_element(elem)?;
        }
        if self.body.is_empty() && !self.dynamic {
            return Err(CspecError::new(format!(
                "Missing <body> subtag in <pcode>: {}",
                self.source
            )));
        }
        Ok(())
    }
}

/// A `<segmentop>` declaration (Ghidra `SegmentOp`'s decoded fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentOpDecl {
    /// The segmented space.
    pub space: SpaceId,
    /// The user op it is based on (resolved by D07).
    pub userop: String,
    /// The space supports far pointers.
    pub far_pointer: bool,
    /// Where a constant segment value is read from, if given.
    pub const_resolve: Option<VarnodeData>,
    /// The payload computing the address.
    pub inject_id: u32,
    /// Size of the base (segment) input, 0 if absent.
    pub base_in_size: u32,
    /// Size of the inner (offset) input.
    pub inner_in_size: u32,
}

/// A `<jumpassist>` declaration (Ghidra `JumpAssistOp`'s decoded fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpAssistDecl {
    /// The user op name.
    pub name: String,
    /// `<case_pcode>` payload.
    pub index2case: Option<u32>,
    /// `<addr_pcode>` payload.
    pub index2addr: u32,
    /// `<default_pcode>` payload.
    pub defaultaddr: u32,
    /// `<size_pcode>` payload.
    pub calcsize: Option<u32>,
}

/// The registered payloads and their name tables (Ghidra
/// `PcodeInjectLibrary`). Ids are indices in declaration order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InjectLibrary {
    payloads: Vec<InjectPayload>,
    call_fixups: BTreeMap<String, u32>,
    call_other_fixups: BTreeMap<String, u32>,
    call_mechanisms: BTreeMap<String, u32>,
    scripts: BTreeMap<String, u32>,
}

impl InjectLibrary {
    /// Every payload, by id.
    pub fn payloads(&self) -> &[InjectPayload] {
        &self.payloads
    }
    /// The payload with an id (Ghidra `getPayload`).
    pub fn payload(&self, id: u32) -> Option<&InjectPayload> {
        self.payloads.get(id as usize)
    }
    /// The id of a payload by kind and name (Ghidra `getPayloadId`).
    pub fn payload_id(&self, kind: InjectKind, name: &str) -> Option<u32> {
        let map = match kind {
            InjectKind::CallFixup => &self.call_fixups,
            InjectKind::CallOtherFixup => &self.call_other_fixups,
            InjectKind::CallMechanism => &self.call_mechanisms,
            InjectKind::ExecutablePcode => &self.scripts,
        };
        map.get(name).copied()
    }
    /// The name of a call fix-up by id, or "" (Ghidra `getCallFixupName`).
    pub fn call_fixup_name(&self, id: u32) -> &str {
        self.payload(id)
            .filter(|p| p.kind == InjectKind::CallFixup)
            .map_or("", |p| p.name.as_str())
    }

    /// Adds a payload under its kind's table (Ghidra `registerInject`).
    fn register(&mut self, payload: InjectPayload) -> Result<u32> {
        let id = self.payloads.len() as u32;
        let (map, what) = match payload.kind {
            InjectKind::CallFixup => (&mut self.call_fixups, "callfixup"),
            InjectKind::CallOtherFixup => (&mut self.call_other_fixups, "callotherfixup"),
            InjectKind::CallMechanism => (&mut self.call_mechanisms, "callmechanism"),
            InjectKind::ExecutablePcode => (&mut self.scripts, "script"),
        };
        if map.contains_key(&payload.name) {
            return Err(CspecError::new(format!(
                "Duplicate <{what}>: {}",
                payload.name
            )));
        }
        map.insert(payload.name.clone(), id);
        self.payloads.push(payload);
        Ok(id)
    }

    /// Reads a call-mechanism `<pcode>` of a model named `name` (Ghidra
    /// `decodeInject` with `CALLMECHANISM_TYPE`).
    pub(crate) fn decode_mechanism(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        name: &str,
    ) -> Result<u32> {
        let mut p = InjectPayload::new(
            InjectKind::CallMechanism,
            name,
            &format!("Protomodel : {name}"),
        );
        let elem = dec.open_element_expecting(ELEM_PCODE)?;
        p.decode_attributes(dec)?;
        p.decode_params(dec)?;
        p.decode_body(dec)?;
        dec.close_element(elem)?;
        self.register(p)
    }

    /// Reads a `<callfixup>` (Ghidra `InjectPayloadCallfixup::decode`).
    pub fn decode_call_fixup(&mut self, dec: &mut dyn Decoder<'_>, source: &str) -> Result<u32> {
        let mut p = InjectPayload::new(InjectKind::CallFixup, "unknown", source);
        let elem = dec.open_element_expecting(ELEM_CALLFIXUP)?;
        dec.read_string_attr(ATTRIB_NAME)?.clone_into(&mut p.name);
        let mut saw_pcode = false;
        while let Some(sub) = dec.open_element()? {
            if sub == ELEM_PCODE {
                p.decode_attributes(dec)?;
                p.decode_params(dec)?;
                p.decode_body(dec)?;
                saw_pcode = true;
            } else if sub == ELEM_TARGET {
                p.targets
                    .push(dec.read_string_attr(ATTRIB_NAME)?.to_owned());
            }
            dec.close_element(sub)?;
        }
        dec.close_element(elem)?;
        if !saw_pcode {
            return Err(CspecError::new(format!(
                "<callfixup> is missing <pcode> subtag: {}",
                p.name
            )));
        }
        self.register(p)
    }

    /// Reads a `<callotherfixup>` (Ghidra `InjectPayloadCallother::decode`).
    /// The user op it names is resolved by the caller (D07).
    pub fn decode_call_other_fixup(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        source: &str,
    ) -> Result<u32> {
        let mut p = InjectPayload::new(InjectKind::CallOtherFixup, "unknown", source);
        let elem = dec.open_element_expecting(ELEM_CALLOTHERFIXUP)?;
        dec.read_string_attr(ATTRIB_TARGETOP)?
            .clone_into(&mut p.name);
        let sub = dec.open_element()?;
        if sub.is_none_or(|s| s != ELEM_PCODE) {
            return Err(CspecError::new(
                "<callotherfixup> does not contain a <pcode> tag",
            ));
        }
        p.decode_attributes(dec)?;
        p.decode_params(dec)?;
        p.decode_body(dec)?;
        if let Some(sub) = sub {
            dec.close_element(sub)?;
        }
        dec.close_element(elem)?;
        self.register(p)
    }

    /// Reads an executable script element (Ghidra
    /// `ExecutablePcodeSleigh::decode`).
    fn decode_script(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        source: &str,
        name: &str,
    ) -> Result<u32> {
        let mut p = InjectPayload::new(InjectKind::ExecutablePcode, name, source);
        let elem = dec.open_element()?;
        let ok = [
            ELEM_PCODE,
            ELEM_CASE_PCODE,
            ELEM_ADDR_PCODE,
            ELEM_DEFAULT_PCODE,
            ELEM_SIZE_PCODE,
        ];
        let Some(elem) = elem.filter(|e| ok.iter().any(|k| e == k)) else {
            return Err(CspecError::new(
                "Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>",
            ));
        };
        p.decode_attributes(dec)?;
        p.decode_params(dec)?;
        let body = dec.open_element_expecting(ELEM_BODY)?;
        dec.read_string_attr(ATTRIB_CONTENT)?
            .clone_into(&mut p.body);
        dec.close_element(body)?;
        dec.close_element(elem)?;
        self.register(p)
    }

    /// Reads a `<segmentop>` (Ghidra `SegmentOp::decode`, without the user
    /// op checks, which need the language).
    pub fn decode_segment_op(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        manager: &SpaceManager,
    ) -> Result<SegmentOpDecl> {
        let elem = dec.open_element_expecting(ELEM_SEGMENTOP)?;
        let mut space = None;
        let mut far_pointer = false;
        let mut userop = "segment".to_owned();
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_SPACE {
                space = Some(dec.read_space()?);
            } else if attr == ATTRIB_FARPOINTER {
                far_pointer = true;
            } else if attr == ATTRIB_USEROP {
                dec.read_string()?.clone_into(&mut userop);
            }
        }
        let space =
            space.ok_or_else(|| CspecError::new("<segmentop> expecting space attribute"))?;
        let mut const_resolve = None;
        let mut inject = None;
        while let Some(sub) = dec.peek_element() {
            if sub == ELEM_CONSTRESOLVE {
                let e = dec.open_element_expecting(ELEM_CONSTRESOLVE)?;
                if dec.peek_element().is_some() {
                    const_resolve = Some(VarnodeData::decode(dec, manager)?);
                }
                dec.close_element(e)?;
            } else if sub == ELEM_PCODE {
                inject = Some(self.decode_script(dec, "cspec", &format!("{userop}_pcode"))?);
            } else {
                return Err(CspecError::new("Unknown element in <segmentop>"));
            }
        }
        dec.close_element(elem)?;
        let inject_id =
            inject.ok_or_else(|| CspecError::new("Missing <pcode> child in <segmentop> tag"))?;
        let payload = self
            .payload(inject_id)
            .cloned()
            .unwrap_or_else(|| InjectPayload::new(InjectKind::ExecutablePcode, "", ""));
        if payload.outputs.len() != 1 {
            return Err(CspecError::new(
                "<pcode> child of <segmentop> tag must declare one <output>",
            ));
        }
        let (base_in_size, inner_in_size) = match payload.inputs.as_slice() {
            [inner] => (0, inner.size),
            [base, inner] => (base.size, inner.size),
            _ => {
                return Err(CspecError::new(
                    "<pcode> child of <segmentop> tag must declare one or two <input> tags",
                ));
            }
        };
        Ok(SegmentOpDecl {
            space,
            userop,
            far_pointer,
            const_resolve,
            inject_id,
            base_in_size,
            inner_in_size,
        })
    }

    /// Reads a `<jumpassist>` of a `.pspec` (Ghidra `JumpAssistOp::decode`,
    /// without the user op checks).
    pub fn decode_jump_assist(&mut self, dec: &mut dyn Decoder<'_>) -> Result<JumpAssistDecl> {
        let elem = dec.open_element_expecting(ELEM_JUMPASSIST)?;
        let name = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
        let mut slots: [Option<u32>; 4] = [None; 4];
        let kinds = [
            (ELEM_CASE_PCODE, "case", "_index2case"),
            (ELEM_ADDR_PCODE, "addr", "_index2addr"),
            (ELEM_DEFAULT_PCODE, "default", "_defaultaddr"),
            (ELEM_SIZE_PCODE, "size", "_calcsize"),
        ];
        while let Some(sub) = dec.peek_element() {
            let Some(k) = kinds.iter().position(|(e, _, _)| sub == *e) else {
                // Ghidra's loop does not end on another element.
                return Err(CspecError::new("Unknown element in <jumpassist>"));
            };
            let (_, tag, suffix) = kinds.get(k).copied().unwrap_or(kinds[0]);
            if slots.get(k).copied().flatten().is_some() {
                return Err(CspecError::new(format!("Too many <{tag}_pcode> tags")));
            }
            let id = self.decode_script(dec, "jumpassistop", &format!("{name}{suffix}"))?;
            if let Some(s) = slots.get_mut(k) {
                *s = Some(id);
            }
        }
        dec.close_element(elem)?;
        let [index2case, index2addr, defaultaddr, calcsize] = slots;
        let index2addr = index2addr
            .ok_or_else(|| CspecError::new(format!("userop: {name} is missing <addr_pcode>")))?;
        let defaultaddr = defaultaddr
            .ok_or_else(|| CspecError::new(format!("userop: {name} is missing <default_pcode>")))?;
        Ok(JumpAssistDecl {
            name,
            index2case,
            index2addr,
            defaultaddr,
            calcsize,
        })
    }
}
