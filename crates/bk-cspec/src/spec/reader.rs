//! The `<compiler_spec>` element loop (Ghidra `parseCompilerConfig`,
//! `decodeProto`, `decodeProtoEval`, `decodeDefaultProto`,
//! `createModelAlias`, `setDefaultModel`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use bk_core::SpaceManager;
use bk_marshal::ids::ATTRIB_NAME;
use bk_marshal::{DecodeError, Decoder, Document, ElemCode, XmlDecoder};

use super::{CompilerSpec, KeptElement, elements as el};
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_PARENT, ELEM_AGGRESSIVETRIM, ELEM_CALLFIXUP, ELEM_CALLOTHERFIXUP, ELEM_COMPILER_SPEC,
    ELEM_CONTEXT_DATA, ELEM_DATA_ORGANIZATION, ELEM_DEADCODEDELAY, ELEM_DEFAULT_PROTO, ELEM_ENUM,
    ELEM_EVAL_CALLED_PROTOTYPE, ELEM_EVAL_CURRENT_PROTOTYPE, ELEM_FUNCPTR, ELEM_GLOBAL,
    ELEM_INFERPTRBOUNDS, ELEM_MODELALIAS, ELEM_NOHIGHPTR, ELEM_PREFERSPLIT, ELEM_PROTOTYPE,
    ELEM_READONLY, ELEM_RESOLVEPROTOTYPE, ELEM_SEGMENTOP, ELEM_SPACEBASE, ELEM_SPECEXTENSIONS,
    ELEM_STACKPOINTER, id_table,
};
use crate::inject::InjectLibrary;
use crate::model::{DecodeContext, ModelId, ProtoModel, decode_merged, decode_model};

/// What a read needs besides the document and the space manager.
#[derive(Clone, Debug, Default)]
pub struct ReadOptions {
    /// A `<specextensions>` document read after the specification (Ghidra
    /// reads one from the program's options).
    pub extensions: Option<String>,
    /// Payloads declared before the `.cspec`, by the `.pspec`; ids continue
    /// after them, as in Ghidra.
    pub injects: InjectLibrary,
    /// The language/compiler id, used in fix-up source descriptions
    /// (Ghidra `archid`).
    pub arch_id: String,
}

/// The `.cspec` file of a language/compiler pair, by language id (as in
/// `x86:LE:64:default`) and compiler id, through `bk-lang`'s registry; `None`
/// when the pair is unknown.
pub fn find_cspec_path(
    registry: &bk_lang::LanguageRegistry,
    language: &str,
    compiler: &str,
) -> Option<PathBuf> {
    registry
        .find(language)?
        .compiler_specs()
        .iter()
        .find(|c| c.id.as_str() == compiler)
        .map(|c| c.file.clone())
}

struct State {
    models: Vec<ProtoModel>,
    names: BTreeMap<String, ModelId>,
    default_model: Option<ModelId>,
    spec: CompilerSpec,
}

impl State {
    fn ctx<'a>(&'a mut self, manager: &'a SpaceManager) -> DecodeContext<'a> {
        DecodeContext {
            manager,
            stack: self.spec.stack_pointer.as_ref().map(|s| s.space),
            default_return: self.spec.default_return,
            injects: &mut self.spec.injects,
        }
    }

    /// Ghidra `decodeProto`.
    fn decode_proto(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        manager: &SpaceManager,
    ) -> Result<ModelId> {
        let peek = dec.peek_element();
        let model = if peek.is_some_and(|p| p == ELEM_PROTOTYPE) {
            let mut ctx = self.ctx(manager);
            decode_model(dec, &mut ctx)?
        } else if peek.is_some_and(|p| p == ELEM_RESOLVEPROTOTYPE) {
            let models = &self.models;
            let names = &self.names;
            let lookup = |n: &str| {
                names
                    .get(n)
                    .and_then(|&id| models.get(id.0 as usize).map(|m| (id, m.clone())))
            };
            let ctx = DecodeContext {
                manager,
                stack: self.spec.stack_pointer.as_ref().map(|s| s.space),
                default_return: self.spec.default_return,
                injects: &mut InjectLibrary::default(),
            };
            decode_merged(dec, &ctx, &lookup)?
        } else {
            return Err(CspecError::new(
                "Expecting <prototype> or <resolveprototype> tag",
            ));
        };
        if self.names.contains_key(&model.name) {
            return Err(CspecError::new(format!(
                "Duplicate ProtoModel name: {}",
                model.name
            )));
        }
        Ok(self.add(model))
    }

    fn add(&mut self, model: ProtoModel) -> ModelId {
        let id = ModelId(self.models.len() as u32);
        self.names.insert(model.name.clone(), id);
        self.models.push(model);
        id
    }

    /// Ghidra `setDefaultModel`.
    fn set_default(&mut self, id: ModelId) {
        if let Some(old) = self
            .default_model
            .and_then(|o| self.models.get_mut(o.0 as usize))
        {
            old.is_printed = true;
        }
        if let Some(m) = self.models.get_mut(id.0 as usize) {
            m.is_printed = false;
        }
        self.default_model = Some(id);
    }

    /// Ghidra `createModelAlias`.
    fn create_alias(&mut self, alias: &str, parent: &str) -> Result<()> {
        let Some(&pid) = self.names.get(parent) else {
            return Err(CspecError::new(format!(
                "Requesting non-existent prototype model: {parent}"
            )));
        };
        let Some(model) = self.models.get(pid.0 as usize) else {
            return Err(CspecError::new("Corrupt model table"));
        };
        if model.is_merged() {
            return Err(CspecError::new(format!(
                "Cannot make alias of merged model: {parent}"
            )));
        }
        if model.alias_of.is_some() {
            return Err(CspecError::new(format!(
                "Cannot make alias of an alias: {parent}"
            )));
        }
        if self.names.contains_key(alias) {
            return Err(CspecError::new(format!(
                "Duplicate ProtoModel name: {alias}"
            )));
        }
        let copy = model.alias(alias, pid);
        self.add(copy);
        Ok(())
    }

    /// Ghidra `decodeProtoEval`.
    fn decode_eval(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        let elem = dec
            .open_element()?
            .ok_or_else(|| CspecError::new("Missing element"))?;
        let name = dec.read_string_attr(ATTRIB_NAME)?;
        let Some(&id) = self.names.get(name) else {
            return Err(CspecError::new(format!(
                "Unknown prototype model name: {name}"
            )));
        };
        if elem == ELEM_EVAL_CALLED_PROTOTYPE {
            if self.spec.eval_called.is_some() {
                return Err(CspecError::new("Duplicate <eval_called_prototype> tag"));
            }
            self.spec.eval_called = Some(id);
        } else {
            if self.spec.eval_current.is_some() {
                return Err(CspecError::new("Duplicate <eval_current_prototype> tag"));
            }
            self.spec.eval_current = Some(id);
        }
        dec.close_element(elem)?;
        Ok(())
    }
}

fn element_name(dec: &XmlDecoder<'_>) -> String {
    dec.current_element()
        .map_or_else(String::new, |e| e.name().to_owned())
}

impl CompilerSpec {
    /// Reads a `.cspec` document against `manager`, which must hold the
    /// language's spaces and registers. Spaces the file creates
    /// (`<stackpointer>`, `<spacebase>`) and the memory properties it sets
    /// are added to `manager` in document order, as Ghidra does (Ghidra
    /// `parseCompilerConfig`).
    pub fn read(text: &str, manager: &mut SpaceManager, options: ReadOptions) -> Result<Self> {
        let doc = Document::parse(text).map_err(DecodeError::from)?;
        let dir = manager.directory();
        let mut dec = XmlDecoder::new(&doc, id_table(), &*dir);
        let mut st = State {
            models: Vec::new(),
            names: BTreeMap::new(),
            default_model: None,
            spec: Self::empty(text, options.injects),
        };
        let root = dec.open_element_expecting(ELEM_COMPILER_SPEC)?;
        let mut position = 0usize;
        while let Some(sub) = dec.peek_element() {
            let name = doc_child_name(&dec, position);
            read_element(
                &mut st,
                &mut dec,
                manager,
                (sub, position),
                &options.arch_id,
            )
            .map_err(|e| e.at(&format!("compiler_spec/{name}")))?;
            position += 1;
        }
        dec.close_element(root)?;
        if let Some(ext) = &options.extensions {
            read_extensions(&mut st, ext, manager, &options.arch_id)
                .map_err(|e| e.at("specextensions"))?;
        }
        if st.default_model.is_none() {
            let Some(&first) = st.names.values().next() else {
                return Err(CspecError::new("No default prototype specified"));
            };
            st.set_default(first);
        }
        if !st.names.contains_key("__thiscall") {
            let parent = st
                .default_model
                .and_then(|d| st.models.get(d.0 as usize))
                .map(|m| m.name.clone())
                .unwrap_or_default();
            st.create_alias("__thiscall", &parent)?;
        }
        // Ghidra `PreferSplitManager::initialize` sorts the records: by
        // space, larger sizes first, then offset.
        st.spec.prefer_split.sort_by(|a, b| {
            a.storage
                .space()
                .cmp(&b.storage.space())
                .then(b.storage.size.cmp(&a.storage.size))
                .then(a.storage.offset.cmp(&b.storage.offset))
        });
        let mut spec = st.spec;
        spec.models = st.models;
        spec.names = st.names;
        spec.default_model = st.default_model.unwrap_or(ModelId(0));
        Ok(spec)
    }

    fn empty(text: &str, injects: InjectLibrary) -> Self {
        Self {
            source: Arc::from(text),
            models: Vec::new(),
            names: BTreeMap::new(),
            default_model: ModelId(0),
            eval_current: None,
            eval_called: None,
            stack_pointer: None,
            spacebases: Vec::new(),
            default_return: None,
            globals: Vec::new(),
            readonly: Vec::new(),
            no_high_ptr: Vec::new(),
            prefer_split: Vec::new(),
            aggressive_trim: false,
            funcptr_align: 0,
            deadcode_delays: Vec::new(),
            infer_ptr_bounds: Vec::new(),
            injects,
            call_other_fixups: Vec::new(),
            segment_ops: Vec::new(),
            kept: Vec::new(),
        }
    }
}

/// The name of the `index`-th child of the root, for error paths.
fn doc_child_name(dec: &XmlDecoder<'_>, index: usize) -> String {
    dec.current_element()
        .and_then(|root| root.children().nth(index))
        .map_or_else(String::new, |e| e.name().to_owned())
}

fn read_element(
    st: &mut State,
    dec: &mut XmlDecoder<'_>,
    manager: &mut SpaceManager,
    (sub, position): (ElemCode, usize),
    arch_id: &str,
) -> Result<()> {
    if sub == ELEM_DEFAULT_PROTO {
        let elem = dec.open_element_expecting(ELEM_DEFAULT_PROTO)?;
        while dec.peek_element().is_some() {
            if st.default_model.is_some() {
                return Err(CspecError::new("More than one default prototype model"));
            }
            let id = st.decode_proto(dec, manager)?;
            st.set_default(id);
        }
        dec.close_element(elem)?;
    } else if sub == ELEM_PROTOTYPE || sub == ELEM_RESOLVEPROTOTYPE {
        st.decode_proto(dec, manager)?;
    } else if sub == ELEM_STACKPOINTER {
        st.spec.stack_pointer = Some(el::decode_stack_pointer(dec, manager)?);
    } else if sub == bk_marshal::ids::ELEM_RETURNADDRESS {
        st.spec.default_return = el::decode_return_address(dec, manager, st.spec.default_return)?;
    } else if sub == ELEM_SPACEBASE {
        let def = el::decode_spacebase(dec, manager)?;
        st.spec.spacebases.push(def);
    } else if sub == ELEM_NOHIGHPTR {
        for r in el::decode_range_list(dec, manager)? {
            manager.add_no_high_ptr(&r)?;
            st.spec.no_high_ptr.push(r);
        }
    } else if sub == ELEM_PREFERSPLIT {
        let list = el::decode_prefer_split(dec, manager)?;
        st.spec.prefer_split.extend(list);
    } else if sub == ELEM_AGGRESSIVETRIM {
        st.spec.aggressive_trim = el::decode_aggressive_trim(dec, st.spec.aggressive_trim)?;
    } else if sub == ELEM_DATA_ORGANIZATION || sub == ELEM_ENUM || sub == ELEM_CONTEXT_DATA {
        let elem = dec
            .open_element()?
            .ok_or_else(|| CspecError::new("Missing element"))?;
        let (name, offset) = dec.current_element().map_or((String::new(), 0), |e| {
            (e.name().to_owned(), e.source_offset())
        });
        dec.close_element_skipping(elem)?;
        st.spec.kept.push(KeptElement {
            name,
            position,
            source_offset: offset,
        });
    } else if sub == ELEM_GLOBAL {
        el::decode_global(dec, &mut st.spec.globals)?;
    } else if sub == ELEM_SEGMENTOP {
        let op = st.spec.injects.decode_segment_op(dec, manager)?;
        st.spec.segment_ops.push(op);
    } else if sub == ELEM_READONLY {
        let list = el::decode_range_list(dec, manager)?;
        st.spec.readonly.extend(list);
    } else if sub == ELEM_EVAL_CALLED_PROTOTYPE || sub == ELEM_EVAL_CURRENT_PROTOTYPE {
        st.decode_eval(dec)?;
    } else if sub == ELEM_CALLFIXUP {
        st.spec
            .injects
            .decode_call_fixup(dec, &format!("{arch_id} : compiler spec"))?;
    } else if sub == ELEM_CALLOTHERFIXUP {
        let id = st.spec.injects.decode_call_other_fixup(dec, "userop")?;
        st.spec.call_other_fixups.push(id);
    } else if sub == ELEM_FUNCPTR {
        st.spec.funcptr_align = el::decode_funcptr_align(dec)?;
    } else if sub == ELEM_DEADCODEDELAY {
        let (space, delay) = el::decode_deadcode_delay(dec)?;
        manager.set_deadcode_delay(space, delay)?;
        st.spec.deadcode_delays.push((space, delay));
    } else if sub == ELEM_INFERPTRBOUNDS {
        for r in el::decode_range_list(dec, manager)? {
            manager.set_infer_ptr_bounds(&r)?;
            st.spec.infer_ptr_bounds.push(r);
        }
    } else if sub == ELEM_MODELALIAS {
        let elem = dec
            .open_element()?
            .ok_or_else(|| CspecError::new("Missing element"))?;
        let alias = dec.read_string_attr(ATTRIB_NAME)?.to_owned();
        let parent = dec.read_string_attr(ATTRIB_PARENT)?.to_owned();
        dec.close_element(elem)?;
        st.create_alias(&alias, &parent)?;
    } else {
        // Ghidra's loop has no final `else`: it would never end.
        dec.open_element()?;
        let name = element_name(dec);
        return Err(CspecError::new(format!(
            "Unknown element in <compiler_spec>: {name}"
        )));
    }
    Ok(())
}

/// The `<specextensions>` document, read with its own decoder (Ghidra
/// passes the closed `.cspec` decoder for fix-ups and globals).
fn read_extensions(
    st: &mut State,
    text: &str,
    manager: &SpaceManager,
    arch_id: &str,
) -> Result<()> {
    let doc = Document::parse(text).map_err(DecodeError::from)?;
    let dir = manager.directory();
    let mut dec = XmlDecoder::new(&doc, id_table(), &*dir);
    let root = dec.open_element_expecting(ELEM_SPECEXTENSIONS)?;
    while let Some(sub) = dec.peek_element() {
        if sub == ELEM_PROTOTYPE {
            st.decode_proto(&mut dec, manager)?;
        } else if sub == ELEM_CALLFIXUP {
            st.spec
                .injects
                .decode_call_fixup(&mut dec, &format!("{arch_id} : compiler spec"))?;
        } else if sub == ELEM_CALLOTHERFIXUP {
            let id = st
                .spec
                .injects
                .decode_call_other_fixup(&mut dec, "userop")?;
            st.spec.call_other_fixups.push(id);
        } else if sub == ELEM_GLOBAL {
            el::decode_global(&mut dec, &mut st.spec.globals)?;
        } else {
            dec.open_element()?;
            let name = element_name(&dec);
            return Err(CspecError::new(format!(
                "Unknown element in <specextensions>: {name}"
            )));
        }
    }
    dec.close_element(root)?;
    Ok(())
}
