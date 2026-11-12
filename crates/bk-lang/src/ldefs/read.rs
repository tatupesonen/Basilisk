//! Reading `.ldefs` files.

use std::path::Path;

use roxmltree::Node;

use super::model::{
    CompilerDefinition, ExternalName, LanguageDefinition, LanguageDefinitions, LanguageVersion,
    TruncatedSpace,
};
use crate::{
    endian::Endian,
    error::{Mode, ParseError, ParseErrorKind, ReadError},
    id::{CompilerSpecId, LanguageId},
    reader::{Parsed, Reader, children_named, parse_with, read_file_with, text_of},
    schema::{
        COMPILER, DESCRIPTION, EXTERNAL_NAME, LANGUAGE, LANGUAGE_DEFINITIONS, TRUNCATE_SPACE,
    },
    value::decode_i32,
};

const SIZE: &str = "a non-negative integer (decimal, 0x hexadecimal or 0 octal)";

/// Parses the text of a `.ldefs` file.
pub fn parse(text: &str, mode: Mode) -> Result<Parsed<LanguageDefinitions>, ParseError> {
    parse_with(text, mode, |r| {
        let root = r.root(&LANGUAGE_DEFINITIONS)?;
        let languages = children_named(root, LANGUAGE.name)
            .map(|node| language(r, node))
            .collect::<Result<_, _>>()?;
        Ok(LanguageDefinitions { languages })
    })
}

/// Reads a `.ldefs` file.
pub fn read_file(path: &Path, mode: Mode) -> Result<Parsed<LanguageDefinitions>, ReadError> {
    read_file_with(path, |text| parse(text, mode))
}

fn size(
    r: &Reader<'_, '_>,
    node: Node<'_, '_>,
    def: &'static crate::schema::ElementDef,
) -> Result<u32, ParseError> {
    let text = r.required(node, def, "size")?;
    decode_i32(text)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| r.invalid(node, def, "size", text, SIZE))
}

fn endian(
    r: &Reader<'_, '_>,
    node: Node<'_, '_>,
    attribute: &'static str,
    text: &str,
) -> Result<Endian, ParseError> {
    Endian::parse_long_name(text)
        .ok_or_else(|| r.invalid(node, &LANGUAGE, attribute, text, "big or little"))
}

fn language(r: &mut Reader<'_, '_>, node: Node<'_, '_>) -> Result<LanguageDefinition, ParseError> {
    let def = &LANGUAGE;
    r.check(node, def)?;
    let id_text = r.required(node, def, "id")?;
    let id = LanguageId::new(id_text)
        .map_err(|_| r.invalid(node, def, "id", id_text, "a non-empty language id"))?;
    let data_endian = endian(r, node, "endian", r.required(node, def, "endian")?)?;
    let instruction_endian = match node.attribute("instructionEndian") {
        Some(text) => endian(r, node, "instructionEndian", text)?,
        None => data_endian,
    };
    let version_text = r.required(node, def, "version")?;
    let version = LanguageVersion::parse(version_text).ok_or_else(|| {
        r.invalid(
            node,
            def,
            "version",
            version_text,
            "<major>[.<minor>] version numbers",
        )
    })?;

    let description = match children_named(node, DESCRIPTION.name).next() {
        Some(d) => {
            r.check(d, &DESCRIPTION)?;
            text_of(d)
        }
        // Ghidra's reader cannot get past a language without a description.
        None => {
            return Err(r.fatal(
                node,
                ParseErrorKind::Rejected {
                    element: def.name,
                    message: "no <description> element".to_owned(),
                },
            ));
        }
    };

    let mut truncated_spaces: Vec<TruncatedSpace> = Vec::new();
    for t in children_named(node, TRUNCATE_SPACE.name) {
        r.check(t, &TRUNCATE_SPACE)?;
        let space = r.required(t, &TRUNCATE_SPACE, "space")?;
        if truncated_spaces.iter().any(|s| s.space == space) {
            return Err(r.fatal(
                t,
                ParseErrorKind::Rejected {
                    element: TRUNCATE_SPACE.name,
                    message: format!("truncated space '{space}' already specified"),
                },
            ));
        }
        truncated_spaces.push(TruncatedSpace {
            space: space.to_owned(),
            size: size(r, t, &TRUNCATE_SPACE)?,
        });
    }

    let mut compilers: Vec<CompilerDefinition> = Vec::new();
    for c in children_named(node, COMPILER.name) {
        r.check(c, &COMPILER)?;
        let compiler = CompilerDefinition {
            id: CompilerSpecId::new(r.required(c, &COMPILER, "id")?),
            name: r.required(c, &COMPILER, "name")?.to_owned(),
            spec: r.required(c, &COMPILER, "spec")?.to_owned(),
        };
        // Ghidra keeps compiler specs in a map in insertion order: a
        // repeated id replaces the earlier entry where it stands.
        match compilers
            .iter_mut()
            .find(|existing| existing.id == compiler.id)
        {
            Some(existing) => *existing = compiler,
            None => compilers.push(compiler),
        }
    }

    let mut external_names = Vec::new();
    for e in children_named(node, EXTERNAL_NAME.name) {
        r.check(e, &EXTERNAL_NAME)?;
        let tool = r.required(e, &EXTERNAL_NAME, "tool")?;
        let name = r.required(e, &EXTERNAL_NAME, "name")?;
        // Ghidra silently drops an entry with an empty tool or name.
        if !tool.is_empty() && !name.is_empty() {
            external_names.push(ExternalName {
                tool: tool.to_owned(),
                name: name.to_owned(),
            });
        }
    }

    Ok(LanguageDefinition {
        id,
        processor: r.required(node, def, "processor")?.to_owned(),
        endian: data_endian,
        instruction_endian,
        size: size(r, node, def)?,
        variant: r.required(node, def, "variant")?.to_owned(),
        version,
        sla_file: r.required(node, def, "slafile")?.to_owned(),
        processor_spec: r.required(node, def, "processorspec")?.to_owned(),
        manual_index_file: node.attribute("manualindexfile").map(str::to_owned),
        deprecated: Reader::flag(node, "deprecated"),
        hidden: Reader::flag(node, "hidden"),
        description,
        truncated_spaces,
        compilers,
        external_names,
    })
}
