//! Reading `.pspec` files.

use std::path::Path;

use roxmltree::Node;

use super::{
    address::AddressRange,
    context, memory,
    model::{DataSpace, MemoryTag, ProcessorSpec, Property, Section, SegmentedAddress, Volatile},
    registers, segment, symbols,
};
use crate::{
    error::{Mode, ParseError, ParseErrorKind, ReadError},
    reader::{Parsed, Reader, children_named, parse_with, read_file_with},
    schema::{
        DATA_SPACE, INCIDENTALCOPY, INFERPTRBOUNDS, PROCESSOR_SPEC, PROGRAMCOUNTER, PROPERTIES,
        PROPERTY, RANGE, SEGMENTED_ADDRESS, TAG_REGISTER, VOLATILE,
    },
    value::decode_i32,
};

/// Parses the text of a `.pspec` file.
pub fn parse(text: &str, mode: Mode) -> Result<Parsed<ProcessorSpec>, ParseError> {
    parse_with(text, mode, |r| {
        let root = r.root(&PROCESSOR_SPEC)?;
        let mut spec = ProcessorSpec::default();
        for node in root.children().filter(Node::is_element) {
            if node.tag_name().namespace().is_none() {
                section(r, node, &mut spec)?;
            }
        }
        Ok(spec)
    })
}

/// Reads a `.pspec` file.
pub fn read_file(path: &Path, mode: Mode) -> Result<Parsed<ProcessorSpec>, ReadError> {
    read_file_with(path, |text| parse(text, mode))
}

/// Reads one top-level element into `spec`. An element that occurs again
/// where the schema allows one (reported by the root's check) adds to or
/// replaces the earlier one, as it would in Ghidra's reader.
fn section(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    spec: &mut ProcessorSpec,
) -> Result<(), ParseError> {
    let kind = match node.tag_name().name() {
        "properties" => {
            r.check(node, &PROPERTIES)?;
            for p in children_named(node, PROPERTY.name) {
                r.check(p, &PROPERTY)?;
                let key = r.required(p, &PROPERTY, "key")?;
                let value = r.required(p, &PROPERTY, "value")?.to_owned();
                match spec
                    .properties
                    .iter_mut()
                    .find(|existing| existing.key == key)
                {
                    Some(existing) => existing.value = value,
                    None => spec.properties.push(Property {
                        key: key.to_owned(),
                        value,
                    }),
                }
            }
            Section::Properties
        }
        "programcounter" => {
            r.check(node, &PROGRAMCOUNTER)?;
            spec.program_counter = Some(r.required(node, &PROGRAMCOUNTER, "register")?.to_owned());
            Section::ProgramCounter
        }
        "data_space" => {
            let def = &DATA_SPACE;
            r.check(node, def)?;
            let ptr_wordsize = match node.attribute("ptr_wordsize") {
                None => None,
                Some(text) => match decode_i32(text) {
                    None => {
                        return Err(r.invalid(node, def, "ptr_wordsize", text, "an integer"));
                    }
                    Some(size @ 1..=31) => Some(size as u32),
                    Some(_) => {
                        return Err(r.fatal(
                            node,
                            ParseErrorKind::Rejected {
                                element: def.name,
                                message: "Bad ptr_wordsize attribute".to_owned(),
                            },
                        ));
                    }
                },
            };
            spec.data_space = Some(DataSpace {
                space: r.required(node, def, "space")?.to_owned(),
                ptr_wordsize,
            });
            Section::DataSpace
        }
        "inferptrbounds" => {
            r.check(node, &INFERPTRBOUNDS)?;
            for range in children_named(node, RANGE.name) {
                r.check(range, &RANGE)?;
                spec.infer_ptr_bounds
                    .push(AddressRange::read(r, range, &RANGE)?);
            }
            Section::InferPtrBounds
        }
        "segmented_address" => {
            let def = &SEGMENTED_ADDRESS;
            r.check(node, def)?;
            spec.segmented_address = Some(SegmentedAddress {
                space: r.required(node, def, "space")?.to_owned(),
                segment_type: node.attribute("type").map(str::to_owned),
            });
            Section::SegmentedAddress
        }
        "segmentop" => {
            spec.segment_ops.push(segment::segment_op(r, node)?);
            Section::SegmentOp
        }
        "context_data" => {
            context::read(r, node, &mut spec.context_data)?;
            Section::ContextData
        }
        "volatile" => {
            volatile(r, node, &mut spec.volatile)?;
            Section::Volatile
        }
        "incidentalcopy" => {
            r.check(node, &INCIDENTALCOPY)?;
            let before = spec.incidental_copy.len();
            segment::varnode_tags(r, node, &mut spec.incidental_copy)?;
            if spec.incidental_copy.len() == before {
                r.rule(
                    node,
                    &INCIDENTALCOPY,
                    "at least one <register> or <varnode> is required",
                )?;
            }
            Section::IncidentalCopy
        }
        "jumpassist" => {
            spec.jump_assists.push(segment::jump_assist(r, node)?);
            Section::JumpAssist
        }
        "register_data" => {
            registers::read(r, node, &mut spec.registers)?;
            Section::RegisterData
        }
        "default_symbols" => {
            symbols::read(r, node, &mut spec.default_symbols)?;
            Section::DefaultSymbols
        }
        "default_memory_blocks" => {
            memory::read(r, node, &mut spec.default_memory_blocks)?;
            Section::DefaultMemoryBlocks
        }
        // Not in the schema: already reported by the root's check.
        _ => return Ok(()),
    };
    spec.sections.push(kind);
    Ok(())
}

fn volatile(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    volatile: &mut Option<Volatile>,
) -> Result<(), ParseError> {
    let def = &VOLATILE;
    r.check(node, def)?;
    let mut locations = Vec::new();
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "register" => {
                r.check(child, &TAG_REGISTER)?;
                locations.push(MemoryTag::Register(
                    r.required(child, &TAG_REGISTER, "name")?.to_owned(),
                ));
            }
            "range" => {
                r.check(child, &RANGE)?;
                locations.push(MemoryTag::Range(AddressRange::read(r, child, &RANGE)?));
            }
            _ => {}
        }
    }
    if locations.is_empty() {
        r.rule(node, def, "at least one <register> or <range> is required")?;
    }
    let inputop = r.required(node, def, "inputop")?.to_owned();
    let outputop = r.required(node, def, "outputop")?.to_owned();
    let format = node.attribute("format").map(str::to_owned);
    match volatile {
        // A second <volatile> (a schema violation) adds its ranges, as in
        // Ghidra's Java reader.
        Some(existing) => {
            existing.locations.append(&mut locations);
            existing.inputop = inputop;
            existing.outputop = outputop;
            existing.format = format.or(existing.format.take());
        }
        None => {
            *volatile = Some(Volatile {
                inputop,
                outputop,
                format,
                locations,
            });
        }
    }
    Ok(())
}
