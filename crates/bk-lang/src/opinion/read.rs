//! Reading `.opinion` files.

use std::path::Path;

use roxmltree::Node;

use super::model::{Constraint, ConstraintId, Opinions};
use crate::{
    endian::Endian,
    error::{Mode, ParseError, ReadError},
    id::CompilerSpecId,
    reader::{Parsed, Reader, is, parse_with, read_file_with},
    schema::{CONSTRAINT, OPINIONS},
};

/// Parses the text of a `.opinion` file.
///
/// Ghidra does not validate opinion files against their schema; strict
/// mode does, and lenient mode skips what the schema does not allow. An
/// unknown byte order or a size that is not a decimal integer is an error
/// in both modes, as it is in Ghidra.
pub fn parse(text: &str, mode: Mode) -> Result<Parsed<Opinions>, ParseError> {
    parse_with(text, mode, |r| {
        let root = r.root(&OPINIONS)?;
        let mut constraints: Vec<Constraint> = Vec::new();
        // Constraints nest to any depth, so walk with an explicit stack
        // rather than recursion: document order, parent before children.
        let mut stack: Vec<(Node<'_, '_>, Option<ConstraintId>)> = Vec::new();
        push_children(&mut stack, root, None);
        while let Some((node, parent)) = stack.pop() {
            r.check(node, &CONSTRAINT)?;
            let id = ConstraintId(u32::try_from(constraints.len()).unwrap_or(u32::MAX));
            constraints.push(constraint(r, node, parent)?);
            push_children(&mut stack, node, Some(id));
        }
        Ok(Opinions { constraints })
    })
}

/// Reads a `.opinion` file.
pub fn read_file(path: &Path, mode: Mode) -> Result<Parsed<Opinions>, ReadError> {
    read_file_with(path, |text| parse(text, mode))
}

/// Pushes `node`'s `<constraint>` children so that they pop in document
/// order.
fn push_children<'a, 'i>(
    stack: &mut Vec<(Node<'a, 'i>, Option<ConstraintId>)>,
    node: Node<'a, 'i>,
    id: Option<ConstraintId>,
) {
    let mut child = node.last_child();
    while let Some(c) = child {
        if is(c, CONSTRAINT.name) {
            stack.push((c, id));
        }
        child = c.prev_sibling();
    }
}

fn constraint(
    r: &Reader<'_, '_>,
    node: Node<'_, '_>,
    parent: Option<ConstraintId>,
) -> Result<Constraint, ParseError> {
    let def = &CONSTRAINT;
    let text = |name: &str| node.attribute(name).map(str::to_owned);
    Ok(Constraint {
        parent,
        loader: text("loader"),
        primary: text("primary"),
        secondary: text("secondary"),
        processor: text("processor"),
        endian: r.decode(node, def, "endian", "big, little, BE or LE", Endian::parse)?,
        size: r.decode(node, def, "size", "a decimal integer", |s| s.parse().ok())?,
        variant: text("variant"),
        compiler_spec_id: node.attribute("compilerSpecID").map(CompilerSpecId::new),
    })
}
