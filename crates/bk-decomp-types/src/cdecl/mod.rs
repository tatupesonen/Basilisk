//! The C declaration parser (Ghidra `grammar.y`: `parse_type`,
//! `parse_protopieces`, `parse_C`).
//!
//! Type names are whatever the factory knows; prototype-model names come
//! from a callback, because models belong to the compiler specification.

mod actions;
mod ast;
mod lexer;
mod parser;

pub use lexer::LINE_BUFFER;
pub use parser::MAX_NESTING;

use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::typedef::PrototypePieces;
use crate::ids::TypeId;
use crate::meta::Metatype;
use ast::flag;
use parser::Parser;

/// The largest input accepted, in bytes (ADR-009; Ghidra limits each line
/// to [`LINE_BUFFER`]).
pub const MAX_INPUT: usize = 1 << 20;

/// What a declaration parsed by [`parse_declaration`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Declaration {
    /// An `extern` function prototype, for the caller to register (Ghidra
    /// calls `Architecture::setPrototype`).
    Prototype(PrototypePieces),
    /// A `typedef`: the type now carrying the name.
    Typedef(TypeId),
    /// A structure, union or enumeration definition (already added).
    Defined(TypeId),
}

fn parse(
    f: &mut TypeFactory,
    text: &str,
    param: bool,
    has_model: &dyn Fn(&str) -> bool,
) -> Result<Vec<ast::Declarator>> {
    if text.len() > MAX_INPUT {
        return Err(TypeError::parse(format!(
            "Input longer than {MAX_INPUT} bytes"
        )));
    }
    let mut p = Parser::new(f, text, has_model);
    p.run(param)
}

fn single(decls: Vec<ast::Declarator>, f: &TypeFactory) -> Result<ast::Declarator> {
    let mut it = decls.into_iter();
    let Some(d) = it.next() else {
        return Err(TypeError::parse("Did not parse a datatype"));
    };
    if it.next().is_some() {
        return Err(TypeError::parse("Parsed multiple declarations"));
    }
    if !d.is_valid(f)? {
        return Err(TypeError::parse("Parsed type is invalid"));
    }
    Ok(d)
}

/// Ghidra `parse_type`: one parameter-style declaration; the type and the
/// declared identifier.
pub fn parse_type(
    f: &mut TypeFactory,
    text: &str,
    has_model: &dyn Fn(&str) -> bool,
) -> Result<(TypeId, String)> {
    let d = single(parse(f, text, true, has_model)?, f)?;
    let ty = d.build(f, has_model)?;
    Ok((ty, d.ident))
}

/// Ghidra `parse_protopieces`: one declaration that must be a function
/// declarator.
pub fn parse_prototype(
    f: &mut TypeFactory,
    text: &str,
    has_model: &dyn Fn(&str) -> bool,
) -> Result<PrototypePieces> {
    let d = single(parse(f, text, false, has_model)?, f)?;
    d.prototype(f, has_model)?
        .ok_or_else(|| TypeError::parse("Did not parse a prototype"))
}

/// Ghidra `parse_C`: one declaration, acted on.
pub fn parse_declaration(
    f: &mut TypeFactory,
    text: &str,
    has_model: &dyn Fn(&str) -> bool,
) -> Result<Declaration> {
    let d = single(parse(f, text, false, has_model)?, f)?;
    if d.flags & flag::EXTERN != 0 {
        let pieces = d
            .prototype(f, has_model)?
            .ok_or_else(|| TypeError::parse("Did not parse prototype as expected"))?;
        return Ok(Declaration::Prototype(pieces));
    }
    if d.flags & flag::TYPEDEF != 0 {
        let ct = d.build(f, has_model)?;
        if d.ident.is_empty() {
            return Err(TypeError::parse("Missing identifier for typedef"));
        }
        let res = if f.entry(ct).metatype() == Metatype::Struct {
            f.set_name(ct, &d.ident)?
        } else {
            f.typedef(ct, &d.ident, 0, 0)?
        };
        return Ok(Declaration::Typedef(res));
    }
    let base = d
        .base
        .ok_or_else(|| TypeError::parse("Parsed type is invalid"))?;
    let e = f.entry(base);
    if matches!(e.metatype(), Metatype::Struct | Metatype::Union) || e.is_enum() {
        return Ok(Declaration::Defined(base));
    }
    Err(TypeError::new("Not sure what to do with this type"))
}

/// Parses with no prototype models known.
pub fn no_models(_: &str) -> bool {
    false
}
