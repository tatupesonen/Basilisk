//! Declarators and specifiers (Ghidra `TypeDeclarator`, `TypeModifier` and
//! its subclasses, `TypeSpecifiers`), and building types from them.

use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::typedef::PrototypePieces;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// Specifier and qualifier flags (Ghidra `CParse::f_*`).
pub(crate) mod flag {
    pub(crate) const TYPEDEF: u32 = 1;
    pub(crate) const EXTERN: u32 = 2;
    pub(crate) const STATIC: u32 = 4;
    pub(crate) const AUTO: u32 = 8;
    pub(crate) const REGISTER: u32 = 16;
    pub(crate) const CONST: u32 = 32;
    pub(crate) const RESTRICT: u32 = 64;
    pub(crate) const VOLATILE: u32 = 128;
    pub(crate) const INLINE: u32 = 256;
    pub(crate) const STRUCT: u32 = 512;
    pub(crate) const UNION: u32 = 1024;
    pub(crate) const ENUM: u32 = 2048;
}

/// The keywords and their flags (Ghidra `CParse::keywords`).
pub(crate) fn keyword(name: &str) -> Option<u32> {
    Some(match name {
        "typedef" => flag::TYPEDEF,
        "extern" => flag::EXTERN,
        "static" => flag::STATIC,
        "auto" => flag::AUTO,
        "register" => flag::REGISTER,
        "const" => flag::CONST,
        "restrict" => flag::RESTRICT,
        "volatile" => flag::VOLATILE,
        "inline" => flag::INLINE,
        "struct" => flag::STRUCT,
        "union" => flag::UNION,
        "enum" => flag::ENUM,
        _ => return None,
    })
}

/// A type modifier (Ghidra `PointerModifier`, `ArrayModifier`,
/// `FunctionModifier`).
#[derive(Clone, Debug)]
pub(crate) enum Modifier {
    Pointer,
    Array(i32),
    Function {
        params: Vec<Declarator>,
        dotdotdot: bool,
    },
}

impl Modifier {
    /// Ghidra's `FunctionModifier` constructor: a single `void` parameter
    /// means none.
    pub(crate) fn function(mut params: Vec<Declarator>, dotdotdot: bool, f: &TypeFactory) -> Self {
        if let [only] = params.as_slice() {
            if only.mods.is_empty()
                && only
                    .base
                    .is_some_and(|b| f.entry(b).metatype() == Metatype::Void)
            {
                params.clear();
            }
        }
        Self::Function { params, dotdotdot }
    }
}

/// A declarator with its specifiers merged in (Ghidra `TypeDeclarator`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Declarator {
    pub(crate) mods: Vec<Modifier>,
    pub(crate) base: Option<TypeId>,
    pub(crate) ident: String,
    pub(crate) model: String,
    pub(crate) flags: u32,
    pub(crate) num_bits: i32,
}

/// Declaration specifiers (Ghidra `TypeSpecifiers`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Specifiers {
    pub(crate) ty: Option<TypeId>,
    pub(crate) function: String,
    pub(crate) flags: u32,
}

impl Declarator {
    /// Ghidra `mergeSpecDec`.
    pub(crate) fn merge(&mut self, spec: &Specifiers) {
        self.base = spec.ty;
        self.model.clone_from(&spec.function);
        self.flags |= spec.flags;
    }

    /// Ghidra `TypeDeclarator::isValid` (multiple storage classes or
    /// qualifiers are errors, as Ghidra throws them).
    pub(crate) fn is_valid(&self, f: &TypeFactory) -> Result<bool> {
        if self.base.is_none() {
            return Ok(false);
        }
        let storage = [
            flag::TYPEDEF,
            flag::EXTERN,
            flag::STATIC,
            flag::AUTO,
            flag::REGISTER,
        ];
        if storage.iter().filter(|&&b| self.flags & b != 0).count() > 1 {
            return Err(TypeError::parse("Multiple storage specifiers"));
        }
        let quals = [flag::CONST, flag::RESTRICT, flag::VOLATILE];
        if quals.iter().filter(|&&b| self.flags & b != 0).count() > 1 {
            return Err(TypeError::parse("Multiple type qualifiers"));
        }
        for m in &self.mods {
            match m {
                Modifier::Pointer => {}
                Modifier::Array(n) => {
                    if *n <= 0 {
                        return Ok(false);
                    }
                }
                Modifier::Function { params, .. } => {
                    for p in params {
                        if !p.is_valid(f)? {
                            return Ok(false);
                        }
                        if p.mods.is_empty()
                            && p.base
                                .is_some_and(|b| f.entry(b).metatype() == Metatype::Void)
                        {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    /// Ghidra `getModel`: the model name if the architecture has it, else
    /// the default (`None`).
    fn model_name(&self, has_model: &dyn Fn(&str) -> bool) -> Option<String> {
        (!self.model.is_empty() && has_model(&self.model)).then(|| self.model.clone())
    }

    fn apply(
        &self,
        m: &Modifier,
        base: Option<TypeId>,
        f: &mut TypeFactory,
        has_model: &dyn Fn(&str) -> bool,
    ) -> Result<TypeId> {
        match m {
            Modifier::Pointer => {
                let base = base.ok_or_else(|| TypeError::parse("Parsed type is invalid"))?;
                let (size, ws) = (f.env.data_space.addr_size, f.env.data_space.word_size);
                f.pointer(size, base, ws)
            }
            Modifier::Array(n) => {
                let base = base.ok_or_else(|| TypeError::parse("Parsed type is invalid"))?;
                f.array(*n, base)
            }
            Modifier::Function { params, .. } => {
                let output = match base {
                    Some(b) => b,
                    None => f.type_void()?,
                };
                let mut inputs = Vec::with_capacity(params.len());
                for p in params {
                    inputs.push(p.build(f, has_model)?);
                }
                // Ghidra's FunctionModifier::modType looks for the varargs
                // marker that newFunc has already removed, so a function
                // type never gets one.
                let pieces = PrototypePieces {
                    model: self.model_name(has_model),
                    name: String::new(),
                    output: Some(output),
                    inputs,
                    names: Vec::new(),
                    first_vararg: -1,
                };
                f.type_code_signature(&pieces)
            }
        }
    }

    /// Ghidra `buildType`: the modifiers applied innermost last.
    pub(crate) fn build(
        &self,
        f: &mut TypeFactory,
        has_model: &dyn Fn(&str) -> bool,
    ) -> Result<TypeId> {
        let mut res = self.base;
        for m in self.mods.iter().rev() {
            res = Some(self.apply(m, res, f, has_model)?);
        }
        res.ok_or_else(|| TypeError::parse("Parsed type is invalid"))
    }

    /// Ghidra `getPrototype`: the pieces when the outermost modifier is a
    /// function, else `None`.
    pub(crate) fn prototype(
        &self,
        f: &mut TypeFactory,
        has_model: &dyn Fn(&str) -> bool,
    ) -> Result<Option<PrototypePieces>> {
        let Some(Modifier::Function { params, dotdotdot }) = self.mods.first() else {
            return Ok(None);
        };
        let mut inputs = Vec::with_capacity(params.len());
        for p in params {
            inputs.push(p.build(f, has_model)?);
        }
        let names = params.iter().map(|p| p.ident.clone()).collect();
        let first_vararg = if *dotdotdot { inputs.len() as i32 } else { -1 };
        let mut output = self.base;
        for m in self.mods.iter().skip(1).rev() {
            output = Some(self.apply(m, output, f, has_model)?);
        }
        Ok(Some(PrototypePieces {
            model: self.model_name(has_model),
            name: self.ident.clone(),
            output,
            inputs,
            names,
            first_vararg,
        }))
    }
}
