//! Typedefs, renaming and function types (Ghidra `getTypedef`, `setName`,
//! `resolveIncompleteTypedefs`, `setPrototype`, `getTypeCode(PrototypePieces)`).

use crate::entry::{CodeSignature, TypeEntry, TypeFlags, TypeKind, hash_name, sigflags};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::factory::composite::Layout;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// The pieces of a function prototype as the C parser produces them
/// (Ghidra `PrototypePieces`, with the model given by name).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PrototypePieces {
    /// Model name, or `None` for the architecture's default model.
    pub model: Option<String>,
    /// Function name.
    pub name: String,
    /// Return type.
    pub output: Option<TypeId>,
    /// Parameter types.
    pub inputs: Vec<TypeId>,
    /// Parameter names.
    pub names: Vec<String>,
    /// First variadic slot, or -1.
    pub first_vararg: i32,
}

impl TypeFactory {
    /// Ghidra `getTypedef`: a copy of `ct` under a new name and id (hashed
    /// from the name when 0).
    pub fn typedef(&mut self, ct: TypeId, name: &str, id: u64, format: u32) -> Result<TypeId> {
        self.entry_checked(ct)?;
        let id = if id == 0 { hash_name(name) } else { id };
        if let Some(res) = self.find_by_id_local(name, id) {
            if self.entry(res).typedef_imm != Some(ct) {
                return Err(TypeError::new(format!(
                    "Trying to create typedef of existing type: {name}"
                )));
            }
            return Ok(res);
        }
        let mut res: TypeEntry = self.entry(ct).clone();
        res.set_name(name, id);
        res.flags.remove(TypeFlags::CORETYPE);
        res.typedef_imm = Some(ct);
        res.set_display_format(format);
        let incomplete = res.is_incomplete();
        let new = self.insert(res)?;
        if incomplete {
            self.incomplete_typedefs.push(new);
        }
        Ok(new)
    }

    /// Ghidra `setName`: renames a type in place.
    pub fn set_name(&mut self, ct: TypeId, name: &str) -> Result<TypeId> {
        self.entry_checked(ct)?;
        self.modify(ct, |e| {
            e.name = name.into();
            e.display_name = name.into();
            if e.id == 0 {
                e.id = hash_name(name);
            }
        })?;
        Ok(ct)
    }

    /// Ghidra `resolveIncompleteTypedefs`: completes typedefs of types that
    /// have since been completed.
    pub(crate) fn resolve_incomplete_typedefs(&mut self) -> Result<()> {
        let mut i = 0;
        while let Some(&dt) = self.incomplete_typedefs.get(i) {
            let Some(defed) = self.entry(dt).typedef_imm else {
                i += 1;
                continue;
            };
            let d = self.entry(defed).clone();
            if d.is_incomplete() {
                i += 1;
                continue;
            }
            let layout = Layout {
                size: d.size,
                align: d.alignment,
                flags: d.flags,
            };
            match (self.entry(dt).metatype, d.kind) {
                (Metatype::Struct, TypeKind::Struct { fields, bitfields }) => {
                    self.set_struct_fields(dt, fields, bitfields, layout)?;
                }
                (Metatype::Union, TypeKind::Union { fields }) => {
                    self.set_union_fields(dt, fields, layout)?;
                }
                (Metatype::Code, TypeKind::Code(sig)) => {
                    self.set_prototype(dt, sig.map(|s| *s), d.flags)?;
                }
                _ => {
                    i += 1;
                    continue;
                }
            }
            self.incomplete_typedefs.remove(i);
        }
        Ok(())
    }

    /// Ghidra `setPrototype`: completes an incomplete function type.
    pub fn set_prototype(
        &mut self,
        id: TypeId,
        sig: Option<CodeSignature>,
        flags: TypeFlags,
    ) -> Result<()> {
        let e = self.entry_checked(id)?;
        if !e.is_incomplete() || !matches!(e.kind, TypeKind::Code(_)) {
            return Err(TypeError::new(
                "Can only set prototype on incomplete data-type",
            ));
        }
        self.modify(id, |e| {
            e.kind = TypeKind::Code(sig.map(Box::new));
            e.flags.remove(TypeFlags::TYPE_INCOMPLETE);
            e.flags |= flags & (TypeFlags::VARIABLE_LENGTH | TypeFlags::TYPE_INCOMPLETE);
        })
    }

    /// The signature a function type built from `pieces` holds.
    pub fn signature_of(&mut self, pieces: &PrototypePieces) -> Result<CodeSignature> {
        let output = match pieces.output {
            Some(o) => o,
            None => self.type_void()?,
        };
        let model = pieces
            .model
            .clone()
            .or_else(|| self.env.default_model.clone())
            .map(String::into_boxed_str);
        Ok(CodeSignature {
            model,
            flags: if pieces.first_vararg >= 0 {
                sigflags::DOTDOTDOT
            } else {
                0
            },
            output: Some(output),
            params: pieces
                .inputs
                .iter()
                .enumerate()
                .map(|(i, &t)| {
                    (
                        t,
                        pieces
                            .names
                            .get(i)
                            .map_or_else(|| "".into(), |n| n.as_str().into()),
                    )
                })
                .collect(),
            first_vararg: pieces.first_vararg,
        })
    }

    /// Ghidra `getTypeCode(const PrototypePieces&)`: an anonymous function
    /// type with a signature.
    pub fn type_code_signature(&mut self, pieces: &PrototypePieces) -> Result<TypeId> {
        let sig = self.signature_of(pieces)?;
        self.type_code_from_signature(sig)
    }

    /// Interns an anonymous function type holding `sig`.
    pub fn type_code_from_signature(&mut self, sig: CodeSignature) -> Result<TypeId> {
        let mut tc = TypeEntry::new(1, 1, Metatype::Code, TypeKind::Code(Some(Box::new(sig))));
        tc.flags |= TypeFlags::VARIABLE_LENGTH;
        self.find_add(tc)
    }
}
