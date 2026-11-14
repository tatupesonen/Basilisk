//! The semantic actions of the C declaration parser (Ghidra
//! `CParse::newStruct`, `newUnion`, `newEnum`, `oldStruct`, `oldUnion`,
//! `oldEnum`).

use crate::cdecl::ast::Declarator;
use crate::cdecl::parser::{PResult, Parser};
use crate::entry::{BitField, Field};
use crate::error::TypeError;
use crate::factory::enumeration::{Enumerator, assign_values};
use crate::ids::TypeId;

impl Parser<'_, '_> {
    // ---- actions ------------------------------------------------------

    pub(super) fn old_composite(&mut self, name: &str, is_struct: bool) -> Option<TypeId> {
        let res = self.f.find_by_name(name);
        let want = if is_struct {
            crate::Metatype::Struct
        } else {
            crate::Metatype::Union
        };
        if res.is_none_or(|t| self.f.entry(t).metatype() != want) {
            self.set_error(if is_struct {
                "Identifier does not represent a struct as required"
            } else {
                "Identifier does not represent a union as required"
            });
        }
        res
    }

    pub(super) fn old_enum(&mut self, name: &str) -> Option<TypeId> {
        let res = self.f.find_by_name(name);
        if res.is_none_or(|t| !self.f.entry(t).is_enum()) {
            self.set_error("Identifier does not represent an enum as required");
        }
        res
    }

    /// Ghidra `CParse::newStruct`.
    pub(super) fn new_struct(
        &mut self,
        name: &str,
        decls: &[Declarator],
    ) -> PResult<Option<TypeId>> {
        let res = self.f.structure_stub(name)?;
        let big = self.f.env.data_space.big_endian;
        let mut fields = Vec::new();
        let mut bits = Vec::new();
        for d in decls {
            if !d.is_valid(self.f)? {
                self.set_error("Invalid structure declarator");
                self.f.destroy_type(res)?;
                return Ok(None);
            }
            let ty = d.build(self.f, self.has_model)?;
            if d.num_bits != 0 {
                bits.push(BitField::declared(
                    fields.len() as i32,
                    d.num_bits,
                    big,
                    &d.ident,
                    ty,
                ));
            } else {
                fields.push(Field {
                    ident: 0,
                    offset: -1,
                    name: d.ident.as_str().into(),
                    ty,
                });
            }
        }
        if let Err(e) = self.f.assign_raw_struct_fields(res, fields, bits) {
            if let TypeError::Lowlevel(msg) = &e {
                self.set_error(msg);
                self.f.destroy_type(res)?;
                return Ok(None);
            }
            return Err(e.into());
        }
        Ok(Some(res))
    }

    /// Ghidra `CParse::newUnion`.
    pub(super) fn new_union(
        &mut self,
        name: &str,
        decls: &[Declarator],
    ) -> PResult<Option<TypeId>> {
        let res = self.f.union_stub(name)?;
        let mut fields = Vec::new();
        for (i, d) in decls.iter().enumerate() {
            if !d.is_valid(self.f)? {
                self.set_error("Invalid union declarator");
                self.f.destroy_type(res)?;
                return Ok(None);
            }
            let ty = d.build(self.f, self.has_model)?;
            fields.push(Field {
                ident: i as i32,
                offset: 0,
                name: d.ident.as_str().into(),
                ty,
            });
        }
        if let Err(e) = self.f.assign_raw_union_fields(res, fields) {
            if let TypeError::Lowlevel(msg) = &e {
                self.set_error(msg);
                self.f.destroy_type(res)?;
                return Ok(None);
            }
            return Err(e.into());
        }
        Ok(Some(res))
    }

    /// Ghidra `CParse::newEnum`.
    pub(super) fn new_enum(&mut self, name: &str, list: &[Enumerator]) -> PResult<Option<TypeId>> {
        let res = self.f.enum_stub(name)?;
        let (size, tname) = {
            let e = self.f.entry(res);
            (e.size(), e.name().to_owned())
        };
        let outcome =
            assign_values(list, size, &tname).and_then(|map| self.f.set_enum_values(res, map));
        if let Err(e) = outcome {
            if let TypeError::Lowlevel(msg) = &e {
                self.set_error(msg);
                self.f.destroy_type(res)?;
                return Ok(None);
            }
            return Err(e.into());
        }
        Ok(Some(res))
    }
}
