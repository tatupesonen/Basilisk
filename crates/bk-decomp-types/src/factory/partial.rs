//! Partial types and pieces (Ghidra `getTypePartialStruct`,
//! `getTypePartialUnion`, `getTypePartialEnum`, `getExactPiece`,
//! `concretize`, `resizeInteger`).

use crate::entry::{TypeEntry, TypeFlags, TypeKind};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};

impl TypeFactory {
    /// Ghidra `getTypePartialStruct`: bytes `off..off+size` of a structure
    /// or array (a partial structure as container is flattened).
    pub fn partial_struct(&mut self, container: TypeId, offset: i32, size: i32) -> Result<TypeId> {
        self.entry_checked(container)?;
        let strip = self.base(size, Metatype::Unknown)?;
        let (mut contain, mut off) = (container, offset);
        if let TypeKind::PartialStruct {
            container: c,
            offset: o,
            ..
        } = self.entry(contain).kind
        {
            if self.entry(contain).metatype == Metatype::PartialStruct {
                contain = c;
                off = off.saturating_add(o);
            }
        }
        let c = self.entry(contain);
        let mut e = TypeEntry::new(
            size,
            1,
            Metatype::PartialStruct,
            TypeKind::PartialStruct {
                container: contain,
                offset: off,
                stripped: strip,
            },
        );
        e.flags |= c.inherit_for_partial() | TypeFlags::HAS_STRIPPED;
        if c.has_bitfields() && self.has_bitfields_in_range(contain, off, size) {
            e.flags |= TypeFlags::HAS_BITFIELDS;
        }
        self.find_add(e)
    }

    /// Ghidra `getTypePartialUnion`.
    pub fn partial_union(&mut self, container: TypeId, offset: i32, size: i32) -> Result<TypeId> {
        self.entry_checked(container)?;
        let strip = self.base(size, Metatype::Unknown)?;
        let mut e = TypeEntry::new(
            size,
            1,
            Metatype::PartialUnion,
            TypeKind::PartialUnion {
                container,
                offset,
                stripped: strip,
            },
        );
        e.flags |= self.entry(container).inherit_for_partial()
            | TypeFlags::NEEDS_RESOLUTION
            | TypeFlags::HAS_STRIPPED;
        self.find_add(e)
    }

    /// Ghidra `getTypePartialEnum`.
    pub fn partial_enum(&mut self, container: TypeId, offset: i32, size: i32) -> Result<TypeId> {
        self.entry_checked(container)?;
        let strip = self.base(size, Metatype::Unknown)?;
        let mut e = TypeEntry::new(
            size,
            -1,
            Metatype::Uint,
            TypeKind::PartialEnum {
                parent: container,
                offset,
                stripped: strip,
            },
        );
        e.submeta = SubMetatype::UintPartialEnum;
        e.flags |= TypeFlags::ENUMTYPE
            | self.entry(container).inherit_for_partial()
            | TypeFlags::HAS_STRIPPED;
        self.find_add(e)
    }

    /// Ghidra `getExactPiece`: the type of bytes `offset..offset+size` of
    /// `ct`, drilling down; a partial type where no component matches
    /// exactly; `None` where the range crosses components.
    pub fn exact_piece(&mut self, ct: TypeId, offset: i32, size: i32) -> Result<Option<TypeId>> {
        self.entry_checked(ct)?;
        let mut cur = Some(ct);
        let mut last: Option<(TypeId, i64)> = None;
        let mut cur_off = i64::from(offset);
        let mut guard = 0;
        while let Some(t) = cur {
            let tsize = i64::from(self.entry(t).size);
            if tsize < i64::from(size) + cur_off {
                break;
            }
            if tsize == i64::from(size) {
                return Ok(Some(t));
            }
            last = Some((t, cur_off));
            let (sub, newoff) = self.sub_type(t, cur_off);
            cur = sub;
            cur_off = newoff;
            guard += 1;
            if guard > crate::MAX_DEPTH {
                return Err(TypeError::TooDeep(crate::MAX_DEPTH));
            }
        }
        let Some((last, last_off)) = last else {
            return Ok(None);
        };
        let last_off = last_off as i32;
        let le = self.entry(last);
        let meta = le.metatype;
        Ok(match meta {
            Metatype::Struct | Metatype::Array | Metatype::PartialStruct => {
                Some(self.partial_struct(last, last_off, size)?)
            }
            Metatype::Union => Some(self.partial_union(last, last_off, size)?),
            Metatype::PartialUnion => match le.kind {
                TypeKind::PartialUnion {
                    container,
                    offset: po,
                    ..
                } => Some(self.partial_union(container, last_off.saturating_add(po), size)?),
                _ => None,
            },
            _ if le.is_enum() && !le.has_stripped() => {
                Some(self.partial_enum(last, last_off, size)?)
            }
            _ => None,
        })
    }

    /// Ghidra `concretize`: a representable type of the same size.
    pub fn concretize(&mut self, ct: TypeId) -> Result<TypeId> {
        let e = self.entry_checked(ct)?;
        if e.metatype == Metatype::Code {
            if e.size != 1 {
                return Err(TypeError::new(
                    "Primitive code data-type that is not size 1",
                ));
            }
            return self.base(1, Metatype::Unknown);
        }
        Ok(ct)
    }

    /// Ghidra `resizeInteger`: the integer of another size.
    pub fn resize_integer(&mut self, ct: TypeId, new_size: i32) -> Result<TypeId> {
        let e = self.entry_checked(ct)?;
        if new_size == e.size {
            return Ok(ct);
        }
        let meta = match e.metatype {
            m @ (Metatype::Int | Metatype::Uint) => m,
            _ => Metatype::Uint,
        };
        if e.is_char_print() {
            self.base(new_size, meta)
        } else {
            self.base_no_char(new_size, meta)
        }
    }
}
