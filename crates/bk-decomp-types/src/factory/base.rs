//! Atomic types and the caches (Ghidra `getBase`, `getBaseNoChar`,
//! `getTypeChar`, `getTypeUnicode`, `getTypeVoid`, `getTypeCode`,
//! `setCoreType`, `cacheCoreTypes`, and `SleighArchitecture::buildCoreTypes`).

use crate::entry::{TypeEntry, TypeFlags, TypeKind, hash_name};
use crate::error::Result;
use crate::factory::{BaseCache, TypeFactory};
use crate::ids::TypeId;
use crate::meta::{Metatype, SubMetatype};

/// The default core types: name, size, metatype, character type
/// (`SleighArchitecture::buildCoreTypes`).
pub const DEFAULT_CORE_TYPES: [(&str, i32, Metatype, bool); 22] = [
    ("void", 1, Metatype::Void, false),
    ("bool", 1, Metatype::Bool, false),
    ("uint1", 1, Metatype::Uint, false),
    ("uint2", 2, Metatype::Uint, false),
    ("uint4", 4, Metatype::Uint, false),
    ("uint8", 8, Metatype::Uint, false),
    ("int1", 1, Metatype::Int, false),
    ("int2", 2, Metatype::Int, false),
    ("int4", 4, Metatype::Int, false),
    ("int8", 8, Metatype::Int, false),
    ("float4", 4, Metatype::Float, false),
    ("float8", 8, Metatype::Float, false),
    ("float10", 10, Metatype::Float, false),
    ("float16", 16, Metatype::Float, false),
    ("xunknown1", 1, Metatype::Unknown, false),
    ("xunknown2", 2, Metatype::Unknown, false),
    ("xunknown4", 4, Metatype::Unknown, false),
    ("xunknown8", 8, Metatype::Unknown, false),
    ("code", 1, Metatype::Code, false),
    ("char", 1, Metatype::Int, true),
    ("wchar2", 2, Metatype::Int, true),
    ("wchar4", 4, Metatype::Int, true),
];

impl TypeFactory {
    /// Creates Ghidra's default core types and caches them.
    pub(crate) fn build_default_core_types(&mut self) -> Result<()> {
        for (name, size, meta, chartp) in DEFAULT_CORE_TYPES {
            self.set_core_type(name, size, meta, chartp)?;
        }
        self.cache_core_types();
        Ok(())
    }

    /// Ghidra `setCoreType`: creates a type and marks it core.
    pub fn set_core_type(
        &mut self,
        name: &str,
        size: i32,
        meta: Metatype,
        chartp: bool,
    ) -> Result<TypeId> {
        let id = if chartp {
            if size == 1 {
                self.type_char_named(name)?
            } else {
                self.type_unicode_named(name, size, meta)?
            }
        } else if meta == Metatype::Code {
            self.type_code_named(name)?
        } else if meta == Metatype::Void {
            self.type_void()?
        } else {
            self.base_named(size, meta, name)?
        };
        self.modify(id, |e| e.flags |= TypeFlags::CORETYPE)?;
        Ok(id)
    }

    /// Ghidra `cacheCoreTypes`: fills the caches from the core types, in
    /// identity order.
    pub fn cache_core_types(&mut self) {
        for id in self.sorted_ids() {
            let e = self.entry(id);
            if !e.is_core() {
                continue;
            }
            let size = e.size;
            if size > 8 {
                if e.metatype == Metatype::Float {
                    if size == 10 {
                        self.cache.float10 = Some(id);
                    } else if size == 16 {
                        self.cache.float16 = Some(id);
                    }
                }
                continue;
            }
            let Ok(sz) = usize::try_from(size) else {
                continue;
            };
            let meta = e.metatype;
            let (is_ascii, is_enum, is_char) = (e.is_ascii(), e.is_enum(), e.is_char_print());
            let col = BaseCache::column(meta);
            let mut fill_first = false;
            match meta {
                Metatype::Int | Metatype::Uint => {
                    if meta == Metatype::Int && size == 1 && !is_ascii {
                        self.cache.nochar = Some(id);
                    }
                    if is_enum {
                        continue;
                    }
                    if is_char {
                        if size < 5
                            && let Some(slot) = self.cache.chars.get_mut(sz)
                        {
                            *slot = Some(id);
                        }
                        if is_ascii
                            && let Some(slot) =
                                col.and_then(|c| self.cache.table.get_mut(sz)?.get_mut(c))
                        {
                            *slot = Some(id);
                        }
                        continue;
                    }
                    fill_first = true;
                }
                Metatype::Void
                | Metatype::Unknown
                | Metatype::Bool
                | Metatype::Code
                | Metatype::Float => fill_first = true,
                _ => {}
            }
            if fill_first
                && let Some(slot) = col.and_then(|c| self.cache.table.get_mut(sz)?.get_mut(c))
                && slot.is_none()
            {
                *slot = Some(id);
            }
        }
    }

    fn cached(&self, size: i32, meta: Metatype) -> Option<TypeId> {
        let col = BaseCache::column(meta)?;
        let row = usize::try_from(size).ok()?;
        *self.cache.table.get(row)?.get(col)?
    }

    /// Ghidra `getTypeVoid`: the single void type.
    pub fn type_void(&mut self) -> Result<TypeId> {
        if let Some(id) = self.cached(0, Metatype::Void) {
            return Ok(id);
        }
        let mut tv = TypeEntry::new(0, 1, Metatype::Void, TypeKind::Void);
        tv.set_name("void", hash_name("void"));
        tv.flags |= TypeFlags::CORETYPE;
        let id = self.insert(tv)?;
        if let Some(slot) = self.cache.table.get_mut(0).and_then(|r| r.get_mut(7)) {
            *slot = Some(id);
        }
        Ok(id)
    }

    /// The void type if it exists, without creating it.
    pub fn void_if_present(&self) -> Option<TypeId> {
        self.cached(0, Metatype::Void).or_else(|| {
            self.find_by_name("void")
                .filter(|&v| self.entry(v).metatype == Metatype::Void)
        })
    }

    /// Ghidra `getTypeChar(const string&)`: a 1-byte character type.
    pub(crate) fn type_char_named(&mut self, name: &str) -> Result<TypeId> {
        let mut tc = TypeEntry::new(1, -1, Metatype::Int, TypeKind::Char);
        tc.set_name(name, hash_name(name));
        tc.flags |= TypeFlags::CHARTYPE;
        tc.submeta = SubMetatype::IntChar;
        self.find_add(tc)
    }

    /// Ghidra `getTypeUnicode`: a wide character type.
    pub(crate) fn type_unicode_named(
        &mut self,
        name: &str,
        size: i32,
        meta: Metatype,
    ) -> Result<TypeId> {
        let mut tu = TypeEntry::new(size, -1, meta, TypeKind::Unicode);
        tu.set_name(name, hash_name(name));
        unicode_flags(&mut tu);
        tu.submeta = if meta == Metatype::Int {
            SubMetatype::IntUnicode
        } else {
            SubMetatype::UintUnicode
        };
        self.find_add(tu)
    }

    /// Ghidra `getBaseNoChar`: like [`base`](Self::base) but a 1-byte
    /// signed integer is never `char`.
    pub fn base_no_char(&mut self, size: i32, meta: Metatype) -> Result<TypeId> {
        if size == 1
            && meta == Metatype::Int
            && let Some(id) = self.cache.nochar
        {
            return Ok(id);
        }
        self.base(size, meta)
    }

    /// Ghidra `getBase(size, meta)`: the atomic type of a size and
    /// metatype; above `max_basetype_size`, an array of 1-byte unknowns.
    pub fn base(&mut self, size: i32, meta: Metatype) -> Result<TypeId> {
        if (0..9).contains(&size) {
            if meta >= Metatype::Float
                && let Some(id) = self.cached(size, meta)
            {
                return Ok(id);
            }
        } else if meta == Metatype::Float {
            if size == 10 {
                if let Some(id) = self.cache.float10 {
                    return Ok(id);
                }
            } else if size == 16
                && let Some(id) = self.cache.float16
            {
                return Ok(id);
            }
        }
        if size > self.env.max_basetype_size {
            let byte = match self.cached(1, Metatype::Unknown) {
                Some(b) => b,
                None => self.find_add(TypeEntry::new(1, -1, Metatype::Unknown, TypeKind::Base))?,
            };
            return self.array(size, byte);
        }
        if size < 0 {
            return Err(crate::TypeError::new("Bad data-type size"));
        }
        self.find_add(TypeEntry::new(size, -1, meta, TypeKind::Base))
    }

    /// Ghidra `getBase(size, meta, name)`: a named atomic type.
    pub fn base_named(&mut self, size: i32, meta: Metatype, name: &str) -> Result<TypeId> {
        if size < 0 {
            return Err(crate::TypeError::new("Bad data-type size"));
        }
        let mut tmp = TypeEntry::new(size, -1, meta, TypeKind::Base);
        tmp.set_name(name, hash_name(name));
        self.find_add(tmp)
    }

    /// Ghidra `getTypeChar(int4)`: the core character type of a size.
    pub fn type_char(&self, size: i32) -> Result<TypeId> {
        usize::try_from(size)
            .ok()
            .and_then(|s| *self.cache.chars.get(s)?)
            .ok_or_else(|| crate::TypeError::new("Request for unsupported character data-type"))
    }

    /// Ghidra `getTypeCode()`: the anonymous function type.
    pub fn type_code(&mut self) -> Result<TypeId> {
        if let Some(id) = self.cached(1, Metatype::Code) {
            return Ok(id);
        }
        self.find_add(TypeEntry::new(1, 1, Metatype::Code, TypeKind::Code(None)))
    }

    /// Ghidra `getTypeCode(const string&)`: a named function type without a
    /// prototype.
    pub fn type_code_named(&mut self, name: &str) -> Result<TypeId> {
        if name.is_empty() {
            return self.type_code();
        }
        let mut tmp = TypeEntry::new(1, 1, Metatype::Code, TypeKind::Code(None));
        tmp.set_name(name, hash_name(name));
        self.find_add(tmp)
    }
}

/// Ghidra `TypeUnicode::setflags`.
pub(crate) fn unicode_flags(e: &mut TypeEntry) {
    match e.size {
        2 => e.flags |= TypeFlags::UTF16,
        4 => e.flags |= TypeFlags::UTF32,
        1 => e.flags |= TypeFlags::CHARTYPE,
        _ => {}
    }
}
