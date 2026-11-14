//! `testtypes`: a small type model implementing `ParamTypes` for the tests
//! (spec 4.5): primitives, pointers, arrays, structures and unions, with
//! alignment taken from a size map as Ghidra's data organisation does.
//! Nothing in `src/` uses it.

use std::collections::BTreeMap;

use bk_cspec::types::{Metatype, ParamTypes, TypeField, TypeHandle, TypeQueryError};
use bk_marshal::ids::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE};
use bk_marshal::{Decoder, ElementId, Encoder};

/// `<type>` / `<typeref>`, as Ghidra names them.
const ELEM_TYPE: ElementId = ElementId::new("type", 60);
const ELEM_TYPEREF: ElementId = ElementId::new("typeref", 63);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Prim,
    Void,
    Ptr(TypeHandle),
    Array(TypeHandle, i32),
    Struct(Vec<TypeField>),
    Union(Vec<TypeField>),
}

#[derive(Clone, Debug)]
pub(crate) struct Def {
    pub(crate) name: String,
    pub(crate) meta: Metatype,
    pub(crate) size: i32,
    pub(crate) align: i32,
    pub(crate) kind: Kind,
}

/// The type model: an arena of definitions addressed by handle.
#[derive(Clone, Debug)]
pub(crate) struct TestTypes {
    pub(crate) defs: Vec<Def>,
    by_name: BTreeMap<String, TypeHandle>,
    pointers: BTreeMap<(u32, i32), TypeHandle>,
    /// Alignment by size, as a data organisation's map (index = size).
    pub(crate) align_map: Vec<i32>,
    /// Size of `int`, `long`, `long long`, `long double`, pointers.
    pub(crate) c_sizes: CSizes,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CSizes {
    pub(crate) int: i32,
    pub(crate) long: i32,
    pub(crate) long_long: i32,
    pub(crate) long_double: i32,
    pub(crate) pointer: i32,
}

impl Default for CSizes {
    fn default() -> Self {
        Self {
            int: 4,
            long: 4,
            long_long: 8,
            long_double: 8,
            pointer: 4,
        }
    }
}

fn round_up(size: i32, align: i32) -> i32 {
    let a = align.max(1);
    (size + a - 1) / a * a
}

impl TestTypes {
    /// A model with Ghidra's core types and the given alignment map
    /// (index = size; sizes past the end use the last entry).
    pub(crate) fn new(align_map: Vec<i32>, c_sizes: CSizes) -> Self {
        let mut t = Self {
            defs: Vec::new(),
            by_name: BTreeMap::new(),
            pointers: BTreeMap::new(),
            align_map,
            c_sizes,
        };
        t.add("void", Metatype::Void, 0, 1, Kind::Void);
        for (name, meta, size) in [
            ("int1", Metatype::Int, 1),
            ("int2", Metatype::Int, 2),
            ("int4", Metatype::Int, 4),
            ("int8", Metatype::Int, 8),
            ("uint1", Metatype::Uint, 1),
            ("uint2", Metatype::Uint, 2),
            ("uint4", Metatype::Uint, 4),
            ("uint8", Metatype::Uint, 8),
            ("char", Metatype::Int, 1),
            ("bool", Metatype::Bool, 1),
            ("float4", Metatype::Float, 4),
            ("float8", Metatype::Float, 8),
            ("float10", Metatype::Float, 10),
            ("float16", Metatype::Float, 16),
            ("xunknown1", Metatype::Unknown, 1),
            ("xunknown2", Metatype::Unknown, 2),
            ("xunknown4", Metatype::Unknown, 4),
            ("xunknown8", Metatype::Unknown, 8),
            ("code", Metatype::Code, 1),
        ] {
            let align = t.prim_align(size);
            t.add(name, meta, size, align, Kind::Prim);
        }
        let c = t.c_sizes;
        for (alias, base) in [
            ("int", int_name(c.int)),
            ("long", int_name(c.long)),
            ("long long", int_name(c.long_long)),
            ("short", "int2".into()),
            ("int32_t", "int4".into()),
            ("unsigned int", uint_name(c.int)),
            ("unsigned long", uint_name(c.long)),
            ("float", "float4".into()),
            ("double", "float8".into()),
            ("long double", float_name(c.long_double)),
            ("undefined4", "xunknown4".into()),
            ("undefined8", "xunknown8".into()),
        ] {
            if let Some(&h) = t.by_name.get(&base) {
                t.by_name.insert(alias.to_owned(), h);
            }
        }
        t
    }

    /// Alignment of a primitive of `size` bytes.
    pub(crate) fn prim_align(&self, size: i32) -> i32 {
        let s = size.max(0) as usize;
        self.align_map
            .get(s)
            .or_else(|| self.align_map.last())
            .copied()
            .unwrap_or(1)
            .max(1)
    }

    fn add(&mut self, name: &str, meta: Metatype, size: i32, align: i32, kind: Kind) -> TypeHandle {
        let h = TypeHandle(self.defs.len() as u32);
        self.defs.push(Def {
            name: name.to_owned(),
            meta,
            size,
            align,
            kind,
        });
        self.by_name.entry(name.to_owned()).or_insert(h);
        h
    }

    /// The type of a name, or `None`.
    pub(crate) fn named(&self, name: &str) -> Option<TypeHandle> {
        self.by_name.get(name).copied()
    }

    /// The type of a name; panics in tests when unknown.
    pub(crate) fn get(&self, name: &str) -> TypeHandle {
        self.named(name)
            .unwrap_or_else(|| panic!("unknown test type {name}"))
    }

    fn def(&self, h: TypeHandle) -> &Def {
        &self.defs[h.0 as usize]
    }

    /// An array of `count` elements.
    pub(crate) fn array(&mut self, elem: TypeHandle, count: i32) -> TypeHandle {
        let d = self.def(elem).clone();
        let size = round_up(d.size, d.align) * count;
        let name = format!("{}[{count}]", d.name);
        if let Some(h) = self
            .defs
            .iter()
            .position(|x| x.kind == Kind::Array(elem, count))
        {
            return TypeHandle(h as u32);
        }
        self.add(
            &name,
            Metatype::Array,
            size,
            d.align,
            Kind::Array(elem, count),
        )
    }

    /// A structure laid out with natural alignment.
    pub(crate) fn structure(&mut self, name: &str, members: &[TypeHandle]) -> TypeHandle {
        let mut off = 0;
        let mut align = 1;
        let mut fields = Vec::new();
        for &m in members {
            let d = self.def(m);
            off = round_up(off, d.align);
            fields.push(TypeField { offset: off, ty: m });
            off += round_up(d.size, d.align);
            align = align.max(d.align);
        }
        let size = round_up(off, align);
        let h = self.add(name, Metatype::Struct, size, align, Kind::Struct(fields));
        self.by_name.insert(name.to_owned(), h);
        h
    }

    /// A union of the members.
    pub(crate) fn union(&mut self, name: &str, members: &[TypeHandle]) -> TypeHandle {
        let mut size = 0;
        let mut align = 1;
        let fields = members
            .iter()
            .map(|&m| {
                let d = self.def(m);
                size = size.max(d.size);
                align = align.max(d.align);
                TypeField { offset: 0, ty: m }
            })
            .collect();
        let size = round_up(size, align);
        let h = self.add(name, Metatype::Union, size, align, Kind::Union(fields));
        self.by_name.insert(name.to_owned(), h);
        h
    }

    /// A short description of a type for oracle rows: metatype, size and
    /// name, recursively for pointers.
    pub(crate) fn describe(&self, h: TypeHandle) -> String {
        let d = self.def(h);
        match d.kind {
            Kind::Ptr(to) => format!("ptr{}({})", d.size, self.describe(to)),
            _ => format!("{}{}:{}", d.meta.name(), d.size, d.name),
        }
    }
}

fn int_name(size: i32) -> String {
    format!("int{size}")
}
fn uint_name(size: i32) -> String {
    format!("uint{size}")
}
fn float_name(size: i32) -> String {
    format!("float{size}")
}

impl ParamTypes for TestTypes {
    fn size(&self, ty: TypeHandle) -> i32 {
        self.defs.get(ty.0 as usize).map_or(0, |d| d.size)
    }
    fn align_size(&self, ty: TypeHandle) -> i32 {
        self.defs
            .get(ty.0 as usize)
            .map_or(0, |d| round_up(d.size, d.align))
    }
    fn alignment(&self, ty: TypeHandle) -> i32 {
        self.defs.get(ty.0 as usize).map_or(1, |d| d.align)
    }
    fn metatype(&self, ty: TypeHandle) -> Metatype {
        self.defs
            .get(ty.0 as usize)
            .map_or(Metatype::Void, |d| d.meta)
    }
    fn name(&self, ty: TypeHandle) -> String {
        self.defs
            .get(ty.0 as usize)
            .map_or_else(String::new, |d| d.name.clone())
    }
    fn array_element(&self, ty: TypeHandle) -> Option<(TypeHandle, i32)> {
        match self.defs.get(ty.0 as usize)?.kind {
            Kind::Array(e, n) => Some((e, n)),
            _ => None,
        }
    }
    fn field_count(&self, ty: TypeHandle) -> usize {
        match &self.defs.get(ty.0 as usize).map(|d| &d.kind) {
            Some(Kind::Struct(f) | Kind::Union(f)) => f.len(),
            _ => 0,
        }
    }
    fn field(&self, ty: TypeHandle, index: usize) -> Option<TypeField> {
        match &self.defs.get(ty.0 as usize)?.kind {
            Kind::Struct(f) | Kind::Union(f) => f.get(index).copied(),
            _ => None,
        }
    }
    fn pointed_to(&self, ty: TypeHandle) -> Option<TypeHandle> {
        match self.defs.get(ty.0 as usize)?.kind {
            Kind::Ptr(to) => Some(to),
            _ => None,
        }
    }
    fn pointer_to(&mut self, to: TypeHandle, size: i32, _word_size: u32) -> TypeHandle {
        if let Some(&h) = self.pointers.get(&(to.0, size)) {
            return h;
        }
        let name = format!("{} *", self.name(to));
        let align = self.prim_align(size);
        let h = TypeHandle(self.defs.len() as u32);
        self.defs.push(Def {
            name,
            meta: Metatype::Ptr,
            size,
            align,
            kind: Kind::Ptr(to),
        });
        self.pointers.insert((to.0, size), h);
        h
    }
    fn void(&mut self) -> TypeHandle {
        self.get("void")
    }
    fn unknown(&mut self, size: i32) -> TypeHandle {
        let name = format!("xunknown{size}");
        if let Some(h) = self.named(&name) {
            return h;
        }
        let align = self.prim_align(size);
        self.add(&name, Metatype::Unknown, size, align, Kind::Prim)
    }
    fn encode_ref(&self, enc: &mut dyn Encoder, ty: TypeHandle) -> Result<(), TypeQueryError> {
        enc.open_element(ELEM_TYPEREF);
        enc.write_string(ATTRIB_NAME, &self.name(ty))
            .map_err(|e| TypeQueryError(e.to_string()))?;
        enc.write_unsigned(ATTRIB_ID, u64::from(ty.0));
        enc.write_signed(ATTRIB_SIZE, i64::from(self.size(ty)));
        enc.close_element(ELEM_TYPEREF);
        Ok(())
    }
    fn decode_type(&mut self, dec: &mut dyn Decoder<'_>) -> Result<TypeHandle, TypeQueryError> {
        let err = |e: bk_marshal::DecodeError| TypeQueryError(e.to_string());
        let elem = dec
            .open_element()
            .map_err(err)?
            .ok_or_else(|| TypeQueryError("no type".into()))?;
        if elem != ELEM_TYPEREF && elem != ELEM_TYPE {
            return Err(TypeQueryError("expected <typeref>".into()));
        }
        let id = dec.read_unsigned_attr(ATTRIB_ID).map_err(err)?;
        dec.close_element_skipping(elem).map_err(err)?;
        let h = TypeHandle(id as u32);
        if (id as usize) < self.defs.len() {
            Ok(h)
        } else {
            Err(TypeQueryError(format!("unknown type id {id}")))
        }
    }
}
