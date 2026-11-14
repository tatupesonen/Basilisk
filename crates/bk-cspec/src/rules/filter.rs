//! Data-type filters and qualifier filters of a `<rule>` (Ghidra
//! `DatatypeFilter`, `SizeRestrictedFilter`, `MetaTypeFilter`,
//! `ArrayFilter`, `HomogeneousAggregate`, `QualifierFilter`, `AndFilter`,
//! `VarargsFilter`, `PositionMatchFilter`, `DatatypeMatchFilter`).

use bk_marshal::Decoder;
use bk_marshal::ids::{ATTRIB_INDEX, ATTRIB_NAME};

use super::extractor::PrimitiveExtractor;
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_FIRST, ATTRIB_LAST, ATTRIB_MAX_PRIMITIVES, ATTRIB_MAXELEMENTS, ATTRIB_MAXSIZE,
    ATTRIB_MINELEMENTS, ATTRIB_MINSIZE, ATTRIB_SIZES, ELEM_DATATYPE, ELEM_DATATYPE_AT,
    ELEM_POSITION, ELEM_VARARGS,
};
use crate::proto::PrototypePieces;
use crate::types::{Metatype, ParamTypes, TypeHandle};

/// Bounds on the size of a type: a range or an enumerated set (Ghidra
/// `SizeRestrictedFilter`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SizeRestriction {
    /// Smallest size.
    pub min: i32,
    /// Largest size; 0 means no filtering.
    pub max: i32,
    /// Allowed sizes, sorted; empty for a range.
    pub sizes: Vec<i32>,
}

impl SizeRestriction {
    /// A range from `min` to `max`, where `max` 0 means unbounded (Ghidra
    /// `SizeRestrictedFilter(min,max)`).
    pub fn range(min: i32, max: i32) -> Self {
        let max = if max == 0 && min >= 0 {
            0x7fff_ffff
        } else {
            max
        };
        Self {
            min,
            max,
            sizes: Vec::new(),
        }
    }

    /// Whether a size passes (Ghidra `filterOnSize`).
    pub fn accepts(&self, size: i32) -> bool {
        if self.max == 0 {
            return true;
        }
        if !self.sizes.is_empty() {
            return self.sizes.binary_search(&size).is_ok();
        }
        size >= self.min && size <= self.max
    }

    fn decode(&mut self, dec: &mut dyn Decoder<'_>) -> Result<()> {
        const MIXING: &str = "Mixing \"sizes\" with \"minsize\" and \"maxsize\"";
        while let Some(attr) = dec.next_attribute()? {
            if attr == ATTRIB_MINSIZE {
                if !self.sizes.is_empty() {
                    return Err(CspecError::new(MIXING));
                }
                self.min = dec.read_unsigned()? as i32;
            } else if attr == ATTRIB_MAXSIZE {
                if !self.sizes.is_empty() {
                    return Err(CspecError::new(MIXING));
                }
                self.max = dec.read_unsigned()? as i32;
            } else if attr == ATTRIB_SIZES {
                if self.min != 0 || self.max != 0 {
                    return Err(CspecError::new(MIXING));
                }
                self.init_from_list(dec.read_string()?)?;
            }
        }
        if self.max == 0 && self.min >= 0 {
            self.max = 0x7fff_ffff;
        }
        Ok(())
    }

    /// Parses a comma or space separated list of positive sizes (Ghidra
    /// `initFromSizeList`).
    fn init_from_list(&mut self, text: &str) -> Result<()> {
        let mut rest = text.trim_start();
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix(',') {
                rest = after.trim_start();
            }
            let digits = rest
                .char_indices()
                .take_while(|&(i, c)| c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+')))
                .map(|(i, c)| i + c.len_utf8())
                .last()
                .unwrap_or(0);
            let value: i64 = rest
                .get(..digits)
                .and_then(|d| d.parse().ok())
                .unwrap_or(-1);
            if value <= 0 || value > i64::from(i32::MAX) {
                return Err(CspecError::new("Bad filter size"));
            }
            let value = value as i32;
            if let Err(pos) = self.sizes.binary_search(&value) {
                self.sizes.insert(pos, value);
            }
            rest = rest.get(digits..).unwrap_or("").trim_start();
        }
        if let (Some(&first), Some(&last)) = (self.sizes.first(), self.sizes.last()) {
            self.min = first;
            self.max = last;
        }
        Ok(())
    }
}

/// Which data types a rule applies to (Ghidra's `DatatypeFilter`
/// hierarchy).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatatypeFilter {
    /// Any type within the size bounds (`any`).
    Size(SizeRestriction),
    /// One metatype within the size bounds (Ghidra `MetaTypeFilter`).
    Meta {
        /// The metatype let through.
        meta: Metatype,
        /// Size bounds.
        size: SizeRestriction,
    },
    /// Arrays (Ghidra `ArrayFilter`).
    Array {
        /// Size bounds.
        size: SizeRestriction,
        /// Fewest elements.
        min_elements: i32,
        /// Most elements; 0 is unbounded.
        max_elements: i32,
    },
    /// Structures or arrays made of one primitive type (Ghidra
    /// `HomogeneousAggregate`).
    Homogeneous {
        /// The metatype of the primitive.
        meta: Metatype,
        /// Most primitives.
        max_primitives: usize,
        /// Size bounds.
        size: SizeRestriction,
    },
}

impl DatatypeFilter {
    /// Reads a `<datatype>` element (Ghidra `DatatypeFilter::decodeFilter`).
    pub(crate) fn decode(dec: &mut dyn Decoder<'_>) -> Result<Self> {
        let elem = dec.open_element_expecting(ELEM_DATATYPE)?;
        let name = dec.read_string_attr(ATTRIB_NAME)?;
        let mut filter = match name {
            "any" => Self::Size(SizeRestriction::default()),
            "homogeneous-float-aggregate" => Self::Homogeneous {
                meta: Metatype::Float,
                max_primitives: 4,
                size: SizeRestriction::range(0, 0),
            },
            other => {
                let meta = Metatype::from_name(other)
                    .ok_or_else(|| CspecError::new(format!("Unknown metatype: {other}")))?;
                if meta == Metatype::Array {
                    Self::Array {
                        size: SizeRestriction::default(),
                        min_elements: 0,
                        max_elements: 0,
                    }
                } else {
                    Self::Meta {
                        meta,
                        size: SizeRestriction::default(),
                    }
                }
            }
        };
        match &mut filter {
            Self::Size(size) | Self::Meta { size, .. } => size.decode(dec)?,
            Self::Array {
                size,
                min_elements,
                max_elements,
            } => {
                size.decode(dec)?;
                dec.rewind_attributes();
                while let Some(attr) = dec.next_attribute()? {
                    if attr == ATTRIB_MINELEMENTS {
                        *min_elements = dec.read_unsigned()? as i32;
                    } else if attr == ATTRIB_MAXELEMENTS {
                        *max_elements = dec.read_unsigned()? as i32;
                    }
                }
            }
            Self::Homogeneous {
                size,
                max_primitives,
                ..
            } => {
                size.decode(dec)?;
                dec.rewind_attributes();
                while let Some(attr) = dec.next_attribute()? {
                    if attr == ATTRIB_MAX_PRIMITIVES {
                        let v = dec.read_unsigned()? as u32;
                        if v > 0 {
                            *max_primitives = v as usize;
                        }
                    }
                }
            }
        }
        dec.close_element(elem)?;
        Ok(filter)
    }

    /// Whether a type belongs to the filter's class (Ghidra `filter`).
    pub fn accepts(&self, types: &dyn ParamTypes, ty: TypeHandle) -> bool {
        match self {
            Self::Size(size) => size.accepts(types.size(ty)),
            Self::Meta { meta, size } => {
                types.metatype(ty) == *meta && size.accepts(types.size(ty))
            }
            Self::Array {
                size,
                min_elements,
                max_elements,
            } => {
                if types.metatype(ty) != Metatype::Array || !size.accepts(types.size(ty)) {
                    return false;
                }
                let n = types.array_element(ty).map_or(0, |(_, n)| n);
                n >= *min_elements && (*max_elements == 0 || n <= *max_elements)
            }
            Self::Homogeneous {
                meta,
                max_primitives,
                ..
            } => {
                let m = types.metatype(ty);
                if m != Metatype::Array && m != Metatype::Struct {
                    return false;
                }
                let prims = PrimitiveExtractor::new(types, ty, (true, false), 0, *max_primitives);
                if !prims.is_valid()
                    || prims.is_empty()
                    || prims.contains_unknown()
                    || !prims.is_aligned()
                    || prims.contains_holes()
                {
                    return false;
                }
                let Some(base) = prims.get(0) else {
                    return false;
                };
                if types.metatype(base.ty) != *meta {
                    return false;
                }
                prims.primitives().iter().all(|p| p.ty == base.ty)
            }
        }
    }
}

/// A condition on the prototype as a whole (Ghidra's `QualifierFilter`
/// hierarchy).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QualifierFilter {
    /// Optional arguments relative to the first variadic one (Ghidra
    /// `VarargsFilter`).
    Varargs {
        /// Start of the range, relative to the first variadic argument.
        first: i32,
        /// End of the range.
        last: i32,
    },
    /// The parameter at one position (Ghidra `PositionMatchFilter`).
    Position(i32),
    /// The prototype has a type of a class at a position (Ghidra
    /// `DatatypeMatchFilter`); position -1 is the return value.
    DatatypeAt {
        /// Position checked.
        position: i32,
        /// Class required there.
        filter: DatatypeFilter,
    },
    /// All of several qualifiers (Ghidra `AndFilter`).
    And(Vec<Self>),
}

impl QualifierFilter {
    /// Reads the next element if it is a qualifier (Ghidra
    /// `QualifierFilter::decodeFilter`).
    pub(crate) fn decode(dec: &mut dyn Decoder<'_>) -> Result<Option<Self>> {
        let Some(peek) = dec.peek_element() else {
            return Ok(None);
        };
        if peek == ELEM_VARARGS {
            let elem = dec.open_element_expecting(ELEM_VARARGS)?;
            let (mut first, mut last) = (i32::MIN, i32::MAX);
            while let Some(attr) = dec.next_attribute()? {
                if attr == ATTRIB_FIRST {
                    first = dec.read_signed()? as i32;
                } else if attr == ATTRIB_LAST {
                    last = dec.read_signed()? as i32;
                }
            }
            dec.close_element(elem)?;
            Ok(Some(Self::Varargs { first, last }))
        } else if peek == ELEM_POSITION {
            let elem = dec.open_element_expecting(ELEM_POSITION)?;
            let position = dec.read_signed_attr(ATTRIB_INDEX)? as i32;
            dec.close_element(elem)?;
            Ok(Some(Self::Position(position)))
        } else if peek == ELEM_DATATYPE_AT {
            let elem = dec.open_element_expecting(ELEM_DATATYPE_AT)?;
            let position = dec.read_signed_attr(ATTRIB_INDEX)? as i32;
            let filter = DatatypeFilter::decode(dec)?;
            dec.close_element(elem)?;
            Ok(Some(Self::DatatypeAt { position, filter }))
        } else {
            Ok(None)
        }
    }

    /// Whether the prototype meets the condition for the parameter at
    /// `pos` (-1 for the return value) (Ghidra `filter`).
    pub fn accepts(&self, types: &dyn ParamTypes, proto: &PrototypePieces, pos: i32) -> bool {
        match self {
            Self::Varargs { first, last } => {
                if proto.first_vararg < 0 {
                    return false;
                }
                let p = pos.wrapping_sub(proto.first_vararg);
                p >= *first && p <= *last
            }
            Self::Position(p) => *p == pos,
            Self::DatatypeAt { position, filter } => {
                let ty = if *position < 0 {
                    proto.outtype
                } else {
                    match proto.intypes.get(*position as usize) {
                        Some(t) => *t,
                        None => return false,
                    }
                };
                filter.accepts(types, ty)
            }
            Self::And(list) => list.iter().all(|q| q.accepts(types, proto, pos)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SizeRestriction;

    #[test]
    fn size_lists_parse_as_ghidra() {
        let mut s = SizeRestriction::default();
        s.init_from_list(" 8, 4 16").unwrap();
        assert_eq!(s.sizes, vec![4, 8, 16]);
        assert_eq!((s.min, s.max), (4, 16));
        assert!(s.accepts(8) && !s.accepts(12));
        for bad in ["0", "4,,8", "x", "-4"] {
            let mut s = SizeRestriction::default();
            assert!(s.init_from_list(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unbounded_ranges() {
        let s = SizeRestriction::range(9, 0);
        assert!(s.accepts(9) && s.accepts(1 << 30) && !s.accepts(8));
    }
}
