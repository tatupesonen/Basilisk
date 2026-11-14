//! The processor specification's `<context_data>`, resolved against a
//! language's spaces, registers and context variables (Ghidra
//! `ContextInternal::decodeFromSpec`, inventory section 4.3).

use bk_core::{Address, Range, RegisterLookup, SpaceManager};
use bk_lang::pspec::{AddressRange, AddressResolver, AddressSpec, ContextKind, ProcessorSpec};

use crate::context::{ContextDb, ContextVar, TrackedValue};
use crate::error::LoadError;
use crate::language::RegisterTable;

/// One resolved setting of `<context_data>`, applied by
/// [`Language::initial_context`](crate::Language::initial_context).
#[derive(Clone, Debug)]
pub(crate) enum InitialSetting {
    /// `<context_set>`: a variable set over a region.
    Region {
        /// Index into the language's context variables.
        var: usize,
        /// First address.
        first: Address,
        /// The address after the region.
        end: Address,
        /// The value.
        value: u32,
    },
    /// `<tracked_set>`: tracked values replacing those over a region.
    Tracked {
        /// First address.
        first: Address,
        /// The address after the region.
        end: Address,
        /// The values.
        values: Vec<TrackedValue>,
    },
}

impl InitialSetting {
    pub(crate) fn apply(&self, db: &mut ContextDb, vars: &[ContextVar]) {
        match self {
            Self::Region {
                var,
                first,
                end,
                value,
            } => {
                if let Some(var) = vars.get(*var) {
                    db.set_variable_region(var, *first, Some(*end), *value);
                }
            }
            Self::Tracked { first, end, values } => db.set_tracked(*first, *end, values.clone()),
        }
    }
}

/// Resolves `.pspec` ranges against a language's spaces.
struct Spaces<'a>(&'a SpaceManager);

impl AddressResolver for Spaces<'_> {
    type Address = Address;

    fn resolve_address(&self, spec: &AddressSpec) -> Option<Address> {
        let space = match spec.space() {
            Some(name) => self.0.space_by_name(name)?,
            None => self.0.default_code_space()?,
        };
        let offset = spec.offset()?;
        Some(Address::new(
            space.id(),
            space.wrap_offset(space.address_to_byte(offset.units)),
        ))
    }

    /// The first address and the address after the range (Ghidra
    /// `Range::decodeFromAttributes` and `getLastAddrOpen`).
    fn resolve_range(&self, range: &AddressRange) -> Option<(Address, Address)> {
        let space = self.0.space_by_name(&range.space)?;
        let first = range.first.unwrap_or(0);
        let last = range.last.unwrap_or_else(|| space.highest());
        if first > space.highest() || last > space.highest() || last < first {
            return None;
        }
        let range = Range::new(space.id(), first, last);
        Some((range.first_addr(), range.last_addr_open(self.0)))
    }
}

/// Resolves every block of `<context_data>`, in file order.
pub(crate) fn resolve(
    pspec: &ProcessorSpec,
    spaces: &SpaceManager,
    registers: &RegisterTable,
    vars: &[ContextVar],
) -> Result<Vec<InitialSetting>, LoadError> {
    let resolver = Spaces(spaces);
    let mut out = Vec::new();
    for block in &pspec.context_data {
        let (first, end) = resolver
            .resolve_range(&block.range)
            .ok_or_else(|| LoadError::BadRange {
                space: block.range.space.clone(),
            })?;
        match block.kind {
            ContextKind::Context => {
                for set in &block.values {
                    let var = vars
                        .binary_search_by(|var| var.name().cmp(set.name.as_str()))
                        .map_err(|_| LoadError::UnknownContextVariable(set.name.clone()))?;
                    out.push(InitialSetting::Region {
                        var,
                        first,
                        end,
                        value: set.value() as u32,
                    });
                }
            }
            ContextKind::Tracked => {
                let mut values = Vec::with_capacity(block.values.len());
                for set in &block.values {
                    let register = registers
                        .register(&set.name)
                        .ok_or_else(|| LoadError::UnknownRegister(set.name.clone()))?;
                    let space = register.space().ok_or_else(|| LoadError::UnknownRegister(set.name.clone()))?;
                    values.push(TrackedValue {
                        space,
                        offset: register.offset,
                        size: register.size,
                        big_endian: spaces.space(space).is_some_and(bk_core::Space::is_big_endian),
                        value: set.value() as u64,
                    });
                }
                out.push(InitialSetting::Tracked { first, end, values });
            }
        }
    }
    Ok(out)
}
