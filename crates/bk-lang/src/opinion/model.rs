//! The typed content of a `.opinion` file.

use crate::{endian::Endian, id::CompilerSpecId};

/// The index of a [`Constraint`] within its [`Opinions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConstraintId(pub(crate) u32);

impl ConstraintId {
    /// The position of the constraint in [`Opinions::constraints`].
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// One `<constraint>` element: the attributes it gives itself. Attributes
/// it leaves out are inherited from its ancestors; see
/// [`Opinions::resolved`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Constraint {
    /// The enclosing constraint, if any.
    pub parent: Option<ConstraintId>,
    /// The loader's name (`Executable and Linking Format (ELF)`).
    pub loader: Option<String>,
    /// The primary key, usually a machine number in decimal; may be a
    /// comma-separated list.
    pub primary: Option<String>,
    /// The secondary key: a decimal number, or a `0x` hexadecimal or `0b`
    /// binary pattern (see
    /// [`secondary_attribute_matches`](super::secondary_attribute_matches)).
    pub secondary: Option<String>,
    /// The processor name to match languages by.
    pub processor: Option<String>,
    /// The byte order to match languages by.
    pub endian: Option<Endian>,
    /// The address size in bits to match languages by.
    pub size: Option<i32>,
    /// The variant to match languages by.
    pub variant: Option<String>,
    /// The compiler spec that is preferred among the matching languages'.
    pub compiler_spec_id: Option<CompilerSpecId>,
}

impl Constraint {
    /// This constraint with every attribute it lacks taken from `parent`.
    fn inherit(&self, parent: &Self) -> Self {
        Self {
            parent: self.parent,
            loader: self.loader.clone().or_else(|| parent.loader.clone()),
            primary: self.primary.clone().or_else(|| parent.primary.clone()),
            secondary: self.secondary.clone().or_else(|| parent.secondary.clone()),
            processor: self.processor.clone().or_else(|| parent.processor.clone()),
            endian: self.endian.or(parent.endian),
            size: self.size.or(parent.size),
            variant: self.variant.clone().or_else(|| parent.variant.clone()),
            compiler_spec_id: self
                .compiler_spec_id
                .clone()
                .or_else(|| parent.compiler_spec_id.clone()),
        }
    }
}

/// The content of one `.opinion` file: its constraints in document order
/// (a parent before its children), each naming its parent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Opinions {
    pub(crate) constraints: Vec<Constraint>,
}

impl Opinions {
    /// The constraints as written, in document order.
    #[must_use]
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    /// The constraint with the given id.
    #[must_use]
    pub fn get(&self, id: ConstraintId) -> Option<&Constraint> {
        self.constraints.get(id.index())
    }

    /// The constraints with inherited attributes filled in, in document
    /// order: a constraint's own attributes override its ancestors'.
    ///
    /// Ghidra registers every constraint this way — inner elements as well
    /// as leaves.
    #[must_use]
    pub fn resolved(&self) -> Vec<Constraint> {
        let mut resolved: Vec<Constraint> = Vec::with_capacity(self.constraints.len());
        for constraint in &self.constraints {
            // A parent always precedes its children, so it is resolved.
            let parent = constraint.parent.and_then(|p| resolved.get(p.index()));
            let full = match parent {
                Some(parent) => constraint.inherit(parent),
                None => constraint.clone(),
            };
            resolved.push(full);
        }
        resolved
    }
}
