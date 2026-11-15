//! Units of the pipeline as data (ADR-025 item 1, ADR-028; spec 4.9):
//! every action, rule, merge pass, structuring step and output pass is a
//! named unit with an origin, groups and a soundness. The arrangement of
//! units into a pipeline (a profile) is D07's.

mod ghidra;

pub use ghidra::{GHIDRA_ACTIONS, GHIDRA_RULES};

use std::collections::HashMap;

use bk_pcode::OpCode;

use crate::ids::UnitId;

/// Where a unit comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    /// A port of a Ghidra action or rule (the `ghidra` profile).
    Ghidra,
    /// An improvement of Basilisk's.
    Basilisk,
}

/// What kind of unit it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitKind {
    /// An action (`Action`).
    Action,
    /// A rule of a pool (`Rule`).
    Rule,
    /// A merge pass.
    MergePass,
    /// A structuring step (`bk-decomp-cfg`).
    StructureStep,
    /// An output pass on the printer's tree.
    OutputPass,
}

/// A named assumption a unit makes (ADR-028).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssumptionId(pub u16);

/// The registry of named assumptions; the id is the position.
pub const ASSUMPTIONS: [&str; 5] = [
    "no-nan",
    "readonly-memory-constant",
    "prototype-effects",
    "dead-by-consume",
    "parameter-recovery",
];

impl AssumptionId {
    /// The assumption called `name`.
    pub fn named(name: &str) -> Option<Self> {
        ASSUMPTIONS
            .iter()
            .position(|&n| n == name)
            .map(|i| Self(i as u16))
    }

    /// Its name.
    pub fn name(self) -> &'static str {
        ASSUMPTIONS.get(usize::from(self.0)).copied().unwrap_or("")
    }
}

/// Whether a unit preserves meaning (ADR-028).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Soundness {
    /// Meaning is unchanged.
    Exact,
    /// Meaning is unchanged under the named assumption.
    Assumes(AssumptionId),
}

/// One unit as a pass crate declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnitInfo {
    /// Ghidra's name (`Action::getName`, `Rule::getName`) or Basilisk's.
    pub name: &'static str,
    /// Its origin.
    pub origin: Origin,
    /// Its groups (`basegroup`). Ghidra places some actions in two groups
    /// (`directwrite`: `protorecovery_a` and `protorecovery_b`).
    pub groups: &'static [&'static str],
    /// Its kind.
    pub kind: UnitKind,
    /// The opcodes a rule is tried on (`getOpList`); empty otherwise.
    pub opcodes: &'static [OpCode],
    /// Its soundness.
    pub soundness: Soundness,
}

/// Why a unit table cannot be built.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnitError {
    /// Two units of the same kind and origin share a name.
    #[error("unit {name:?} declared twice ({kind:?}, {origin:?})")]
    Duplicate {
        /// The name.
        name: &'static str,
        /// The kind.
        kind: UnitKind,
        /// The origin.
        origin: Origin,
    },
    /// More units than a `UnitId` can name.
    #[error("too many units")]
    TooMany,
    /// A name the table was checked against is missing.
    #[error("unit {0:?} is not in the table")]
    Unknown(String),
    /// A unit's groups differ from the reference list.
    #[error("unit {name:?} has groups {found:?}, expected {expected:?}")]
    Groups {
        /// The unit.
        name: String,
        /// Its groups.
        found: Vec<String>,
        /// The reference groups.
        expected: Vec<String>,
    },
}

/// The units of a build, numbered by `UnitId` in declaration order.
#[derive(Clone, Debug, Default)]
pub struct UnitTable {
    units: Vec<UnitInfo>,
    by_name: HashMap<(&'static str, UnitKind, Origin), UnitId>,
}

impl UnitTable {
    /// Builds the table from each pass crate's slice; a name declared twice
    /// for one kind and origin is an error.
    pub fn build(slices: &[&[UnitInfo]]) -> Result<Self, UnitError> {
        let mut t = Self::default();
        for slice in slices {
            for u in *slice {
                let key = (u.name, u.kind, u.origin);
                if t.by_name.contains_key(&key) {
                    return Err(UnitError::Duplicate {
                        name: u.name,
                        kind: u.kind,
                        origin: u.origin,
                    });
                }
                let id = u16::try_from(t.units.len()).map_err(|_| UnitError::TooMany)?;
                t.by_name.insert(key, UnitId::new(u32::from(id)));
                t.units.push(*u);
            }
        }
        Ok(t)
    }

    /// The number of units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// The unit `id`.
    pub fn get(&self, id: UnitId) -> Option<&UnitInfo> {
        self.units.get(id.index())
    }

    /// Looks a unit up by name, kind and origin.
    pub fn find(&self, name: &str, kind: UnitKind, origin: Origin) -> Option<UnitId> {
        self.units
            .iter()
            .position(|u| u.name == name && u.kind == kind && u.origin == origin)
            .map(|i| UnitId::new(i as u32))
    }

    /// Every unit with its id.
    pub fn iter(&self) -> impl Iterator<Item = (UnitId, &UnitInfo)> {
        self.units
            .iter()
            .enumerate()
            .map(|(i, u)| (UnitId::new(i as u32), u))
    }

    /// Checks the Ghidra-origin units of the table against Ghidra's names
    /// and groups ([`GHIDRA_ACTIONS`], [`GHIDRA_RULES`]): every Ghidra-origin
    /// unit must be in the reference list with the same groups, and with
    /// `complete` every reference name must be present.
    pub fn check_ghidra(&self, complete: bool) -> Result<(), UnitError> {
        for u in &self.units {
            if u.origin != Origin::Ghidra {
                continue;
            }
            let expected: Vec<&str> = match u.kind {
                UnitKind::Action => GHIDRA_ACTIONS
                    .iter()
                    .find(|(n, _)| *n == u.name)
                    .map(|(_, g)| g.to_vec())
                    .ok_or_else(|| UnitError::Unknown(u.name.to_owned()))?,
                UnitKind::Rule => GHIDRA_RULES
                    .iter()
                    .find(|(n, _)| *n == u.name)
                    .map(|(_, g)| vec![*g])
                    .ok_or_else(|| UnitError::Unknown(u.name.to_owned()))?,
                _ => continue,
            };
            if expected != u.groups {
                return Err(UnitError::Groups {
                    name: u.name.to_owned(),
                    found: u.groups.iter().map(|s| (*s).to_owned()).collect(),
                    expected: expected.iter().map(|s| (*s).to_owned()).collect(),
                });
            }
        }
        if complete {
            for (n, _) in GHIDRA_ACTIONS {
                if self.find(n, UnitKind::Action, Origin::Ghidra).is_none() {
                    return Err(UnitError::Unknown(n.to_owned()));
                }
            }
            for (n, _) in GHIDRA_RULES {
                if self.find(n, UnitKind::Rule, Origin::Ghidra).is_none() {
                    return Err(UnitError::Unknown(n.to_owned()));
                }
            }
        }
        Ok(())
    }
}
