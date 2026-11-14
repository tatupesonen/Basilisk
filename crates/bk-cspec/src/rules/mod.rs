//! Model rules: how a `<rule>` assigns storage to a class of data types
//! (Ghidra `modelrules.cc`: `ModelRule`, the filters, the assign actions
//! and the primitive extractor; the shared actions live with the model).

mod action;
mod dualclass;
pub mod extractor;
pub mod filter;
mod multislot;

use bk_marshal::Decoder;

pub use action::AssignAction;
pub use dualclass::DualClassAssign;
pub use filter::{DatatypeFilter, QualifierFilter, SizeRestriction};
pub use multislot::{MultiMemberAssign, MultiSlotAssign};

use crate::error::Result;
use crate::ids::ELEM_RULE;
use crate::list::{AssignResult, Env, ParamList};
use crate::proto::ParameterPieces;
use crate::status::Status;
use crate::trial::ParamActive;
use crate::types::TypeHandle;

/// A rule for assigning storage (Ghidra `ModelRule`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRule {
    /// Which data types the rule applies to.
    pub filter: DatatypeFilter,
    /// Further conditions on the prototype.
    pub qualifier: Option<QualifierFilter>,
    /// Actions run before the assignment, kept only if it succeeds.
    pub preconditions: Vec<AssignAction>,
    /// How storage is assigned.
    pub assign: AssignAction,
    /// Actions run after a successful assignment.
    pub side_effects: Vec<AssignAction>,
}

impl ModelRule {
    /// A rule with a filter and an action only (Ghidra's constructor from
    /// components, used for the `pointermax` rule).
    pub(crate) fn simple(filter: DatatypeFilter, assign: AssignAction) -> Self {
        Self {
            filter,
            qualifier: None,
            preconditions: Vec::new(),
            assign,
            side_effects: Vec::new(),
        }
    }

    /// Reads a `<rule>` for `list`, whose entries are already decoded
    /// (Ghidra `ModelRule::decode`).
    pub(crate) fn decode(dec: &mut dyn Decoder<'_>, list: &ParamList) -> Result<Self> {
        let elem = dec.open_element_expecting(ELEM_RULE)?;
        let filter = DatatypeFilter::decode(dec)?;
        let mut qualifiers = Vec::new();
        while let Some(q) = QualifierFilter::decode(dec)? {
            qualifiers.push(q);
        }
        let qualifier = match qualifiers.len() {
            0 => None,
            1 => qualifiers.pop(),
            _ => Some(QualifierFilter::And(qualifiers)),
        };
        let mut preconditions = Vec::new();
        while let Some(p) = AssignAction::decode_precondition(dec, list)? {
            preconditions.push(p);
        }
        let assign = AssignAction::decode_action(dec, list)?;
        let mut side_effects = Vec::new();
        while dec.peek_element().is_some() {
            side_effects.push(AssignAction::decode_side_effect(dec, list)?);
        }
        dec.close_element(elem)?;
        Ok(Self {
            filter,
            qualifier,
            preconditions,
            assign,
            side_effects,
        })
    }

    /// Assigns storage if the filters pass (Ghidra
    /// `ModelRule::assignAddress`).
    pub(crate) fn assign_address(
        &self,
        list: &ParamList,
        env: &mut Env<'_>,
        dt: TypeHandle,
        pos: i32,
        status: &mut Status,
        res: &mut ParameterPieces,
    ) -> Result<AssignResult> {
        if !self.filter.accepts(&*env.types, dt) {
            return Ok(AssignResult::Fail);
        }
        if let Some(q) = &self.qualifier
            && !q.accepts(&*env.types, env.proto, pos)
        {
            return Ok(AssignResult::Fail);
        }
        let mut tmp = status.clone();
        for p in &self.preconditions {
            p.assign_address(list, env, dt, pos, &mut tmp, res)?;
        }
        let code = self
            .assign
            .assign_address(list, env, dt, pos, &mut tmp, res)?;
        if code != AssignResult::Fail {
            *status = tmp;
            for s in &self.side_effects {
                s.assign_address(list, env, dt, pos, status, res)?;
            }
        }
        Ok(code)
    }

    /// Whether the trials can be return storage under this rule's action
    /// (Ghidra `fillinOutputMap`).
    pub(crate) fn fillin_output_map(&self, list: &ParamList, active: &mut ParamActive) -> bool {
        self.assign.fillin_output_map(list, active)
    }

    /// Whether the action takes part in return value recovery (Ghidra
    /// `canAffectFillinOutput`).
    pub fn can_affect_fillin_output(&self) -> bool {
        self.assign.can_affect_fillin_output()
    }
}
