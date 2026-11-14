//! The label check of a template, kept apart from reading.
//!
//! Ghidra's decoders (`ConstructTpl::decode`, `OpTpl::decode` in
//! `semantics.cc`; `ConstructTpl.decode` in the Java `template` package)
//! read label numbers without checking them, and its snippet compiler
//! (`PcodeSnippet`) produces a branch to a label that is never placed
//! without complaint. The template fails only when p-code is built from it:
//! `PcodeCacher::resolveRelatives` (`sleigh.cc`) and Java's
//! `PcodeEmit.resolveRelatives` throw "Reference to non-existant sleigh
//! label", which `bk-sleigh` returns as `LiftError::MissingLabel`. So
//! reading accepts such a template, and a consumer that wants to refuse it
//! before use calls [`Template::check_labels`] or [`Sla::check_labels`].
//! Everything Ghidra's SLEIGH compiler writes passes: it refuses a label
//! that is used but never placed.

use std::fmt::Display;

use bk_pcode::OpCode;

use super::fail;
use super::tables::CtorPath;
use crate::error::SlaError;
use crate::model::Sla;
use crate::model::handles::SymbolId;
use crate::model::symbol::SymbolKind;
use crate::model::template::{ConstTpl, Template, TemplateRef};

/// Checks the labels of one template: every `LABEL` directive and every
/// `const_relative` names a label below the template's `labels` count, and
/// every op whose first input is a `const_relative` (the operand Ghidra
/// resolves to a branch displacement) names a label that a `LABEL`
/// directive of the same template places.
pub(crate) fn check_labels(path: &dyn Display, template: &TemplateRef<'_>) -> Result<(), SlaError> {
    let count = u64::try_from(template.header().labels).unwrap_or(0);
    let placed = |label: u64| {
        template.ops().iter().any(|op| {
            op.opcode == OpCode::PtrAdd
                && matches!(
                    template.inputs(op).first().map(|v| v.offset),
                    Some(ConstTpl::Real(l)) if l == label
                )
        })
    };
    for (number, op) in template.ops().iter().enumerate() {
        let inputs = template.inputs(op);
        if op.opcode == OpCode::PtrAdd {
            if let Some(ConstTpl::Real(label)) = inputs.first().map(|v| v.offset)
                && label >= count
            {
                return fail(
                    format!("{path} op {number}"),
                    format!("label {label} is not below {count}"),
                );
            }
            continue;
        }
        let varnodes = template.output(op).into_iter().chain(inputs);
        for vn in varnodes {
            for c in [vn.space, vn.offset, vn.size] {
                if let ConstTpl::Relative(label) = c
                    && label >= count
                {
                    return fail(
                        format!("{path} op {number}"),
                        format!("label {label} is not below {count}"),
                    );
                }
            }
        }
        if let Some(ConstTpl::Relative(label)) = inputs.first().map(|v| v.offset)
            && !placed(label)
        {
            return fail(
                format!("{path} op {number}"),
                format!("label {label} is never placed"),
            );
        }
    }
    Ok(())
}

impl Template {
    /// Checks the template's labels: every label it refers to is below its
    /// label count and every branch to a label names one the template
    /// places. Reading does not check this, as Ghidra does not; building
    /// p-code from a template that fails it fails where the branch is
    /// resolved ("Reference to non-existant sleigh label").
    pub fn check_labels(&self) -> Result<(), SlaError> {
        check_labels(&"construct_tpl", &self.as_ref())
    }
}

impl Sla {
    /// [`Template::check_labels`] for every template of every constructor.
    /// Every file Ghidra's SLEIGH compiler writes passes.
    pub fn check_labels(&self) -> Result<(), SlaError> {
        for (index, symbol) in self.a.symbols.iter().enumerate() {
            let SymbolKind::Subtable(table) = symbol.kind else {
                continue;
            };
            let id = SymbolId::new(u32::try_from(index).unwrap_or(u32::MAX));
            for ct in 0..table.num_constructors() {
                let Some(ctor) = table.constructor(ct).and_then(|c| self.constructor(c)) else {
                    continue;
                };
                let path = CtorPath::new(self, id, ct, ctor);
                for template in self.template_ids(ctor).filter_map(|t| self.template(t)) {
                    check_labels(&path, &template)?;
                }
            }
        }
        Ok(())
    }
}
