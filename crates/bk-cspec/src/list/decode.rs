//! Reading an `<input>` or `<output>` (Ghidra `ParamListStandard::decode`,
//! `parsePentry`, `parseGroup`, `calcDelay`, `ParamListStandardOut::
//! initialize`).

use bk_core::{SpaceManager, SpaceType, VarnodeData};
use bk_marshal::Decoder;

use super::resolver::Resolver;
use super::{ListKind, ParamList};
use crate::effect::{EffectKind, EffectRecord};
use crate::entry::{EntryContext, decode_entry, order_within_group};
use crate::error::{CspecError, Result};
use crate::ids::{
    ATTRIB_KILLEDBYCALL, ATTRIB_POINTERMAX, ATTRIB_SEPARATEFLOAT, ATTRIB_THISBEFORERETPOINTER,
    ELEM_GROUP, ELEM_PENTRY, ELEM_RULE,
};
use crate::rules::{AssignAction, DatatypeFilter, ModelRule, SizeRestriction};
use crate::types::TypeClass;

struct ListReader<'m> {
    manager: &'m SpaceManager,
    list: ParamList,
    normal_stack: bool,
    split_float: bool,
}

/// Reads the list element that is next, of the given kind; effects of
/// `killedbycall` lists are added to `effects`.
pub(crate) fn decode_list(
    dec: &mut dyn Decoder<'_>,
    manager: &SpaceManager,
    kind: ListKind,
    effects: &mut Vec<EffectRecord>,
    normal_stack: bool,
) -> Result<ParamList> {
    let mut r = ListReader {
        manager,
        list: ParamList::empty(kind),
        normal_stack,
        split_float: true,
    };
    let mut pointermax: i64 = 0;
    let elem = dec
        .open_element()?
        .ok_or_else(|| CspecError::new("Missing parameter list"))?;
    while let Some(attr) = dec.next_attribute()? {
        if attr == ATTRIB_POINTERMAX {
            pointermax = dec.read_signed()?;
        } else if attr == ATTRIB_THISBEFORERETPOINTER {
            r.list.thisbeforeret = dec.read_bool()?;
        } else if attr == ATTRIB_KILLEDBYCALL {
            r.list.auto_killed_by_call = dec.read_bool()?;
        } else if attr == ATTRIB_SEPARATEFLOAT {
            r.split_float = dec.read_bool()?;
        }
    }
    while let Some(sub) = dec.peek_element() {
        if sub == ELEM_PENTRY {
            let group = r.list.numgroup;
            r.parse_pentry(dec, effects, group, false)?;
        } else if sub == ELEM_GROUP {
            r.parse_group(dec, effects)?;
        } else if sub == ELEM_RULE {
            break;
        } else {
            // Ghidra's loop never consumes such an element and does not end.
            return Err(CspecError::new("Unknown element in parameter list"));
        }
    }
    while let Some(sub) = dec.peek_element() {
        if sub != ELEM_RULE {
            return Err(CspecError::new(
                "<pentry> and <group> elements must come before any <modelrule>",
            ));
        }
        let rule = ModelRule::decode(dec, &r.list)?;
        r.list.rules.push(rule);
    }
    dec.close_element(elem)?;
    let mut list = r.list;
    list.resource_start.push(list.numgroup);
    list.maxdelay = list
        .entries
        .iter()
        .map(|e| manager.space(e.space()).map_or(0, bk_core::Space::delay))
        .max()
        .unwrap_or(0)
        .max(0);
    list.resolver = Resolver::build(&list.entries);
    if pointermax > 0 {
        let min = i32::try_from(pointermax.saturating_add(1)).unwrap_or(i32::MAX);
        list.rules.push(ModelRule::simple(
            DatatypeFilter::Size(SizeRestriction::range(min, 0)),
            AssignAction::ConvertToPointer {
                space: list.spacebase(),
            },
        ));
    }
    if kind.is_output() {
        list.use_fillin_fallback = !list.rules.iter().any(ModelRule::can_affect_fillin_output);
        if list.use_fillin_fallback {
            list.auto_killed_by_call = true;
        }
    }
    Ok(list)
}

impl ListReader<'_> {
    /// Ghidra `parsePentry`.
    fn parse_pentry(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        effects: &mut Vec<EffectRecord>,
        group: i32,
        grouped: bool,
    ) -> Result<()> {
        let last_class = self.list.entries.last().map_or(TypeClass::Class4, |e| {
            if e.is_grouped() {
                TypeClass::General
            } else {
                e.type_class()
            }
        });
        let ctx = EntryContext {
            group,
            normal_stack: self.normal_stack,
            grouped,
        };
        let entry = decode_entry(dec, self.manager, ctx, &self.list.entries)
            .map_err(|e| e.at(&format!("pentry[{}]", self.list.entries.len())))?;
        if self.split_float {
            let current = if grouped {
                TypeClass::General
            } else {
                entry.type_class()
            };
            if last_class != current {
                if last_class < current {
                    return Err(CspecError::new(
                        "parameter list entries must be ordered by storage class",
                    ));
                }
                self.list.resource_start.push(group);
            }
        }
        if !entry.is_stack_spill() && self.list.auto_killed_by_call {
            effects.push(EffectRecord::new(
                VarnodeData::new(entry.space(), entry.base(), entry.size() as u32),
                EffectKind::KilledByCall,
            ));
        }
        let maxgroup = entry
            .all_groups()
            .last()
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if maxgroup > self.list.numgroup {
            self.list.numgroup = maxgroup;
        }
        self.list.entries.push(entry);
        Ok(())
    }

    /// Ghidra `parseGroup`.
    fn parse_group(
        &mut self,
        dec: &mut dyn Decoder<'_>,
        effects: &mut Vec<EffectRecord>,
    ) -> Result<()> {
        let base = self.list.numgroup;
        let elem = dec.open_element_expecting(ELEM_GROUP)?;
        let first = self.list.entries.len();
        while dec.peek_element().is_some() {
            self.parse_pentry(dec, effects, base, true)?;
            let n = self.list.entries.len();
            let Some(cur) = self.list.entries.last() else {
                break;
            };
            if cur.space_type == SpaceType::Join {
                return Err(CspecError::new(
                    "<pentry> in the join space not allowed in <group> tag",
                ));
            }
            if n >= first + 2
                && let Some(prev1) = self.list.entries.get(n - 2)
            {
                order_within_group(prev1, cur)?;
                if n >= first + 3
                    && let Some(prev2) = self.list.entries.get(n - 3)
                {
                    order_within_group(prev2, cur)?;
                }
            }
        }
        dec.close_element(elem)?;
        Ok(())
    }
}
