//! The `print raw` names a dump carries: call specs from `@callspecs`;
//! user-op names given by the caller (from the language).

use std::collections::HashMap;

use bk_core::{Address, SpaceManager};
use bk_testkit::oracle::StateDump;

use crate::ids::{CallSpecId, OpId};
use crate::print::{CallName, RawNames};
use crate::ssa::Ssa;

/// [`RawNames`] for a loaded dump.
#[derive(Clone, Debug, Default)]
pub struct DumpNames {
    calls: HashMap<u32, CallName>,
    userops: Vec<Option<String>>,
    /// Java operators (`>>>`).
    pub java: bool,
}

impl DumpNames {
    /// The call specs of `dump` (`C` records: name and entry), resolved in
    /// `spaces`.
    pub fn from_dump(dump: &StateDump, spaces: &SpaceManager) -> Self {
        let mut calls = HashMap::new();
        for c in &dump.call_specs {
            let entry = c.call.entry.as_ref().map_or(Address::INVALID, |a| {
                spaces
                    .space_by_name(&a.space)
                    .map_or(Address::INVALID, |s| Address::new(s.id(), a.offset))
            });
            calls.insert(
                c.call.call.0,
                CallName {
                    name: c.call.name.clone(),
                    entry,
                },
            );
        }
        Self {
            calls,
            userops: Vec::new(),
            java: false,
        }
    }

    /// Sets the user-op names by index (`getUserOpNames`).
    #[must_use]
    pub fn with_userops(mut self, names: Vec<Option<String>>) -> Self {
        self.userops = names;
        self
    }
}

impl RawNames for DumpNames {
    fn call_name(&self, call: CallSpecId) -> Option<CallName> {
        self.calls.get(&call.get()).cloned()
    }

    fn userop_name(&self, ssa: &Ssa, op: OpId, index: u64) -> Option<String> {
        // Ghidra's built-in user ops (userop.cc:30-35) come after the
        // language's.
        let builtin = match index {
            0x1000_0000 => Some("stringdata"),
            0x1000_0001 => Some("read_volatile"),
            0x1000_0002 => Some("write_volatile"),
            0x1000_0003 => Some("builtin_memcpy"),
            0x1000_0004 => Some("builtin_strncpy"),
            0x1000_0005 => Some("builtin_wcsncpy"),
            _ => None,
        };
        let base = match builtin {
            Some(b) => b.to_owned(),
            None => self.userops.get(usize::try_from(index).ok()?)?.clone()?,
        };
        // VolatileReadOp / VolatileWriteOp append the size (userop.cc:108).
        let sized = |size: i32| {
            if size == 8 {
                format!("{base}_8")
            } else {
                format!("{base}_{size}")
            }
        };
        match base.as_str() {
            "read_volatile" => Some(
                ssa.op_output(op)
                    .map_or_else(|| base.clone(), |o| sized(ssa.varnode_size(o))),
            ),
            "write_volatile" if ssa.op_num_inputs(op) >= 3 => Some(sized(
                ssa.op_input(op, 2).map_or(0, |v| ssa.varnode_size(v)),
            )),
            _ => Some(base),
        }
    }

    fn cpool_token(&self, _refs: &[u64]) -> Option<String> {
        None
    }

    fn java_operators(&self) -> bool {
        self.java
    }
}
