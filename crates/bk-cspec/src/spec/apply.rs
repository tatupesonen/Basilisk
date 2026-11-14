//! Applying a read specification to another space manager (spec 3: the
//! decompiler's program-wide manager is D07's; tests and tools need the
//! stack space too).

use bk_core::{Space, SpaceManager};

use super::CompilerSpec;
use crate::error::{CspecError, Result};

/// A space to create: index, name, base, register, size, and the flags
/// (reverse justified, grows negative, formal stack).
type SpaceDef<'a> = (
    u32,
    &'a str,
    bk_core::SpaceId,
    bk_core::VarnodeData,
    u32,
    (bool, bool, bool),
);

impl CompilerSpec {
    /// Adds the stack and spacebase spaces to `manager`, which must be in
    /// the state the reading manager was in before
    /// [`CompilerSpec::read`]: the same spaces, so the new spaces receive
    /// the same indices. Fails if an index differs.
    pub fn apply_spaces(&self, manager: &mut SpaceManager) -> Result<()> {
        let mut defs: Vec<SpaceDef<'_>> = Vec::new();
        if let Some(sp) = &self.stack_pointer {
            defs.push((
                sp.space.index(),
                "stack",
                sp.base,
                sp.register,
                sp.truncated_size,
                (sp.reverse_justify, sp.grows_negative, true),
            ));
        }
        for sb in &self.spacebases {
            defs.push((
                sb.space.index(),
                &sb.name,
                sb.base,
                sb.register,
                sb.register.size,
                (false, false, false),
            ));
        }
        defs.sort_by_key(|d| d.0);
        for (index, name, base, reg, trunc, (reverse, negative, formal)) in defs {
            if manager.num_spaces() != index {
                return Err(CspecError::new(format!(
                    "Space {name} would get index {} instead of {index}",
                    manager.num_spaces()
                )));
            }
            let base_space = manager.require(base)?.clone();
            let delay = reg
                .space()
                .and_then(|s| manager.space(s))
                .map_or(0, Space::delay)
                .wrapping_add(1);
            let big_endian = manager
                .default_code_space()
                .map_or_else(|| base_space.is_big_endian(), Space::is_big_endian);
            let id = manager.insert_space(Space::spacebase(
                name,
                index,
                trunc,
                &base_space,
                delay,
                formal,
                big_endian,
            )?)?;
            if reverse {
                manager.set_reverse_justified(id)?;
            }
            manager.add_spacebase_pointer(id, reg, trunc, negative)?;
        }
        Ok(())
    }

    /// Sets the memory properties the file names on `manager`: ranges
    /// without high pointers, dead-code delays and pointer-inference
    /// bounds (Ghidra `addNoHighPtr`, `setDeadcodeDelay`,
    /// `setInferPtrBounds`).
    pub fn apply_properties(&self, manager: &mut SpaceManager) -> Result<()> {
        for r in &self.no_high_ptr {
            manager.add_no_high_ptr(r)?;
        }
        for &(space, delay) in &self.deadcode_delays {
            manager.set_deadcode_delay(space, delay)?;
        }
        for r in &self.infer_ptr_bounds {
            manager.set_infer_ptr_bounds(r)?;
        }
        Ok(())
    }
}
