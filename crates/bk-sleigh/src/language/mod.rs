//! A loaded language: the compiled model and everything derived from it
//! once, shared by every decoder (Ghidra `Sleigh`/`SleighBase` after
//! `initialize`, plus the language set-up `SleighArchitecture` applies).

mod load;
mod registers;
mod setup;
pub(crate) mod tables;

use std::sync::Arc;

use bk_core::{Address, SpaceId, SpaceKind, SpaceManager};
use bk_lang::LanguageId;
use bk_pcode::FloatFormats;
use bk_sla::Sla;

pub use registers::RegisterTable;
pub(crate) use setup::InitialSetting;

use crate::context::{ContextDb, ContextVar};
use crate::error::{RawForm, RawText};
use tables::Tables;

/// What error messages need to print an address of a space.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SpaceText {
    shortcut: char,
    form: RawForm,
}

/// A compiled language ready for decoding: its model, address spaces,
/// registers, user ops, context variables and context defaults.
///
/// Immutable after loading, `Send + Sync`; share it as `Arc<Language>` and
/// give each thread its own [`Decoder`](crate::Decoder).
#[derive(Debug)]
pub struct Language {
    id: Option<LanguageId>,
    sla: Arc<Sla>,
    spaces: SpaceManager,
    registers: Arc<RegisterTable>,
    user_ops: Vec<Option<Box<str>>>,
    context_vars: Vec<ContextVar>,
    context_words: usize,
    default_space: SpaceId,
    space_text: Vec<SpaceText>,
    initial: Vec<InitialSetting>,
    float_formats: FloatFormats,
    pub(crate) tables: Tables,
}

impl Language {
    /// The language id, when loaded through a registry.
    pub fn id(&self) -> Option<&LanguageId> {
        self.id.as_ref()
    }

    /// The compiled model.
    pub fn sla(&self) -> &Arc<Sla> {
        &self.sla
    }

    /// The address spaces, with the register table installed as their
    /// register lookup.
    pub fn spaces(&self) -> &SpaceManager {
        &self.spaces
    }

    /// The register table.
    pub fn registers(&self) -> &Arc<RegisterTable> {
        &self.registers
    }

    /// The name of user op `index` (Ghidra `getUserOpNames`; gaps are
    /// `None`).
    pub fn user_op_name(&self, index: usize) -> Option<&str> {
        self.user_ops.get(index).and_then(|name| name.as_deref())
    }

    /// The number of user-op slots (the largest index plus one).
    pub fn num_user_ops(&self) -> usize {
        self.user_ops.len()
    }

    /// The context variables, in name order.
    pub fn context_variables(&self) -> &[ContextVar] {
        &self.context_vars
    }

    /// The context variable called `name`.
    pub fn context_variable(&self, name: &str) -> Option<&ContextVar> {
        self.context_vars
            .binary_search_by(|var| var.name().cmp(name))
            .ok()
            .and_then(|slot| self.context_vars.get(slot))
    }

    /// The number of 32-bit context words.
    pub fn context_words(&self) -> usize {
        self.context_words
    }

    /// The default code space.
    pub fn default_space(&self) -> SpaceId {
        self.default_space
    }

    /// Whether the language is big endian.
    pub fn is_big_endian(&self) -> bool {
        self.sla.header().big_endian
    }

    /// Instruction alignment in bytes (1 = none).
    pub fn alignment(&self) -> u32 {
        self.sla.header().align.max(1) as u32
    }

    /// The first offset in the unique space free for analysis temporaries.
    pub fn unique_base(&self) -> u32 {
        self.sla.header().unique_base
    }

    /// The address bits folded into temporaries for `crossbuild`.
    pub fn unique_mask(&self) -> u32 {
        self.sla.header().unique_mask
    }

    /// The largest delay-slot byte count of any constructor.
    pub fn max_delay(&self) -> u32 {
        self.sla.header().max_delay
    }

    /// The number of named p-code sections.
    pub fn num_sections(&self) -> u32 {
        self.sla.header().num_sections
    }

    /// The floating-point formats (Ghidra's defaults, `setDefaultFloatFormats`).
    pub fn float_formats(&self) -> &FloatFormats {
        &self.float_formats
    }

    /// A fresh context database with the processor specification's
    /// `<context_set>` values applied as region sets and its `<tracked_set>`
    /// values stored (Ghidra `ContextInternal::decodeFromSpec`).
    pub fn initial_context(&self) -> ContextDb {
        let mut db = self.empty_context();
        for setting in &self.initial {
            setting.apply(&mut db, &self.context_vars);
        }
        db
    }

    /// A context database of the language's size with nothing set.
    pub fn empty_context(&self) -> ContextDb {
        let mut db = ContextDb::new(self.context_words);
        db.set_space_limits(
            (0..self.spaces.num_spaces())
                .map(|index| self.spaces.space_at(index).map_or(u64::MAX, bk_core::Space::highest))
                .collect(),
        );
        db
    }

    /// Sets a variable over the whole default code space, as `pcodedump`'s
    /// `--context NAME=VALUE` does. `false` if there is no such variable.
    pub fn set_context_everywhere(&self, db: &mut ContextDb, name: &str, value: u32) -> bool {
        let Some(var) = self.context_variable(name) else {
            return false;
        };
        db.set_variable_region(var, Address::new(self.default_space, 0), None, value);
        true
    }

    /// The text error messages use for an address: the space's shortcut and
    /// its raw form.
    pub(crate) fn raw_text(&self, addr: Address) -> RawText {
        let text = addr
            .space()
            .and_then(|space| self.space_text.get(space.index() as usize));
        match text {
            Some(text) => RawText::new(text.shortcut, addr.offset(), text.form),
            None => RawText::new(' ', addr.offset(), RawForm::Plain),
        }
    }

    fn compute_space_text(spaces: &SpaceManager) -> Vec<SpaceText> {
        (0..spaces.num_spaces())
            .map(|index| match spaces.space_at(index) {
                Some(space) => SpaceText {
                    shortcut: space.shortcut().unwrap_or(' '),
                    form: match space.kind() {
                        SpaceKind::Constant | SpaceKind::Other | SpaceKind::Join => RawForm::Plain,
                        _ => RawForm::Padded {
                            size: space.addr_size().min(255) as u8,
                            word: space.word_size(),
                        },
                    },
                },
                None => SpaceText {
                    shortcut: ' ',
                    form: RawForm::Plain,
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_types_are_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<Language>();
        check::<ContextDb>();
        check::<Arc<Language>>();
    }
}
