//! Building the address spaces a file declares (Ghidra
//! `SleighBase::decodeSlaSpaces`, `features/sla.md` 4.6).

use bk_core::{Space, SpaceId, SpaceManager};

use crate::error::SlaError;
use crate::model::Sla;
use crate::model::symbol::SpaceKind;

/// The constant space's name; it has index 0 and is not in the file.
pub const CONSTANT_SPACE_NAME: &str = "const";

impl Sla {
    /// Builds the space manager: the constant space, then each declared
    /// space in file order, then the default code space.
    ///
    /// As in Ghidra, the unique space takes the language's endianness and
    /// ignores the file's other attributes, the other space is always
    /// `OTHER` (index 1, little endian), and a processor space takes its
    /// own `bigendian` attribute with a dead-code delay equal to its delay.
    pub fn build_spaces(&self) -> Result<SpaceManager, SlaError> {
        let mut manager = SpaceManager::new();
        manager.insert_space(Space::constant())?;
        for record in self.space_records() {
            let space = match record.kind {
                SpaceKind::Unique => Space::unique(record.index, self.header.big_endian)?,
                SpaceKind::Other => {
                    if record.index != 1 {
                        return Err(SlaError::structure(
                            "sleigh/spaces/space_other",
                            format!("the OTHER space has index {}, not 1", record.index),
                        ));
                    }
                    Space::other()
                }
                SpaceKind::Processor => Space::processor(
                    self.text(record.name),
                    record.big_endian,
                    record.size.max(0) as u32,
                    record.word_size.max(1) as u32,
                    record.index,
                    record.physical,
                    record.delay,
                    record.delay,
                )?,
            };
            manager.insert_space(space)?;
        }
        manager.set_default_code_space(SpaceId::new(self.default_space))?;
        Ok(manager)
    }
}
