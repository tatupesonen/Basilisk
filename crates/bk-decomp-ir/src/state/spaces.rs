//! A space manager rebuilt from a dump's `@spaces` records, so a dump can
//! be read without the architecture (the registers come from elsewhere).

use std::sync::Arc;

use bk_core::{RegisterLookup, Space, SpaceManager};
use bk_testkit::oracle::StateDump;

use super::StateError;

const BIG_ENDIAN: u32 = 1;
const FORMAL_STACK: u32 = 0x20;
const HAS_PHYSICAL: u32 = 0x200;

/// The spaces of the dump's `@spaces`, with `registers` attached and the
/// space of the function's entry as the default code space. Each space's
/// shortcut must come out as the dump has it.
pub fn spaces_from_dump(
    dump: &StateDump,
    registers: Arc<dyn RegisterLookup>,
) -> Result<SpaceManager, StateError> {
    let mut m = SpaceManager::new();
    let err = |name: &str| {
        let name = name.to_owned();
        move |source| StateError::Space { name, source }
    };
    let mut records: Vec<_> = dump.spaces.iter().collect();
    records.sort_by_key(|r| r.index);
    let mut base_for_spacebase: Option<Space> = None;
    for r in records {
        let index = u32::try_from(r.index).map_err(|source| StateError::Convert {
            source,
            what: "space index",
            value: r.index.to_string(),
        })?;
        let big = r.flags & BIG_ENDIAN != 0;
        let space = match r.kind {
            0 => Space::constant(),
            1 if r.name == "OTHER" => Space::other(),
            1 => Space::processor(
                &r.name,
                big,
                r.addr_size,
                r.word_size,
                index,
                r.flags & HAS_PHYSICAL != 0,
                r.delay,
                r.deadcode_delay,
            )
            .map_err(err(&r.name))?,
            2 => {
                let base = base_for_spacebase.clone().ok_or_else(|| {
                    super::inconsistent("spacebase space before any processor space", &r.name)
                })?;
                Space::spacebase(
                    &r.name,
                    index,
                    r.addr_size,
                    &base,
                    r.delay,
                    r.flags & FORMAL_STACK != 0,
                    big,
                )
                .map_err(err(&r.name))?
            }
            3 => Space::unique(index, big).map_err(err(&r.name))?,
            4 => Space::fspec(index).map_err(err(&r.name))?,
            5 => Space::iop(index).map_err(err(&r.name))?,
            6 => Space::join(index, big).map_err(err(&r.name))?,
            k => {
                return Err(StateError::Range {
                    what: "space type",
                    value: k.to_string(),
                });
            }
        };
        if r.kind == 1 && r.flags & HAS_PHYSICAL != 0 && base_for_spacebase.is_none() {
            base_for_spacebase = Some(space.clone());
        }
        m.insert_space(space).map_err(err(&r.name))?;
    }
    for r in &dump.spaces {
        let got = m
            .space_by_name(&r.name)
            .and_then(Space::shortcut)
            .map_or_else(|| "-".to_owned(), |c| c.to_string());
        if got != r.shortcut {
            return Err(super::inconsistent(
                "space shortcut",
                format!("{}: dump {}, rebuilt {got}", r.name, r.shortcut),
            ));
        }
    }
    let entry_space = &dump.function.function.entry.space;
    if let Some(id) = m.space_by_name(entry_space).map(Space::id) {
        m.set_default_code_space(id).map_err(err(entry_space))?;
    }
    m.set_registers(registers);
    Ok(m)
}
