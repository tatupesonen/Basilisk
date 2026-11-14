//! Arbitrary text read as a `.cspec` by `bk-cspec` against a small
//! Toy-like architecture (spaces ram, register, unique, join; registers
//! r0–r12, sp, lr), then each decoded model classifies trials made from
//! its own entries. The process must not panic, overflow the stack or hang.

#![no_main]

use std::sync::Arc;

use bk_core::{RegisterLookup, Space, SpaceId, SpaceManager, VarnodeData};
use bk_cspec::{CompilerSpec, ParamActive, ReadOptions};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct Regs(Vec<(String, VarnodeData)>);

impl RegisterLookup for Regs {
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.0.iter().find(|(n, _)| n == name).map(|r| r.1)
    }
    fn register_name(&self, _: SpaceId, _: u64, _: u32) -> Option<&str> {
        None
    }
    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        let v = VarnodeData::new(space, offset, size);
        self.0.iter().find(|(_, r)| *r == v).map(|r| r.0.as_str())
    }
}

fn manager() -> Option<SpaceManager> {
    let mut m = SpaceManager::new();
    m.insert_space(Space::constant()).ok()?;
    m.insert_space(Space::other()).ok()?;
    m.insert_space(Space::processor("ram", false, 4, 1, 2, true, 0, 0).ok()?).ok()?;
    m.insert_space(Space::processor("register", false, 2, 1, 3, false, 0, 0).ok()?).ok()?;
    m.insert_space(Space::unique(4, false).ok()?).ok()?;
    m.insert_space(Space::join(5, false).ok()?).ok()?;
    m.set_default_code_space(SpaceId::new(2)).ok()?;
    let names = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr"];
    let regs = names
        .iter()
        .enumerate()
        .map(|(i, n)| ((*n).to_owned(), VarnodeData::new(SpaceId::new(3), 0x1000 + 4 * i as u64, 4)))
        .collect();
    m.set_registers(Arc::new(Regs(regs)));
    Some(m)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Some(mut m) = manager() else { return };
    let Ok(spec) = CompilerSpec::read(text, &mut m, ReadOptions::default()) else { return };
    for model in spec.models() {
        for list in [model.input(), model.output()] {
            let mut active = ParamActive::new(false);
            for e in list.entries().iter().take(16) {
                let size = if e.align() != 0 { e.align() } else { e.size() };
                let i = active.register_trial(&m, e.address(), size);
                if let Some(t) = active.trial_mut(i) {
                    t.mark_active();
                }
            }
            let _ = list.fillin_map(&m, &mut active);
        }
    }
});
