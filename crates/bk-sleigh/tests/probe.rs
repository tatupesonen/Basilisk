#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]
mod common;
use std::sync::Arc;
#[test]
fn probe() {
    let Some(reference) = common::reference() else { return };
    let id = std::env::var("BK_LANGS").unwrap();
    let lang = common::load(&reference, &id);
    let mut rng = common::directed::Rng::new(1);
    let plan = common::directed::plan(&lang, 1, &mut rng);
    let sla = lang.sla();
    let mut shown = 0;
    let mut dec = bk_sleigh::Decoder::new(Arc::clone(&lang));
    for (config, samples) in &plan.groups {
        let db = common::sweep::start_context(&lang, config);
        for (t, s) in samples {
            if plan.hit.contains(t) { continue; }
            if shown > 12 { return; }
            shown += 1;
            let tg = &plan.targets[*t];
            let c = sla.constructor(bk_sla::ConstructorId::new(tg.constructor)).unwrap();
            let r = dec.decode(bk_core::Address::new(lang.default_space(), 0), &bk_sleigh::SliceBytes::new(0, s), &db).map(|p| p.root().unwrap().constructor().unwrap().index());
            let got = match r { Ok(g) => { let gc = sla.constructor(bk_sla::ConstructorId::new(g)).unwrap(); format!("ctor {} line {}", g, gc.line) }, Err(e) => e.to_string() };
            eprintln!("target ctor {} line {} config {:?} ctx {:?} instr {:?}\n   bytes {:02x?}\n   got {}", tg.constructor, c.line, config, tg.context, tg.instruction, s, got);
        }
    }
}
