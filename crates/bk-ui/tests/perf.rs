//! Frame time while scrolling a ten-million-row listing (spec 5,
//! performance). Run in release:
//! `cargo test -p bk-ui --release --test perf -- --ignored --nocapture`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    clippy::cast_precision_loss,
    reason = "test code"
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bk_ui::demo::synthetic::SyntheticProgram;
use bk_ui::design::{Density, ThemeKind};
use bk_ui::model::{Address, Location, ProgramSource};
use egui_kittest::kittest::Queryable;

const ROWS: u64 = 10_000_000;

fn stats(name: &str, mut v: Vec<Duration>) -> (f64, f64, f64) {
    v.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    let mean = v.iter().map(|d| ms(*d)).sum::<f64>() / v.len() as f64;
    let p95 = ms(v[v.len() * 95 / 100]);
    let max = ms(*v.last().unwrap());
    eprintln!(
        "{name}: {} frames, mean {mean:.2} ms, p95 {p95:.2} ms, max {max:.2} ms",
        v.len()
    );
    (mean, p95, max)
}

#[test]
#[ignore = "benchmark: run in release with --ignored"]
fn scrolling_ten_million_rows() {
    let source = Arc::new(SyntheticProgram::with_rows(ROWS));
    assert!(source.listing_len().unwrap() >= ROWS);
    let opener: bk_ui::shell::tool::Opener =
        Arc::new(move || Ok(Arc::clone(&source) as Arc<dyn ProgramSource>));
    let mut h = common::harness_with(common::prefs(ThemeKind::Dark, Density::Comfortable), opener);
    common::settle(&mut h);
    let listing = h.get_by_label_contains("Listing: synthetic").rect();
    let over = listing.center() + egui::vec2(0.0, 200.0);
    let ppp = h.ctx.pixels_per_point();

    // One frame: input → layout → tessellation (what the UI thread does
    // before the GPU gets the triangles).
    let mut frame = |h: &mut egui_kittest::Harness<'static, bk_ui::BasiliskApp>| {
        let t0 = Instant::now();
        h.step();
        let shapes = h.output().shapes.clone();
        let _ = h.ctx.tessellate(shapes, ppp);
        t0.elapsed()
    };

    let links = |h: &egui_kittest::Harness<'static, bk_ui::BasiliskApp>| -> Vec<String> {
        use egui_kittest::kittest::NodeT as _;
        h.query_all(egui_kittest::kittest::by())
            .filter_map(|n| n.accesskit_node().label())
            .filter(|l| l.starts_with("FUN_"))
            .collect()
    };
    let before = links(&h);
    // Wheel scrolling: 3 rows a frame for 600 frames.
    let mut wheel = Vec::new();
    for _ in 0..600 {
        h.event(egui::Event::PointerMoved(over));
        h.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, -60.0),
            modifiers: egui::Modifiers::NONE,
            phase: egui::TouchPhase::Move,
        });
        wheel.push(frame(&mut h));
    }
    let (_, wheel_p95, _) = stats("wheel scroll (60 px/frame)", wheel);
    common::settle(&mut h);
    // 600 frames × 3 rows moved the listing about 17 functions on.
    assert_ne!(links(&h), before, "the listing did not scroll");

    // Jumps across the whole program (go to addresses spread over 10 M rows).
    let mut jumps = Vec::new();
    for i in 0..200u64 {
        let k = (i * 7919) % 90_000;
        let a = Address(0x40_0000 + k * 0x200 + 0x40);
        h.state()
            .tool()
            .ws
            .as_mut()
            .unwrap()
            .shared
            .nav
            .go(Location::at(a));
        jumps.push(frame(&mut h));
        jumps.push(frame(&mut h));
    }
    let (_, jump_p95, _) = stats("go-to jumps across 10 M rows", jumps);
    // The last jump's function is shown once its data has arrived.
    let last = 0x40_0000 + ((199 * 7919) % 90_000) * 0x200;
    common::settle(&mut h);
    h.get_by_label_contains(&format!("Decompile: FUN_{last:08x}"));

    // Steady state on one screen (no input).
    let mut idle = Vec::new();
    for _ in 0..200 {
        idle.push(frame(&mut h));
    }
    stats("idle redraw", idle);

    // The budget: 60 frames per second, 16.7 ms.
    assert!(wheel_p95 < 16.7, "wheel p95 {wheel_p95} ms");
    assert!(jump_p95 < 16.7, "jump p95 {jump_p95} ms");
}
