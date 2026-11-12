//! Helpers shared by the interface tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

use std::path::Path;
use std::time::{Duration, Instant};

use bk_ui::BasiliskApp;
use bk_ui::design::{Density, ThemeKind};
use bk_ui::model::{Location, ProgramSource};
use bk_ui::shell::Prefs;
use egui_kittest::Harness;

/// Preferences for tests: a theme and density, Ghidra's layout, the demo.
pub(crate) fn prefs(theme: ThemeKind, density: Density) -> Prefs {
    Prefs {
        theme,
        density,
        ..Prefs::default()
    }
}

/// A headless harness (no GPU) on the demo program.
pub(crate) fn harness() -> Harness<'static, BasiliskApp> {
    harness_with(prefs(ThemeKind::Dark, Density::Comfortable), bk_ui::shell::app::demo_opener())
}

/// A headless harness with `prefs` and an opener.
pub(crate) fn harness_with(prefs: Prefs, opener: bk_ui::shell::tool::Opener) -> Harness<'static, BasiliskApp> {
    let ctx = egui::Context::default();
    let app = BasiliskApp::new(&ctx, prefs, opener);
    Harness::builder()
        .with_size(egui::vec2(1440.0, 900.0))
        .build_ui_state(|ui, app: &mut BasiliskApp| app.frame(ui), app)
}

/// A harness that can render images.
pub(crate) fn gpu_harness(theme: ThemeKind, density: Density, w: f32, h: f32) -> Harness<'static, BasiliskApp> {
    let ctx = egui::Context::default();
    let app = BasiliskApp::new(&ctx, prefs(theme, density), bk_ui::shell::app::demo_opener());
    Harness::builder()
        .with_size(egui::vec2(w, h))
        .with_pixels_per_point(2.0)
        .wgpu()
        .build_ui_state(|ui, app: &mut BasiliskApp| app.frame(ui), app)
}

/// Steps until background work is done and the screen is still.
pub(crate) fn settle(h: &mut Harness<'_, BasiliskApp>) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut quiet = 0;
    while Instant::now() < deadline {
        h.step();
        let busy = h.state().tool().ws.as_ref().is_some_and(|w| w.client.busy() > 0);
        if busy {
            quiet = 0;
            std::thread::yield_now();
        } else {
            quiet += 1;
            if quiet > 6 {
                return;
            }
        }
    }
    panic!("the interface did not settle");
}

/// Goes to a symbol by name (through the data source, as Go To does).
pub(crate) fn go_to(h: &mut Harness<'_, BasiliskApp>, name: &str) {
    let addr = {
        let src = bk_ui::demo::DemoProgram::licd().unwrap();
        src.lookup(name, 5).unwrap().into_iter().find(|s| &*s.name == name).unwrap().address
    };
    h.state().tool().ws.as_mut().unwrap().shared.nav.go(Location::at(addr));
}

/// Renders and saves a PNG.
pub(crate) fn save(h: &mut Harness<'_, BasiliskApp>, path: &Path) {
    let img = h.render().unwrap();
    img.save(path).unwrap();
}
