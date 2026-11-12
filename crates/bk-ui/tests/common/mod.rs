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
        .with_step_dt(1.0 / 60.0)
        .build_ui_state(|ui, app: &mut BasiliskApp| app.frame(ui), app)
}

/// A harness that can render images.
pub(crate) fn gpu_harness(theme: ThemeKind, density: Density, w: f32, h: f32) -> Harness<'static, BasiliskApp> {
    let ctx = egui::Context::default();
    let app = BasiliskApp::new(&ctx, prefs(theme, density), bk_ui::shell::app::demo_opener());
    Harness::builder()
        .with_size(egui::vec2(w, h))
        .with_pixels_per_point(2.0)
        .with_step_dt(1.0 / 60.0)
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

/// A source that records every command sent to it (and applies it to the
/// demo program underneath).
#[derive(Debug)]
pub(crate) struct Recording {
    inner: bk_ui::demo::DemoProgram,
    pub(crate) commands: std::sync::Arc<parking_lot::Mutex<Vec<bk_ui::model::Command>>>,
}

macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $ret { self.inner.$name($($arg),*) })*
    };
}

impl ProgramSource for Recording {
    fn info(&self) -> bk_ui::model::ProgramInfo {
        self.inner.info()
    }
    forward! {
        listing_len() -> bk_ui::model::SourceResult<u64>;
        listing_rows(start: bk_ui::model::RowIndex, count: u32) -> bk_ui::model::SourceResult<Vec<bk_ui::model::ListingRow>>;
        rows_for_address(address: bk_ui::model::Address) -> bk_ui::model::SourceResult<bk_ui::model::RowSpan>;
        memory_blocks() -> bk_ui::model::SourceResult<Vec<bk_ui::model::MemoryBlock>>;
        functions(q: &bk_ui::model::TableQuery<bk_ui::model::FunctionColumn>) -> bk_ui::model::SourceResult<bk_ui::model::Page<bk_ui::model::FunctionInfo>>;
        function_containing(address: bk_ui::model::Address) -> bk_ui::model::SourceResult<Option<bk_ui::model::FunctionInfo>>;
        decompile(address: bk_ui::model::Address) -> bk_ui::model::SourceResult<bk_ui::model::DecompiledFunction>;
        symbols(category: bk_ui::model::SymbolCategory, filter: &str, limit: u32) -> bk_ui::model::SourceResult<bk_ui::model::Page<bk_ui::model::Symbol>>;
        lookup(query: &str, limit: u32) -> bk_ui::model::SourceResult<Vec<bk_ui::model::Symbol>>;
        references_to(address: bk_ui::model::Address, limit: u32) -> bk_ui::model::SourceResult<bk_ui::model::Page<bk_ui::model::Reference>>;
        strings(q: &bk_ui::model::TableQuery<bk_ui::model::StringColumn>) -> bk_ui::model::SourceResult<bk_ui::model::Page<bk_ui::model::StringInfo>>;
        search(q: &bk_ui::model::SearchQuery, limit: u32) -> bk_ui::model::SourceResult<bk_ui::model::Page<bk_ui::model::SearchHit>>;
        comments(address: bk_ui::model::Address) -> bk_ui::model::SourceResult<Vec<(bk_ui::model::CommentKind, String)>>;
    }
    fn apply(&self, command: &bk_ui::model::Command) -> bk_ui::model::SourceResult<()> {
        self.commands.lock().push(command.clone());
        self.inner.apply(command)
    }
}

/// A harness on a recording demo source, with the record.
pub(crate) fn recording_harness() -> (Harness<'static, BasiliskApp>, std::sync::Arc<parking_lot::Mutex<Vec<bk_ui::model::Command>>>) {
    let commands = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let c2 = std::sync::Arc::clone(&commands);
    let opener: bk_ui::shell::tool::Opener = std::sync::Arc::new(move || {
        Ok(std::sync::Arc::new(Recording {
            inner: bk_ui::demo::DemoProgram::licd().map_err(|e| e.to_string())?,
            commands: std::sync::Arc::clone(&c2),
        }) as std::sync::Arc<dyn ProgramSource>)
    });
    let mut h = harness_with(prefs(ThemeKind::Dark, Density::Comfortable), opener);
    settle(&mut h);
    (h, commands)
}

/// The address of a demo symbol.
pub(crate) fn addr(name: &str) -> bk_ui::model::Address {
    let src = bk_ui::demo::DemoProgram::licd().unwrap();
    src.lookup(name, 5).unwrap().into_iter().find(|s| &*s.name == name).unwrap().address
}

/// The current location.
pub(crate) fn here(h: &Harness<'_, BasiliskApp>) -> bk_ui::model::Address {
    h.state().tool().ws.as_ref().unwrap().shared.nav.current().address
}

/// Types text into the focused field.
pub(crate) fn type_text(h: &mut Harness<'_, BasiliskApp>, text: &str) {
    h.event(egui::Event::Text(text.to_owned()));
    h.run_steps(2);
}

/// Presses a key (with modifiers) and lets the frame run.
pub(crate) fn press(h: &mut Harness<'_, BasiliskApp>, modifiers: egui::Modifiers, key: egui::Key) {
    h.key_press_modifiers(modifiers, key);
    h.run_steps(2);
    settle(h);
}

/// Double-clicks the centre of a rectangle.
pub(crate) fn double_click(h: &mut Harness<'_, BasiliskApp>, rect: egui::Rect) {
    let pos = rect.center();
    h.event(egui::Event::PointerMoved(pos));
    h.step();
    for _ in 0..2 {
        h.event(egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed: true, modifiers: egui::Modifiers::NONE });
        h.step();
        h.event(egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed: false, modifiers: egui::Modifiers::NONE });
        h.step();
    }
    h.run_steps(2);
    settle(h);
}
