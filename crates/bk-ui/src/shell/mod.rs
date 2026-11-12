//! The application shell: menus, tool bar, status bar, docking (main and
//! detached windows), the palette and dialogs, options, the start screen.

pub mod app;
pub mod brand;
pub mod chrome;
pub mod dock;
pub mod layout;
pub mod notifications;
pub mod options;
pub mod overlay;
pub mod palette;
pub mod tool;
pub mod welcome;
pub mod workspace;

pub use app::BasiliskApp;
pub use layout::{Layout, Tab};
pub use tool::{Prefs, Tool};
pub use workspace::Workspace;

/// Opens the basilisk window on the demo program and runs until it closes.
pub fn run_native() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("basilisk")
        .with_inner_size([1440.0, 900.0])
        .with_min_inner_size([800.0, 500.0]);
    if let Some(icon) = brand::icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        persist_window: true,
        ..eframe::NativeOptions::default()
    };
    eframe::run_native(
        "basilisk",
        options,
        Box::new(|cc| Ok(Box::new(BasiliskApp::from_creation_context(cc)))),
    )
}
