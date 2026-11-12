//! Renders the interface to PNG: the designer's eyes, and the pictures in
//! `docs/features/ui-screenshots/`. Needs a GPU, so it runs only when
//! `BK_UI_SCREENSHOT_DIR` names the folder to write into.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]

mod common;

use bk_ui::design::{Density, ThemeKind};
use common::*;

#[test]
fn screenshots() {
    let Some(dir) = std::env::var_os("BK_UI_SCREENSHOT_DIR") else {
        eprintln!("skipped: set BK_UI_SCREENSHOT_DIR to render screenshots (needs a GPU)");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (theme, tname) in [(ThemeKind::Dark, "dark"), (ThemeKind::Light, "light")] {
        for (density, dname) in [(Density::Comfortable, "normal"), (Density::Compact, "compact")] {
            let mut h = gpu_harness(theme, density, 1440.0, 900.0);
            settle(&mut h);
            go_to(&mut h, "validate_key");
            settle(&mut h);
            save(&mut h, &dir.join(format!("main-{tname}-{dname}.png")));
        }
    }
}
