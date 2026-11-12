//! Renders the interface to PNG: the designer's eyes, and the pictures in
//! `docs/features/ui-screenshots/`. Needs a GPU, so it runs only when
//! `BK_UI_SCREENSHOT_DIR` names the folder to write into.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

mod common;

use std::path::{Path, PathBuf};

use bk_ui::BasiliskApp;
use bk_ui::actions::ActionId;
use bk_ui::design::{Density, ThemeKind};
use common::*;
use egui::{Key, Modifiers};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

type H = Harness<'static, BasiliskApp>;

const CMD_SHIFT: Modifiers = Modifiers {
    alt: false,
    ctrl: false,
    shift: true,
    mac_cmd: false,
    command: true,
};

fn dir() -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var_os("BK_UI_SCREENSHOT_DIR")?);
    std::fs::create_dir_all(&d).unwrap();
    Some(d)
}

fn app(theme: ThemeKind, density: Density) -> H {
    let mut h = gpu_harness(theme, density, 1440.0, 900.0);
    settle(&mut h);
    h
}

fn run(h: &mut H, a: ActionId) {
    let ctx = h.ctx.clone();
    h.state().tool().run(&ctx, a, egui::ViewportId::ROOT);
    h.run_steps(2);
    settle(h);
}

/// Puts the decompiler cursor on the statement calling `callee` (the
/// cross-highlight state).
fn cursor_on_call(h: &mut H, callee: &str) {
    let node = h
        .get_all_by_label(callee)
        .max_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
        .unwrap();
    node.click();
    h.run_steps(3);
    settle(h);
}

fn shot(h: &mut H, d: &Path, name: &str) {
    if !name.starts_with("hover") {
        h.remove_cursor();
    }
    h.run_steps(2);
    save(h, &d.join(format!("{name}.png")));
}

fn theme_name(t: ThemeKind) -> &'static str {
    match t {
        ThemeKind::Dark => "dark",
        ThemeKind::Light => "light",
    }
}

#[test]
fn screenshots() {
    let Some(d) = dir() else {
        eprintln!("skipped: set BK_UI_SCREENSHOT_DIR to render screenshots (needs a GPU)");
        return;
    };
    for theme in [ThemeKind::Dark, ThemeKind::Light] {
        let tn = theme_name(theme);
        for (density, dn) in [
            (Density::Comfortable, "normal"),
            (Density::Compact, "compact"),
        ] {
            // The main window: main in the listing and the decompiler, the
            // decompiler's cursor on a call, its instructions marked in the
            // listing.
            let mut h = app(theme, density);
            cursor_on_call(&mut h, "check_debugger");
            shot(&mut h, &d, &format!("main-{tn}-{dn}"));
        }
        let mut h = app(theme, Density::Comfortable);
        press(&mut h, CMD_SHIFT, Key::P);
        type_text(&mut h, "rc4");
        settle(&mut h);
        shot(&mut h, &d, &format!("palette-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        press(&mut h, Modifiers::NONE, Key::G);
        type_text(&mut h, "conf");
        settle(&mut h);
        shot(&mut h, &d, &format!("goto-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        go_to(&mut h, "parse_config_line");
        settle(&mut h);
        run(&mut h, ActionId::ShowFunctions);
        for label in ["Imports", "Functions"] {
            // The Symbol Tree folder is the leftmost of the nodes so named.
            h.get_all_by_label(label)
                .min_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
                .unwrap()
                .click();
            h.run_steps(2);
            settle(&mut h);
        }
        shot(&mut h, &d, &format!("functions-symbols-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        run(&mut h, ActionId::ShowStrings);
        shot(&mut h, &d, &format!("strings-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        h.get_all_by_label("log_msg").next().unwrap().click();
        h.run_steps(2);
        press(&mut h, CMD_SHIFT, Key::F);
        shot(&mut h, &d, &format!("references-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        h.get_all_by_label("iVar1").next().unwrap().click();
        h.run_steps(2);
        press(&mut h, Modifiers::NONE, Key::L);
        shot(&mut h, &d, &format!("rename-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        h.get_all_by_label("print_banner").next().unwrap().click();
        h.run_steps(2);
        press(&mut h, Modifiers::NONE, Key::Semicolon);
        type_text(&mut h, "prints the decoded banner");
        shot(&mut h, &d, &format!("comment-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        h.get_all_by_label("decode_strings")
            .next()
            .unwrap()
            .click_secondary();
        h.run_steps(3);
        shot(&mut h, &d, &format!("popup-menu-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        h.get_by_label("Navigation").click();
        h.run_steps(3);
        shot(&mut h, &d, &format!("menu-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        // A call operand in the listing (the leftmost node of that name).
        node_hover_again(&mut h, "validate_key");
        settle(&mut h);
        node_hover_again(&mut h, "validate_key");
        shot(&mut h, &d, &format!("hover-preview-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        run(&mut h, ActionId::ShowKeyBindings);
        shot(&mut h, &d, &format!("options-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        press(&mut h, Modifiers::NONE, Key::S);
        type_text(&mut h, "55 48 89 e5");
        press(&mut h, Modifiers::NONE, Key::Enter);
        shot(&mut h, &d, &format!("search-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        go_to(&mut h, "s_banner_enc");
        settle(&mut h);
        shot(&mut h, &d, &format!("data-{tn}"));

        let mut h = app(theme, Density::Comfortable);
        run(&mut h, ActionId::CloseProgram);
        shot(&mut h, &d, &format!("welcome-{tn}"));
    }
}

fn node_hover_again(h: &mut H, label: &str) {
    let node = h
        .get_all_by_label(label)
        .min_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
        .unwrap();
    node.hover();
    h.run_steps(30);
}
