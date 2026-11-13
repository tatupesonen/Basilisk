//! Headless flow tests (spec section 4.1): every common task, by mouse and
//! by keyboard, against the demo program. No GPU needed.
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

use bk_ui::actions::{ActionId, keymap::chord};
use bk_ui::model::ProgramSource as _;
use bk_ui::model::{Command, CommentKind};
use bk_ui::views::ViewKind;
use common::*;
use egui::{Key, Modifiers};
use egui_kittest::kittest::{NodeT as _, Queryable};

const CMD_SHIFT: Modifiers = Modifiers {
    alt: false,
    ctrl: false,
    shift: true,
    mac_cmd: false,
    command: true,
};

fn ready() -> egui_kittest::Harness<'static, bk_ui::BasiliskApp> {
    let mut h = harness();
    settle(&mut h);
    h
}

#[test]
fn opens_the_demo_in_ghidras_code_browser_layout() {
    let h = ready();
    for label in [
        "File",
        "Edit",
        "Analysis",
        "Navigation",
        "Search",
        "Select",
        "Tools",
        "Window",
        "Help",
    ] {
        h.get_by_label(label);
    }
    h.get_by_label_contains("Listing: licd");
    h.get_by_label_contains("Decompile: main - (licd)");
    for pane in [
        "Program Trees",
        "Symbol Tree",
        "Console",
        "Functions",
        "Defined Strings",
    ] {
        assert!(
            h.get_all_by_label_contains(pane).next().is_some(),
            "{pane} missing"
        );
    }
    assert_eq!(here(&h), addr("main"));
}

#[test]
fn palette_goes_to_a_function_and_back_returns() {
    let mut h = ready();
    press(&mut h, CMD_SHIFT, Key::P);
    h.get_by_label_contains("Command Palette");
    type_text(&mut h, "parse_config_line");
    settle(&mut h);
    press(&mut h, Modifiers::NONE, Key::Enter);
    assert_eq!(here(&h), addr("parse_config_line"));
    h.get_by_label_contains("Decompile: parse_config_line");
    press(&mut h, Modifiers::ALT, Key::ArrowLeft);
    assert_eq!(here(&h), addr("main"));
    press(&mut h, Modifiers::ALT, Key::ArrowRight);
    assert_eq!(here(&h), addr("parse_config_line"));
}

#[test]
fn g_goes_to_an_address() {
    let mut h = ready();
    press(&mut h, Modifiers::NONE, Key::G);
    h.get_by_label_contains("Go To Address/Label");
    let target = addr("crc32");
    type_text(&mut h, &target.to_string());
    press(&mut h, Modifiers::NONE, Key::Enter);
    assert_eq!(here(&h), target);
}

#[test]
fn double_click_follows_a_call_in_the_listing_and_the_toolbar_goes_back() {
    let mut h = ready();
    let rect = h
        .get_all_by_label("config_defaults")
        .next()
        .expect("call operand on screen")
        .rect();
    double_click(&mut h, rect);
    assert_eq!(here(&h), addr("config_defaults"));
    h.get_by_label_contains("Previous Location in History")
        .click();
    h.run_steps(2);
    settle(&mut h);
    // Back returns to the call site, where the cursor was.
    let src = bk_ui::demo::DemoProgram::licd().unwrap();
    assert_eq!(
        src.function_containing(here(&h)).unwrap().unwrap().entry,
        addr("main")
    );
    assert_ne!(here(&h), addr("main"));
}

#[test]
fn double_click_follows_a_call_in_the_decompiler() {
    let mut h = ready();
    // The decompiler shows main; `load_config` is called from it.
    let rect = h
        .get_all_by_label("load_config")
        .max_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
        .unwrap()
        .rect();
    double_click(&mut h, rect);
    assert_eq!(here(&h), addr("load_config"));
}

#[test]
fn decompiler_and_listing_cross_highlight() {
    let mut h = ready();
    // Decompiler → Listing: putting the cursor on a statement moves the
    // location to its first instruction and marks its instructions.
    let call = h
        .get_all_by_label("check_debugger")
        .max_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
        .unwrap();
    call.click();
    h.run_steps(2);
    settle(&mut h);
    let (related, at) = {
        let tool = h.state().tool();
        let ws = tool.ws.as_ref().unwrap();
        (ws.shared.related.clone(), ws.shared.nav.current().address)
    };
    assert!(!related.ranges.is_empty());
    assert!(related.contains(at));
    let f = bk_ui::demo::DemoProgram::licd().unwrap();
    assert_eq!(
        f.function_containing(at).unwrap().unwrap().entry,
        addr("main")
    );
    // Listing → Decompiler: the decompiler follows a location in another
    // function and shows it.
    h.state()
        .tool()
        .ws
        .as_mut()
        .unwrap()
        .shared
        .nav
        .go(bk_ui::model::Location::at(addr("rc4_init")));
    h.run_steps(2);
    settle(&mut h);
    h.get_by_label_contains("Decompile: rc4_init");
}

#[test]
fn functions_table_filters_and_navigates() {
    let mut h = ready();
    h.get_all_by_label("Functions")
        .max_by(|a, b| a.rect().top().total_cmp(&b.rect().top()))
        .unwrap()
        .click();
    h.run_steps(2);
    settle(&mut h);
    let filter = h.get_by_label("Filter functions");
    filter.focus();
    h.run_steps(1);
    type_text(&mut h, "rc4");
    settle(&mut h);
    h.get_by_label_contains("Functions - 2 items");
    h.get_by_label("rc4_crypt").click();
    h.run_steps(2);
    settle(&mut h);
    assert_eq!(here(&h), addr("rc4_crypt"));
}

#[test]
fn rename_a_variable_from_the_decompiler_by_keyboard_and_undo() {
    let (mut h, commands) = recording_harness();
    let var = h.get_all_by_label("iVar1").next().unwrap();
    var.click();
    h.run_steps(2);
    press(&mut h, Modifiers::NONE, Key::L);
    h.get_by_label_contains("Rename Variable");
    // The field starts with the old name selected: typing replaces it.
    type_text(&mut h, "status");
    press(&mut h, Modifiers::NONE, Key::Enter);
    settle(&mut h);
    let main = addr("main");
    assert!(
        matches!(
            commands.lock().last(),
            Some(Command::RenameVariable { function, name, .. }) if *function == main && name == "status"
        ),
        "{:?}",
        commands.lock()
    );
    h.get_all_by_label("status")
        .next()
        .expect("renamed in the decompiler");
    press(&mut h, Modifiers::COMMAND, Key::Z);
    settle(&mut h);
    assert!(
        matches!(commands.lock().last(), Some(Command::RenameVariable { name, .. }) if name == "iVar1")
    );
}

#[test]
fn rename_a_function_from_the_listing_by_mouse() {
    let (mut h, commands) = recording_harness();
    let call = h.get_all_by_label("decode_strings").next().unwrap();
    call.click_secondary();
    h.run_steps(2);
    h.get_by_label_contains("Rename Function").click();
    h.run_steps(2);
    type_text(&mut h, "deobfuscate");
    h.get_by_label("OK").click();
    h.run_steps(2);
    settle(&mut h);
    assert_eq!(
        commands.lock().last(),
        Some(&Command::RenameSymbol {
            address: addr("decode_strings"),
            name: "deobfuscate".into()
        })
    );
    h.get_all_by_label("deobfuscate")
        .next()
        .expect("new name in the listing");
}

#[test]
fn comment_a_line_with_semicolon() {
    let (mut h, commands) = recording_harness();
    let call = h.get_all_by_label("print_banner").next().unwrap();
    call.click();
    h.run_steps(2);
    press(&mut h, Modifiers::NONE, Key::Semicolon);
    h.get_by_label_contains("Set Comment at");
    type_text(&mut h, "prints the decoded banner");
    press(&mut h, Modifiers::NONE, Key::Enter);
    settle(&mut h);
    assert!(matches!(
        commands.lock().last(),
        Some(Command::SetComment { kind: CommentKind::Eol, text, .. }) if text == "prints the decoded banner"
    ));
    let a = addr("print_banner");
    let _ = a;
}

#[test]
fn show_references_lists_the_callers() {
    let mut h = ready();
    h.get_all_by_label("validate_key").next().unwrap().click();
    h.run_steps(2);
    press(&mut h, CMD_SHIFT, Key::F);
    h.get_by_label_contains("References to validate_key");
    let main_row = h
        .get_all_by_label("main")
        .find(|n| n.rect().top() > 600.0)
        .expect("caller row");
    let _ = main_row;
}

#[test]
fn search_memory_lists_hits() {
    let mut h = ready();
    press(&mut h, Modifiers::NONE, Key::S);
    h.get_by_label_contains("Search Memory");
    type_text(&mut h, "55 48 89 e5");
    press(&mut h, Modifiers::NONE, Key::Enter);
    settle(&mut h);
    h.get_by_label_contains("Search: 55 48 89 e5 -");
    let tool = h.state().tool();
    assert_eq!(
        tool.ws.as_ref().unwrap().active_kind(),
        Some(ViewKind::SearchResults)
    );
}

#[test]
fn search_program_text_with_ctrl_f() {
    let mut h = ready();
    press(&mut h, Modifiers::COMMAND, Key::F);
    h.get_by_label_contains("Search Program Text");
    type_text(&mut h, "getaddrinfo");
    press(&mut h, Modifiers::NONE, Key::Enter);
    h.get_by_label_contains("Search: \"getaddrinfo\"");
}

#[test]
fn several_functions_stay_open_as_snapshots() {
    let mut h = ready();
    h.state().tool().run(
        &h.ctx.clone(),
        ActionId::ShowDecompiler,
        egui::ViewportId::ROOT,
    );
    h.state()
        .tool()
        .run(&h.ctx.clone(), ActionId::Snapshot, egui::ViewportId::ROOT);
    h.run_steps(2);
    settle(&mut h);
    h.state()
        .tool()
        .ws
        .as_mut()
        .unwrap()
        .shared
        .nav
        .go(bk_ui::model::Location::at(addr("crc32")));
    h.run_steps(2);
    settle(&mut h);
    // The snapshot still shows main; the live decompiler follows to crc32
    // (shown once its tab is brought to the front).
    {
        let mut tool = h.state().tool();
        let ws = tool.ws.as_mut().unwrap();
        let live = ws.layout.find_kind(ViewKind::Decompiler).unwrap();
        ws.layout.focus(live);
    }
    h.run_steps(2);
    settle(&mut h);
    h.get_by_label_contains("Decompile: crc32");
    assert_eq!(h.get_all_by_label_contains("Decompile: main").count(), 1);
}

#[test]
fn window_menu_reopens_a_closed_pane_and_reset_restores_ghidras_layout() {
    let mut h = ready();
    {
        let mut tool = h.state().tool();
        let ws = tool.ws.as_mut().unwrap();
        let id = ws.layout.find_kind(ViewKind::Decompiler).unwrap();
        ws.layout.remove(id);
    }
    h.run_steps(2);
    assert!(h.query_by_label_contains("Decompile:").is_none());
    h.get_by_label("Window").click();
    h.run_steps(1);
    let item = h
        .get_all_by_label_contains("Decompile")
        .find(|n| {
            let l = n.accesskit_node().label().unwrap_or_default();
            !l.contains(':') && !l.contains('(')
        })
        .expect("Window → Decompile");
    item.click();
    h.run_steps(2);
    settle(&mut h);
    h.get_by_label_contains("Decompile: main");
    h.state().tool().run(
        &h.ctx.clone(),
        ActionId::DetachWindow,
        egui::ViewportId::ROOT,
    );
    h.run_steps(2);
    assert_eq!(
        h.state().tool().ws.as_ref().unwrap().layout.windows.len(),
        1
    );
    press(&mut h, CMD_SHIFT, Key::P);
    type_text(&mut h, "reset window layout");
    press(&mut h, Modifiers::NONE, Key::Enter);
    let tool = h.state().tool();
    let layout = &tool.ws.as_ref().unwrap().layout;
    assert!(layout.windows.is_empty());
    assert_eq!(
        layout.tabs().len(),
        bk_ui::shell::Layout::ghidra().tabs().len()
    );
}

#[test]
fn a_detached_pane_follows_navigation_and_docks_back() {
    let mut h = ready();
    // Activate the decompiler by clicking in it, then detach it.
    h.get_all_by_label("load_config").last().unwrap().click();
    h.run_steps(2);
    h.state().tool().run(
        &h.ctx.clone(),
        ActionId::DetachWindow,
        egui::ViewportId::ROOT,
    );
    h.run_steps(3);
    settle(&mut h);
    {
        let tool = h.state().tool();
        let ws = tool.ws.as_ref().unwrap();
        assert_eq!(ws.layout.windows.len(), 1);
        assert_eq!(
            ws.layout.windows[0].tabs().next().unwrap().kind,
            ViewKind::Decompiler
        );
    }
    // The detached window is shown (embedded in tests) and follows the
    // tool's location like a docked pane.
    h.get_by_label("Detached window");
    h.state()
        .tool()
        .ws
        .as_mut()
        .unwrap()
        .shared
        .nav
        .go(bk_ui::model::Location::at(addr("heartbeat")));
    h.run_steps(3);
    settle(&mut h);
    h.get_by_label_contains("Decompile: heartbeat");
    // Its Dock Window button puts it back.
    h.get_by_label("Dock Window").click();
    h.run_steps(3);
    let tool = h.state().tool();
    let ws = tool.ws.as_ref().unwrap();
    assert!(ws.layout.windows.is_empty());
    assert_eq!(
        ws.layout
            .window_of(ws.layout.find_kind(ViewKind::Decompiler).unwrap()),
        Some(bk_ui::shell::layout::Place::Main)
    );
}

#[test]
fn a_saved_layout_with_a_detached_window_is_restored() {
    let mut layout = bk_ui::shell::Layout::ghidra();
    let strings = layout.find_kind(ViewKind::Strings).unwrap();
    layout.detach(strings);
    let w = layout.windows[0].id;
    layout.set_window_rect(
        w,
        Some(egui::pos2(1600.0, 120.0)),
        Some(egui::vec2(600.0, 500.0)),
    );
    let prefs = bk_ui::shell::Prefs {
        layout: Some(layout),
        ..prefs(
            bk_ui::design::ThemeKind::Dark,
            bk_ui::design::Density::Comfortable,
        )
    };
    let mut h = harness_with(prefs, bk_ui::shell::app::demo_opener());
    settle(&mut h);
    h.get_by_label("Detached window");
    h.get_by_label_contains("Defined Strings - ");
    let tool = h.state().tool();
    assert_eq!(
        tool.ws.as_ref().unwrap().layout.windows[0].position,
        Some([1600.0, 120.0])
    );
}

#[test]
fn remapped_key_runs_the_action() {
    let mut p = prefs(
        bk_ui::design::ThemeKind::Dark,
        bk_ui::design::Density::Comfortable,
    );
    p.keymap
        .bind(ActionId::GoTo, chord(Key::J, false, false, false));
    let mut h = harness_with(p, bk_ui::shell::app::demo_opener());
    settle(&mut h);
    press(&mut h, Modifiers::NONE, Key::G);
    assert!(h.query_by_label_contains("Go To Address/Label").is_none());
    press(&mut h, Modifiers::NONE, Key::J);
    h.get_by_label_contains("Go To Address/Label");
}

#[test]
fn remap_a_key_in_tool_options() {
    let mut h = ready();
    h.state().tool().run(
        &h.ctx.clone(),
        ActionId::ShowKeyBindings,
        egui::ViewportId::ROOT,
    );
    h.run_steps(2);
    let filter = h.get_by_label("Filter actions");
    filter.focus();
    type_text(&mut h, "Go To...");
    h.get_by_label("Set…").click();
    h.run_steps(2);
    h.key_press(Key::K);
    h.run_steps(2);
    assert_eq!(
        h.state().tool().prefs.keymap.primary(ActionId::GoTo),
        Some(chord(Key::K, false, false, false))
    );
}

#[test]
fn close_returns_to_the_start_screen_and_open_comes_back() {
    let mut h = ready();
    press(&mut h, Modifiers::COMMAND, Key::W);
    h.get_by_label("Open demo program (licd)").click();
    h.run_steps(3);
    settle(&mut h);
    h.get_by_label_contains("Listing: licd");
}

#[test]
fn keyboard_moves_the_listing_cursor_and_enter_follows() {
    let mut h = ready();
    // Focus the listing by clicking its body.
    let listing = h.get_by_label_contains("Listing: licd").rect();
    h.event(egui::Event::PointerMoved(
        listing.center() + egui::vec2(0.0, 200.0),
    ));
    let pos = listing.center() + egui::vec2(0.0, 200.0);
    h.event(egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed: true,
        modifiers: Modifiers::NONE,
    });
    h.event(egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed: false,
        modifiers: Modifiers::NONE,
    });
    h.run_steps(2);
    let start = here(&h);
    // Walk down until Enter leads somewhere.
    for _ in 0..40 {
        press(&mut h, Modifiers::NONE, Key::ArrowDown);
        let before = here(&h);
        press(&mut h, Modifiers::NONE, Key::Enter);
        if h.state().tool().ws.as_ref().unwrap().shared.nav.can_back() && here(&h) != before {
            assert_ne!(here(&h), start);
            return;
        }
    }
    panic!("no followable operand reached by keyboard");
}
