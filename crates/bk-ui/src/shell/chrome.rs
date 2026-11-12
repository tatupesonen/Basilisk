//! The frame around the panes: Ghidra's menu bar (File, Edit, Analysis,
//! Navigation, Search, Select, Tools, Window, Help), the tool bar in
//! Ghidra's order (Save; Back, Forward; next Instruction, Data, Label,
//! Function; Undo, Redo) with the palette field added at its end, and the
//! status bar.

use egui::{RichText, Sense, vec2};

use super::tool::Tool;
use crate::actions::{ACTIONS, ActionId, Menu, action};
use crate::design::{Density, ThemeKind, Tokens, icons, tokens::radius, tokens::space, widgets};
use crate::views::ViewKind;

fn item(ui: &mut egui::Ui, tool: &Tool, id: ActionId, checked: Option<bool>, run: &mut Vec<ActionId>) {
    let Some(a) = action(id) else { return };
    let cx = tool.action_context();
    let shortcut = tool.prefs.keymap.primary(id).map(|k| k.label(tool.mac)).unwrap_or_default();
    let text = match checked {
        Some(true) => format!("✓  {}", a.name),
        Some(false) => format!("     {}", a.name),
        None => a.name.to_owned(),
    };
    let mut resp = ui.add_enabled(a.enabled(&cx), egui::Button::new(text).shortcut_text(shortcut));
    resp = match a.unavailable_reason() {
        Some(r) => resp.on_disabled_hover_text(r),
        None => resp.on_hover_text(a.description),
    };
    if resp.clicked() {
        run.push(id);
        ui.close();
    }
}

fn menu_items(ui: &mut egui::Ui, tool: &Tool, menu: Menu, run: &mut Vec<ActionId>) {
    ui.set_min_width(240.0);
    let mut group = None;
    for a in ACTIONS.iter().filter(|a| a.menu == Some(menu)) {
        if group.is_some_and(|g| g != a.group) {
            ui.separator();
        }
        group = Some(a.group);
        let checked = match a.id {
            ActionId::SwitchTheme => Some(tool.prefs.theme == ThemeKind::Light),
            ActionId::ToggleDensity => Some(tool.prefs.density == Density::Compact),
            _ => None,
        };
        let checked = if menu == Menu::Window {
            ViewKind::ALL
                .iter()
                .find(|k| k.show_action() == Some(a.id))
                .map(|k| tool.ws.as_ref().is_some_and(|w| w.layout.find_kind(*k).is_some()))
        } else {
            checked
        };
        item(ui, tool, a.id, checked, run);
    }
}

/// The menu bar.
pub fn menu_bar(ui: &mut egui::Ui, tool: &Tool, t: &Tokens) -> Vec<ActionId> {
    let mut run = Vec::new();
    egui::Frame::NONE
        .fill(t.palette.chrome)
        .inner_margin(egui::Margin::symmetric(space::SM as i8, space::XXS as i8))
        .show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                for m in Menu::ALL {
                    ui.menu_button(m.title(), |ui| menu_items(ui, tool, m, &mut run));
                }
            });
        });
    run
}

/// What the tool bar asked for.
#[derive(Debug, Default)]
pub struct ToolbarOut {
    /// Actions to run.
    pub run: Vec<ActionId>,
    /// Go back this many entries (history drop-down).
    pub back_by: Option<usize>,
    /// Go forward this many entries.
    pub forward_by: Option<usize>,
}

/// The tool bar.
pub fn toolbar(ui: &mut egui::Ui, tool: &Tool, t: &Tokens) -> ToolbarOut {
    let mut out = ToolbarOut::default();
    let cx = tool.action_context();
    let p = t.palette;
    let button = |ui: &mut egui::Ui, id: ActionId, icon: &str, out: &mut ToolbarOut| {
        let Some(a) = action(id) else { return };
        let key = tool.prefs.keymap.primary(id).map(|k| format!("  ({})", k.label(tool.mac))).unwrap_or_default();
        let tip = match a.unavailable_reason() {
            Some(r) => format!("{} — {r}", a.name),
            None => format!("{}{key}", a.name),
        };
        if widgets::icon_button(ui, t, icon, &tip, a.enabled(&cx)).clicked() {
            out.run.push(id);
        }
    };
    egui::Frame::NONE
        .fill(p.chrome)
        .inner_margin(egui::Margin::symmetric(space::MD as i8, 0))
        .show(ui, |ui| {
            ui.set_height(t.metrics.toolbar_height);
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                button(ui, ActionId::SaveProgram, icons::SAVE, &mut out);
                widgets::toolbar_divider(ui, t);
                button(ui, ActionId::Back, icons::BACK, &mut out);
                history_menu(ui, tool, t, true, &mut out);
                button(ui, ActionId::Forward, icons::FORWARD, &mut out);
                history_menu(ui, tool, t, false, &mut out);
                widgets::toolbar_divider(ui, t);
                button(ui, ActionId::NextInstruction, icons::NEXT_INSTRUCTION, &mut out);
                button(ui, ActionId::NextData, icons::NEXT_DATA, &mut out);
                button(ui, ActionId::NextLabel, icons::NEXT_LABEL, &mut out);
                button(ui, ActionId::NextFunction, icons::NEXT_FUNCTION, &mut out);
                widgets::toolbar_divider(ui, t);
                button(ui, ActionId::Undo, icons::UNDO, &mut out);
                button(ui, ActionId::Redo, icons::REDO, &mut out);
                widgets::toolbar_divider(ui, t);
                button(ui, ActionId::ShowListing, icons::LISTING, &mut out);
                button(ui, ActionId::ShowDecompiler, icons::DECOMPILER, &mut out);
                button(ui, ActionId::ShowSymbolTree, icons::TREE, &mut out);
                button(ui, ActionId::ShowFunctions, icons::FUNCTION, &mut out);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let icon = match tool.prefs.theme {
                        ThemeKind::Dark => icons::LIGHT,
                        ThemeKind::Light => icons::DARK,
                    };
                    button(ui, ActionId::SwitchTheme, icon, &mut out);
                    ui.add_space(space::SM);
                    if palette_field(ui, tool, t).clicked() {
                        out.run.push(ActionId::CommandPalette);
                    }
                });
            });
        });
    out
}

/// The back/forward drop-down (Ghidra's navigation history list).
fn history_menu(ui: &mut egui::Ui, tool: &Tool, t: &Tokens, back: bool, out: &mut ToolbarOut) {
    let entries = tool.ws.as_ref().map(|w| if back { w.shared.nav.back_list() } else { w.shared.nav.forward_list() }).unwrap_or_default();
    let enabled = !entries.is_empty();
    let color = if enabled { t.palette.text_muted } else { t.palette.text_disabled };
    let r = ui
        .add_enabled_ui(enabled, |ui| {
            ui.menu_button(icons::rich(icons::EXPANDED).size(10.0).color(color), |ui| {
                ui.set_min_width(180.0);
                for (i, l) in entries.iter().enumerate().take(20) {
                    if ui.button(RichText::new(l.address.to_string()).monospace()).clicked() {
                        if back {
                            out.back_by = Some(i + 1);
                        } else {
                            out.forward_by = Some(i + 1);
                        }
                        ui.close();
                    }
                }
            })
        })
        .response;
    let _ = r.on_hover_text(if back { "Back to…" } else { "Forward to…" });
}

/// The palette field at the end of the tool bar: a search box that opens
/// the command palette.
fn palette_field(ui: &mut egui::Ui, tool: &Tool, t: &Tokens) -> egui::Response {
    let p = t.palette;
    let w = 300.0_f32.min(ui.available_width() - 8.0).max(120.0);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, t.metrics.toolbar_height - 10.0), Sense::click());
    let fill = if resp.hovered() { p.hover } else { p.input };
    ui.painter().rect(rect, egui::CornerRadius::same(radius::SM), fill, egui::Stroke::new(1.0, p.hairline), egui::StrokeKind::Inside);
    let y = rect.center().y;
    ui.painter().text(egui::pos2(rect.left() + 10.0, y), egui::Align2::LEFT_CENTER, icons::SEARCH, icons::font(t.metrics.icon_size - 1.0), p.text_muted);
    ui.painter().text(egui::pos2(rect.left() + 30.0, y), egui::Align2::LEFT_CENTER, "Search actions and symbols", egui::FontId::proportional(t.metrics.small_size), p.text_muted);
    if let Some(k) = tool.prefs.keymap.primary(ActionId::CommandPalette) {
        let g = ui.painter().layout_no_wrap(k.label(tool.mac), egui::FontId::monospace(t.metrics.small_size - 1.0), p.text_muted);
        let chip = egui::Rect::from_min_size(egui::pos2(rect.right() - g.size().x - 14.0, y - g.size().y / 2.0 - 2.0), g.size() + vec2(8.0, 4.0));
        ui.painter().rect(chip, egui::CornerRadius::same(3), p.chrome, egui::Stroke::new(1.0, p.hairline), egui::StrokeKind::Inside);
        ui.painter().galley(chip.min + vec2(4.0, 2.0), g, p.text_muted);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Command Palette: every action, function, label and address")
}

/// The status bar: last message on the left; running jobs, the current
/// function and address on the right.
pub fn status_bar(ui: &mut egui::Ui, tool: &Tool, t: &Tokens) -> Vec<crate::task::Job> {
    let p = t.palette;
    let mut cancel = Vec::new();
    egui::Frame::NONE
        .fill(p.chrome)
        .inner_margin(egui::Margin::symmetric(space::LG as i8, 0))
        .show(ui, |ui| {
            ui.set_height(t.metrics.status_height);
            ui.horizontal_centered(|ui| {
                let small = |s: &str, c| RichText::new(s).size(t.metrics.small_size).color(c);
                let Some(ws) = &tool.ws else {
                    ui.label(small("No program open", p.text_muted));
                    return;
                };
                if let Some(line) = ws.shared.log.last() {
                    let c = match line.level {
                        crate::views::Level::Error => p.error,
                        crate::views::Level::Warning => p.warning,
                        crate::views::Level::Info => p.text_muted,
                    };
                    ui.add(egui::Label::new(small(&line.text, c)).truncate());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = space::LG;
                    let prog = &ws.shared.program;
                    ui.label(small(&prog.language, p.text_muted));
                    let here = ws.shared.nav.current().address;
                    ui.label(RichText::new(here.to_string()).monospace().size(t.metrics.small_size).color(p.text));
                    if let Some(f) = &ws.shared.function {
                        let off = here.0.saturating_sub(f.entry.0);
                        let text = if off == 0 { f.name.to_string() } else { format!("{} + {off:#x}", f.name) };
                        ui.label(RichText::new(text).monospace().size(t.metrics.small_size).color(t.syntax.function));
                    }
                    for job in ws.client.jobs() {
                        if ui.add(egui::Button::new(icons::rich(icons::CLOSE).size(t.metrics.small_size).color(p.text_muted)).frame(false)).on_hover_text("Cancel").clicked() {
                            cancel.push(job.clone());
                        }
                        ui.add(egui::ProgressBar::new(job.progress.fraction()).desired_width(80.0).desired_height(6.0));
                        ui.label(small(&job.name, p.text_secondary));
                    }
                    if ws.client.busy() > 0 {
                        ui.add(egui::Spinner::new().size(t.metrics.small_size).color(p.text_muted));
                    }
                });
            });
        });
    cancel
}
