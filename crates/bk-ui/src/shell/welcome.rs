//! The start screen when no program is open: the mark, the name, how to
//! open something, and the recent programs.

use egui::{RichText, vec2};

use super::tool::Tool;
use crate::actions::ActionId;
use crate::design::{Tokens, icons, tokens::space, typography, widgets};

/// Draws the start screen; returns the action chosen.
pub fn ui(ui: &mut egui::Ui, tool: &Tool, t: &Tokens) -> Option<ActionId> {
    let p = t.palette;
    let mut chosen = None;
    ui.painter()
        .rect_filled(ui.max_rect(), egui::CornerRadius::ZERO, p.surface);
    let width = 520.0_f32.min(ui.available_width() - 2.0 * space::XXXL);
    let top = (ui.available_height() * 0.16).max(space::XXL);
    ui.add_space(top);
    ui.vertical_centered(|ui| {
        ui.set_max_width(width);
        if let Some(tex) = super::brand::mark(ui.ctx(), t.kind) {
            ui.add(egui::Image::new(&tex).fit_to_exact_size(vec2(96.0, 96.0)));
        }
        ui.add_space(space::LG);
        ui.label(
            RichText::new("Basilisk")
                .text_style(typography::style::display())
                .color(p.text),
        );
        ui.add_space(space::XS);
        ui.label(
            RichText::new("A software reverse-engineering suite: Ghidra, in Rust")
                .color(p.text_secondary),
        );
        ui.add_space(space::XXL + space::MD);
        if widgets::primary_button(ui, t, "Open demo program (licd)").clicked() {
            chosen = Some(ActionId::OpenProgram);
        }
        ui.add_space(space::SM);
        ui.label(
            RichText::new("Importing your own files arrives with the loaders (milestone M2).")
                .size(t.metrics.small_size)
                .color(p.text_muted),
        );
        ui.add_space(space::XXL);
        if !tool.prefs.recent.is_empty() {
            widgets::section_label(ui, t, "RECENT");
            ui.add_space(space::XS);
            for name in &tool.prefs.recent {
                let r = ui
                    .horizontal(|ui| {
                        let w = 160.0;
                        ui.add_space((ui.available_width() - w).max(0.0) / 2.0);
                        ui.label(icons::rich(icons::PROGRAM).color(p.text_muted));
                        ui.add(egui::Button::new(RichText::new(name).color(p.text)).frame(false))
                    })
                    .inner;
                if r.clicked() {
                    chosen = Some(ActionId::OpenProgram);
                }
            }
            ui.add_space(space::XL);
        }
        ui.horizontal(|ui| {
            let k = tool
                .prefs
                .keymap
                .primary(ActionId::CommandPalette)
                .map(|k| k.label(tool.mac))
                .unwrap_or_default();
            let w = 260.0;
            ui.add_space((ui.available_width() - w).max(0.0) / 2.0);
            widgets::key_chip(ui, t, &k);
            ui.label(
                RichText::new("Command Palette")
                    .size(t.metrics.small_size)
                    .color(p.text_muted),
            );
        });
    });
    chosen
}
