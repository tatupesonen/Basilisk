//! The Console: messages from the tool, newest at the bottom.

use egui::RichText;

use super::{Level, Shared, View, ViewCx, ViewKind};
use crate::design::{icons, widgets};

/// The Console window.
#[derive(Debug, Default)]
pub struct ConsoleView {
    seen: usize,
}

impl View for ConsoleView {
    fn kind(&self) -> ViewKind {
        ViewKind::Console
    }

    fn title(&self, _shared: &Shared) -> String {
        "Console".to_owned()
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let p = t.palette;
        let mut clear = false;
        widgets::pane_toolbar(ui, &t, |ui| {
            ui.label(RichText::new(match cx.shared.log.len() {
                1 => "1 message".to_owned(),
                n => format!("{n} messages"),
            }).color(p.text_muted).size(t.metrics.small_size));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::icon_button(ui, &t, icons::CLOSE, "Clear the Console", !cx.shared.log.is_empty()).clicked() {
                    clear = true;
                }
            });
        });
        if clear {
            cx.shared.log.clear();
        }
        let grew = cx.shared.log.len() != self.seen;
        self.seen = cx.shared.log.len();
        egui::Frame::NONE.fill(p.surface).inner_margin(egui::Margin::symmetric(8, 4)).show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            if cx.shared.log.is_empty() {
                widgets::empty_state(ui, &t, icons::CONSOLE, "No messages", "Messages from basilisk appear here.");
                return;
            }
            let row_h = t.metrics.code_row;
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .stick_to_bottom(true)
                .show_rows(ui, row_h, cx.shared.log.len(), |ui, range| {
                    for line in cx.shared.log.get(range).unwrap_or_default() {
                        let color = match line.level {
                            Level::Info => p.text_secondary,
                            Level::Warning => p.warning,
                            Level::Error => p.error,
                        };
                        ui.horizontal(|ui| {
                            ui.set_height(row_h);
                            ui.label(RichText::new(format!("{:>8.3}", line.time)).monospace().size(t.metrics.code_size - 1.0).color(p.text_disabled));
                            ui.label(RichText::new(&line.text).monospace().size(t.metrics.code_size - 0.5).color(color));
                        });
                    }
                });
            if grew {
                ui.ctx().request_repaint();
            }
        });
    }
}
