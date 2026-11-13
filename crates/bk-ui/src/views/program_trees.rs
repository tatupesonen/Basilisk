//! Program Trees: the program's memory blocks as fragments of one tree
//! (Ghidra's Program Tree window, default view).

use egui::RichText;

use super::{Shared, View, ViewCx, ViewKind};
use crate::design::{icons, widgets};
use crate::model::{Location, MemoryBlock, SourceResult};
use crate::task::Pending;

/// The Program Trees window.
#[derive(Debug, Default)]
pub struct ProgramTreesView {
    blocks: Option<Pending<SourceResult<Vec<MemoryBlock>>>>,
    collapsed: bool,
}

impl View for ProgramTreesView {
    fn kind(&self) -> ViewKind {
        ViewKind::ProgramTrees
    }

    fn title(&self, _shared: &Shared) -> String {
        "Program Trees".to_owned()
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let p = t.palette;
        let blocks = self
            .blocks
            .get_or_insert_with(|| cx.client.request(|s| s.memory_blocks()));
        let here = cx.shared.nav.current().address;
        let mut go = None;
        egui::Frame::NONE
            .fill(p.surface)
            .inner_margin(egui::Margin::symmetric(4, 4))
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let caret = if self.collapsed {
                            icons::COLLAPSED
                        } else {
                            icons::EXPANDED
                        };
                        let root = ui
                            .horizontal(|ui| {
                                ui.label(icons::rich(caret).color(p.text_muted));
                                ui.label(icons::rich(icons::PROGRAM).color(p.text_secondary));
                                ui.add(
                                    egui::Button::new(
                                        RichText::new(&cx.shared.program.name).color(p.text),
                                    )
                                    .frame(false),
                                )
                            })
                            .inner;
                        if root.clicked() {
                            self.collapsed = !self.collapsed;
                        }
                        if self.collapsed {
                            return;
                        }
                        match blocks.poll() {
                            Some(Ok(list)) => {
                                for b in list {
                                    let inside = b.start <= here && here.0 < b.start.0 + b.size;
                                    let text = RichText::new(&*b.name)
                                        .monospace()
                                        .size(t.metrics.code_size - 0.5)
                                        .color(if inside { p.text } else { p.text_secondary });
                                    let r = ui
                                        .horizontal(|ui| {
                                            ui.add_space(24.0);
                                            ui.label(
                                                icons::rich(icons::BLOCKS).color(p.text_muted),
                                            );
                                            ui.add(
                                                egui::Button::new(text)
                                                    .frame(false)
                                                    .selected(inside),
                                            )
                                        })
                                        .inner
                                        .on_hover_text(format!(
                                            "{},{}  {}–{:08x}  {}  {} bytes",
                                            b.parent,
                                            b.name,
                                            b.start,
                                            b.start.0 + b.size.saturating_sub(1),
                                            b.permissions,
                                            b.size
                                        ));
                                    if r.clicked() {
                                        go = Some(b.start);
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                ui.label(RichText::new(e.to_string()).color(p.error));
                            }
                            None => widgets::empty_state(ui, &t, icons::BLOCKS, "Loading…", ""),
                        }
                    });
            });
        if let Some(a) = go {
            cx.shared.nav.go(Location::at(a));
        }
    }
}
