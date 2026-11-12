//! The Symbol Tree: Imports, Exports, Functions, Labels, Classes and
//! Namespaces folders, each loaded when opened, with a filter.

use std::collections::{HashMap, HashSet};

use egui::{CornerRadius, RichText, Sense, vec2};

use super::{Shared, View, ViewCx, ViewKind};
use crate::design::{Tokens, icons, syntax, widgets};
use crate::model::{Location, Page, SourceResult, Symbol, SymbolCategory, SymbolKind};
use crate::task::Pending;

/// Most symbols listed in one folder.
const LIMIT: u32 = 5_000;

/// The Symbol Tree.
#[derive(Debug, Default)]
pub struct SymbolTreeView {
    filter: String,
    open: HashSet<SymbolCategory>,
    libraries_closed: HashSet<String>,
    folders: HashMap<SymbolCategory, Pending<SourceResult<Page<Symbol>>>>,
    key: Option<(String, u64)>,
}

fn kind_icon(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => icons::FUNCTION,
        SymbolKind::Import => icons::IMPORT,
        SymbolKind::Data => icons::DATA,
        SymbolKind::String => icons::STRING,
        _ => icons::LABEL,
    }
}

fn category_icon(c: SymbolCategory) -> &'static str {
    match c {
        SymbolCategory::Imports => icons::IMPORT,
        SymbolCategory::Exports => icons::EXPORT,
        SymbolCategory::Functions => icons::FUNCTION,
        SymbolCategory::Labels => icons::LABEL,
        _ => icons::FOLDER,
    }
}

/// One tree row: indent, caret, icon, text. Returns the response.
fn tree_row(
    ui: &mut egui::Ui,
    t: &Tokens,
    depth: usize,
    caret: Option<bool>,
    icon: &str,
    text: RichText,
    selected: bool,
) -> egui::Response {
    let h = t.metrics.table_row;
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), h), Sense::click());
    let p = t.palette;
    if selected {
        ui.painter().rect_filled(rect, CornerRadius::same(3), p.selection);
    } else if resp.hovered() {
        ui.painter().rect_filled(rect, CornerRadius::same(3), p.hover);
    }
    let mut x = rect.left() + 6.0 + depth as f32 * 16.0;
    if let Some(open) = caret {
        ui.painter().text(
            egui::pos2(x + 5.0, rect.center().y),
            egui::Align2::CENTER_CENTER,
            if open { icons::EXPANDED } else { icons::COLLAPSED },
            icons::font(t.metrics.small_size),
            p.text_muted,
        );
    }
    x += 16.0;
    ui.painter().text(
        egui::pos2(x + 6.0, rect.center().y),
        egui::Align2::CENTER_CENTER,
        icon,
        icons::font(t.metrics.icon_size - 1.0),
        p.text_secondary,
    );
    x += 18.0;
    let name = text.text().to_owned();
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &name));
    let galley = egui::WidgetText::from(text).into_galley(
        ui,
        Some(egui::TextWrapMode::Truncate),
        rect.right() - x - 4.0,
        egui::TextStyle::Body,
    );
    ui.painter().galley(
        egui::pos2(x, rect.center().y - galley.size().y / 2.0),
        galley,
        p.text,
    );
    resp
}

impl SymbolTreeView {
    fn folder(&mut self, cx: &ViewCx<'_>, c: SymbolCategory) -> Option<&SourceResult<Page<Symbol>>> {
        let filter = self.filter.clone();
        self.folders
            .entry(c)
            .or_insert_with(|| cx.client.request(move |s| s.symbols(c, &filter, LIMIT)))
            .poll()
            .map(|r| &*r)
    }
}

impl View for SymbolTreeView {
    fn kind(&self) -> ViewKind {
        ViewKind::SymbolTree
    }

    fn title(&self, _shared: &Shared) -> String {
        "Symbol Tree".to_owned()
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let p = t.palette;
        let key = (self.filter.clone(), cx.client.revision());
        if self.key.as_ref() != Some(&key) {
            self.key = Some(key);
            self.folders.clear();
        }
        widgets::pane_toolbar(ui, &t, |ui| {
            widgets::filter_field(ui, &t, &mut self.filter, "Filter symbols", ui.id().with("symfilter"));
        });
        let filtering = !self.filter.is_empty();
        let current_fn = cx.shared.function.as_ref().map(|f| f.entry);
        let here = cx.shared.nav.current().address;
        let mut go = None;
        egui::Frame::NONE.fill(p.surface).inner_margin(egui::Margin::symmetric(4, 4)).show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for c in SymbolCategory::ALL {
                    let open = self.open.contains(&c) || filtering;
                    let count = match self.folders.get_mut(&c).and_then(|p| p.poll()) {
                        Some(Ok(page)) => format!("  {}", page.total),
                        _ => String::new(),
                    };
                    let label = RichText::new(format!("{}{count}", c.title())).color(p.text);
                    if tree_row(ui, &t, 0, Some(open), category_icon(c), label, false).clicked() {
                        if !self.open.remove(&c) {
                            self.open.insert(c);
                        }
                    }
                    if !open && !filtering {
                        // Load counts lazily only for open folders.
                        continue;
                    }
                    let rows = match self.folder(cx, c) {
                        Some(Ok(page)) => page.rows.clone(),
                        Some(Err(e)) => {
                            ui.label(RichText::new(e.to_string()).color(p.error));
                            continue;
                        }
                        None => {
                            ui.ctx().request_repaint_after(std::time::Duration::from_millis(30));
                            tree_row(ui, &t, 1, None, icons::FOLDER, RichText::new("Loading…").color(p.text_muted), false);
                            continue;
                        }
                    };
                    if rows.is_empty() && open {
                        tree_row(ui, &t, 1, None, "", RichText::new("(empty)").color(p.text_disabled), false);
                    }
                    let mut library: Option<String> = None;
                    for s in rows {
                        let mut depth = 1;
                        if c == SymbolCategory::Imports && !s.namespace.is_empty() {
                            if library.as_deref() != Some(&*s.namespace) {
                                library = Some(s.namespace.to_string());
                                let lib_open = !self.libraries_closed.contains(&*s.namespace);
                                if tree_row(ui, &t, 1, Some(lib_open), icons::FOLDER, RichText::new(&*s.namespace).color(p.text), false).clicked() {
                                    let n = s.namespace.to_string();
                                    if !self.libraries_closed.remove(&n) {
                                        self.libraries_closed.insert(n);
                                    }
                                }
                            }
                            if self.libraries_closed.contains(&*s.namespace) {
                                continue;
                            }
                            depth = 2;
                        }
                        let kind = s.kind.token_kind();
                        let selected = Some(s.address) == current_fn && c == SymbolCategory::Functions || s.address == here;
                        let text = RichText::new(&*s.name).monospace().size(t.metrics.code_size - 0.5).color(syntax::color(&t.syntax, kind));
                        let r = tree_row(ui, &t, depth, None, kind_icon(s.kind), text, selected)
                            .on_hover_text(format!("{} at {}", s.name, s.address));
                        if r.clicked() || r.double_clicked() {
                            go = Some(s.address);
                        }
                    }
                }
            });
        });
        if let Some(a) = go {
            cx.shared.nav.go(Location::at(a));
        }
    }
}
