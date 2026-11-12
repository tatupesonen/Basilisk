//! A sortable, filterable table over paged queries (the Functions, Defined
//! Strings, References and search-results windows).
//!
//! Rows are fetched a page at a time from the data interface with the
//! current filter and sort, so a table of any size costs one page per
//! screenful. Drawn with `egui_extras::TableBuilder` (resizable columns,
//! virtualised body). Selecting a row navigates, as Ghidra's tables do.

use std::collections::HashMap;
use std::sync::Arc;

use egui::{RichText, Sense};
use egui_extras::{Column, TableBuilder};

use super::ViewCx;
use crate::design::{icons, widgets};
use crate::model::{Page, ProgramSource, SortOrder, SourceResult};
use crate::task::Pending;

/// Rows per fetched page.
const PAGE: u64 = 100;

/// Fetches one page: `(source, filter, sort column, order, offset, limit)`.
pub type Fetch<T> = Arc<
    dyn Fn(&dyn ProgramSource, &str, usize, SortOrder, u64, u32) -> SourceResult<Page<T>>
        + Send
        + Sync,
>;

/// One column.
#[derive(Debug, Clone, Copy)]
pub struct ColumnDef {
    /// Header text.
    pub title: &'static str,
    /// Initial width in points (the last column takes the rest).
    pub width: f32,
    /// Whether clicking the header sorts by it.
    pub sortable: bool,
    /// Right-aligned numbers.
    pub numeric: bool,
}

/// What the user did with a row this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableEvent<T> {
    /// A row was selected (click or arrow keys).
    Selected(T),
    /// A row was activated (double-click or Enter).
    Activated(T),
}

/// The table's state.
pub struct PagedTable<T> {
    /// Filter text.
    pub filter: String,
    /// Sorted column index.
    pub sort: usize,
    /// Sort direction.
    pub order: SortOrder,
    fetch: Fetch<T>,
    pages: HashMap<u64, Pending<SourceResult<Page<T>>>>,
    total: Option<u64>,
    key: Option<(String, usize, SortOrder, u64, u64)>,
    selected: Option<u64>,
    error: Option<String>,
    /// Bumped by the owner to refetch (a new References target).
    pub generation: u64,
}

impl<T> std::fmt::Debug for PagedTable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PagedTable")
            .field("filter", &self.filter)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

impl<T: Clone + Send + 'static> PagedTable<T> {
    /// A table fetched with `fetch`, sorted by column `sort`.
    pub fn new(fetch: Fetch<T>, sort: usize) -> Self {
        Self {
            filter: String::new(),
            sort,
            order: SortOrder::Ascending,
            fetch,
            pages: HashMap::new(),
            total: None,
            key: None,
            selected: None,
            error: None,
            generation: 0,
        }
    }

    /// Replaces the fetch function (a new target) and refetches.
    pub fn set_fetch(&mut self, fetch: Fetch<T>) {
        self.fetch = fetch;
        self.generation += 1;
        self.selected = None;
    }

    /// Rows matching the filter, once known.
    pub fn total(&self) -> Option<u64> {
        self.total
    }

    fn page(&mut self, cx: &ViewCx<'_>, p: u64) -> Option<&Page<T>> {
        let fetch = Arc::clone(&self.fetch);
        let (filter, sort, order) = (self.filter.clone(), self.sort, self.order);
        let pending = self.pages.entry(p).or_insert_with(|| {
            cx.client
                .request(move |s| fetch(s, &filter, sort, order, p * PAGE, PAGE as u32))
        });
        match pending.poll()? {
            Ok(page) => Some(page),
            Err(_) => None,
        }
    }

    fn row(&mut self, cx: &ViewCx<'_>, i: u64) -> Option<T> {
        let page = self.page(cx, i / PAGE)?;
        page.rows.get((i % PAGE) as usize).cloned()
    }

    fn refresh(&mut self, cx: &ViewCx<'_>) {
        let key = (
            self.filter.clone(),
            self.sort,
            self.order,
            cx.client.revision(),
            self.generation,
        );
        if self.key.as_ref() != Some(&key) {
            self.key = Some(key);
            self.pages.clear();
            self.selected = None;
            self.error = None;
        }
        // The first page tells the total.
        let total = match self.pages.entry(0).or_insert_with(|| {
            let fetch = Arc::clone(&self.fetch);
            let (filter, sort, order) = (self.filter.clone(), self.sort, self.order);
            cx.client
                .request(move |s| fetch(s, &filter, sort, order, 0, PAGE as u32))
        }).poll() {
            Some(Ok(p)) => Some(p.total),
            Some(Err(e)) => {
                self.error = Some(e.to_string());
                Some(0)
            }
            None => None,
        };
        if total.is_some() {
            self.total = total;
        }
    }

    /// Draws the filter bar and the table.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        cx: &mut ViewCx<'_>,
        id: &str,
        columns: &[ColumnDef],
        filter_hint: &str,
        mut cell: impl FnMut(&mut egui::Ui, &T, usize),
    ) -> Option<TableEvent<T>> {
        let t = *cx.tokens;
        let p = t.palette;
        self.refresh(cx);
        let mut event = None;
        widgets::pane_toolbar(ui, &t, |ui| {
            let total = self
                .total
                .map_or_else(|| "…".to_owned(), |n| n.to_string());
            let r = widgets::filter_field(
                ui,
                &t,
                &mut self.filter,
                filter_hint,
                ui.id().with(id).with("filter"),
            );
            let _ = r;
            ui.add_space(-ui.available_width());
            let _ = total;
        });
        let total = self.total.unwrap_or(0);
        egui::Frame::NONE.fill(p.surface).show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            if let Some(e) = &self.error {
                widgets::empty_state(ui, &t, icons::WARNING, "Could not load", e);
                return;
            }
            if self.total == Some(0) {
                let what = if self.filter.is_empty() {
                    "Nothing to show"
                } else {
                    "No matches"
                };
                widgets::empty_state(ui, &t, icons::SEARCH, what, "");
                return;
            }
            // Keyboard: arrows move the selection, Enter activates.
            if cx.focused && !ui.ctx().egui_wants_keyboard_input() && total > 0 {
                let (down, up, enter) = ui.input(|i| {
                    (
                        i.key_pressed(egui::Key::ArrowDown),
                        i.key_pressed(egui::Key::ArrowUp),
                        i.key_pressed(egui::Key::Enter),
                    )
                });
                let cur = self.selected;
                let next = if down {
                    Some(cur.map_or(0, |c| (c + 1).min(total - 1)))
                } else if up {
                    Some(cur.map_or(0, |c| c.saturating_sub(1)))
                } else {
                    None
                };
                if let Some(n) = next {
                    self.selected = Some(n);
                    if let Some(row) = self.row(cx, n) {
                        event = Some(TableEvent::Selected(row));
                    }
                }
                if enter {
                    if let Some(row) = self.selected.and_then(|s| self.row(cx, s)) {
                        event = Some(TableEvent::Activated(row));
                    }
                }
            }
            let row_h = t.metrics.table_row;
            let mut builder = TableBuilder::new(ui)
                .id_salt(id)
                .striped(false)
                .resizable(true)
                .sense(Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
            for (i, c) in columns.iter().enumerate() {
                let col = if i + 1 == columns.len() {
                    Column::remainder().at_least(60.0)
                } else {
                    Column::initial(c.width).at_least(40.0).clip(true)
                };
                builder = builder.column(col);
            }
            if let Some(sel) = self.selected {
                if matches!(event, Some(TableEvent::Selected(_))) {
                    builder = builder.scroll_to_row(sel as usize, None);
                }
            }
            builder
                .header(row_h, |mut header| {
                    for (i, c) in columns.iter().enumerate() {
                        header.col(|ui| {
                            let arrow = if self.sort == i {
                                match self.order {
                                    SortOrder::Ascending => " ↑",
                                    SortOrder::Descending => " ↓",
                                }
                            } else {
                                ""
                            };
                            let text = RichText::new(format!("{}{arrow}", c.title))
                                .size(t.metrics.small_size)
                                .color(if self.sort == i { p.text } else { p.text_secondary });
                            let r = ui.add(egui::Label::new(text).sense(if c.sortable {
                                Sense::click()
                            } else {
                                Sense::hover()
                            }));
                            if c.sortable && r.clicked() {
                                if self.sort == i {
                                    self.order = match self.order {
                                        SortOrder::Ascending => SortOrder::Descending,
                                        SortOrder::Descending => SortOrder::Ascending,
                                    };
                                } else {
                                    self.sort = i;
                                    self.order = SortOrder::Ascending;
                                }
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_h, total as usize, |mut row| {
                        let i = row.index() as u64;
                        let data = self.row(cx, i);
                        row.set_selected(self.selected == Some(i));
                        for c in 0..columns.len() {
                            row.col(|ui| match &data {
                                Some(d) => cell(ui, d, c),
                                None => {
                                    let r = ui.available_rect_before_wrap();
                                    widgets::placeholder_bar(ui, &t, r.shrink2(egui::vec2(0.0, 5.0)), 0.5);
                                }
                            });
                        }
                        let resp = row.response();
                        if resp.clicked() {
                            self.selected = Some(i);
                            if let Some(d) = &data {
                                event = Some(TableEvent::Selected(d.clone()));
                            }
                        }
                        if resp.double_clicked() {
                            if let Some(d) = &data {
                                event = Some(TableEvent::Activated(d.clone()));
                            }
                        }
                    });
                });
        });
        if self.pages.values_mut().any(|p| p.poll().is_none()) {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(30));
        }
        event
    }
}

/// A cell of monospaced text in a syntax colour.
pub fn code_cell(ui: &mut egui::Ui, cx_tokens: &crate::design::Tokens, text: &str, color: egui::Color32) {
    ui.add(
        egui::Label::new(
            RichText::new(text)
                .monospace()
                .size(cx_tokens.metrics.code_size - 0.5)
                .color(color),
        )
        .truncate()
        .selectable(false),
    );
}

/// A cell of plain text.
pub fn text_cell(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    ui.add(egui::Label::new(RichText::new(text).color(color)).truncate().selectable(false));
}
