//! Search results (Search → Program Text and Search → Memory).

use std::sync::Arc;

use super::table::{ColumnDef, PagedTable, TableEvent, code_cell};
use super::{Shared, View, ViewCx, ViewKind};
use crate::design::{icons, widgets};
use crate::model::{Location, Page, SearchHit, SearchQuery};

const COLUMNS: [ColumnDef; 2] = [
    ColumnDef {
        title: "Location",
        width: 100.0,
        sortable: false,
        numeric: false,
    },
    ColumnDef {
        title: "Code Unit",
        width: 400.0,
        sortable: false,
        numeric: false,
    },
];

/// Most hits listed.
const LIMIT: u32 = 5_000;

/// A search the user ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// What to look for.
    pub query: SearchQuery,
    /// How it was typed, for the title.
    pub text: String,
    /// Bumped for every new search.
    pub serial: u64,
}

/// The search results window.
#[derive(Debug)]
pub struct SearchView {
    table: PagedTable<SearchHit>,
    serial: Option<u64>,
}

impl Default for SearchView {
    fn default() -> Self {
        Self {
            table: PagedTable::new(
                Arc::new(|_, _, _, _, _, _| {
                    Ok(Page {
                        rows: Vec::new(),
                        total: 0,
                    })
                }),
                0,
            ),
            serial: None,
        }
    }
}

impl View for SearchView {
    fn kind(&self) -> ViewKind {
        ViewKind::SearchResults
    }

    fn title(&self, shared: &Shared) -> String {
        match (&shared.search, self.table.total()) {
            (Some(s), Some(n)) => format!("Search: {} - {n} results", s.text),
            (Some(s), None) => format!("Search: {}", s.text),
            _ => "Search Results".to_owned(),
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let Some(req) = cx.shared.search.clone() else {
            widgets::empty_state(
                ui,
                &t,
                icons::SEARCH,
                "No search yet",
                "Search → Program Text (Ctrl+F) or Memory (S).",
            );
            return;
        };
        if self.serial != Some(req.serial) {
            self.serial = Some(req.serial);
            let query = req.query.clone();
            self.table
                .set_fetch(Arc::new(move |s, filter: &str, _, _, offset, limit| {
                    let all = s.search(&query, LIMIT)?;
                    let f = filter.to_lowercase();
                    let rows: Vec<SearchHit> = all
                        .rows
                        .into_iter()
                        .filter(|h| f.is_empty() || h.preview.to_lowercase().contains(&f))
                        .collect();
                    let total = rows.len() as u64;
                    Ok(Page {
                        rows: rows
                            .into_iter()
                            .skip(offset as usize)
                            .take(limit as usize)
                            .collect(),
                        total,
                    })
                }));
        }
        let ev = self.table.ui(
            ui,
            cx,
            "search",
            &COLUMNS,
            "Filter results",
            |ui, h, c| match c {
                0 => code_cell(ui, &t, &h.address.to_string(), t.syntax.address),
                _ => code_cell(ui, &t, &h.preview, t.syntax.mnemonic),
            },
        );
        if let Some(TableEvent::Selected(h) | TableEvent::Activated(h)) = ev {
            cx.shared.nav.go(Location::at(h.address));
        }
    }
}
