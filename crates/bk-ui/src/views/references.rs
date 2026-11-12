//! The references window: "References to …" (Ghidra's Location References
//! provider), filled by Show References to.

use std::sync::Arc;

use super::table::{ColumnDef, PagedTable, TableEvent, code_cell, text_cell};
use super::{Shared, View, ViewCx, ViewKind};
use crate::design::{icons, widgets};
use crate::model::{Address, Location, Page, Reference, SortOrder};

const COLUMNS: [ColumnDef; 4] = [
    ColumnDef { title: "Location", width: 100.0, sortable: true, numeric: false },
    ColumnDef { title: "Label", width: 140.0, sortable: true, numeric: false },
    ColumnDef { title: "Code Unit", width: 260.0, sortable: false, numeric: false },
    ColumnDef { title: "Ref Type", width: 120.0, sortable: true, numeric: false },
];

/// Most references listed for one target.
const LIMIT: u32 = 10_000;

/// The references window.
#[derive(Debug)]
pub struct ReferencesView {
    table: PagedTable<Reference>,
    target: Option<Address>,
}

fn fetch_for(target: Address) -> super::table::Fetch<Reference> {
    Arc::new(move |s, filter: &str, sort: usize, order, offset, limit| {
        let all = s.references_to(target, LIMIT)?;
        let f = filter.to_lowercase();
        let mut rows: Vec<Reference> = all
            .rows
            .into_iter()
            .filter(|r| {
                f.is_empty()
                    || r.code.to_lowercase().contains(&f)
                    || r.from_function.as_deref().is_some_and(|n| n.to_lowercase().contains(&f))
            })
            .collect();
        rows.sort_by(|a, b| match sort {
            1 => a.from_function.cmp(&b.from_function).then(a.from.cmp(&b.from)),
            3 => a.kind.name().cmp(b.kind.name()).then(a.from.cmp(&b.from)),
            _ => a.from.cmp(&b.from),
        });
        if order == SortOrder::Descending {
            rows.reverse();
        }
        let total = rows.len() as u64;
        Ok(Page {
            rows: rows.into_iter().skip(offset as usize).take(limit as usize).collect(),
            total,
        })
    })
}

impl Default for ReferencesView {
    fn default() -> Self {
        Self {
            table: PagedTable::new(Arc::new(|_, _, _, _, _, _| Ok(Page { rows: Vec::new(), total: 0 })), 0),
            target: None,
        }
    }
}

impl View for ReferencesView {
    fn kind(&self) -> ViewKind {
        ViewKind::References
    }

    fn title(&self, shared: &Shared) -> String {
        match &shared.references_to {
            Some((_, name)) => format!("References to {name}"),
            None => "References".to_owned(),
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let wanted = cx.shared.references_to.as_ref().map(|(a, _)| *a);
        if wanted != self.target {
            self.target = wanted;
            if let Some(a) = wanted {
                self.table.set_fetch(fetch_for(a));
            }
        }
        if self.target.is_none() {
            widgets::empty_state(
                ui,
                &t,
                icons::REFERENCES,
                "No references shown",
                "Put the cursor on a name and choose Show References to (Ctrl+Shift+F).",
            );
            return;
        }
        let ev = self.table.ui(ui, cx, "references", &COLUMNS, "Filter references", |ui, r, c| match c {
            0 => code_cell(ui, &t, &r.from.to_string(), t.syntax.address),
            1 => code_cell(ui, &t, r.from_function.as_deref().unwrap_or(""), t.syntax.function),
            2 => code_cell(ui, &t, &r.code, t.syntax.mnemonic),
            _ => text_cell(ui, r.kind.name(), t.palette.text_secondary),
        });
        if let Some(TableEvent::Selected(r) | TableEvent::Activated(r)) = ev {
            cx.shared.nav.go(Location::at(r.from));
        }
    }
}
