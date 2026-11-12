//! The Functions window: every function, sortable and filterable.

use std::sync::Arc;

use super::table::{ColumnDef, PagedTable, TableEvent, code_cell, text_cell};
use super::{Shared, View, ViewCx, ViewKind};
use crate::model::{FunctionColumn, FunctionInfo, Location, TableQuery};

const COLUMNS: [ColumnDef; 4] = [
    ColumnDef { title: "Name", width: 180.0, sortable: true, numeric: false },
    ColumnDef { title: "Location", width: 100.0, sortable: true, numeric: false },
    ColumnDef { title: "Size", width: 56.0, sortable: true, numeric: true },
    ColumnDef { title: "Function Signature", width: 240.0, sortable: false, numeric: false },
];

fn column(i: usize) -> FunctionColumn {
    match i {
        0 => FunctionColumn::Name,
        2 => FunctionColumn::Size,
        3 => FunctionColumn::References,
        _ => FunctionColumn::Location,
    }
}

/// The Functions window.
#[derive(Debug)]
pub struct FunctionsView {
    table: PagedTable<FunctionInfo>,
}

impl Default for FunctionsView {
    fn default() -> Self {
        let fetch = Arc::new(|s: &dyn crate::model::ProgramSource, filter: &str, sort: usize, order, offset, limit| {
            s.functions(&TableQuery {
                filter: filter.to_owned(),
                sort: column(sort),
                order,
                offset,
                limit,
            })
        });
        Self {
            table: PagedTable::new(fetch, 1),
        }
    }
}

impl View for FunctionsView {
    fn kind(&self) -> ViewKind {
        ViewKind::Functions
    }

    fn title(&self, _shared: &Shared) -> String {
        match self.table.total() {
            Some(n) => format!("Functions - {n} items"),
            None => "Functions".to_owned(),
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let ev = self.table.ui(ui, cx, "functions", &COLUMNS, "Filter functions", |ui, f, c| match c {
            0 => code_cell(ui, &t, &f.name, t.syntax.function),
            1 => code_cell(ui, &t, &f.entry.to_string(), t.syntax.address),
            2 => code_cell(ui, &t, &f.size.to_string(), t.syntax.number),
            _ => text_cell(ui, &f.signature, t.palette.text_secondary),
        });
        if let Some(TableEvent::Selected(f) | TableEvent::Activated(f)) = ev {
            cx.shared.nav.go(Location::at(f.entry));
        }
    }
}
