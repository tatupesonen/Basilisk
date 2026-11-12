//! The Defined Strings window.

use std::sync::Arc;

use super::table::{ColumnDef, PagedTable, TableEvent, code_cell};
use super::{Shared, View, ViewCx, ViewKind};
use crate::model::{Location, StringColumn, StringInfo, TableQuery};

const COLUMNS: [ColumnDef; 4] = [
    ColumnDef { title: "Location", width: 100.0, sortable: true, numeric: false },
    ColumnDef { title: "String Value", width: 320.0, sortable: true, numeric: false },
    ColumnDef { title: "Length", width: 56.0, sortable: true, numeric: true },
    ColumnDef { title: "Data Type", width: 60.0, sortable: false, numeric: false },
];

fn column(i: usize) -> StringColumn {
    match i {
        1 => StringColumn::Value,
        2 => StringColumn::Length,
        _ => StringColumn::Location,
    }
}

/// The Defined Strings window.
#[derive(Debug)]
pub struct StringsView {
    table: PagedTable<StringInfo>,
}

impl Default for StringsView {
    fn default() -> Self {
        let fetch = Arc::new(|s: &dyn crate::model::ProgramSource, filter: &str, sort: usize, order, offset, limit| {
            s.strings(&TableQuery {
                filter: filter.to_owned(),
                sort: column(sort),
                order,
                offset,
                limit,
            })
        });
        Self {
            table: PagedTable::new(fetch, 0),
        }
    }
}

impl View for StringsView {
    fn kind(&self) -> ViewKind {
        ViewKind::Strings
    }

    fn title(&self, _shared: &Shared) -> String {
        match self.table.total() {
            Some(n) => format!("Defined Strings - {n} items"),
            None => "Defined Strings".to_owned(),
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        let ev = self.table.ui(ui, cx, "strings", &COLUMNS, "Filter strings", |ui, s, c| match c {
            0 => code_cell(ui, &t, &s.address.to_string(), t.syntax.address),
            1 => code_cell(ui, &t, &format!("\"{}\"", s.value), t.syntax.string),
            2 => code_cell(ui, &t, &s.length.to_string(), t.syntax.number),
            _ => code_cell(ui, &t, &s.datatype, t.syntax.datatype),
        });
        if let Some(TableEvent::Selected(s) | TableEvent::Activated(s)) = ev {
            cx.shared.nav.go(Location::at(s.address));
        }
    }
}
