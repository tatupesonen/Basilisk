//! The listing's cache: pages of rows fetched in the background, and the
//! laid-out text of the rows near the screen.
//!
//! Rows arrive in pages of [`PAGE`] from the data interface. A frame asks
//! for the rows it shows; missing pages are requested (plus one page either
//! side, so scrolling a little never shows placeholders) and drawn as
//! placeholders until they land. Pages far from the screen are dropped, so
//! memory stays bounded by the view, not by the program.

use std::collections::HashMap;
use std::sync::Arc;

use super::layout::RowLayout;
use crate::model::{ListingRow, RowIndex, SourceResult};
use crate::task::{DataClient, Pending};

/// Rows per page.
pub(crate) const PAGE: u64 = 64;

/// Pages kept beyond the visible ones before the farthest are dropped.
const KEEP_PAGES: usize = 48;

#[derive(Debug)]
enum PageState {
    Loading(Pending<SourceResult<Vec<ListingRow>>>),
    Ready(Arc<[ListingRow]>),
    Failed(String),
}

/// Pages of rows and their layouts.
#[derive(Debug, Default)]
pub(crate) struct RowCache {
    pages: HashMap<u64, PageState>,
    layouts: HashMap<u64, RowLayout>,
    /// Bumped when pages change, so layouts can be rebuilt.
    style_key: u64,
}

impl RowCache {
    /// Drops everything (after an edit, or a different program).
    pub(crate) fn clear(&mut self) {
        self.pages.clear();
        self.layouts.clear();
    }

    /// Drops the layouts (theme or density changed).
    pub(crate) fn restyle(&mut self, key: u64) {
        if key != self.style_key {
            self.layouts.clear();
            self.style_key = key;
        }
    }

    /// Makes sure the pages for rows `first..end` are loaded or loading,
    /// and drops pages far away.
    pub(crate) fn want(&mut self, client: &DataClient, first: u64, end: u64, total: u64) {
        let p0 = (first / PAGE).saturating_sub(1);
        let p1 = (end / PAGE + 1).min(total.div_ceil(PAGE));
        for p in p0..=p1 {
            if p * PAGE >= total {
                break;
            }
            self.pages.entry(p).or_insert_with(|| {
                PageState::Loading(
                    client.request(move |s| s.listing_rows(RowIndex(p * PAGE), PAGE as u32)),
                )
            });
        }
        for state in self.pages.values_mut() {
            if let PageState::Loading(pending) = state
                && let Some(result) = pending.take()
            {
                *state = match result {
                    Ok(rows) => PageState::Ready(rows.into()),
                    Err(e) => PageState::Failed(e.to_string()),
                };
            }
        }
        if self.pages.len() > KEEP_PAGES + (p1 - p0 + 1) as usize {
            let centre = u64::midpoint(p0, p1);
            let mut far: Vec<u64> = self.pages.keys().copied().collect();
            far.sort_by_key(|p| std::cmp::Reverse(p.abs_diff(centre)));
            for p in far.into_iter().take(self.pages.len() - KEEP_PAGES) {
                self.pages.remove(&p);
            }
            let (lo, hi) = (p0 * PAGE, (p1 + 1) * PAGE);
            self.layouts.retain(|r, _| (lo..hi).contains(r));
        }
    }

    /// The row, if its page has arrived.
    pub(crate) fn row(&self, row: u64) -> Option<&ListingRow> {
        match self.pages.get(&(row / PAGE))? {
            PageState::Ready(rows) => rows.get((row % PAGE) as usize),
            _ => None,
        }
    }

    /// The error that stopped a page loading.
    pub(crate) fn error(&self, row: u64) -> Option<&str> {
        match self.pages.get(&(row / PAGE))? {
            PageState::Failed(e) => Some(e),
            _ => None,
        }
    }

    /// Whether any page is still loading.
    pub(crate) fn loading(&self) -> bool {
        self.pages
            .values()
            .any(|p| matches!(p, PageState::Loading(_)))
    }

    /// The layout of `row`, built with `make` the first time.
    pub(crate) fn layout(
        &mut self,
        row: u64,
        make: impl FnOnce(&ListingRow) -> RowLayout,
    ) -> Option<&RowLayout> {
        if !self.layouts.contains_key(&row) {
            let PageState::Ready(rows) = self.pages.get(&(row / PAGE))? else {
                return None;
            };
            let l = make(rows.get((row % PAGE) as usize)?);
            self.layouts.insert(row, l);
        }
        self.layouts.get(&row)
    }

    /// The layout of `row` if it has been built.
    pub(crate) fn peek_layout(&self, row: u64) -> Option<&RowLayout> {
        self.layouts.get(&row)
    }
}
