//! The hover preview: a few listing rows at what a token refers to, shown
//! beside the pointer (Ghidra's reference hover), in the Listing and the
//! Decompiler alike.

use super::ViewCx;
use super::listing::layout::{self, Columns};
use crate::design::Tokens;
use crate::model::{Address, ListingRow, RowContent, SourceResult};
use crate::task::Pending;

/// Rows shown in the preview.
const ROWS: usize = 12;

/// The preview's state: what it shows, loaded in the background.
#[derive(Debug, Default)]
pub(crate) struct Preview {
    target: Option<(Address, Pending<SourceResult<Vec<ListingRow>>>)>,
}

impl Preview {
    /// Shows `a` (or nothing). Loads the rows when the target changes.
    pub(crate) fn want(&mut self, cx: &ViewCx<'_>, a: Option<Address>) {
        match a {
            None => self.target = None,
            Some(a) if self.target.as_ref().map(|t| t.0) != Some(a) => {
                self.target = Some((
                    a,
                    cx.client.request(move |s| {
                        let span = s.rows_for_address(a)?;
                        s.listing_rows(span.first, ROWS as u32 + 4)
                    }),
                ));
            }
            Some(_) => {}
        }
    }

    /// Whether there is something to show.
    pub(crate) fn active(&self) -> bool {
        self.target.is_some()
    }

    /// Draws the preview inside a tooltip.
    pub(crate) fn ui(&mut self, ui: &mut egui::Ui, t: &Tokens, digits: usize) {
        let Some((a, req)) = &mut self.target else {
            return;
        };
        let a = *a;
        let font = egui::FontId::monospace(t.metrics.code_size);
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        match req.poll() {
            Some(Ok(rows)) => {
                let painter = ui.painter().clone();
                let cols = Columns::new(digits);
                let shown = rows
                    .iter()
                    .filter(|r| !matches!(r.content, RowContent::Blank))
                    .take(ROWS);
                for r in shown {
                    let l = layout::layout(r, &cols, t, cw, &painter);
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(l.galley.size().x.min(640.0), t.metrics.code_row),
                        egui::Sense::hover(),
                    );
                    painter
                        .with_clip_rect(rect)
                        .galley(rect.left_top(), l.galley, t.palette.text);
                }
            }
            Some(Err(e)) => {
                ui.label(e.to_string());
            }
            None => {
                ui.label(format!("Loading {a}…"));
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(30));
            }
        }
    }
}
