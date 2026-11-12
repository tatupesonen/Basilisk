//! A scroll area over any number of uniform rows.
//!
//! egui's `ScrollArea` measures in `f32` pixels: at ten million 20-px rows
//! the offset (2·10⁸ px) is past `f32`'s exact integers and scrolling
//! stutters in 16-px steps. This scroller keeps the position as a row
//! index (`u64`) plus a pixel offset inside that row, so every row of any
//! program is reachable exactly, jumping to a row is O(1), and only the
//! visible rows are ever touched.

use egui::{CornerRadius, Rect, Sense, Ui, pos2, vec2};

use crate::design::Tokens;

/// Width of the scroll bar's track.
const BAR: f32 = 10.0;

/// Scroll position over rows.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Scroller {
    /// First (partly) visible row.
    pub top: u64,
    /// Pixels of `top` scrolled out above the view, `0..row_height`.
    pub offset: f32,
    /// Rows that fit the last drawn height.
    pub visible: u64,
    drag_start: Option<(f32, u64)>,
}

/// What [`Scroller::show`] reports.
#[derive(Debug)]
pub struct Shown {
    /// The rows area's response (clicks, drags, hover).
    pub response: egui::Response,
    /// The area rows were drawn in.
    pub rect: Rect,
    /// First drawn row.
    pub first: u64,
    /// One past the last drawn row.
    pub end: u64,
}

impl Scroller {
    fn max_top(&self, total: u64) -> u64 {
        total.saturating_sub(self.visible.max(1).saturating_sub(1))
    }

    /// Scrolls by `dy` pixels (positive: down).
    pub fn scroll_px(&mut self, dy: f32, row_h: f32, total: u64) {
        let pos = self.offset + dy;
        let rows = (pos / row_h).floor();
        let new_top = if rows < 0.0 {
            self.top.saturating_sub((-rows) as u64)
        } else {
            self.top.saturating_add(rows as u64)
        };
        self.offset = pos - rows * row_h;
        self.top = new_top;
        self.clamp(total);
    }

    /// Scrolls by whole rows.
    pub fn scroll_rows(&mut self, rows: i64, total: u64) {
        self.top = if rows < 0 {
            self.top.saturating_sub(rows.unsigned_abs())
        } else {
            self.top.saturating_add(rows.unsigned_abs())
        };
        self.offset = 0.0;
        self.clamp(total);
    }

    fn clamp(&mut self, total: u64) {
        let max = self.max_top(total);
        if self.top >= max {
            self.top = max;
            self.offset = 0.0;
        }
    }

    /// Puts `row` a third of the way down the view (Ghidra's go-to
    /// placement), unless it is already comfortably visible.
    pub fn reveal(&mut self, row: u64, total: u64) {
        if self.is_visible(row) {
            return;
        }
        self.top = row.saturating_sub(self.visible / 3);
        self.offset = 0.0;
        self.clamp(total);
    }

    /// Puts `row` at the top of the view.
    pub fn show_at_top(&mut self, row: u64, total: u64) {
        self.top = row;
        self.offset = 0.0;
        self.clamp(total);
    }

    /// Scrolls the least distance that makes `row` fully visible.
    pub fn keep_visible(&mut self, row: u64, total: u64) {
        if row < self.top || row == self.top && self.offset > 0.0 {
            self.top = row;
            self.offset = 0.0;
        } else if self.visible > 1 && row >= self.top + self.visible - 1 {
            self.top = row + 2 - self.visible;
            self.offset = 0.0;
        }
        self.clamp(total);
    }

    /// Whether `row` is fully visible.
    pub fn is_visible(&self, row: u64) -> bool {
        row > self.top && row + 1 < self.top + self.visible || row == self.top && self.offset == 0.0
    }

    /// Draws the visible rows with `draw(ui, row, rect)` and a scroll bar.
    pub fn show(
        &mut self,
        ui: &mut Ui,
        t: &Tokens,
        total: u64,
        row_h: f32,
        mut draw: impl FnMut(&mut Ui, u64, Rect),
    ) -> Shown {
        let full = ui.available_rect_before_wrap();
        let response = ui.allocate_rect(full, Sense::click_and_drag());
        let rect = Rect::from_min_max(full.min, pos2(full.max.x - BAR, full.max.y));
        self.visible = ((rect.height() / row_h).floor() as u64).max(1);
        if response.hovered() || ui.rect_contains_pointer(full) {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            if dy != 0.0 {
                self.scroll_px(-dy, row_h, total);
            }
        }
        self.clamp(total);
        let first = self.top;
        let mut y = rect.top() - self.offset;
        let mut row = first;
        let painter_clip = ui.clip_rect().intersect(rect);
        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
        child.set_clip_rect(painter_clip);
        while y < rect.bottom() && row < total {
            let r = Rect::from_min_size(pos2(rect.left(), y), vec2(rect.width(), row_h));
            draw(&mut child, row, r);
            y += row_h;
            row += 1;
        }
        self.scrollbar(ui, t, full, total);
        Shown {
            response,
            rect,
            first,
            end: row,
        }
    }

    fn scrollbar(&mut self, ui: &mut Ui, t: &Tokens, full: Rect, total: u64) {
        let track = Rect::from_min_max(pos2(full.max.x - BAR, full.min.y), full.max);
        let max = self.max_top(total);
        if max == 0 {
            return;
        }
        let id = ui.id().with("bk-scrollbar");
        let resp = ui.interact(track, id, Sense::click_and_drag());
        let thumb_h = (track.height() * self.visible as f32 / total as f32).clamp(28.0, track.height());
        let travel = (track.height() - thumb_h).max(1.0);
        let frac = self.top as f64 / max as f64;
        let thumb_top = track.top() + (frac as f32) * travel;
        let thumb = Rect::from_min_size(pos2(track.left() + 2.0, thumb_top), vec2(BAR - 4.0, thumb_h));
        if resp.drag_started() {
            let y = resp.interact_pointer_pos().map_or(thumb.center().y, |p| p.y);
            if thumb.contains(pos2(thumb.center().x, y)) {
                self.drag_start = Some((y, self.top));
            } else {
                // Click on the track: jump there.
                let f = ((y - track.top() - thumb_h / 2.0) / travel).clamp(0.0, 1.0);
                self.top = (f64::from(f) * max as f64) as u64;
                self.offset = 0.0;
                self.drag_start = Some((y, self.top));
            }
        }
        if resp.dragged() {
            if let (Some((y0, top0)), Some(p)) = (self.drag_start, resp.interact_pointer_pos()) {
                let rows = f64::from((p.y - y0) / travel) * max as f64;
                let top = (top0 as f64 + rows).clamp(0.0, max as f64);
                self.top = top as u64;
                self.offset = 0.0;
            }
        }
        if resp.drag_stopped() {
            self.drag_start = None;
        }
        if resp.clicked() {
            if let Some(p) = resp.interact_pointer_pos() {
                let f = ((p.y - track.top() - thumb_h / 2.0) / travel).clamp(0.0, 1.0);
                self.top = (f64::from(f) * max as f64) as u64;
                self.offset = 0.0;
            }
        }
        let p = t.palette;
        let active = resp.hovered() || resp.dragged();
        let color = if active { p.text_muted } else { p.hairline };
        ui.painter()
            .rect_filled(thumb, CornerRadius::same(3), color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(visible: u64) -> Scroller {
        Scroller {
            visible,
            ..Scroller::default()
        }
    }

    #[test]
    fn pixel_scrolling_carries_into_rows_exactly() {
        let mut sc = s(40);
        let total = 10_000_000;
        sc.scroll_px(45.0, 20.0, total);
        assert_eq!((sc.top, sc.offset), (2, 5.0));
        sc.scroll_px(-10.0, 20.0, total);
        assert_eq!((sc.top, sc.offset), (1, 15.0));
        sc.scroll_rows(9_999_990, total);
        assert_eq!(sc.top, total - 39);
        sc.scroll_px(1e6, 20.0, total);
        assert_eq!(sc.top, total - 39);
        sc.scroll_rows(-20_000_000, total);
        assert_eq!(sc.top, 0);
    }

    #[test]
    fn reveal_places_rows_a_third_down() {
        let mut sc = s(30);
        sc.reveal(9_000_000, 10_000_000);
        assert_eq!(sc.top, 9_000_000 - 10);
        // Already visible: no move.
        sc.reveal(9_000_005, 10_000_000);
        assert_eq!(sc.top, 9_000_000 - 10);
        sc.keep_visible(9_000_100, 10_000_000);
        assert_eq!(sc.top, 9_000_100 + 2 - 30);
    }
}
