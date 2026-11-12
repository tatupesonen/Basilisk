//! The Listing: Ghidra's code browser, virtualised over the paged data
//! interface.
//!
//! Rows are uniform, so the view knows where any row is without measuring
//! the ones before it; it draws only the rows on screen, from pages fetched
//! in the background, and caches each row's laid-out text. The cursor is a
//! row (and a token in it); moving it moves the tool's current location
//! without a history entry, as clicking in Ghidra's listing does.

mod cache;
mod find;
pub(crate) mod layout;

use egui::{CornerRadius, Rect, Stroke, pos2, vec2};

use self::cache::RowCache;
use self::find::{Find, UnitKind};
use self::layout::{Columns, RowLayout};
use super::scroller::Scroller;
use super::{Request, Target, View, ViewCx, ViewKind};
use crate::actions::ActionId;
use crate::design::{Tokens, widgets};
use crate::model::{
    Address, ListingRow, Location, Referent, RowContent, RowSpan, SourceResult, Token,
};
use crate::task::Pending;

/// Width of the marker gutter left of the address column.
const GUTTER: f32 = 18.0;

/// The Listing view.
#[derive(Debug)]
pub struct ListingView {
    snapshot: Option<Location>,
    scroller: Scroller,
    cache: RowCache,
    total: Option<u64>,
    total_req: Option<Pending<SourceResult<u64>>>,
    revision: u64,
    /// Cursor row and token index within the row's spans.
    cursor: u64,
    cursor_token: Option<usize>,
    /// Selection as an inclusive row range.
    selection: Option<(u64, u64)>,
    anchor: Option<u64>,
    follow: Option<(Pending<SourceResult<RowSpan>>, bool)>,
    seen_generation: Option<u64>,
    columns: Columns,
    cw: f32,
    find: Option<Pending<Option<Address>>>,
    preview: Option<(Address, Pending<SourceResult<Vec<ListingRow>>>)>,
    /// Where the cursor is, for other views and the status bar.
    cursor_address: Option<Address>,
    /// Horizontal scroll in points (the fields are wider than a narrow pane).
    hscroll: f32,
    /// Widest row seen on screen, for the horizontal scroll limit.
    content_width: f32,
}

impl ListingView {
    /// A listing that follows the current location, or a snapshot pinned
    /// at `snapshot`.
    pub fn new(snapshot: Option<Location>) -> Self {
        Self {
            snapshot,
            scroller: Scroller::default(),
            cache: RowCache::default(),
            total: None,
            total_req: None,
            revision: u64::MAX,
            cursor: 0,
            cursor_token: None,
            selection: None,
            anchor: None,
            follow: None,
            seen_generation: None,
            columns: Columns::new(8),
            cw: 8.0,
            find: None,
            preview: None,
            cursor_address: None,
            hscroll: 0.0,
            content_width: 0.0,
        }
    }

    fn total(&self) -> u64 {
        self.total.unwrap_or(0)
    }

    /// Requests the rows of `a` and moves the cursor there when they arrive.
    fn go_to(&mut self, cx: &ViewCx<'_>, a: Address, reveal_header: bool) {
        self.follow = Some((cx.client.request(move |s| s.rows_for_address(a)), reveal_header));
    }

    fn sync(&mut self, cx: &mut ViewCx<'_>) {
        // An edit elsewhere: refetch everything.
        let rev = cx.client.revision();
        if rev != self.revision {
            self.revision = rev;
            self.cache.clear();
            self.total_req = Some(cx.client.request(|s| s.listing_len()));
            if let Some(a) = self.cursor_address {
                self.go_to(cx, a, false);
            }
        }
        if let Some(req) = &mut self.total_req {
            if let Some(r) = req.take() {
                self.total_req = None;
                match r {
                    Ok(n) => self.total = Some(n),
                    Err(e) => cx.shared.log(super::Level::Error, format!("Listing: {e}")),
                }
            }
        }
        // Follow the tool's location unless this is a snapshot.
        let generation = cx.shared.nav.generation();
        if self.seen_generation != Some(generation) {
            self.seen_generation = Some(generation);
            let target = self.snapshot.unwrap_or_else(|| cx.shared.nav.current());
            if self.cursor_address != Some(target.address) || self.snapshot.is_some() {
                self.go_to(cx, target.address, true);
            }
            if self.snapshot.is_some() {
                self.seen_generation = Some(u64::MAX);
            }
        }
        if let Some((req, reveal_header)) = &mut self.follow {
            let reveal = *reveal_header;
            if let Some(r) = req.take() {
                self.follow = None;
                match r {
                    Ok(span) => {
                        self.cursor = span.unit.0;
                        self.cursor_token = None;
                        if reveal {
                            self.scroller.reveal(span.first.0, self.total());
                        }
                        self.scroller.keep_visible(span.unit.0, self.total());
                    }
                    Err(e) => cx.requests.push(Request::Notify(super::Level::Warning, e.to_string())),
                }
            }
        }
        if let Some(f) = &mut self.find {
            if let Some(found) = f.take() {
                self.find = None;
                match found {
                    Some(a) => cx.shared.nav.go(Location::at(a)),
                    None => cx.requests.push(Request::Notify(
                        super::Level::Info,
                        "Nothing further in that direction".into(),
                    )),
                }
            }
        }
    }

    /// Moves the cursor to `row`, updating the tool's location.
    fn set_cursor(&mut self, cx: &mut ViewCx<'_>, row: u64, token: Option<usize>) {
        self.cursor = row.min(self.total().saturating_sub(1));
        self.cursor_token = token;
        if let Some(r) = self.cache.row(self.cursor) {
            let a = r.address;
            self.cursor_address = Some(a);
            cx.shared.related = super::Related::default();
            if self.snapshot.is_none() && cx.shared.nav.current().address != a {
                cx.shared.nav.move_to(Location::at(a));
            }
            self.seen_generation = Some(cx.shared.nav.generation());
        }
    }

    fn cursor_token(&self) -> Option<Token> {
        let i = self.cursor_token?;
        let l = self.cache_layout(self.cursor)?;
        l.spans.get(i).map(|s| s.token.clone())
    }

    fn cache_layout(&self, row: u64) -> Option<&RowLayout> {
        self.cache.peek_layout(row)
    }

    fn follow_cursor(&mut self, cx: &mut ViewCx<'_>) -> bool {
        let token = self.cursor_token().or_else(|| {
            // No token chosen: the first operand that leads somewhere.
            let row = self.cache.row(self.cursor)?;
            row.tokens()
                .into_iter()
                .find(|t| t.referent.as_ref().and_then(Referent::address).is_some())
                .cloned()
        });
        if let Some(a) = token.and_then(|t| t.referent.and_then(|r| r.address())) {
            cx.shared.nav.go(Location::at(a));
            return true;
        }
        false
    }

    fn keyboard(&mut self, ui: &egui::Ui, cx: &mut ViewCx<'_>) {
        if !cx.focused || ui.ctx().egui_wants_keyboard_input() {
            return;
        }
        let total = self.total();
        let page = self.scroller.visible.saturating_sub(1).max(1);
        let (mut row, mut token) = (self.cursor, self.cursor_token);
        let shift = ui.input(|i| i.modifiers.shift);
        ui.input(|i| {
            for e in &i.events {
                if let egui::Event::Key {
                    key, pressed: true, modifiers, ..
                } = e
                {
                    if modifiers.command || modifiers.alt {
                        continue;
                    }
                    match key {
                        egui::Key::ArrowDown => row = row.saturating_add(1),
                        egui::Key::ArrowUp => row = row.saturating_sub(1),
                        egui::Key::PageDown => row = row.saturating_add(page),
                        egui::Key::PageUp => row = row.saturating_sub(page),
                        egui::Key::Home => row = 0,
                        egui::Key::End => row = total.saturating_sub(1),
                        egui::Key::ArrowRight => token = Some(token.map_or(0, |t| t + 1)),
                        egui::Key::ArrowLeft => token = token.and_then(|t| t.checked_sub(1)),
                        _ => continue,
                    }
                }
            }
        });
        if row != self.cursor || token != self.cursor_token {
            if row != self.cursor {
                token = None;
                if shift {
                    let a = *self.anchor.get_or_insert(self.cursor);
                    self.selection = Some((a.min(row), a.max(row)));
                } else {
                    self.anchor = None;
                    self.selection = None;
                }
            }
            if let (Some(t), Some(l)) = (token, self.cache_layout(row)) {
                token = Some(t.min(l.spans.len().saturating_sub(1)));
            }
            self.set_cursor(cx, row, token);
            self.scroller.keep_visible(self.cursor, total);
        }
    }

    fn row_at(&self, rect: Rect, row_h: f32, y: f32) -> u64 {
        let k = ((y - rect.top() + self.scroller.offset) / row_h).floor().max(0.0) as u64;
        self.scroller.top + k
    }

    fn token_at(&self, row: u64, rect: Rect, x: f32) -> Option<usize> {
        let x = x - rect.left() - GUTTER + self.hscroll;
        self.cache_layout(row)?.token_at(x)
    }

    fn paint_row(&mut self, ui: &egui::Ui, cx: &ViewCx<'_>, row: u64, rect: Rect) {
        let t = cx.tokens;
        let p = t.palette;
        let painter = ui.painter();
        let cols = self.columns;
        let cw = self.cw;
        let tt = *t;
        let Some(layout) = self
            .cache
            .layout(row, |r| layout::layout(r, &cols, &tt, cw, painter))
            .cloned()
        else {
            if let Some(e) = self.cache.error(row) {
                painter.text(
                    rect.left_center() + vec2(GUTTER, 0.0),
                    egui::Align2::LEFT_CENTER,
                    e,
                    egui::FontId::proportional(t.metrics.small_size),
                    p.error,
                );
            } else {
                let w = 0.25 + ((row * 37) % 50) as f32 / 100.0;
                let bar = Rect::from_min_max(pos2(rect.left() + GUTTER, rect.top()), rect.max);
                widgets::placeholder_bar(ui, t, bar.shrink2(vec2(0.0, 3.0)), w * 0.6);
            }
            return;
        };
        let address = self.cache.row(row).map(|r| (r.address, r.is_unit()));
        let in_selection = self
            .selection
            .is_some_and(|(a, b)| (a..=b).contains(&row));
        let related = address.is_some_and(|(a, unit)| unit && cx.shared.related.contains(a));
        let bg = if in_selection {
            Some(p.selection)
        } else if row == self.cursor {
            Some(p.cursor_line)
        } else if related {
            Some(p.related_line)
        } else {
            None
        };
        if let Some(bg) = bg {
            painter.rect_filled(rect, CornerRadius::ZERO, bg);
        }
        self.content_width = self.content_width.max(layout.galley.size().x + 2.0 * self.cw);
        let origin = pos2(rect.left() + GUTTER - self.hscroll, rect.center().y - layout.galley.size().y / 2.0);
        let painter = painter.with_clip_rect(rect.intersect(ui.clip_rect()).with_min_x(rect.left() + GUTTER - 2.0));
        // Token highlights under the text.
        for (i, s) in layout.spans.iter().enumerate() {
            let hl = cx.shared.highlight.as_ref().is_some_and(|h| h.matches(&s.token));
            let r = Rect::from_min_max(
                pos2(origin.x + s.x0 - 1.0, rect.top() + 2.0),
                pos2(origin.x + s.x1 + 1.0, rect.bottom() - 2.0),
            );
            if hl {
                painter.rect_filled(r, CornerRadius::same(2), p.token_highlight);
            }
            if s.token.referent.is_some() && rect.contains(r.center()) {
                super::token_node(ui, ui.id().with(("listing-token", row, i)), r, &s.token);
            }
            if row == self.cursor && self.cursor_token == Some(i) {
                painter.rect_stroke(
                    r,
                    CornerRadius::same(2),
                    Stroke::new(1.0, if cx.focused { p.accent } else { p.text_muted }),
                    egui::StrokeKind::Inside,
                );
            }
        }
        painter.galley(origin, layout.galley.clone(), p.text);
        // Gutter: the cursor marker, and a quiet bar on linked rows.
        if row == self.cursor {
            let c = if cx.focused { p.accent } else { p.text_muted };
            ui.painter().rect_filled(
                Rect::from_min_size(pos2(rect.left() + 4.0, rect.top() + 2.0), vec2(3.0, rect.height() - 4.0)),
                CornerRadius::same(1),
                c,
            );
        } else if related {
            ui.painter().rect_filled(
                Rect::from_min_size(pos2(rect.left() + 5.0, rect.top() + 3.0), vec2(1.5, rect.height() - 6.0)),
                CornerRadius::ZERO,
                p.text_muted,
            );
        }
    }

    fn hover(&mut self, ui: &egui::Ui, cx: &ViewCx<'_>, resp: &egui::Response, rect: Rect, row_h: f32) {
        let Some(pos) = resp.hover_pos() else {
            self.preview = None;
            return;
        };
        let row = self.row_at(rect, row_h, pos.y);
        let target = self
            .token_at(row, rect, pos.x)
            .and_then(|i| self.cache_layout(row)?.spans.get(i).cloned());
        let Some(span) = target else {
            self.preview = None;
            return;
        };
        let Some(a) = span.token.referent.as_ref().and_then(Referent::address) else {
            return;
        };
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        // Underline what a double-click would follow.
        let origin_y = rect.top() + (row - self.scroller.top) as f32 * row_h - self.scroller.offset;
        let x0 = rect.left() + GUTTER + span.x0 - self.hscroll;
        let x1 = rect.left() + GUTTER + span.x1 - self.hscroll;
        ui.painter().hline(
            x0..=x1,
            origin_y + row_h - 3.0,
            Stroke::new(1.0, crate::design::syntax::color(&cx.tokens.syntax, span.token.kind)),
        );
        if self.preview.as_ref().map(|p| p.0) != Some(a) {
            self.preview = Some((
                a,
                cx.client.request(move |s| {
                    let span = s.rows_for_address(a)?;
                    s.listing_rows(span.first, 14)
                }),
            ));
        }
    }

    fn preview_ui(&mut self, ui: &mut egui::Ui, t: &Tokens) {
        let Some((a, req)) = &mut self.preview else {
            return;
        };
        let a = *a;
        match req.poll() {
            Some(Ok(rows)) => {
                let painter = ui.painter().clone();
                let cols = Columns::new(self.columns.bytes.saturating_sub(2));
                for r in rows.iter().filter(|r| !matches!(r.content, RowContent::Blank)).take(12) {
                    let l = layout::layout(r, &cols, t, self.cw, &painter);
                    let (rect, _) = ui.allocate_exact_size(
                        vec2(l.galley.size().x.min(640.0), t.metrics.code_row),
                        egui::Sense::hover(),
                    );
                    painter.with_clip_rect(rect).galley(rect.left_top(), l.galley, t.palette.text);
                }
            }
            Some(Err(e)) => {
                ui.label(e.to_string());
            }
            None => {
                ui.label(format!("Loading {a}…"));
            }
        }
    }

    /// Horizontal scrolling (shift+wheel or a trackpad) and its thin bar.
    fn horizontal(&mut self, ui: &egui::Ui, t: &Tokens, rect: Rect) {
        let view = rect.width() - GUTTER;
        let max = (self.content_width - view).max(0.0);
        if ui.rect_contains_pointer(rect) {
            let dx = ui.input(|i| i.smooth_scroll_delta.x);
            self.hscroll = (self.hscroll - dx).clamp(0.0, max);
        }
        self.hscroll = self.hscroll.clamp(0.0, max);
        if max > 0.0 {
            let frac = view / self.content_width;
            let w = (view * frac).max(24.0);
            let x = rect.left() + GUTTER + (view - w) * (self.hscroll / max);
            let bar = Rect::from_min_size(pos2(x, rect.bottom() - 5.0), vec2(w, 3.0));
            ui.painter().rect_filled(bar, CornerRadius::same(2), t.palette.hairline);
        }
        self.content_width = 0.0;
    }

    fn start_find(&mut self, cx: &ViewCx<'_>, kind: UnitKind, forward: bool) {
        let from = self.cursor;
        self.find = Some(cx.client.request(move |s| Find { kind, forward }.run(s, from)));
    }
}

impl View for ListingView {
    fn kind(&self) -> ViewKind {
        ViewKind::Listing
    }

    fn title(&self, shared: &super::Shared) -> String {
        match self.snapshot {
            Some(l) => format!("Listing: {} [{}]", shared.program.name, l.address),
            None => format!("Listing: {}", shared.program.name),
        }
    }

    fn is_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    fn target(&self) -> Option<Target> {
        Some(Target {
            address: self.cursor_address?,
            token: self.cursor_token(),
            function: None,
        })
    }

    fn handle(&mut self, action: ActionId, cx: &mut ViewCx<'_>) -> bool {
        match action {
            ActionId::FollowReference => self.follow_cursor(cx),
            ActionId::Copy => {
                let (a, b) = self.selection.unwrap_or((self.cursor, self.cursor));
                let text: Vec<String> = (a..=b)
                    .filter_map(|r| self.cache.row(r).map(layout::row_text))
                    .collect();
                cx.ctx.copy_text(text.join("\n"));
                true
            }
            ActionId::NextInstruction => {
                self.start_find(cx, UnitKind::Instruction, true);
                true
            }
            ActionId::NextData => {
                self.start_find(cx, UnitKind::Data, true);
                true
            }
            ActionId::NextLabel => {
                self.start_find(cx, UnitKind::Label, true);
                true
            }
            ActionId::NextFunction => {
                self.start_find(cx, UnitKind::Function, true);
                true
            }
            ActionId::PreviousFunction => {
                self.start_find(cx, UnitKind::Function, false);
                true
            }
            _ => false,
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        self.cache.restyle(style_key(&t));
        self.sync(cx);
        let digits = layout::address_digits(cx.shared.program.image_base.offset(0xffff_ffff));
        let font = egui::FontId::monospace(t.metrics.code_size);
        self.cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        let cols = Columns::new(digits.min(16));
        if cols != self.columns {
            self.columns = cols;
            self.cache.restyle(style_key(&t).wrapping_add(digits as u64));
        }
        ui.painter().rect_filled(ui.available_rect_before_wrap(), CornerRadius::ZERO, t.palette.surface);
        let Some(total) = self.total else {
            widgets::empty_state(ui, &t, crate::design::icons::LISTING, "Loading listing…", "");
            return;
        };
        self.keyboard(ui, cx);
        let row_h = t.metrics.code_row;
        let cache = &mut self.cache;
        cache.want(cx.client, self.scroller.top, self.scroller.top + self.scroller.visible + 1, total);
        let mut rows_to_paint = Vec::new();
        let shown = self.scroller.show(ui, &t, total, row_h, |_, row, rect| {
            rows_to_paint.push((row, rect));
        });
        for (row, rect) in rows_to_paint {
            self.paint_row(ui, cx, row, rect);
        }
        if self.cache.loading() {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(50));
        }
        let resp = shown.response;
        let rect = shown.rect;
        self.horizontal(ui, &t, rect);
        self.hover(ui, cx, &resp, rect, row_h);
        if let Some(pos) = resp.interact_pointer_pos() {
            let row = self.row_at(rect, row_h, pos.y);
            let token = self.token_at(row, rect, pos.x);
            if resp.clicked() || resp.secondary_clicked() || resp.double_clicked() {
                if ui.input(|i| i.modifiers.shift) && resp.clicked() {
                    let a = *self.anchor.get_or_insert(self.cursor);
                    self.selection = Some((a.min(row), a.max(row)));
                } else if !resp.secondary_clicked() {
                    self.selection = None;
                    self.anchor = None;
                }
                self.set_cursor(cx, row, token);
            }
            if resp.double_clicked() {
                // Double-click on an XREF entry or operand follows it.
                self.follow_cursor(cx);
            }
            if resp.drag_started() && !ui.input(|i| i.modifiers.shift) {
                self.anchor = Some(row);
            }
            if resp.dragged() {
                if let Some(a) = self.anchor {
                    if a != row {
                        self.selection = Some((a.min(row), a.max(row)));
                    }
                }
            }
        }
        if resp.middle_clicked() {
            if let Some(pos) = resp.interact_pointer_pos() {
                let row = self.row_at(rect, row_h, pos.y);
                let tok = self
                    .token_at(row, rect, pos.x)
                    .and_then(|i| self.cache_layout(row)?.spans.get(i).map(|s| s.token.clone()));
                cx.shared.highlight = match (tok, &cx.shared.highlight) {
                    (Some(t), Some(h)) if t.matches(h) => None,
                    (t, _) => t,
                };
            }
        }
        if self.preview.is_some() {
            let resp = resp.clone();
            resp.on_hover_ui_at_pointer(|ui| self.preview_ui(ui, &t));
        }
        let target = self.target();
        resp.context_menu(|ui| super::popup_menu(ui, cx, target.as_ref()));
    }
}

/// A key for "the look changed": theme and density.
fn style_key(t: &Tokens) -> u64 {
    let k = match t.kind {
        crate::design::ThemeKind::Dark => 1,
        crate::design::ThemeKind::Light => 2,
    };
    let d = match t.density {
        crate::design::Density::Comfortable => 10,
        crate::design::Density::Compact => 20,
    };
    k + d
}
