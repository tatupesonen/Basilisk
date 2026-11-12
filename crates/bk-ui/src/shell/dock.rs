//! Drawing a docking tree: tab strips styled by the tokens, and each pane's
//! view, for the main window and for every detached window alike.

use egui::WidgetText;
use egui_dock::{DockArea, DockState, Style, TabViewer};

use super::layout::Tab;
use super::workspace::Workspace;
use crate::actions::Keymap;
use crate::design::{Tokens, tokens::space};
use crate::views::{Request, Shared, View, ViewCx};
use crate::task::DataClient;

/// What a pane's tab menu asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabCommand {
    /// Detach the pane into its own native window.
    Detach(u64),
    /// Dock the window holding the pane back into the main window.
    Dock(u64),
}

struct Viewer<'a> {
    views: &'a mut std::collections::HashMap<u64, Box<dyn View>>,
    shared: &'a mut Shared,
    client: &'a DataClient,
    tokens: &'a Tokens,
    keymap: &'a Keymap,
    mac: bool,
    ctx: egui::Context,
    active: &'a mut Option<u64>,
    requests: &'a mut Vec<Request>,
    commands: &'a mut Vec<TabCommand>,
    detached: bool,
}

impl TabViewer for Viewer<'_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> egui::Id {
        egui::Id::new(("bk-tab", tab.id))
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        let view = self
            .views
            .entry(tab.id)
            .or_insert_with(|| crate::views::new_view(tab.kind, tab.snapshot));
        let p = self.tokens.palette;
        let active = *self.active == Some(tab.id);
        let title = view.title(self.shared);
        let mut job = egui::text::LayoutJob::default();
        let size = self.tokens.metrics.body_size;
        job.append(
            tab.kind.icon(),
            0.0,
            egui::TextFormat::simple(
                crate::design::icons::font(size),
                if active { p.accent } else { p.text_muted },
            ),
        );
        job.append(
            &title,
            space::SM,
            egui::TextFormat::simple(egui::FontId::proportional(size), p.text),
        );
        WidgetText::LayoutJob(job.into())
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Tab) {
        // A press anywhere in a pane makes it the one keys go to.
        if ui.ui_contains_pointer() && ui.input(|i| i.pointer.any_pressed()) {
            *self.active = Some(tab.id);
        }
        let view = self
            .views
            .entry(tab.id)
            .or_insert_with(|| crate::views::new_view(tab.kind, tab.snapshot));
        let mut cx = ViewCx {
            client: self.client,
            tokens: self.tokens,
            shared: self.shared,
            requests: self.requests,
            keymap: self.keymap,
            focused: *self.active == Some(tab.id),
            mac: self.mac,
            ctx: self.ctx.clone(),
        };
        view.ui(ui, &mut cx);
    }

    fn context_menu(&mut self, ui: &mut egui::Ui, tab: &mut Tab, _path: egui_dock::NodePath) {
        if self.detached {
            if ui.button("Dock Window").clicked() {
                self.commands.push(TabCommand::Dock(tab.id));
                ui.close();
            }
        } else if ui.button("Detach Window").clicked() {
            self.commands.push(TabCommand::Detach(tab.id));
            ui.close();
        }
        if tab.kind.is_code() && ui.button("Snapshot").clicked() {
            self.requests.push(Request::Snapshot(tab.kind, self.shared.nav.current()));
            ui.close();
        }
    }

    fn on_tab_button(&mut self, tab: &mut Tab, response: &egui::Response) {
        if response.clicked() || response.drag_started() {
            *self.active = Some(tab.id);
        }
        if response.double_clicked() && !self.detached {
            // Ghidra undocks a window when its title is dragged out; a
            // double-click on the tab is the quick way here.
            self.commands.push(TabCommand::Detach(tab.id));
        }
    }

    fn allowed_in_windows(&self, _tab: &mut Tab) -> bool {
        // Dragging a tab out of the main window makes a floating surface,
        // which the shell turns into a native window at once.
        !self.detached
    }

    fn scroll_bars(&self, _tab: &Tab) -> [bool; 2] {
        [false, false]
    }
}

/// The tab strip and pane style from the tokens.
pub fn style(ctx: &egui::Context, t: &Tokens) -> Style {
    let p = t.palette;
    let mut s = Style::from_egui(&ctx.global_style());
    s.dock_area_padding = None;
    s.main_surface_border_stroke = egui::Stroke::NONE;
    s.separator.width = 1.0;
    s.separator.extra_interact_width = 4.0;
    s.separator.color_idle = p.border;
    s.separator.color_hovered = p.text_muted;
    s.separator.color_dragged = p.accent;
    s.tab_bar.bg_fill = p.chrome;
    s.tab_bar.height = t.metrics.tab_height;
    s.tab_bar.hline_color = p.border;
    s.tab_bar.corner_radius = egui::CornerRadius::ZERO;
    s.tab_bar.fill_tab_bar = false;
    let tab = |bg, fg| egui_dock::TabInteractionStyle {
        outline_color: egui::Color32::TRANSPARENT,
        corner_radius: egui::CornerRadius {
            nw: 4,
            ne: 4,
            sw: 0,
            se: 0,
        },
        bg_fill: bg,
        text_color: fg,
    };
    s.tab.active = tab(p.surface, p.text);
    s.tab.focused = tab(p.surface, p.text);
    s.tab.inactive = tab(p.chrome, p.text_secondary);
    s.tab.hovered = tab(p.hover, p.text);
    s.tab.active_with_kb_focus = tab(p.surface, p.text);
    s.tab.focused_with_kb_focus = tab(p.surface, p.text);
    s.tab.inactive_with_kb_focus = tab(p.chrome, p.text_secondary);
    s.tab.tab_body.bg_fill = p.surface;
    s.tab.tab_body.stroke = egui::Stroke::NONE;
    s.tab.tab_body.inner_margin = egui::Margin::ZERO;
    s.tab.tab_body.corner_radius = egui::CornerRadius::ZERO;
    s.tab.hline_below_active_tab_name = false;
    s.tab.spacing = 2.0;
    s.buttons.close_tab_color = p.text_muted;
    s.buttons.close_tab_active_color = p.text;
    s.buttons.close_tab_bg_fill = p.hover;
    s.overlay.selection_color = p.accent.gamma_multiply(0.25);
    s.overlay.button_color = p.text_secondary;
    s.overlay.button_border_stroke = egui::Stroke::new(1.0, p.border);
    s
}

/// Draws the docking tree of the main window (`window: None`) or of a
/// detached window, returning tab commands for the shell.
pub fn show(
    ui: &mut egui::Ui,
    ws: &mut Workspace,
    window: Option<u64>,
    t: &Tokens,
    keymap: &Keymap,
    mac: bool,
    requests: &mut Vec<Request>,
) -> Vec<TabCommand> {
    let placeholder = || DockState::new(Vec::new());
    let mut dock = match window {
        None => std::mem::replace(&mut ws.layout.main, placeholder()),
        Some(w) => match ws.layout.windows.iter_mut().find(|d| d.id == w) {
            Some(d) => std::mem::replace(&mut d.dock, placeholder()),
            None => return Vec::new(),
        },
    };
    let mut commands = Vec::new();
    {
        let mut viewer = Viewer {
            views: &mut ws.views,
            shared: &mut ws.shared,
            client: &ws.client,
            tokens: t,
            keymap,
            mac,
            ctx: ui.ctx().clone(),
            active: &mut ws.active,
            requests,
            commands: &mut commands,
            detached: window.is_some(),
        };
        let id = egui::Id::new(("bk-dock", window.unwrap_or(0)));
        DockArea::new(&mut dock)
            .id(id)
            .style(style(ui.ctx(), t))
            .show_close_buttons(true)
            .show_add_buttons(false)
            .draggable_tabs(true)
            .show_leaf_close_all_buttons(false)
            .show_leaf_collapse_buttons(false)
            .tab_context_menus(true)
            .show_inside(ui, &mut viewer);
    }
    match window {
        None => ws.layout.main = dock,
        Some(w) => {
            if let Some(d) = ws.layout.windows.iter_mut().find(|d| d.id == w) {
                d.dock = dock;
            }
        }
    }
    commands
}
