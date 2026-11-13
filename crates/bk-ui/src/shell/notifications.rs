//! Transient messages in the lower right corner. They never take focus,
//! stay for a few seconds and are also written to the Console.

use egui::{Align2, RichText, vec2};

use crate::design::{Tokens, icons, tokens::radius, tokens::space};
use crate::views::Level;

/// Seconds a message stays.
const SHOW_FOR: f64 = 5.0;
/// Messages shown at once.
const MAX: usize = 4;

#[derive(Debug, Clone, PartialEq)]
struct Notice {
    level: Level,
    text: String,
    at: f64,
}

/// The messages showing.
#[derive(Debug, Default)]
pub struct Notices {
    items: Vec<Notice>,
}

impl Notices {
    /// Shows a message.
    pub fn push(&mut self, level: Level, text: impl Into<String>, now: f64) {
        let text = text.into();
        self.items.retain(|n| n.text != text);
        self.items.push(Notice {
            level,
            text,
            at: now,
        });
        if self.items.len() > MAX {
            self.items.remove(0);
        }
    }

    /// Drops old messages.
    pub fn expire(&mut self, now: f64) {
        self.items.retain(|n| now - n.at < SHOW_FOR);
    }

    /// The texts showing (tests).
    pub fn texts(&self) -> Vec<&str> {
        self.items.iter().map(|n| n.text.as_str()).collect()
    }

    /// Draws them.
    pub fn ui(&self, ctx: &egui::Context, t: &Tokens, bottom_margin: f32) {
        if self.items.is_empty() {
            return;
        }
        let p = t.palette;
        egui::Area::new(egui::Id::new("bk-notices"))
            .order(egui::Order::Tooltip)
            .anchor(
                Align2::RIGHT_BOTTOM,
                vec2(-space::LG, -bottom_margin - space::LG),
            )
            .interactable(false)
            .show(ctx, |ui| {
                for n in &self.items {
                    let (icon, color) = match n.level {
                        Level::Info => (icons::INFO, p.text_secondary),
                        Level::Warning => (icons::WARNING, p.warning),
                        Level::Error => (icons::WARNING, p.error),
                    };
                    egui::Frame::popup(ui.style())
                        .fill(p.raised)
                        .corner_radius(egui::CornerRadius::same(radius::MD))
                        .inner_margin(egui::Margin::symmetric(space::LG as i8, space::MD as i8))
                        .show(ui, |ui| {
                            ui.set_max_width(380.0);
                            ui.horizontal(|ui| {
                                ui.label(icons::rich(icon).color(color));
                                ui.label(RichText::new(&n.text).color(p.text));
                            });
                        });
                    ui.add_space(space::SM);
                }
            });
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_expire_and_do_not_repeat() {
        let mut n = Notices::default();
        n.push(Level::Info, "a", 0.0);
        n.push(Level::Info, "a", 1.0);
        n.push(Level::Error, "b", 2.0);
        assert_eq!(n.texts(), vec!["a", "b"]);
        n.expire(6.5);
        assert_eq!(n.texts(), vec!["b"]);
    }
}
