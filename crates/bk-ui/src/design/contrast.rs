//! Colour arithmetic for checking the palette: WCAG contrast ratios and
//! CIELAB distances. The tests assert the figures `ui-design.md` quotes.

use egui::Color32;

fn linear(c: u8) -> f64 {
    let c = f64::from(c) / 255.0;
    if c <= 0.040_45 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// Relative luminance (WCAG 2.x).
pub fn luminance(c: Color32) -> f64 {
    0.2126 * linear(c.r()) + 0.7152 * linear(c.g()) + 0.0722 * linear(c.b())
}

/// WCAG contrast ratio between two opaque colours (1.0 to 21.0).
pub fn contrast(a: Color32, b: Color32) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// CIELAB coordinates (D65).
pub fn lab(c: Color32) -> [f64; 3] {
    let (r, g, b) = (linear(c.r()), linear(c.g()), linear(c.b()));
    let x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.950_47;
    let y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    let z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.088_83;
    let f = |t: f64| {
        if t > 0.008_856 {
            t.cbrt()
        } else {
            7.787 * t + 16.0 / 116.0
        }
    };
    [
        116.0 * f(y) - 16.0,
        500.0 * (f(x) - f(y)),
        200.0 * (f(y) - f(z)),
    ]
}

/// Colour difference ΔE*ab (CIE76). Around 2 is just noticeable; above 10
/// two colours read as different at a glance.
pub fn delta_e(a: Color32, b: Color32) -> f64 {
    let (p, q) = (lab(a), lab(b));
    ((p[0] - q[0]).powi(2) + (p[1] - q[1]).powi(2) + (p[2] - q[2]).powi(2)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::design::tokens::{Density, ThemeKind, Tokens, brand};

    fn both() -> [Tokens; 2] {
        [
            Tokens::new(ThemeKind::Dark, Density::Comfortable),
            Tokens::new(ThemeKind::Light, Density::Comfortable),
        ]
    }

    #[test]
    fn brand_figures_match_the_brand_readme() {
        assert!((contrast(brand::EMBER, brand::SOOT) - 6.6).abs() < 0.1);
        assert!((contrast(brand::BONE, brand::SOOT) - 16.2).abs() < 0.1);
    }

    #[test]
    fn text_meets_wcag_aa_on_every_surface() {
        for t in both() {
            let p = t.palette;
            for bg in [p.chrome, p.surface, p.raised, p.hover, p.cursor_line] {
                assert!(contrast(p.text, bg) >= 12.0, "{:?} text {}", t.kind, contrast(p.text, bg));
                assert!(contrast(p.text_secondary, bg) >= 5.5, "{:?} secondary", t.kind);
                assert!(contrast(p.text_muted, bg) >= 4.5, "{:?} muted {}", t.kind, contrast(p.text_muted, bg));
            }
            // Text stays readable on a selected row and on the accent fill.
            assert!(contrast(p.text, p.selection) >= 10.0);
            assert!(contrast(p.on_accent, p.accent) >= 3.4);
            assert!(contrast(p.accent_text, p.surface) >= 4.5, "{:?} accent text", t.kind);
            // The accent is visible as a mark (WCAG 1.4.11, 3:1).
            assert!(contrast(p.accent, p.surface) >= 3.0);
        }
    }

    #[test]
    fn syntax_colours_are_readable_and_distinct() {
        for t in both() {
            let s = t.syntax;
            let roles = [
                ("mnemonic", s.mnemonic),
                ("register", s.register),
                ("number", s.number),
                ("label", s.label),
                ("function", s.function),
                ("global", s.global),
                ("variable", s.variable),
                ("parameter", s.parameter),
                ("keyword", s.keyword),
                ("type", s.datatype),
                ("string", s.string),
                ("comment", s.comment),
            ];
            let bgs = [t.palette.surface, t.palette.cursor_line, t.palette.related_line];
            for (name, c) in roles {
                for bg in bgs {
                    let min = if name == "comment" { 4.5 } else { 5.0 };
                    assert!(contrast(c, bg) >= min, "{:?} {name}: {:.2}", t.kind, contrast(c, bg));
                }
            }
            for (i, (a, ca)) in roles.iter().enumerate() {
                for (b, cb) in roles.iter().skip(i + 1) {
                    let d = delta_e(*ca, *cb);
                    assert!(d >= 14.0, "{:?} {a} vs {b}: ΔE {d:.1}", t.kind);
                }
            }
            // Text stays legible on the token highlight.
            for (_, c) in roles {
                assert!(contrast(c, t.palette.token_highlight) >= 3.0);
            }
        }
    }
}
