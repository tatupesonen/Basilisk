//! The Basilisk mark as a texture, decoded once per context.

use crate::design::ThemeKind;

const MARK_DARK: &[u8] = include_bytes!("../../assets/brand/mark-ember-256.png");
const MARK_LIGHT: &[u8] = include_bytes!("../../assets/brand/mark-ember-deep-256.png");
/// The application icon (the mark on the soot tile).
pub const ICON: &[u8] = include_bytes!("../../assets/brand/basilisk-icon-256.png");

/// Decodes a PNG into an egui image.
pub fn decode(png: &[u8]) -> Option<egui::ColorImage> {
    let img = image::load_from_memory_with_format(png, image::ImageFormat::Png).ok()?;
    let rgba = img.to_rgba8();
    let size = [rgba.width() as usize, rgba.height() as usize];
    Some(egui::ColorImage::from_rgba_unmultiplied(
        size,
        rgba.as_raw(),
    ))
}

/// The mark for `theme` (Ember on dark, Ember deep on light), as the
/// brand guide asks.
pub fn mark(ctx: &egui::Context, theme: ThemeKind) -> Option<egui::TextureHandle> {
    let (key, bytes) = match theme {
        ThemeKind::Dark => ("bk-mark-dark", MARK_DARK),
        ThemeKind::Light => ("bk-mark-light", MARK_LIGHT),
    };
    let id = egui::Id::new(key);
    if let Some(t) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(t);
    }
    let tex = ctx.load_texture(key, decode(bytes)?, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    Some(tex)
}

/// The window icon.
pub fn icon() -> Option<egui::IconData> {
    let img = image::load_from_memory_with_format(ICON, image::ImageFormat::Png).ok()?;
    let rgba = img.to_rgba8();
    Some(egui::IconData {
        width: rgba.width(),
        height: rgba.height(),
        rgba: rgba.into_raw(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn brand_images_decode() {
        assert!(super::decode(super::MARK_DARK).is_some());
        assert!(super::decode(super::MARK_LIGHT).is_some());
        assert_eq!(super::icon().map(|i| i.width), Some(256));
    }
}
