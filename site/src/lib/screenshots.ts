// The interface screenshots the pages use (docs/features/ui-screenshots/,
// rendered by bk-ui's screenshot test, copied by scripts/prepare.sh).
// Add a line here to use another one: an imported image is emitted into the
// build even when no page shows it, so only used screenshots are listed.
import type { ImageMetadata } from 'astro';
import main_dark_normal from '../generated/screenshots/main-dark-normal.png';
import main_light_normal from '../generated/screenshots/main-light-normal.png';
import palette_detail_dark from '../generated/screenshots/palette-detail-dark.png';
import palette_detail_light from '../generated/screenshots/palette-detail-light.png';
import hover_preview_detail_dark from '../generated/screenshots/hover-preview-detail-dark.png';
import hover_preview_detail_light from '../generated/screenshots/hover-preview-detail-light.png';
import references_detail_dark from '../generated/screenshots/references-detail-dark.png';
import references_detail_light from '../generated/screenshots/references-detail-light.png';

export const screenshots: Record<string, ImageMetadata> = {
  'main-dark-normal': main_dark_normal,
  'main-light-normal': main_light_normal,
  'palette-detail-dark': palette_detail_dark,
  'palette-detail-light': palette_detail_light,
  'hover-preview-detail-dark': hover_preview_detail_dark,
  'hover-preview-detail-light': hover_preview_detail_light,
  'references-detail-dark': references_detail_dark,
  'references-detail-light': references_detail_light,
};
