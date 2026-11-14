// Detail views for the landing page's gallery: regions of the real
// interface screenshots, cropped (never retouched) so the feature each one
// shows is legible at thumbnail size. Runs from prepare.sh after the full
// screenshots are copied; writes <name>-detail-<theme>.png beside them.
import { readdirSync, writeFileSync } from 'node:fs';
import sharp from 'sharp';

const dir = 'src/generated/screenshots';

// The renderer leaves a black margin around the window; trim it so the
// site's own frame is the only border.
for (const file of readdirSync(dir).filter((f) => f.endsWith('.png'))) {
  const path = `${dir}/${file}`;
  const out = await sharp(path).trim({ background: '#000000', threshold: 12 }).png().toBuffer();
  writeFileSync(path, out);
}
// Regions as fractions of the image: [left, top, width, height] (16:10).
const crops = {
  palette: [0.25, 0.03, 0.5, 0.5],
  'hover-preview': [0.25, 0.44, 0.5, 0.5],
  references: [0.19, 0.47, 0.5, 0.5],
};
for (const [name, [l, t, w, h]] of Object.entries(crops)) {
  for (const theme of ['dark', 'light']) {
    const src = `${dir}/${name}-${theme}.png`;
    const { width, height } = await sharp(src).metadata();
    const region = {
      left: Math.round(l * width),
      top: Math.round(t * height),
      width: Math.round(w * width),
      height: Math.round(h * height),
    };
    region.height = Math.min(region.height, height - region.top);
    await sharp(src).extract(region).png().toFile(`${dir}/${name}-detail-${theme}.png`);
  }
}
console.log(`crops: ${Object.keys(crops).length * 2} detail views`);
