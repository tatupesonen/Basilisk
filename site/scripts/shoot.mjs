// Screenshots of the built site with Playwright's Chromium (in the site
// image): desktop (1440 px) and phone (390 px), dark and light.
//   node scripts/shoot.mjs <dist> <out-dir> [--review]
// Serves <dist> on a local port at the base path recorded in it, so the
// pages load exactly as deployed. JPEG keeps the set small enough to commit.
import { createServer } from 'node:http';
import { readFile, stat, mkdir } from 'node:fs/promises';
import { join, extname, resolve } from 'node:path';
import { chromium } from 'playwright';

const [dist = 'dist', out = '../docs/features/site-screenshots'] = process.argv.slice(2);
const review = process.argv.includes('--review');
const root = resolve(dist);

const types = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.webp': 'image/webp', '.woff2': 'font/woff2', '.json': 'application/json', '.txt': 'text/plain',
  '.wasm': 'application/wasm', '.pf_meta': 'application/octet-stream', '.pf_index': 'application/octet-stream',
  '.pf_fragment': 'application/octet-stream', '.pagefind': 'application/octet-stream',
};
const server = createServer(async (req, res) => {
  let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  let file = join(root, path);
  try {
    if ((await stat(file)).isDirectory()) file = join(file, 'index.html');
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/html' });
    res.end(await readFile(join(root, '404.html')).catch(() => 'not found'));
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const desktop = { width: 1440, height: 900 };
const phone = { width: 390, height: 844 };
const shots = review
  ? [
      ['/', desktop, true], ['/', phone, true],
      ['/status/', desktop, true], ['/status/', phone, false],
      ['/roadmap/', desktop, true],
      ['/docs/', desktop, false], ['/docs/internals/', desktop, true], ['/docs/internals/', phone, true],
      ['/docs/decompiler/', desktop, false], ['/docs/interface/', desktop, false], ['/docs/getting-started/build/', desktop, false],
      ['/404.html', desktop, false],
    ]
  : [
      ['/', desktop, true], ['/', phone, true],
      ['/status/', desktop, false], ['/status/', phone, false],
      ['/docs/internals/', desktop, false], ['/docs/internals/', phone, false],
      ['/roadmap/', desktop, false],
    ];

await mkdir(out, { recursive: true });
const browser = await chromium.launch();
for (const theme of ['dark', 'light']) {
  for (const [path, vp, full] of shots) {
    const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: vp === phone ? 2 : 1 });
    await ctx.addInitScript((t) => localStorage.setItem('starlight-theme', t), theme);
    const page = await ctx.newPage();
    const external = [];
    page.on('request', (r) => {
      if (!r.url().startsWith(origin) && !r.url().startsWith('data:')) external.push(r.url());
    });
    await page.goto(origin + (process.env.SITE_BASE || '/').replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
    await page.evaluate(() => document.fonts.ready);
    // Load lazy images before a full-page capture.
    if (full) {
      await page.evaluate(async () => {
        for (let y = 0; y < document.body.scrollHeight; y += 600) {
          window.scrollTo(0, y);
          await new Promise((r) => setTimeout(r, 40));
        }
        window.scrollTo(0, 0);
      });
      await page.waitForLoadState('networkidle');
    }
    const name = `${path.replace(/^\/|\/$/g, '').replace(/[/.]/g, '-') || 'home'}-${vp === phone ? 'phone' : 'desktop'}-${theme}.jpg`;
    await page.screenshot({ path: join(out, name), fullPage: full, type: 'jpeg', quality: review ? 70 : 72 });
    if (external.length) console.error(`EXTERNAL REQUESTS from ${path}: ${external.join(', ')}`);
    console.log(name);
    await ctx.close();
  }
}
await browser.close();
server.close();
