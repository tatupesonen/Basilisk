// Build-time Mermaid rendering (docs/features/site.md, "Mermaid diagrams").
//
// Fenced ```mermaid blocks become inline SVG when the site is built, twice:
// once with the light theme and once with the dark, both inside one
// <figure>; tokens.css shows the copy that matches the active theme. No
// Mermaid code reaches the browser, so diagrams work without scripts.
//
// Mermaid lays text out with the browser's measurements, so it runs in
// headless Chromium (Playwright, from the build image) with the site's own
// Inter loaded: the boxes fit the text the page will draw. A diagram that
// does not parse or render throws, and the build fails with the file name.

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { mermaidThemes } from './mermaid-theme.mjs';

const require = createRequire(import.meta.url);
const fontDir = new URL('../generated/fonts/', import.meta.url);

let session; // Promise<{ browser, page }>
let queue = Promise.resolve();
let rendered = 0;

function fontFace(file, family, weight) {
  const data = readFileSync(new URL(file, fontDir)).toString('base64');
  return `@font-face{font-family:'${family}';font-weight:${weight};src:url(data:font/woff2;base64,${data}) format('woff2');}`;
}

async function open() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent(
    `<!doctype html><html><head><style>${fontFace('Inter-Regular.woff2', 'Inter', 400)}${fontFace('Inter-SemiBold.woff2', 'Inter', 600)}${fontFace('JetBrainsMonoNL-Regular.woff2', 'JetBrains Mono', 400)}
     body{font-family:Inter}</style></head><body><span style="font-weight:400">a</span><b style="font-weight:600">a</b></body></html>`,
  );
  await page.addScriptTag({ path: require.resolve('mermaid/dist/mermaid.min.js') });
  await page.evaluate(async () => {
    await document.fonts.load("400 16px Inter");
    await document.fonts.load("600 16px Inter");
    await document.fonts.load("400 12px 'JetBrains Mono'");
    await document.fonts.ready;
  });
  return { browser, page };
}

/** Renders one diagram in both themes. Serialised: Mermaid's config is global. */
export function renderDiagram(code, where) {
  const id = 'mmd-' + createHash('sha256').update(code).digest('hex').slice(0, 10);
  const job = queue.then(async () => {
    session ??= open();
    const { page } = await session;
    const result = await page.evaluate(
      async ({ code, id, themes }) => {
        const out = {};
        for (const [name, config] of Object.entries(themes)) {
          // @ts-ignore - mermaid is the global from the script tag
          mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', ...config });
          try {
            // @ts-ignore
            await mermaid.parse(code);
            // @ts-ignore
            const { svg } = await mermaid.render(`${id}-${name}`, code);
            out[name] = svg;
          } catch (e) {
            return { error: String(e && e.message ? e.message : e) };
          } finally {
            document.querySelectorAll(`[id^="d${id}"], #${id}-${name}`).forEach((n) => n.remove());
          }
        }
        return out;
      },
      { code, id, themes: mermaidThemes },
    );
    if (result.error) {
      throw new Error(`Mermaid diagram in ${where} does not render: ${result.error}`);
    }
    rendered += 1;
    return { id, ...result };
  });
  queue = job.catch(() => {});
  return job;
}

/** Closes the browser; called when the build or dev server ends. */
export async function closeRenderer() {
  if (!session) return;
  const { browser } = await session.catch(() => ({ browser: null }));
  session = undefined;
  await browser?.close();
}

function oneLine(svg) {
  // The figure is spliced into Markdown as one HTML block; a blank line
  // would end the block early.
  return svg.replace(/\r?\n\s*/g, ' ');
}

/** Sätteri mdast plugin: ```mermaid code → <figure> with both SVGs. */
export function mermaidPlugin() {
  return {
    name: 'bk-mermaid',
    async code(node, ctx) {
      if (node.lang !== 'mermaid') return;
      const where = ctx.fileURL ? fileURLToPath(ctx.fileURL) : 'a Markdown file';
      const { id, light, dark } = await renderDiagram(node.value, where);
      const caption = (node.meta ?? '').match(/title="([^"]*)"/)?.[1];
      const label = caption ? ` aria-label="${caption.replace(/[<>&"]/g, '')}"` : '';
      const html =
        `<figure class="bk-diagram" data-diagram="${id}"${label}>` +
        `<div class="bk-diagram-svg bk-only-light">${oneLine(light)}</div>` +
        `<div class="bk-diagram-svg bk-only-dark">${oneLine(dark)}</div>` +
        (caption ? `<figcaption>${caption.replace(/[<>&]/g, '')}</figcaption>` : '') +
        `</figure>`;
      return { type: 'html', value: html };
    },
  };
}

/** Astro integration that closes the renderer's browser when work ends. */
export function mermaidIntegration() {
  return {
    name: 'bk-mermaid',
    hooks: {
      'astro:build:done': async ({ logger }) => {
        logger.info(`${rendered} Mermaid diagram(s) rendered to SVG in both themes`);
        await closeRenderer();
      },
      'astro:server:done': closeRenderer,
    },
  };
}
