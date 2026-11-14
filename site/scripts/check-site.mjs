// Checks a built site (scripts/site.sh check):
//   node scripts/check-site.mjs <dist> <base>
// 1. Every internal link and resource (href, src, srcset, CSS url()) resolves
//    to a file in <dist>, and every #fragment to an id in its target page.
// 2. Root-relative URLs stay under <base>, so the site works under a sub-path.
// 3. No external subresources: scripts, stylesheets, images, fonts and icons
//    all come from the site itself (links to other sites are allowed).
// 4. Every ```mermaid block in the documentation was rendered to SVG in both
//    themes; none is left as code.
// Exits 1 with a list of problems.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const [dist, base = '/'] = process.argv.slice(2);
if (!dist) {
  console.error('usage: check-site.mjs <dist> <base>');
  process.exit(2);
}
const problems = [];
const files = [];
(function walk(d) {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(dist);

const htmlFiles = files.filter((f) => f.endsWith('.html'));
const cssFiles = files.filter((f) => f.endsWith('.css'));
const idCache = new Map();
function idsOf(file) {
  if (!idCache.has(file)) {
    const html = readFileSync(file, 'utf8');
    idCache.set(file, new Set([...html.matchAll(/\s(?:id|name)=["']?([^"'\s>]+)/g)].map((m) => m[1])));
  }
  return idCache.get(file);
}

function pageUrl(file) {
  const rel = relative(dist, file).split('\\').join('/');
  return base + (rel.endsWith('index.html') ? rel.slice(0, -'index.html'.length) : rel);
}

function resolveTarget(urlPath) {
  if (!urlPath.startsWith(base)) return { error: `outside the base path ${base}` };
  let rel = decodeURIComponent(urlPath.slice(base.length));
  const candidates = rel === '' || rel.endsWith('/') ? [join(dist, rel, 'index.html')] : [join(dist, rel), join(dist, rel, 'index.html')];
  const hit = candidates.find((c) => existsSync(c) && statSync(c).isFile());
  return hit ? { file: hit } : { error: 'no such file' };
}

function check(file, raw, kind) {
  const from = relative(dist, file);
  const url = raw.trim().replace(/&amp;/g, '&');
  if (!url || url.startsWith('data:') || url.startsWith('mailto:') || url.startsWith('javascript:') || url.startsWith('blob:')) return;
  if (/^(https?:)?\/\//.test(url)) {
    if (kind !== 'link') problems.push(`${from}: external ${kind} ${url}`);
    return;
  }
  const page = pageUrl(file);
  let resolved;
  try {
    resolved = new URL(url, 'http://site' + page);
  } catch {
    problems.push(`${from}: malformed URL ${url}`);
    return;
  }
  if (url.startsWith('/') && !url.startsWith(base)) {
    problems.push(`${from}: ${url} ignores the base path ${base}`);
    return;
  }
  const target = resolveTarget(resolved.pathname);
  if (target.error) {
    problems.push(`${from}: ${kind} ${url} → ${resolved.pathname}: ${target.error}`);
    return;
  }
  const frag = decodeURIComponent(resolved.hash.slice(1));
  if (frag && target.file.endsWith('.html') && !idsOf(target.file).has(frag)) {
    problems.push(`${from}: ${url}: no element with id "${frag}"`);
  }
}

let links = 0;
for (const file of htmlFiles) {
  const html = readFileSync(file, 'utf8');
  const rel = relative(dist, file);
  for (const m of html.matchAll(/<(a|link|script|img|source|iframe|video|audio|use)\b([^>]*)>/gi)) {
    const tag = m[1].toLowerCase();
    const attrs = m[2];
    const relAttr = (attrs.match(/\srel=["']?([^"'>]+)/i) ?? [])[1] ?? '';
    for (const a of attrs.matchAll(/\s(href|src|srcset|xlink:href)=("([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
      const value = a[3] ?? a[4] ?? a[5] ?? '';
      const name = a[1].toLowerCase();
      if (tag === 'link' && /\b(canonical|alternate|me)\b/.test(relAttr)) continue;
      const kind = tag === 'a' ? 'link' : `${tag}${tag === 'link' ? `[rel=${relAttr}]` : ''}`;
      const urls = name === 'srcset' ? value.split(',').map((s) => s.trim().split(/\s+/)[0]) : [value];
      for (const u of urls) {
        links += 1;
        check(file, u, kind);
      }
    }
  }
  // Inline styles and <style> blocks.
  for (const m of html.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)) {
    if (!m[1].startsWith('#')) check(file, m[1], 'css url');
  }
  if (/<pre[^>]*data-language=["']mermaid["']/.test(html) || /class=["'][^"']*language-mermaid/.test(html)) {
    problems.push(`${rel}: a mermaid block was not rendered to SVG`);
  }
  for (const fig of html.matchAll(/<figure class="bk-diagram"[^>]*>([\s\S]*?)<\/figure>/g)) {
    const svgs = (fig[1].match(/<svg\b/g) ?? []).length;
    if (svgs !== 2) problems.push(`${rel}: a diagram has ${svgs} SVGs, expected 2 (light and dark)`);
  }
}
for (const file of cssFiles) {
  const css = readFileSync(file, 'utf8');
  const rel = relative(dist, file);
  for (const m of css.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)) {
    const u = m[1];
    if (u.startsWith('#') || u.startsWith('data:')) continue;
    if (/^(https?:)?\/\//.test(u)) {
      problems.push(`${rel}: external CSS url ${u}`);
      continue;
    }
    // Relative to the stylesheet itself.
    const asPage = pageUrl(file);
    const resolved = new URL(u, 'http://site' + asPage);
    const target = resolveTarget(resolved.pathname);
    if (target.error) problems.push(`${rel}: url(${u}): ${target.error}`);
  }
  if (/@import\s+(url\()?['"]?https?:/.test(css)) problems.push(`${rel}: imports an external stylesheet`);
}

// Every fenced mermaid block in the sources must appear as a diagram.
const srcRoot = 'src/content/docs';
let fenced = 0;
(function walk(d) {
  if (!existsSync(d)) return;
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.mdx?$/.test(name)) fenced += (readFileSync(p, 'utf8').match(/^\s*```mermaid\b/gm) ?? []).length;
  }
})(srcRoot);
const rendered = htmlFiles.reduce((n, f) => n + (readFileSync(f, 'utf8').match(/<figure class="bk-diagram"/g) ?? []).length, 0);
if (rendered !== fenced) problems.push(`${fenced} mermaid blocks in ${srcRoot}, but ${rendered} rendered diagrams in ${dist}`);

if (problems.length) {
  console.error(`check-site: ${problems.length} problem(s) in ${dist} (base ${base}):`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`check-site: ${htmlFiles.length} pages, ${links} links and resources, ${rendered} diagrams in both themes — all good (base ${base})`);
