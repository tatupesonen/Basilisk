// The repository root, for build-time reads of docs/*.md. Builds run with
// the site directory as the working directory (scripts/site.sh).
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';

export const repoRoot = resolve(process.cwd(), '..');

export function readRepoFile(rel: string): string {
  return readFileSync(resolve(repoRoot, rel), 'utf8');
}

/** Minimal inline Markdown → HTML for table cells and list items:
 *  escapes HTML, then `code`, **strong** and [text](url). */
export function inlineMarkdown(text: string, linkCode?: (code: string) => string | undefined): string {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const parts = text.split(/(`[^`]+`)/g);
  return parts
    .map((p) => {
      if (p.startsWith('`') && p.endsWith('`') && p.length > 1) {
        const code = p.slice(1, -1);
        const href = linkCode?.(code);
        const html = `<code>${esc(code)}</code>`;
        return href ? `<a href="${href}">${html}</a>` : html;
      }
      return esc(p)
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2">$1</a>');
    })
    .join('');
}
