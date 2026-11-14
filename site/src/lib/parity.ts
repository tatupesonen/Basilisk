// Parses docs/PARITY.md at build time, so the site can never claim more than
// the parity matrix does (ADR-031). An unknown status or a table whose
// columns the parser does not recognise fails the build.
import { readRepoFile } from './repo';

export const STATUSES = ['Done', 'Partial', 'In progress', 'Reused', 'Replaced', 'Missing', 'Out of scope'] as const;
export type Status = (typeof STATUSES)[number];

export interface ParityRow {
  module: string;
  crates: string;
  milestone: string;
  status: Status;
  notes: string;
}
export interface ParitySection {
  title: string;
  slug: string;
  rows: ParityRow[];
}
export interface Parity {
  updated: string;
  sections: ParitySection[];
}

function cells(line: string): string[] {
  const inner = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  // Split on pipes that are not inside backticks.
  const out: string[] = [];
  let cur = '';
  let code = false;
  for (const ch of inner) {
    if (ch === '`') code = !code;
    if (ch === '|' && !code) {
      out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  out.push(cur.trim());
  return out;
}

export function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

let cached: Parity | undefined;

export function loadParity(): Parity {
  if (cached) return cached;
  const text = readRepoFile('docs/PARITY.md');
  const lines = text.split(/\r?\n/);
  const updated = (text.match(/^Last updated:\s*(\d{4}-\d{2}-\d{2})/m) ?? [])[1];
  if (!updated) throw new Error('docs/PARITY.md: no "Last updated: YYYY-MM-DD" line');
  const sections: ParitySection[] = [];
  let current: ParitySection | undefined;
  let header: string[] | undefined;
  for (const line of lines) {
    const h = line.match(/^##\s+(.+?)\s*$/);
    if (h) {
      current = { title: h[1], slug: slugify(h[1]), rows: [] };
      sections.push(current);
      header = undefined;
      continue;
    }
    if (!current || !line.trim().startsWith('|')) {
      if (!line.trim().startsWith('|')) header = undefined;
      continue;
    }
    const c = cells(line);
    if (!header) {
      header = c.map((x) => x.toLowerCase());
      const want = ['basilisk', 'milestone', 'status', 'notes'];
      if (!/^ghidra (module|part)$/.test(header[0] ?? '') || want.some((w, i) => header![i + 1] !== w)) {
        throw new Error(`docs/PARITY.md, section "${current.title}": unexpected columns ${JSON.stringify(c)}`);
      }
      continue;
    }
    if (c.every((x) => /^:?-+:?$/.test(x))) continue;
    const [module, crates, milestone, status, notes = ''] = c;
    if (!STATUSES.includes(status as Status)) {
      throw new Error(`docs/PARITY.md, "${module}": unknown status "${status}" (known: ${STATUSES.join(', ')})`);
    }
    current.rows.push({ module, crates, milestone, status: status as Status, notes });
  }
  const withRows = sections.filter((s) => s.rows.length > 0);
  if (withRows.length === 0) throw new Error('docs/PARITY.md: no status tables found');
  cached = { updated, sections: withRows };
  return cached;
}

export function countByStatus(rows: ParityRow[]): Record<Status, number> {
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0])) as Record<Status, number>;
  for (const r of rows) counts[r.status] += 1;
  return counts;
}

/** CSS class suffix and short description for each status. */
export const STATUS_INFO: Record<Status, { key: string; meaning: string }> = {
  Done: { key: 'done', meaning: 'Implemented, its Ghidra tests marked, on master.' },
  Partial: { key: 'partial', meaning: 'Some of it exists; the notes say what is missing.' },
  'In progress': { key: 'progress', meaning: 'A track is working on it now.' },
  Reused: { key: 'reused', meaning: 'Ghidra’s files are read unchanged.' },
  Replaced: { key: 'replaced', meaning: 'Provided by different means, by decision.' },
  Missing: { key: 'missing', meaning: 'Nothing on master yet.' },
  'Out of scope': { key: 'out', meaning: 'Excluded by an owner decision.' },
};
