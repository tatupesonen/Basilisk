// Parses the milestones of docs/PLAN.md at build time for the roadmap.
// Headings "### Mn — Title (remark)" with "- [x]" / "- [ ]" items below.
import { readRepoFile } from './repo';

export interface MilestoneItem {
  done: boolean;
  text: string;
}
export interface Milestone {
  id: string; // "M0"
  title: string;
  remark?: string;
  intro: string;
  items: MilestoneItem[];
  // done: every item checked. partial: work has moved on, a few items are
  // still open. current: the latest milestone with work done in it.
  state: 'done' | 'partial' | 'current' | 'planned';
  checked: number;
  total: number;
}

let cached: Milestone[] | undefined;

export function loadMilestones(): Milestone[] {
  if (cached) return cached;
  const text = readRepoFile('docs/PLAN.md');
  const start = text.indexOf('\n## Milestones');
  if (start < 0) throw new Error('docs/PLAN.md: no "## Milestones" section');
  const rest = text.slice(start + 1);
  const end = rest.slice(3).search(/\n## /);
  const body = end < 0 ? rest : rest.slice(0, end + 3);
  const out: Milestone[] = [];
  let cur: Milestone | undefined;
  let lastItem: MilestoneItem | undefined;
  for (const line of body.split(/\r?\n/)) {
    const h = line.match(/^###\s+(M\d+)\s+[—-]\s+(.+?)\s*$/);
    if (h) {
      const m = h[2].match(/^(.*?)\s*\((.*)\)$/);
      cur = { id: h[1], title: m ? m[1] : h[2], remark: m ? m[2] : undefined, intro: '', items: [], state: 'planned', checked: 0, total: 0 };
      out.push(cur);
      lastItem = undefined;
      continue;
    }
    if (!cur) continue;
    const item = line.match(/^- \[([ xX])\]\s+(.*)$/);
    if (item) {
      lastItem = { done: item[1] !== ' ', text: item[2] };
      cur.items.push(lastItem);
    } else if (lastItem && /^\s{2,}\S/.test(line)) {
      lastItem.text += ' ' + line.trim();
    } else if (line.trim() && !line.startsWith('#')) {
      lastItem = undefined;
      cur.intro += (cur.intro ? ' ' : '') + line.trim();
    }
  }
  if (out.length === 0) throw new Error('docs/PLAN.md: no milestones parsed');
  for (const m of out) {
    m.total = m.items.length;
    m.checked = m.items.filter((i) => i.done).length;
  }
  // The current milestone is the latest one that is started and unfinished;
  // earlier unfinished ones with work done are "partial" (open items remain).
  let now = -1;
  out.forEach((m, i) => {
    if (m.checked > 0 && m.checked < m.total) now = i;
  });
  if (now < 0) now = out.findIndex((m) => m.total === 0 || m.checked < m.total);
  out.forEach((m, i) => {
    if (m.total > 0 && m.checked === m.total) m.state = 'done';
    else if (i === now) m.state = 'current';
    else if (m.checked > 0) m.state = 'partial';
  });
  cached = out;
  return out;
}
