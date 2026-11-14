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
  state: 'done' | 'current' | 'planned';
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
      cur = { id: h[1], title: m ? m[1] : h[2], remark: m ? m[2] : undefined, intro: '', items: [], state: 'planned' };
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
  let currentSet = false;
  for (const m of out) {
    const complete = m.items.length > 0 && m.items.every((i) => i.done);
    if (complete) m.state = 'done';
    else if (!currentSet) {
      m.state = 'current';
      currentSet = true;
    }
  }
  cached = out;
  return out;
}
