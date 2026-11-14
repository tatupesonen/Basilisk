// Checks that every package in package-lock.json was published at least
// 14 days ago (docs/LOOP.md, Dependencies; ADR-030), by asking the npm
// registry for each package's publish times. Needs the network, so it is
// run by hand when dependencies change (scripts/site.sh dep-age), like
// scripts/check-dep-age.py for crates.
//   node scripts/check-dep-age.mjs [--days 14] [--direct]
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const days = Number(args[args.indexOf('--days') + 1]) || 14;
const directOnly = args.includes('--direct');
const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const direct = new Set(Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }));

const wanted = new Map(); // name -> Set(versions)
for (const [path, info] of Object.entries(lock.packages)) {
  if (!path) continue;
  const name = info.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
  if (directOnly && !direct.has(name)) continue;
  if (!wanted.has(name)) wanted.set(name, new Set());
  wanted.get(name).add(info.version);
}

const cutoff = Date.now() - days * 86400e3;
const rows = [];
const failures = [];
const unknown = [];
const names = [...wanted.keys()].sort();
let next = 0;
async function worker() {
  while (next < names.length) {
    const name = names[next++];
    let times;
    for (let attempt = 0; attempt < 3 && !times; attempt++) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, { headers: { accept: 'application/json' } });
        if (res.ok) times = (await res.json()).time;
      } catch {
        /* retry */
      }
    }
    for (const version of wanted.get(name)) {
      const t = times?.[version];
      if (!t) {
        unknown.push(`${name}@${version}`);
        continue;
      }
      rows.push({ name, version, published: t.slice(0, 10), direct: direct.has(name) });
      if (Date.parse(t) > cutoff) failures.push(`${name}@${version} published ${t}`);
    }
  }
}
await Promise.all(Array.from({ length: 8 }, worker));

rows.sort((a, b) => (a.direct === b.direct ? a.name.localeCompare(b.name) : a.direct ? -1 : 1));
console.log('Direct dependencies:');
for (const r of rows.filter((r) => r.direct)) console.log(`  ${r.name}@${r.version}  published ${r.published}`);
const newest = rows.reduce((m, r) => (r.published > m.published ? r : m), rows[0]);
console.log(`${rows.length} package versions checked; newest: ${newest.name}@${newest.version} (${newest.published}).`);
if (unknown.length) console.log(`Could not check (no publish time from the registry): ${unknown.join(', ')}`);
if (failures.length) {
  console.error(`Younger than ${days} days:\n  ${failures.join('\n  ')}`);
  process.exit(1);
}
console.log(`All are at least ${days} days old.`);
