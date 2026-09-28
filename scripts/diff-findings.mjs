#!/usr/bin/env node
// Compare two findings.json runs by fingerprint: new, resolved, persisting, severity changes.
// Usage: node diff-findings.mjs <previous.json> <current.json> [--json]
import fs from 'node:fs';

const [prevF, curF] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
if (!prevF || !curF) {
  console.error('usage: diff-findings.mjs <previous.json> <current.json> [--json]');
  process.exit(2);
}
const load = (f) => new Map(JSON.parse(fs.readFileSync(f, 'utf8')).findings.map((x) => [x.fingerprint, x]));
const prev = load(prevF);
const cur = load(curF);
const active = (x) => x && !['fixed', 'false-positive', 'mitigated'].includes(x.status);

const out = { new: [], resolved: [], persisting: [], severityChanged: [] };
for (const [fp, c] of cur) {
  const p = prev.get(fp);
  if (!active(c)) {
    if (active(p)) out.resolved.push({ fp, id: c.id, title: c.title, how: c.status });
    continue;
  }
  if (!active(p)) out.new.push({ fp, id: c.id, severity: c.severity, title: c.title });
  else {
    out.persisting.push({ fp, id: c.id, severity: c.severity, title: c.title });
    if (p.severity !== c.severity) out.severityChanged.push({ fp, id: c.id, from: p.severity, to: c.severity });
  }
}
for (const [fp, p] of prev) if (active(p) && !cur.has(fp)) out.resolved.push({ fp, id: p.id, title: p.title, how: 'no longer reported' });

if (process.argv.includes('--json')) console.log(JSON.stringify(out, null, 2));
else
  for (const [k, v] of Object.entries(out)) {
    console.log(`## ${k} (${v.length})`);
    v.forEach((x) => console.log(`- ${x.id} ${x.title ?? ''} ${x.severity ?? ''}${x.from ? `${x.from} -> ${x.to}` : ''}${x.how ? ` [${x.how}]` : ''}`));
  }
