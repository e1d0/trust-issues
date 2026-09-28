#!/usr/bin/env node
// Scores a findings.json produced by the skill against evals.json ground truth.
// Usage: node evals/score.mjs <eval-id> <findings.json>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const [evalId, findingsFile] = process.argv.slice(2);
const ev = JSON.parse(fs.readFileSync(path.join(here, 'evals.json'), 'utf8')).evals.find((e) => e.id === evalId);
if (!ev || !findingsFile) {
  console.error('usage: score.mjs <eval-id> <findings.json>');
  process.exit(2);
}
const findings = JSON.parse(fs.readFileSync(findingsFile, 'utf8')).findings.filter((f) => !['false-positive', 'fixed', 'mitigated'].includes(f.status));
const checkOf = (f) => String(f.fingerprint).split(':')[0];
const matches = (exp) => findings.filter((f) => exp.checks.includes(checkOf(f)) && `${f.element} ${f.fingerprint}`.toLowerCase().includes(exp.elementIncludes));

const report = (label, list, wantHit) =>
  list.map((exp) => {
    const hit = matches(exp).length > 0;
    console.log(`${hit === wantHit ? 'PASS' : 'FAIL'}  ${label}: ${exp.checks.join('|')} on ${exp.elementIncludes} (${exp.why})`);
    return hit === wantHit;
  });

const must = report('must_find', ev.must_find, true);
const should = report('should_find', ev.should_find ?? [], true);
const not = report('must_not_find', ev.must_not_find ?? [], false);
const recall = must.filter(Boolean).length / must.length;
console.log(`\nrecall(must)=${(recall * 100).toFixed(0)}%  should=${should.filter(Boolean).length}/${should.length}  false-positive-guards=${not.filter(Boolean).length}/${not.length}  total findings=${findings.length}`);
process.exit(must.every(Boolean) && not.every(Boolean) ? 0 : 1);
