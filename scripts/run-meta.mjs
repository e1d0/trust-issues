#!/usr/bin/env node
// Run metadata (run-meta.json): timing, owner gates, measured subagent usage, and counts.
// Usage:
//   node run-meta.mjs start  <runDir> --target <id> --mode <full|diff|verify> [--scope "..."] [--commit <sha>] [--since <ref>]
//   node run-meta.mjs stage  <runDir> --name <stage> [--agents N] [--tokens N] [--ms N]
//   node run-meta.mjs gate   <runDir> --name <inventory|diagrams> --outcome <approved|corrected|skipped> [--note "..."]
//   node run-meta.mjs finish <runDir>
// Tokens: a script cannot read session usage. Record the total_tokens and duration_ms that each subagent fan-out
// reports in its notification. Main-loop tokens are not exposed, so they are not counted and must not be guessed.
import fs from 'node:fs';
import path from 'node:path';

const [cmd, dir, ...rest] = process.argv.slice(2);
const flag = (name, def) => {
  const i = rest.indexOf(name);
  return i >= 0 ? rest[i + 1] : def;
};
const now = () => new Date().toISOString();
const file = () => path.join(dir, 'run-meta.json');
const read = () => JSON.parse(fs.readFileSync(file(), 'utf8'));
const write = (m) => fs.writeFileSync(file(), `${JSON.stringify(m, null, 2)}\n`);
const readJson = (f) => (fs.existsSync(path.join(dir, f)) ? JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) : undefined);

function counts() {
  const model = readJson('model.json');
  const findings = readJson('findings.json')?.findings ?? [];
  const nodes = (model?.diagrams ?? []).flatMap((d) => d.nodes ?? []);
  const bySeverity = {};
  const byStatus = {};
  for (const f of findings) {
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
    if (!['fixed', 'false-positive', 'mitigated'].includes(f.status)) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }
  return {
    diagrams: model?.diagrams?.length ?? 0,
    elements: new Set(nodes.map((n) => n.id)).size,
    flows: (model?.diagrams ?? []).reduce((s, d) => s + (d.flows?.length ?? 0), 0),
    trustZones: new Set(nodes.map((n) => n.trust)).size,
    findings: findings.length,
    openBySeverity: bySeverity,
    byStatus,
  };
}

if (!dir || !['start', 'stage', 'gate', 'finish'].includes(cmd)) {
  console.error('usage: run-meta.mjs start|stage|gate|finish <runDir> [...]');
  process.exit(2);
}
if (cmd === 'start') {
  fs.mkdirSync(dir, { recursive: true });
  write({
    target: flag('--target', path.basename(path.dirname(path.resolve(dir)))),
    mode: flag('--mode', 'full'),
    scope: flag('--scope', ''),
    commit: flag('--commit', ''),
    since: flag('--since', null),
    date: now().slice(0, 10),
    startedAt: now(),
    finishedAt: null,
    wallClockSeconds: null,
    gates: [],
    stages: [],
    tokens: { subagentTotal: 0, subagentDurationMs: 0 },
    counts: {},
  });
  console.log(dir);
} else if (cmd === 'stage') {
  const m = read();
  m.stages.push({ name: flag('--name', 'stage'), agents: Number(flag('--agents', 0)), subagentTokens: Number(flag('--tokens', 0)), durationMs: Number(flag('--ms', 0)), at: now() });
  write(m);
  console.log(`recorded stage ${m.stages.at(-1).name}`);
} else if (cmd === 'gate') {
  const outcome = flag('--outcome');
  if (!['approved', 'corrected', 'skipped'].includes(outcome)) {
    console.error('--outcome must be approved, corrected or skipped');
    process.exit(2);
  }
  const m = read();
  m.gates.push({ name: flag('--name', 'gate'), outcome, note: flag('--note', ''), at: now() });
  write(m);
  console.log(`recorded gate ${m.gates.at(-1).name}: ${outcome}`);
} else {
  const m = read();
  m.finishedAt = now();
  m.wallClockSeconds = Math.round((Date.parse(m.finishedAt) - Date.parse(m.startedAt)) / 1000);
  m.tokens.subagentTotal = m.stages.reduce((s, x) => s + (x.subagentTokens || 0), 0);
  m.tokens.subagentDurationMs = m.stages.reduce((s, x) => s + (x.durationMs || 0), 0);
  m.counts = counts();
  write(m);
  console.log(`finished: ${m.wallClockSeconds}s wall-clock, ${m.tokens.subagentTotal} measured subagent tokens, ${m.counts.findings} findings, ${m.counts.elements} elements`);
}
