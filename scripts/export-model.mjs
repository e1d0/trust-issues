#!/usr/bin/env node
// Renders a run's model.json (DFD nodes and flows) plus findings.json (optional) into every view of the model:
//   dataflow.md                  Mermaid DFDs, one per diagram, trust zones as subgraphs
//   dfd-<key>.threat-dragon.json one OWASP Threat Dragon v2 model per diagram, findings attached as threats
//   stride.md                    Element | STRIDE | Threat | Mitigation | Residual risk
// findings.json stays the single source of truth for threats; re-run this after every change to either file.
// Ids and UUIDs are derived from content, so re-running on the same input gives the same files.
// Usage: node export-model.mjs <runDir> [--check]   --check validates model.json and prints warnings without writing
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const args = process.argv.slice(2);
const dir = args.find((a) => !a.startsWith('--'));
const checkOnly = args.includes('--check');
if (!dir) {
  console.error('usage: export-model.mjs <runDir> [--check]');
  process.exit(2);
}
const readJson = (f) => (fs.existsSync(path.join(dir, f)) ? JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) : undefined);
const model = readJson('model.json');
if (!model) {
  console.error(`no model.json in ${dir}`);
  process.exit(2);
}
const findingsDoc = readJson('findings.json');
const findings = (findingsDoc?.findings ?? []).filter((f) => !['fixed', 'false-positive'].includes(f.status));

const KINDS = ['actor', 'process', 'store'];
const ELEMENT_ID = /^(actor|route|service|fn|lambda|gateway|middleware|authorizer|queue|schedule|job|rule|webhook|ws|grpc|gql|store|ext|shared|edge|stack|cli):/;
const STRIDE = { S: 'Spoofing', T: 'Tampering', R: 'Repudiation', I: 'Information disclosure', D: 'Denial of service', E: 'Elevation of privilege' };
const TD_SEVERITY = { critical: 'High', high: 'High', medium: 'Medium', low: 'Low', info: 'Low' };
const TD_STATUS = { open: 'Open', 'accepted-risk': 'Open', mitigated: 'Mitigated' };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const errors = [];
const warnings = [];

// ---------- validate the model ----------
if (!Array.isArray(model.diagrams) || !model.diagrams.length) errors.push('model.diagrams must be a non-empty array');
const keys = new Set();
for (const d of model.diagrams ?? []) {
  const at = `diagram ${d.key ?? '?'}`;
  if (!/^[a-z0-9-]+$/.test(d.key ?? '')) errors.push(`${at}: key must match [a-z0-9-]+`);
  if (keys.has(d.key)) errors.push(`${at}: duplicate key`);
  keys.add(d.key);
  if (!d.title) errors.push(`${at}: missing title`);
  const ids = new Set();
  for (const n of d.nodes ?? []) {
    if (!n.id || !n.name || !n.trust) errors.push(`${at}: node ${n.id ?? '?'} needs id, name and trust`);
    if (!KINDS.includes(n.kind)) errors.push(`${at}: node ${n.id}: kind "${n.kind}" not in ${KINDS.join('|')}`);
    if (ids.has(n.id)) errors.push(`${at}: duplicate node ${n.id}`);
    ids.add(n.id);
    if (n.id && !ELEMENT_ID.test(n.id)) warnings.push(`${at}: node ${n.id} does not use a checklist element id, so findings cannot attach to it unless it lists them in "elements"`);
  }
  for (const [i, f] of (d.flows ?? []).entries()) {
    if (!ids.has(f.from) || !ids.has(f.to)) errors.push(`${at}: flow ${i} references unknown node ${ids.has(f.from) ? f.to : f.from}`);
    if (!f.data || !f.sensitivity) errors.push(`${at}: flow ${i} (${f.from} -> ${f.to}) needs data and sensitivity`);
  }
  if (!(d.nodes ?? []).length) errors.push(`${at}: no nodes`);
}

// A node covers a finding when its id is the element, or its "elements" list names it (a trailing * is a prefix match).
const covers = (n, el) => n.id === el || (n.elements ?? []).some((e) => (e.endsWith('*') ? el.startsWith(e.slice(0, -1)) : e === el));
const homeOf = new Map(); // finding id -> diagram key where stride.md lists it
for (const f of findings) {
  const exact = model.diagrams?.find((d) => d.nodes?.some((n) => n.id === f.element));
  const alias = model.diagrams?.find((d) => d.nodes?.some((n) => covers(n, f.element)));
  const home = exact ?? alias;
  if (home) homeOf.set(f.id, home.key);
  else if (!f.element.startsWith('shared:')) warnings.push(`finding ${f.id} (${f.element}) is not on any diagram; it goes under "Not on a diagram" in stride.md`);
}

warnings.forEach((w) => console.log(`WARN  ${w}`));
errors.forEach((e) => console.log(`ERROR ${e}`));
if (errors.length) {
  console.log(`invalid model: ${errors.length} error(s)`);
  process.exit(1);
}
if (checkOnly) {
  console.log(`model ok: ${model.diagrams.length} diagram(s), ${warnings.length} warning(s)`);
  process.exit(0);
}

// ---------- helpers ----------
const uuid = (s) => {
  const h = crypto.createHash('sha1').update(s).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
const flowLabel = (f) => `${f.data} : ${f.sensitivity}${f.credential ? ` [${f.credential}]` : ''}`;
const bySeverity = (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id);
// Zones in order of their lowest tier, then first appearance.
const zonesOf = (d) => {
  const order = [];
  for (const n of d.nodes) if (!order.includes(n.trust)) order.push(n.trust);
  const minTier = (z) => Math.min(...d.nodes.filter((n) => n.trust === z).map((n) => n.tier ?? 0));
  return order.sort((a, b) => minTier(a) - minTier(b) || order.indexOf(a) - order.indexOf(b));
};

// ---------- dataflow.md (Mermaid) ----------
const mm = (s) => String(s).replace(/"/g, "'").replace(/[\r\n]+/g, ' ');
const SHAPE = { actor: (l) => `["${l}"]`, process: (l) => `(["${l}"])`, store: (l) => `[("${l}")]` };
let dataflow = `# Data flow diagrams: ${model.target ?? path.basename(dir)}\n\n` +
  '> Generated by export-model.mjs from model.json. Edit model.json, not this file. Decision-support: the owner confirms boundaries and flows.\n' +
  '> Shapes: actor = rectangle, process = stadium, store = cylinder. Subgraph = trust zone. Edge label = `data : sensitivity [credential]`. Dashed edge = assumed, not confirmed.\n';
for (const d of model.diagrams) {
  const short = Object.fromEntries(d.nodes.map((n, i) => [n.id, `n${i}`]));
  dataflow += `\n## ${d.title}\n\n${d.description ? `${d.description}\n\n` : ''}\`\`\`mermaid\nflowchart LR\n`;
  zonesOf(d).forEach((z, zi) => {
    dataflow += `  subgraph z${zi}["${mm(z)}"]\n`;
    for (const n of d.nodes.filter((x) => x.trust === z)) dataflow += `    ${short[n.id]}${SHAPE[n.kind](mm(n.name))}\n`;
    dataflow += '  end\n';
  });
  for (const f of d.flows ?? []) {
    const l = mm(flowLabel(f));
    dataflow += f.assumed ? `  ${short[f.from]} -. "${l} (assumed)" .-> ${short[f.to]}\n` : `  ${short[f.from]} -- "${l}" --> ${short[f.to]}\n`;
  }
  dataflow += '```\n';
  const legend = d.nodes.map((n) => `| ${n.name} | \`${n.id}\` | ${n.kind} | ${n.trust} |`);
  dataflow += `\n| Node | Element id | Kind | Trust zone |\n|---|---|---|---|\n${legend.join('\n')}\n`;
}

// ---------- Threat Dragon ----------
const W = 180, H = 70, PAD = 26, LABEL = 26, ROW_H = 110, GAP = 90, X0 = 60, Y0 = 60;
const tdThreat = (f, i) => {
  const types = f.stride.map((s) => STRIDE[s]);
  const evidence = f.evidence.map((e) => `${e.file}:${e.line}`).join(', ');
  const parts = [
    f.scenario,
    types.length > 1 ? `Also: ${types.slice(1).join(', ')}.` : '',
    `Severity ${f.severity} (likelihood ${f.likelihood}, impact ${f.impact}), confidence ${f.confidence}.`,
    f.residual ? `Residual risk: ${f.residual}.` : '',
    f.statusReason ? `Status: ${f.status}, ${f.statusReason}.` : '',
    `Evidence: ${evidence}. Fingerprint: ${f.fingerprint}.`,
  ];
  return {
    title: `${f.id} ${f.title}`,
    type: types[0],
    severity: TD_SEVERITY[f.severity] ?? 'Medium',
    status: TD_STATUS[f.status] ?? 'Open',
    description: parts.filter(Boolean).join(' '),
    mitigation: f.recommendation,
    modelType: 'STRIDE',
    number: i + 1,
    score: f.severity,
    threatId: uuid(`threat:${f.fingerprint}`),
  };
};
const written = [];
for (const d of model.diagrams) {
  const seed = `${model.target ?? ''}:${d.key}`;
  const idOf = (n) => uuid(`${seed}:node:${n.id}`);
  const cells = [];
  let threatNo = 0;
  zonesOf(d).forEach((z, zi) => {
    const x = X0 + zi * (W + 2 * PAD + GAP);
    const ns = d.nodes.filter((n) => n.trust === z);
    cells.push({
      position: { x, y: Y0 },
      size: { width: W + 2 * PAD, height: LABEL + 2 * PAD + (ns.length - 1) * ROW_H + H },
      attrs: { label: { text: z } },
      visible: true,
      shape: 'trust-boundary-box',
      id: uuid(`${seed}:zone:${z}`),
      zIndex: -1,
      data: { type: 'tm.BoundaryBox', name: z, description: '', isTrustBoundary: true, hasOpenThreats: false },
    });
    ns.forEach((n, i) => {
      const threats = findings.filter((f) => covers(n, f.element)).sort(bySeverity).map((f) => tdThreat(f, threatNo++));
      cells.push({
        position: { x: x + PAD, y: Y0 + LABEL + PAD + i * ROW_H },
        size: { width: W, height: H },
        attrs: { text: { text: n.name } },
        visible: true,
        shape: n.kind,
        zIndex: 1,
        id: idOf(n),
        data: {
          type: { actor: 'tm.Actor', process: 'tm.Process', store: 'tm.Store' }[n.kind],
          name: n.name,
          description: `Element ${n.id}. Trust zone: ${n.trust}.${n.description ? ` ${n.description}` : ''}`,
          outOfScope: Boolean(n.outOfScope),
          reasonOutOfScope: n.reasonOutOfScope ?? '',
          hasOpenThreats: threats.some((t) => t.status === 'Open'),
          threats,
        },
      });
    });
  });
  // Flows carry no size or position: the schema requires any size >= 10 and the engine derives edge geometry.
  for (const [i, f] of (d.flows ?? []).entries()) {
    const label = flowLabel(f);
    cells.push({
      shape: 'flow',
      connector: 'smooth',
      source: { cell: idOf({ id: f.from }) },
      target: { cell: idOf({ id: f.to }) },
      visible: true,
      zIndex: 10,
      labels: [{ position: 0.5, attrs: { text: { text: f.assumed ? `${label} (assumed)` : label } } }],
      attrs: { line: { stroke: '#333333', strokeWidth: 1.5, targetMarker: { name: 'block', width: 12, height: 8 }, sourceMarker: { name: '' } } },
      id: uuid(`${seed}:flow:${i}:${f.from}->${f.to}`),
      data: {
        type: 'tm.Flow',
        name: label,
        description: f.assumed ? 'Assumed flow, not confirmed by the owner.' : '',
        isTrustBoundary: d.nodes.find((n) => n.id === f.from).trust !== d.nodes.find((n) => n.id === f.to).trust,
        isEncrypted: Boolean(f.encrypted),
        isPublicNetwork: Boolean(f.publicNetwork),
        protocol: f.protocol ?? '',
        outOfScope: false,
        reasonOutOfScope: '',
        hasOpenThreats: false,
        threats: [],
      },
    });
  }
  const td = {
    version: '2.4.0',
    summary: {
      title: `${model.target ?? 'trust-issues'} - ${d.title}`,
      owner: model.owner ?? '',
      description: 'Generated by trust-issues from model.json and findings.json. Decision-support only; the owner validates the boundaries and the threats. Regenerating overwrites edits made in Threat Dragon.',
      id: 0,
    },
    detail: {
      contributors: [],
      diagrams: [{ id: 0, title: d.title, diagramType: 'STRIDE', placeholder: 'New STRIDE diagram', thumbnail: './public/content/images/thumbnail.stride.jpg', version: '2.4.0', cells }],
      diagramTop: 1,
      reviewer: '',
      threatTop: threatNo,
    },
  };
  fs.writeFileSync(path.join(dir, `dfd-${d.key}.threat-dragon.json`), `${JSON.stringify(td, null, 2)}\n`);
  written.push(`dfd-${d.key}.threat-dragon.json (${d.nodes.length} nodes, ${(d.flows ?? []).length} flows, ${threatNo} threats)`);
}
// Drop Threat Dragon files for diagrams that no longer exist in the model.
for (const f of fs.readdirSync(dir)) {
  const m = f.match(/^dfd-(.+)\.threat-dragon\.json$/);
  if (m && !keys.has(m[1])) fs.unlinkSync(path.join(dir, f));
}

// ---------- stride.md ----------
const md = (s) => String(s ?? '').replace(/\|/g, '/').replace(/[\r\n]+/g, ' ').trim();
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const row = (f, name) =>
  `| ${md(name)} | ${f.stride.map((s) => STRIDE[s]).join(', ')} | ${md(`(${SEV_LABEL[f.severity]}) ${f.id} ${f.title}${f.status === 'mitigated' ? ' [mitigated]' : f.status === 'accepted-risk' ? ' [accepted risk]' : ''}`)} | ${md(f.recommendation)} | ${md(f.residual ?? (f.status === 'mitigated' ? 'Low (mitigated)' : ''))} |`;
const HEAD = '| Element | STRIDE | Threat | Mitigation | Residual risk |\n|---|---|---|---|---|\n';
let stride = `# STRIDE threats: ${model.target ?? path.basename(dir)}\n\n` +
  '> Generated by export-model.mjs from findings.json. Edit findings.json, not this file. Decision-support, not sign-off: the owner validates every row. ' +
  'Findings that affect decisions about people (eligibility, fraud flags, profiling, PII retention) need a human owner to decide and document.\n';
if (!findingsDoc) stride += '\n_No findings.json yet. Stage 3 fills this table._\n';
for (const d of model.diagrams) {
  const rows = findings.filter((f) => homeOf.get(f.id) === d.key).sort(bySeverity)
    .map((f) => row(f, (d.nodes.find((n) => n.id === f.element) ?? d.nodes.find((n) => covers(n, f.element))).name));
  if (findingsDoc) stride += `\n## ${d.title}\n\n${rows.length ? HEAD + rows.join('\n') + '\n' : '_No threats recorded on this view._\n'}`;
}
const loose = findings.filter((f) => !homeOf.has(f.id)).sort(bySeverity);
const shared = loose.filter((f) => f.element.startsWith('shared:'));
const other = loose.filter((f) => !f.element.startsWith('shared:'));
if (shared.length) stride += `\n## Shared code (one fix closes it for every target)\n\n${HEAD}${shared.map((f) => row(f, f.element)).join('\n')}\n`;
if (other.length) stride += `\n## Not on a diagram\n\n${HEAD}${other.map((f) => row(f, f.element)).join('\n')}\n`;
if (findingsDoc) stride += `\n---\n\n_${findings.length} threats across ${model.diagrams.length} diagram(s). Fixed and false-positive findings are left out._\n`;

fs.writeFileSync(path.join(dir, 'dataflow.md'), dataflow);
fs.writeFileSync(path.join(dir, 'stride.md'), stride);
console.log(`wrote dataflow.md, stride.md and ${written.length} Threat Dragon file(s):`);
written.forEach((w) => console.log(`  ${w}`));
console.log(`${warnings.length} warning(s). Next: node validate-threat-dragon.mjs ${dir}`);
