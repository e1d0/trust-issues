// Run from the skill folder: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';

const skill = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = skill;
const script = (n) => path.join(skill, 'scripts', n);
const fx = (n) => path.join(skill, 'tests/fixtures', n);
const node = (args, opts = {}) => spawnSync(process.execPath, args, { cwd: repo, encoding: 'utf8', ...opts });

test('extract-entry-points finds every route, auth type and warning in plain CDK', () => {
  const r = JSON.parse(node([script('extract-entry-points.mjs'), fx('sample-stack.ts'), '--json']).stdout);
  assert.equal(r.summary.apis, 2);
  const routes = r.apis.flatMap((a) => a.routes);
  const by = (m, p) => routes.find((x) => x.method === m && x.path === p);
  assert.equal(by('GET', '/public/thing').auth, 'none');
  assert.equal(by('POST', '/orders').auth, 'lambda-authorizer');
  assert.equal(by('POST', '/orders').hasModel, true);
  assert.equal(by('POST', '/orders').lambdaName, 'order-api');
  assert.equal(by('PATCH', '/orders/{id}').hasModel, false);
  assert.equal(by('GET', '/admin/users').auth, 'cognito');
  assert.equal(by('GET', '/config').apiKeyRequired, true);
  assert.equal(by('POST', '/hooks').auth, 'lambda-authorizer');
  assert.equal(by('POST', '/hooks').integration, 'sqs');
  assert.equal(by('ANY', '/wishlist/{proxy+}').proxy, true);
  assert.equal(by('GET', '/v2/items').auth, 'none');
  assert.equal(by('POST', '/v2/items').auth, 'none');
  assert.equal(r.summary.unauthenticated, 5);
  assert.equal(r.summary.apiKeyOnly, 1);
  assert.equal(r.summary.mutatingWithoutModel, 3, 'PATCH orders/{id}, POST hooks, POST v2/items');
  assert.ok(r.warnings.some((w) => w.includes('loop')), 'routes built in a loop must be flagged');
  assert.equal(r.apis[0].settings.flag, 'CORS allows all origins with credentials');
});

test('extract-entry-points lists non-API entry points and risky settings, and filters with --match', () => {
  const r = JSON.parse(node([script('extract-entry-points.mjs'), fx('sample-stack.ts'), '--json']).stdout);
  const kinds = r.resources.map((x) => x.kind);
  for (const k of ['compute:lambda', 'trigger:queue', 'trigger:schedule', 'entry:function-url', 'store:sqs']) assert.ok(kinds.includes(k), `missing ${k}`);
  const flags = r.resources.flatMap((x) => x.flags ?? []);
  for (const f of ['public function URL (authType NONE)', 'wildcard actions', 'wildcard resources', 'no dead-letter queue', 'no partial batch failure reporting', 'secret-like names in plain environment variables'])
    assert.ok(flags.includes(f), `missing flag ${f}`);
  const m = JSON.parse(node([script('extract-entry-points.mjs'), fx('sample-stack.ts'), '--match', 'order-worker', '--json']).stdout);
  assert.equal(m.summary.routes, 0);
  assert.ok(m.resources.length >= 1 && m.resources.every((x) => JSON.stringify(x).toLowerCase().includes('order-worker')));
  const o = JSON.parse(node([script('extract-entry-points.mjs'), fx('sample-stack.ts'), '--match', 'orders', '--json']).stdout);
  assert.deepEqual(o.apis[0].routes.map((x) => x.path).sort(), ['/orders', '/orders/{id}']);
});

test('spec-drift reports auth mismatch, missing routes, and honours proxy routes', () => {
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tm-')), 'entry-points.json');
  node([script('extract-entry-points.mjs'), fx('sample-stack.ts'), '--json', '--out', tmp]);
  const d = JSON.parse(node([script('spec-drift.mjs'), tmp, fx('sample-spec.yaml'), '--json']).stdout);
  assert.deepEqual(d.authMismatch.map((m) => m.key), ['PATCH /orders/{param}']);
  assert.ok(d.missingInSpec.some((m) => m.key === 'GET /admin/users'));
  assert.deepEqual(d.missingInStack, ['GET /ghost'], 'wishlist/items is served by the proxy route');
});

test('validate-findings accepts a grounded file', () => {
  const r = node([script('validate-findings.mjs'), fx('findings-valid.json'), '--repo', skill]);
  assert.equal(r.status, 0, r.stdout);
});

test('validate-findings rejects hallucinated evidence, bad enums, duplicates and missing reasons', () => {
  const r = node([script('validate-findings.mjs'), fx('findings-invalid.json'), '--repo', skill]);
  assert.equal(r.status, 1);
  for (const needle of ['outside file', 'evidence file not found', 'stride must be', 'severity="severe"', 'duplicate id', 'duplicate fingerprint', 'false-positive needs statusReason', 'at least one file:line'])
    assert.ok(r.stdout.includes(needle), `expected "${needle}" in:\n${r.stdout}`);
});

test('diff-findings classifies new, resolved and persisting', () => {
  const d = JSON.parse(execFileSync(process.execPath, [script('diff-findings.mjs'), fx('findings-valid.json'), fx('findings-next.json'), '--json'], { encoding: 'utf8' }));
  assert.deepEqual(d.new.map((x) => x.id), ['SAMPLE-003']);
  assert.deepEqual(d.resolved.map((x) => x.how).sort(), ['fixed', 'no longer reported']);
  assert.equal(d.persisting.length, 0);
});

const runCopy = () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ti-run-'));
  for (const f of fs.readdirSync(fx('run'))) fs.copyFileSync(path.join(fx('run'), f), path.join(dir, f));
  return dir;
};

test('validate-findings accepts mitigated with a reason, residual and ownerRole', () => {
  const r = node([script('validate-findings.mjs'), fx('run/findings.json'), '--repo', skill]);
  assert.equal(r.status, 0, r.stdout);
});

test('export-model writes schema-valid Threat Dragon files, Mermaid and the STRIDE table', () => {
  const dir = runCopy();
  const r = node([script('export-model.mjs'), dir]);
  assert.equal(r.status, 0, r.stdout);
  assert.equal(node([script('validate-threat-dragon.mjs'), dir]).status, 0, 'Threat Dragon files must match the vendored schema');
  const stride = fs.readFileSync(path.join(dir, 'stride.md'), 'utf8');
  assert.match(stride, /\| PATCH \/orders\/\{id\} \| Tampering, Elevation of privilege \| \(High\) SAMPLE-001/);
  assert.match(stride, /## Shared code[\s\S]*SAMPLE-002 CORS on the HTTP API \[mitigated\][\s\S]*Low \(mitigated\)/);
  assert.ok(!stride.includes('SAMPLE-003'), 'false positives stay out of the table');
  const flow = fs.readFileSync(path.join(dir, 'dataflow.md'), 'utf8');
  assert.match(flow, /subgraph z0\["1 - Internet"\]/);
  assert.match(flow, /n1 -\. "order record : PII \(assumed\)" \.-> n2/);
  const overview = JSON.parse(fs.readFileSync(path.join(dir, 'dfd-0-overview.threat-dragon.json'), 'utf8'));
  const lambdaCell = overview.detail.diagrams[0].cells.find((c) => c.data.name === 'Sample API lambdas');
  assert.deepEqual(lambdaCell.data.threats.map((t) => [t.severity, t.status, t.type]), [['High', 'Open', 'Tampering']], 'alias elements attach findings to overview nodes');
  const before = fs.readFileSync(path.join(dir, 'dfd-1-orders.threat-dragon.json'), 'utf8');
  node([script('export-model.mjs'), dir]);
  assert.equal(fs.readFileSync(path.join(dir, 'dfd-1-orders.threat-dragon.json'), 'utf8'), before, 'output is deterministic');
});

test('export-model rejects a flow to an unknown node', () => {
  const dir = runCopy();
  const model = JSON.parse(fs.readFileSync(path.join(dir, 'model.json'), 'utf8'));
  model.diagrams[0].flows.push({ from: 'actor:browser', to: 'lambda:ghost', data: 'x', sensitivity: 'public' });
  fs.writeFileSync(path.join(dir, 'model.json'), JSON.stringify(model));
  const r = node([script('export-model.mjs'), dir, '--check']);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /unknown node lambda:ghost/);
});

test('run-meta records gates and counts, and build-report renders the run', () => {
  const dir = runCopy();
  assert.equal(node([script('run-meta.mjs'), 'start', dir, '--target', 'sample', '--mode', 'full']).status, 0);
  node([script('run-meta.mjs'), 'gate', dir, '--name', 'inventory', '--outcome', 'corrected', '--note', 'owner fixed Q2']);
  assert.equal(node([script('run-meta.mjs'), 'gate', dir, '--name', 'x', '--outcome', 'maybe']).status, 2);
  node([script('run-meta.mjs'), 'finish', dir]);
  const meta = JSON.parse(fs.readFileSync(path.join(dir, 'run-meta.json'), 'utf8'));
  assert.deepEqual(meta.gates.map((g) => g.outcome), ['corrected']);
  assert.equal(meta.counts.findings, 3);
  assert.deepEqual(meta.counts.openBySeverity, { high: 1 });
  assert.equal(meta.counts.trustZones, 3);
  node([script('export-model.mjs'), dir]);
  assert.equal(node([script('build-report.mjs'), dir]).status, 0);
  const html = fs.readFileSync(path.join(dir, 'report.html'), 'utf8');
  assert.match(html, /<a href="#stride">STRIDE table<\/a>/);
  assert.match(html, /owner fixed Q2/);
  const [markup, data] = html.split('const DATA = ');
  assert.ok(!markup.includes('SAMPLE-001') && data.includes('SAMPLE-001'), 'docs are embedded as data and rendered through DOMPurify, never as raw markup');
});

test('recon finds entry points with route-level auth across C#, Go, Express and a Cloudflare Worker', () => {
  const r = JSON.parse(node([script('recon.mjs'), fx('recon'), '--json']).stdout);
  const route = (m, p) => r.entryPoints.find((e) => e.method === m && e.path === p);
  const expect = {
    'GET /api/loans/{loanId}': ['class:require'],
    'POST /api/loans/reminders': ['anonymous'],
    'GET /api/books/{id}': ['route:require'],
    'POST /api/books': ['none'],
    'GET /health': ['anonymous'],
    'GET /events': ['none'],
    'GET /internal/stats': ['none'],
    'POST /api/events/{id}/tickets': ['group:requireAuth'],
    'GET /profile': ['route:require'],
    'POST /share': ['none'],
  };
  for (const [k, auth] of Object.entries(expect)) {
    const [m, p] = k.split(' ');
    assert.ok(route(m, p), `missing route ${k}`);
    assert.deepEqual(route(m, p).auth, auth, k);
  }
  for (const kind of ['worker:fetch', 'schedule', 'edge-route']) assert.ok(r.entryPoints.some((e) => e.kind === kind), `missing ${kind}`);
  assert.ok(!r.entryPoints.some((e) => e.path?.startsWith('/partners')), 'axios.get is a client call, not a route');
});

test('recon reports sinks, connections and config names without reading secret values', () => {
  const out = node([script('recon.mjs'), fx('recon'), '--json']).stdout;
  const r = JSON.parse(out);
  const sink = (check, file) => r.sinks.some((s) => s.check === check && s.file.includes(file));
  assert.ok(sink('T-INJECTION', 'LoansController.cs') && sink('T-INJECTION', 'main.go'), 'string-built SQL in C# and Go');
  assert.ok(sink('E-SSRF-META', 'main.go') && sink('BFF-REDIRECT', 'app.js') && sink('I-LOGGING', 'app.js') && sink('I-CORS', 'Program.cs'));
  assert.ok(!r.sinks.some((s) => /async fetch\(request/.test(s.text)), 'a Worker fetch handler definition is not a sink');
  assert.ok(r.outbound.some((o) => o.kind === 'binding' && o.text.includes('env.ORDERS.fetch')));
  const names = r.configNames.map((c) => c.name);
  for (const n of ['JWT_SECRET', 'DATABASE_URL', 'ConnectionStrings:Library', 'SIGNING_SECRET']) assert.ok(names.includes(n), `missing config name ${n}`);
  assert.ok(!out.includes('do-not-print-this-value') && !out.includes('Password=placeholder'), 'secret values must never appear');
  const wrangler = r.stack.config.find((c) => c.kind === 'cloudflare-wrangler');
  assert.deepEqual(wrangler.bindings, ['kv_namespaces:SESSIONS', 'services:ORDERS']);
  assert.ok(wrangler.flags.some((f) => f.includes('[vars]')));
  assert.ok(r.stack.frameworks.some((f) => f.name === 'github.com/go-chi/chi/v5'));
});

test('recon skips vendored packages but keeps the function code next to them', () => {
  const r = JSON.parse(node([script('recon.mjs'), fx('recon/py-lambda'), '--json']).stdout);
  assert.ok(r.entryPoints.some((e) => e.kind === 'lambda-handler' && e.file.endsWith('app.py')));
  assert.ok(!r.sinks.some((s) => s.file.includes('certifi')), 'sinks inside vendored libraries are not reported');
  assert.ok(r.warnings.some((w) => w.includes('vendored packages skipped')));
});
