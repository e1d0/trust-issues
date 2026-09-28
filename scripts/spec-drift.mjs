#!/usr/bin/env node
// Compare the deployed route inventory (from extract-entry-points.mjs --json) with an OpenAPI spec.
// Flags: routes missing from the spec, spec paths missing from the stack, and auth mismatches.
// Usage: node spec-drift.mjs <entry-points.json> <openapi.yaml> [--json]
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const load = (name) => {
  for (const base of [import.meta.url, path.join(process.cwd(), 'package.json')]) {
    try {
      return createRequire(base)(name);
    } catch {}
  }
  console.error(`${name} not found. Run npm install in the skill folder, or run from a repo that has it.`);
  process.exit(2);
};
const yaml = load('js-yaml');
const [routesFile, specFile] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const asJson = process.argv.includes('--json');
if (!routesFile || !specFile) {
  console.error('usage: spec-drift.mjs <entry-points.json> <openapi.yaml> [--json]');
  process.exit(2);
}

const norm = (p) =>
  '/' +
  String(p)
    .replace(/\$\{[^}]+\}/g, '{param}')
    .replace(/\{[^}+]+\}/g, '{param}')
    .replace(/^\/+|\/+$/g, '');

const inv = JSON.parse(fs.readFileSync(routesFile, 'utf8'));
const spec = yaml.load(fs.readFileSync(specFile, 'utf8'));
const globalSec = spec.security ?? [];

const stack = new Map();
for (const api of inv.apis) for (const r of api.routes) stack.set(`${r.method} ${norm(r.path)}`, r);

const specOps = new Map();
for (const [p, item] of Object.entries(spec.paths ?? {})) {
  for (const m of ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']) {
    if (!item[m]) continue;
    const sec = item[m].security ?? globalSec;
    specOps.set(`${m.toUpperCase()} ${norm(p)}`, { security: sec.flatMap((s) => Object.keys(s)) });
  }
}

const missingInSpec = [];
const authMismatch = [];
for (const [key, r] of stack) {
  if (r.method === 'ANY' || /\{proxy\+\}/.test(String(r.path))) continue;
  const s = specOps.get(key);
  if (!s) {
    missingInSpec.push({ key, line: r.line, auth: r.auth });
    continue;
  }
  const stackAuthed = r.auth !== 'none';
  const specAuthed = s.security.some((x) => !/apikey/i.test(x));
  if (stackAuthed !== specAuthed || r.apiKeyRequired !== s.security.some((x) => /apikey/i.test(x)))
    authMismatch.push({ key, line: r.line, stack: r.auth + (r.apiKeyRequired ? '+apiKey' : ''), spec: s.security.join(',') || 'none' });
}
const proxyPrefixes = [...stack.values()]
  .filter((r) => /\{proxy\+\}/.test(String(r.path)))
  .map((r) => norm(String(r.path).replace(/\{proxy\+\}.*$/, '')));
const coveredByProxy = (k) => proxyPrefixes.some((pre) => k.split(' ')[1].startsWith(pre));
const missingInStack = [...specOps.keys()].filter((k) => !stack.has(k) && !coveredByProxy(k));

const result = { stackRoutes: stack.size, specOperations: specOps.size, missingInSpec, missingInStack, authMismatch };
if (asJson) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`# Spec drift\n\nStack routes: ${stack.size}. Spec operations: ${specOps.size}.\n`);
  console.log(`## Auth mismatches (${authMismatch.length})\n`);
  authMismatch.forEach((m) => console.log(`- ${m.key} (stack line ${m.line}): stack=${m.stack}, spec=${m.spec}`));
  console.log(`\n## In stack, not in spec (${missingInSpec.length})\n`);
  missingInSpec.forEach((m) => console.log(`- ${m.key} (line ${m.line}, auth=${m.auth})`));
  console.log(`\n## In spec, not in stack (${missingInStack.length})\n`);
  missingInStack.forEach((k) => console.log(`- ${k}`));
}
