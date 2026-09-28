#!/usr/bin/env node
// Validates findings.json: schema, enums, unique ids/fingerprints, and that every evidence file:line exists in the repo.
// Usage: node validate-findings.mjs <findings.json> [--repo <root>]   exit 0 = valid, 1 = invalid
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const repoIdx = args.indexOf('--repo');
const repo = repoIdx >= 0 ? args[repoIdx + 1] : process.cwd();
if (!file) {
  console.error('usage: validate-findings.mjs <findings.json> [--repo root]');
  process.exit(2);
}

const ENUMS = {
  stride: ['S', 'T', 'R', 'I', 'D', 'E'],
  severity: ['critical', 'high', 'medium', 'low', 'info'],
  likelihood: ['high', 'medium', 'low'],
  impact: ['high', 'medium', 'low'],
  confidence: ['confirmed', 'likely', 'needs-verification'],
  status: ['open', 'accepted-risk', 'mitigated', 'false-positive', 'fixed'],
  effort: ['S', 'M', 'L'],
};
const REQUIRED = ['id', 'fingerprint', 'title', 'stride', 'element', 'severity', 'likelihood', 'impact', 'confidence', 'status', 'evidence', 'scenario', 'recommendation', 'effort'];

const errors = [];
const warn = [];
const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
for (const k of ['target', 'generatedAt', 'commit', 'mode', 'findings']) if (doc[k] === undefined) errors.push(`top-level: missing ${k}`);
if (!Array.isArray(doc.findings)) errors.push('findings must be an array');

const lineCache = new Map();
const lines = (f) => {
  if (!lineCache.has(f)) {
    const p = path.resolve(repo, f);
    lineCache.set(f, fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n').length : -1);
  }
  return lineCache.get(f);
};

const ids = new Set();
const fps = new Set();
for (const [i, f] of (doc.findings ?? []).entries()) {
  const at = `findings[${i}]${f.id ? ` (${f.id})` : ''}`;
  for (const k of REQUIRED) if (f[k] === undefined || f[k] === '') errors.push(`${at}: missing ${k}`);
  if (f.id && ids.has(f.id)) errors.push(`${at}: duplicate id`);
  if (f.fingerprint && fps.has(f.fingerprint)) errors.push(`${at}: duplicate fingerprint`);
  ids.add(f.id);
  fps.add(f.fingerprint);
  if (!Array.isArray(f.stride) || !f.stride.length || f.stride.some((s) => !ENUMS.stride.includes(s))) errors.push(`${at}: stride must be a non-empty array of S/T/R/I/D/E`);
  for (const k of ['severity', 'likelihood', 'impact', 'confidence', 'status', 'effort'])
    if (f[k] !== undefined && !ENUMS[k].includes(f[k])) errors.push(`${at}: ${k}="${f[k]}" not in ${ENUMS[k].join('|')}`);
  if (!Array.isArray(f.evidence) || !f.evidence.length) errors.push(`${at}: evidence must list at least one file:line`);
  for (const e of f.evidence ?? []) {
    const n = lines(e.file);
    if (n < 0) errors.push(`${at}: evidence file not found: ${e.file}`);
    else if (!Number.isInteger(e.line) || e.line < 1 || e.line > n) errors.push(`${at}: ${e.file}:${e.line} outside file (1-${n})`);
  }
  if (['critical', 'high'].includes(f.severity) && f.confidence === 'needs-verification')
    warn.push(`${at}: ${f.severity} finding still needs verification`);
  if (f.status === 'false-positive' && !f.statusReason) errors.push(`${at}: false-positive needs statusReason`);
  if (f.status === 'accepted-risk' && !f.statusReason) errors.push(`${at}: accepted-risk needs statusReason (who accepted and why)`);
  if (f.status === 'mitigated' && !f.statusReason) errors.push(`${at}: mitigated needs statusReason (which control covers it, cited in evidence)`);
  for (const k of ['residual', 'ownerRole', 'statusReason']) if (f[k] !== undefined && typeof f[k] !== 'string') errors.push(`${at}: ${k} must be a string`);
}

warn.forEach((w) => console.log(`WARN  ${w}`));
errors.forEach((e) => console.log(`ERROR ${e}`));
console.log(errors.length ? `invalid: ${errors.length} error(s)` : `valid: ${doc.findings.length} finding(s), ${warn.length} warning(s)`);
process.exit(errors.length ? 1 : 0);
