#!/usr/bin/env node
/**
 * Validate Threat Dragon model files against the vendored OWASP Threat Dragon v2 schema.
 *
 * Usage:
 *   node validate-threat-dragon.mjs [dir]        # validates *.threat-dragon.json in dir (default: cwd)
 *   node validate-threat-dragon.mjs --schema <path> [dir]
 *
 * Requires the `ajv` package (v6 or v8). It is resolved from the skill's node_modules
 * (run `npm install` in the skill folder once), then from the working directory.
 *
 * The schema is read from ../assets/threat-dragon-v2.schema.json relative to this
 * script unless --schema is given.
 */

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const HERE = dirname(fileURLToPath(import.meta.url));

// Parse args
const argv = process.argv.slice(2);
let schemaPath = join(HERE, "..", "assets", "threat-dragon-v2.schema.json");
let targetDir = process.cwd();
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--schema") schemaPath = resolve(argv[++i]);
  else targetDir = resolve(argv[i]);
}

if (!existsSync(schemaPath)) {
  console.error(`Schema not found: ${schemaPath}`);
  process.exit(2);
}

// Resolve ajv from the skill's own node_modules first, then from the working directory.
let Ajv;
for (const base of [import.meta.url, join(process.cwd(), "noop.cjs")]) {
  try {
    Ajv = createRequire(base)("ajv");
    Ajv = Ajv.default || Ajv;
    break;
  } catch {}
}
if (!Ajv) {
  console.error('Could not load "ajv". Run `npm install` in the skill folder.');
  process.exit(2);
}

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
let validate;
try {
  validate = new Ajv({ allErrors: true }).compile(schema);
} catch (e) {
  console.error(`Failed to compile schema with ajv: ${e.message}`);
  process.exit(2);
}

const files = readdirSync(targetDir)
  .filter((f) => f.endsWith(".threat-dragon.json"))
  .sort();

if (!files.length) {
  console.error(`No *.threat-dragon.json files found in ${targetDir}`);
  process.exit(1);
}

let allOk = true;
for (const f of files) {
  const data = JSON.parse(readFileSync(join(targetDir, f), "utf8"));
  const ok = validate(data);
  const threats = (data.detail?.diagrams || []).reduce(
    (s, d) => s + (d.cells || []).reduce((t, c) => t + (c.data?.threats?.length || 0), 0),
    0
  );
  if (ok) {
    console.log(`VALID   ${f}  (threats: ${threats})`);
  } else {
    allOk = false;
    console.log(`INVALID ${f}`);
    const seen = new Set();
    for (const e of validate.errors) {
      const key = e.schemaPath + "|" + e.message;
      if (seen.has(key)) continue;
      seen.add(key);
      console.log(`   ${e.instancePath || e.dataPath || "(root)"} ${e.message}  [${e.schemaPath}]`);
    }
  }
}

console.log(allOk ? `\nAll ${files.length} file(s) valid.` : `\nSchema validation FAILED.`);
process.exit(allOk ? 0 : 1);
