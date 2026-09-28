#!/usr/bin/env node
// Stack-agnostic reconnaissance for any folder: what the code is, where requests and events come in, what it calls,
// what configuration it reads, and where the risky sinks are. Every item has file:line and is a CANDIDATE: the skill
// confirms each one by reading the code. Patterns live in recon-patterns.mjs.
// Never reads out secret values: .env and settings files contribute key names only.
// Usage: node recon.mjs <path> [more paths...] [--json] [--out <file>] [--max-files N]
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { ROUTES, PREFIXES, ENTRIES, AUTH, OUTBOUND, CONFIG, SINKS, DEPENDENCIES, CLIENT_RECEIVERS } from './recon-patterns.mjs';

const args = process.argv.slice(2);
const flag = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const asJson = args.includes('--json');
const outFile = flag('--out');
const maxFiles = Number(flag('--max-files') ?? 5000);
const roots = args.filter((a, i) => !a.startsWith('--') && !['--out', '--max-files'].includes(args[i - 1]));
if (!roots.length) {
  console.error('usage: recon.mjs <path> [more paths...] [--json] [--out file] [--max-files N]');
  process.exit(2);
}
let yaml;
for (const base of [import.meta.url, path.join(process.cwd(), 'package.json')]) {
  try {
    yaml = createRequire(base)('js-yaml');
    break;
  } catch {}
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'bin', 'obj', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.wrangler', 'target', '__pycache__', '.venv', 'venv', 'coverage', '.terraform', 'cdk.out', '.serverless', '.aws-sam', '.trust-issues', '.claude', 'site-packages', '.idea', '.vscode', 'Pods', '.gradle']);
const SOURCE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.cs', '.go', '.py', '.java', '.kt', '.rb', '.php', '.rs', '.graphql', '.gql', '.proto']);
const LANG = { '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.jsx': 'JavaScript', '.ts': 'TypeScript', '.mts': 'TypeScript', '.cts': 'TypeScript', '.tsx': 'TypeScript', '.cs': 'C#', '.go': 'Go', '.py': 'Python', '.java': 'Java', '.kt': 'Kotlin', '.rb': 'Ruby', '.php': 'PHP', '.rs': 'Rust', '.graphql': 'GraphQL', '.gql': 'GraphQL', '.proto': 'Protobuf', '.tf': 'Terraform' };
const MAX_BYTES = 1_000_000;

const rel = (f) => path.relative(process.cwd(), f) || f;
const files = [];
const warnings = [];
const walk = (p) => {
  if (files.length >= maxFiles) return;
  let st;
  try {
    st = fs.statSync(p);
  } catch {
    warnings.push(`cannot read ${p}`);
    return;
  }
  if (st.isDirectory()) {
    if (SKIP_DIRS.has(path.basename(p)) && !roots.includes(p)) return;
    const entries = fs.readdirSync(p).sort();
    // A folder with *.dist-info, *.egg-info, *.pth or several well-known libraries holds vendored packages (pip install -t):
    // keep its own files, skip the packages.
    const KNOWN = ['certifi', 'urllib3', 'setuptools', 'pkg_resources', '_distutils_hack', 'six.py', 'botocore', 'idna', 'charset_normalizer', 'chardet', 'typing_extensions.py'];
    const vendored = entries.some((e) => /\.(dist|egg)-info$|\.pth$/.test(e)) || entries.filter((e) => KNOWN.includes(e)).length >= 2;
    if (vendored) warnings.push(`${rel(p)}: vendored packages skipped; only its top-level files were scanned`);
    for (const e of entries) {
      const child = path.join(p, e);
      if (vendored) {
        try {
          if (fs.statSync(child).isDirectory()) continue;
        } catch {
          continue;
        }
      }
      walk(child);
    }
  } else if (st.isFile() && st.size <= MAX_BYTES) files.push(p);
};
roots.forEach(walk);
if (files.length >= maxFiles) warnings.push(`stopped at ${maxFiles} files; narrow the scope or raise --max-files`);

const lineIndex = (content) => {
  const starts = [0];
  for (let i = 0; i < content.length; i++) if (content[i] === '\n') starts.push(i + 1);
  return (idx) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
};
const snippet = (content, idx) => {
  const s = content.lastIndexOf('\n', idx) + 1;
  const e = content.indexOf('\n', idx);
  return content.slice(s, e < 0 ? undefined : e).trim().slice(0, 160);
};
const readText = (f) => {
  try {
    return fs.readFileSync(f, 'utf8');
  } catch {
    return '';
  }
};
const loadYaml = (text) => {
  if (!yaml) return undefined;
  const clean = text.replace(/!(Ref|GetAtt|Sub|Join|If|Equals|Select|Split|FindInMap|ImportValue|Base64|Cidr|GetAZs|And|Or|Not|Condition|Transform)\b/g, '');
  try {
    return yaml.loadAll(clean).filter(Boolean);
  } catch {
    return undefined;
  }
};
const stripJsonc = (t) => t.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str) => str ?? '').replace(/,(\s*[}\]])/g, '$1');

const result = {
  scope: roots.map(rel),
  stats: { files: files.length, sourceFiles: 0, byLanguage: {} },
  stack: { manifests: [], frameworks: [], config: [] },
  entryPoints: [],
  auth: [],
  outbound: [],
  configNames: [],
  sinks: [],
  hotFiles: [],
  suggestions: [],
  warnings,
};
const configNames = new Map();
const addName = (name, file, line, source) => {
  if (!name) return;
  const e = configNames.get(name) ?? { name, source, count: 0, first: `${rel(file)}:${line}` };
  e.count++;
  configNames.set(name, e);
};
const frameworks = new Map();
const addFramework = (name, category, evidence) => {
  if (!frameworks.has(name)) frameworks.set(name, { name, category, evidence });
};
const cfg = (kind, file, details) => result.stack.config.push({ kind, file: rel(file), ...details });

// ---------- manifests ----------
const depsOf = (file, text) => {
  const b = path.basename(file);
  try {
    if (b === 'package.json') {
      const j = JSON.parse(text);
      return Object.keys({ ...j.dependencies, ...j.devDependencies, ...j.peerDependencies });
    }
    if (b === 'composer.json') return Object.keys(JSON.parse(text).require ?? {});
  } catch {
    return [];
  }
  if (b.endsWith('.csproj') || b.endsWith('.fsproj') || b === 'Directory.Packages.props') {
    const deps = [...text.matchAll(/<Package(?:Reference|Version)\s+Include="([^"]+)"/g)].map((m) => m[1]);
    if (/Sdk="Microsoft\.NET\.Sdk\.(Web|Worker)"/.test(text)) deps.push(`Microsoft.NET.Sdk.${RegExp.$1}`);
    return deps;
  }
  if (b === 'go.mod') return [...text.matchAll(/^\s*(?:require\s+)?([\w.-]+\.[\w.-]+\/[^\s]+)\s+v/gm)].map((m) => m[1]);
  if (/^requirements.*\.txt$/.test(b)) return [...text.matchAll(/^\s*([A-Za-z0-9_.-]+)/gm)].map((m) => m[1]);
  if (b === 'pyproject.toml' || b === 'Pipfile') return [...text.matchAll(/^\s*["']?([A-Za-z0-9_.-]+)["']?\s*(?:[=<>~!]|\s*=\s*\{)/gm)].map((m) => m[1]).concat([...text.matchAll(/["']([A-Za-z0-9_.-]+)\s*[<>=~!]/g)].map((m) => m[1]));
  if (b === 'pom.xml') return [...text.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)].map((m) => m[1]);
  if (/^build\.gradle(\.kts)?$/.test(b)) return [...text.matchAll(/['"]([\w.-]+):([\w.-]+)(?::[^'"]*)?['"]/g)].map((m) => m[2]);
  if (b === 'Gemfile') return [...text.matchAll(/^\s*gem\s+['"]([^'"]+)/gm)].map((m) => m[1]);
  if (b === 'Cargo.toml') return [...text.matchAll(/^([A-Za-z0-9_-]+)\s*=/gm)].map((m) => m[1]);
  return [];
};
const MANIFESTS = /^(package\.json|composer\.json|.*\.csproj|.*\.fsproj|Directory\.Packages\.props|go\.mod|requirements.*\.txt|pyproject\.toml|Pipfile|pom\.xml|build\.gradle(\.kts)?|Gemfile|Cargo\.toml)$/;

// ---------- config and IaC ----------
const parseWrangler = (file, text) => {
  let d = {};
  if (/\.jsonc?$/.test(file)) {
    try {
      const j = JSON.parse(stripJsonc(text));
      const routes = [j.route, ...(j.routes ?? [])].filter(Boolean).map((r) => (typeof r === 'string' ? r : r.pattern ?? r.custom_domain));
      const bindings = [];
      for (const k of ['kv_namespaces', 'd1_databases', 'r2_buckets', 'services', 'hyperdrive', 'vectorize', 'analytics_engine_datasets'])
        for (const b of j[k] ?? []) bindings.push(`${k}:${b.binding}`);
      for (const b of j.durable_objects?.bindings ?? []) bindings.push(`durable_objects:${b.name}`);
      for (const b of j.queues?.producers ?? []) bindings.push(`queue-producer:${b.binding}`);
      d = { name: j.name, main: j.main, routes, workersDev: j.workers_dev, crons: j.triggers?.crons ?? [], queueConsumers: (j.queues?.consumers ?? []).map((q) => q.queue), bindings, vars: Object.keys(j.vars ?? {}), environments: Object.keys(j.env ?? {}) };
    } catch {
      warnings.push(`${rel(file)}: could not parse; read by hand`);
    }
  } else {
    const sections = [];
    let current = '';
    const vars = [];
    const bindings = [];
    for (const line of text.split('\n')) {
      const h = line.match(/^\s*\[\[?\s*([\w.]+)\s*\]\]?/);
      if (h) {
        current = h[1];
        sections.push(current);
        continue;
      }
      const kv = line.match(/^\s*([\w-]+)\s*=\s*(.+)$/);
      if (!kv) continue;
      if (/(^|\.)vars$/.test(current)) vars.push(kv[1]);
      if (kv[1] === 'binding' || (current.endsWith('bindings') && kv[1] === 'name')) bindings.push(`${current}:${kv[2].replace(/["']/g, '').trim()}`);
    }
    d = {
      name: text.match(/^name\s*=\s*["']([^"']+)/m)?.[1],
      main: text.match(/^main\s*=\s*["']([^"']+)/m)?.[1],
      routes: [...text.matchAll(/(?:pattern|route|custom_domain)\s*=\s*["']([^"']+)/g)].map((m) => m[1]),
      workersDev: text.match(/^workers_dev\s*=\s*(true|false)/m)?.[1],
      crons: [...(text.match(/crons\s*=\s*\[([^\]]*)\]/)?.[1] ?? '').matchAll(/["']([^"']+)["']/g)].map((m) => m[1]),
      queueConsumers: [...text.matchAll(/\[\[\s*queues\.consumers\s*\]\][^[]*?queue\s*=\s*["']([^"']+)/g)].map((m) => m[1]),
      bindings,
      vars,
      environments: [...new Set(sections.filter((s) => s.startsWith('env.')).map((s) => s.split('.')[1]))],
    };
  }
  const flags = [];
  if (d.workersDev === true || d.workersDev === 'true' || (d.workersDev === undefined && d.routes?.length)) flags.push('workers.dev URL may be enabled alongside custom routes: a second public entry point that can bypass zone-level WAF and Access');
  if (d.vars?.some((v) => /secret|token|key|password/i.test(v))) flags.push('secret-like names in [vars] (plain text in config); use secrets instead');
  cfg('cloudflare-wrangler', file, { ...d, flags });
  const at = lineIndex(text);
  const lineOf = (needle) => {
    const i = text.indexOf(needle);
    return i < 0 ? 1 : at(i);
  };
  for (const r of d.routes ?? []) result.entryPoints.push({ kind: 'edge-route', framework: 'cloudflare', method: 'ANY', path: r, file: rel(file), line: lineOf(r), note: 'Worker route pattern' });
  for (const c of d.crons ?? []) result.entryPoints.push({ kind: 'schedule', framework: 'cloudflare', path: c, file: rel(file), line: lineOf(c) });
  for (const q of d.queueConsumers ?? []) result.entryPoints.push({ kind: 'queue-consumer', framework: 'cloudflare', path: q, file: rel(file), line: lineOf(q) });
  for (const v of d.vars ?? []) addName(v, file, lineOf(v), 'wrangler vars');
};
const parseTerraform = (file, text) => {
  const at = lineIndex(text);
  const res = [...text.matchAll(/^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"/gm)];
  const blocks = res.map((m, i) => ({ type: m[1], name: m[2], line: at(m.index), body: text.slice(m.index, res[i + 1]?.index ?? text.length) }));
  const flags = [];
  for (const b of blocks) {
    if (/authorization_type\s*=\s*"NONE"/.test(b.body)) flags.push(`${b.type}.${b.name}: authorization NONE`);
    if (/0\.0\.0\.0\/0/.test(b.body) && /ingress|security_group|firewall/.test(b.type + b.body)) flags.push(`${b.type}.${b.name}: open to 0.0.0.0/0`);
    if (/proxied\s*=\s*false/.test(b.body)) flags.push(`${b.type}.${b.name}: DNS record not proxied (origin exposed)`);
    if (/acl\s*=\s*"public-read|block_public_\w+\s*=\s*false/.test(b.body)) flags.push(`${b.type}.${b.name}: public access`);
    if (/^(aws_apigatewayv2_route|aws_api_gateway_method|aws_lambda_function_url|cloudflare_workers?_route|cloudflare_worker_script|cloudflare_workers_script|bunnynet_pullzone|bunnynet_edgerule|google_cloud_run_service|azurerm_function_app|azurerm_linux_web_app|aws_lb_listener)/.test(b.type))
      result.entryPoints.push({ kind: 'iac-entry', framework: 'terraform', method: b.body.match(/route_key\s*=\s*"(\w+)\s/)?.[1] ?? b.body.match(/http_method\s*=\s*"(\w+)"/)?.[1] ?? 'ANY', path: b.body.match(/route_key\s*=\s*"\w+\s+([^"]+)"|pattern\s*=\s*"([^"]+)"/)?.slice(1).find(Boolean) ?? `${b.type}.${b.name}`, file: rel(file), line: b.line });
  }
  if (blocks.length) cfg('terraform', file, { resources: blocks.map((b) => `${b.type}.${b.name}`), flags });
};
const parseServerless = (file, docs) => {
  const d = docs[0] ?? {};
  for (const [fname, fn] of Object.entries(d.functions ?? {})) {
    for (const ev of fn?.events ?? []) {
      const [type, v] = Object.entries(ev ?? {})[0] ?? [];
      if (type === 'http' || type === 'httpApi') {
        const o = typeof v === 'string' ? { method: v.split(' ')[0], path: v.split(' ')[1] } : v ?? {};
        result.entryPoints.push({ kind: 'route', framework: `serverless-${type}`, method: String(o.method ?? 'ANY').toUpperCase(), path: o.path ?? '/', file: rel(file), line: 1, handler: fname, auth: o.authorizer ? 'authorizer' : o.private ? 'api-key' : 'none?' });
      } else if (type) result.entryPoints.push({ kind: type, framework: 'serverless', path: typeof v === 'string' ? v : JSON.stringify(v ?? '').slice(0, 80), file: rel(file), line: 1, handler: fname });
    }
  }
  cfg('serverless-framework', file, { service: d.service, provider: d.provider?.name, functions: Object.keys(d.functions ?? {}).length });
};
const parseCfn = (file, docs) => {
  const d = docs[0] ?? {};
  const types = {};
  for (const [name, r] of Object.entries(d.Resources ?? {})) {
    types[r?.Type] = (types[r?.Type] ?? 0) + 1;
    for (const [evName, ev] of Object.entries(r?.Properties?.Events ?? {})) {
      const p = ev?.Properties ?? {};
      result.entryPoints.push({ kind: /Api/.test(ev?.Type) ? 'route' : String(ev?.Type ?? 'event').toLowerCase(), framework: 'sam', method: String(p.Method ?? 'ANY').toUpperCase(), path: p.Path ?? p.Schedule ?? p.Queue ?? evName, file: rel(file), line: 1, handler: name, auth: p.Auth ? JSON.stringify(p.Auth).slice(0, 60) : undefined });
    }
    if (r?.Type === 'AWS::Lambda::Url' || r?.Type === 'AWS::Serverless::Function') {
      const auth = r?.Properties?.AuthType ?? r?.Properties?.FunctionUrlConfig?.AuthType;
      if (auth) result.entryPoints.push({ kind: 'function-url', framework: 'sam', method: 'ANY', path: name, file: rel(file), line: 1, auth: auth === 'NONE' ? 'none' : auth });
    }
  }
  cfg('cloudformation', file, { resourceTypes: types });
};
const parseOpenApi = (file, doc) => {
  const ops = [];
  for (const [p, item] of Object.entries(doc.paths ?? {}))
    for (const m of ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']) if (item?.[m]) ops.push({ method: m.toUpperCase(), path: p, secured: (item[m].security ?? doc.security ?? []).length > 0 });
  cfg('openapi', file, { version: doc.openapi ?? doc.swagger, operations: ops.length, withoutSecurity: ops.filter((o) => !o.secured).length, securitySchemes: Object.keys(doc.components?.securitySchemes ?? doc.securityDefinitions ?? {}) });
  result.suggestions.push(`OpenAPI spec ${rel(file)}: compare it with the real routes (spec-drift.mjs for CDK, by hand otherwise)`);
};
const parseConfigFile = (file) => {
  const b = path.basename(file);
  const text = readText(file);
  if (/^wrangler\.(toml|json|jsonc)$/.test(b)) return parseWrangler(file, text);
  if (/^\.env(\..+)?$/.test(b) || b === '.dev.vars') {
    const names = [...text.matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/gm)].map((m) => m[1]);
    names.forEach((n) => addName(n, file, 1, b));
    return cfg('env-file', file, { names: names.length, note: 'names only; values never read out' });
  }
  if (/^appsettings.*\.json$/.test(b) || b === 'local.settings.json') {
    try {
      const j = JSON.parse(stripJsonc(text));
      const keys = Object.keys(j);
      const sensitive = ['ConnectionStrings', 'Authentication', 'Jwt', 'JwtBearer', 'AzureAd', 'Values'].flatMap((k) => Object.keys(j[k] ?? {}).map((x) => `${k}:${x}`));
      sensitive.forEach((n) => addName(n, file, 1, b));
      return cfg('dotnet-settings', file, { sections: keys, keys: sensitive, note: 'names only; values never read out', flags: /"AllowedHosts"\s*:\s*"\*"/.test(text) ? ['AllowedHosts is *'] : [] });
    } catch {
      return;
    }
  }
  if (/^Dockerfile/.test(b) || b.endsWith('.dockerfile')) {
    const from = [...text.matchAll(/^FROM\s+(\S+)/gim)].map((m) => m[1]);
    const expose = [...text.matchAll(/^EXPOSE\s+(.+)$/gim)].map((m) => m[1].trim());
    return cfg('docker', file, { from, expose, flags: /^USER\s+/im.test(text) ? [] : ['no USER: container runs as root'] });
  }
  if (b === 'nginx.conf' || /\.conf$/.test(b) && /\b(server|location)\s*[^;]*\{/.test(text)) {
    const at = lineIndex(text);
    for (const m of text.matchAll(/location\s+([^\s{]+)\s*\{[^}]*?proxy_pass\s+([^;]+);/g)) result.entryPoints.push({ kind: 'proxy-route', framework: 'nginx', method: 'ANY', path: m[1], upstream: m[2], file: rel(file), line: at(m.index) });
    return cfg('nginx', file, {});
  }
  if (/\.tf$/.test(b)) return parseTerraform(file, text);
  if (/\.(ya?ml|json)$/.test(b)) {
    if (/^(serverless\.ya?ml)$/.test(b)) {
      const docs = loadYaml(text);
      return docs ? parseServerless(file, docs) : warnings.push(`${rel(file)}: could not parse; read by hand`);
    }
    if (/\.github\/workflows\//.test(file) || b === '.gitlab-ci.yml' || b === 'azure-pipelines.yml' || b === 'bitbucket-pipelines.yml') {
      const flags = [];
      if (/pull_request_target/.test(text)) flags.push('pull_request_target: untrusted PR code with repo secrets');
      if (/permissions:\s*write-all/.test(text)) flags.push('permissions: write-all');
      const secrets = [...new Set([...text.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((m) => m[1]))];
      return cfg('ci', file, { secrets, flags });
    }
    if (!/openapi|swagger|AWSTemplateFormatVersion|Transform|apiVersion|services:/.test(text.slice(0, 4000))) return;
    const docs = /\.json$/.test(b) ? (() => {
      try {
        return [JSON.parse(text)];
      } catch {
        return undefined;
      }
    })() : loadYaml(text);
    if (!docs) return;
    const d = docs[0];
    if (d?.openapi || d?.swagger) return parseOpenApi(file, d);
    if (d?.AWSTemplateFormatVersion || d?.Transform || d?.Resources) return parseCfn(file, docs);
    if (docs.some((x) => x?.apiVersion && x?.kind)) {
      const kinds = docs.map((x) => x?.kind).filter(Boolean);
      for (const x of docs.filter((y) => y?.kind === 'Ingress')) for (const r of x.spec?.rules ?? []) for (const p of r.http?.paths ?? []) result.entryPoints.push({ kind: 'ingress', framework: 'kubernetes', method: 'ANY', path: `${r.host ?? '*'}${p.path ?? '/'}`, file: rel(file), line: 1, upstream: p.backend?.service?.name });
      const exposed = docs.filter((y) => y?.kind === 'Service' && ['LoadBalancer', 'NodePort'].includes(y.spec?.type)).map((y) => `${y.metadata?.name}:${y.spec.type}`);
      return cfg('kubernetes', file, { kinds, flags: exposed.map((e) => `Service exposed as ${e}`) });
    }
    if (/^(docker-)?compose.*\.ya?ml$/.test(b) && d?.services) {
      const ports = Object.entries(d.services).flatMap(([n, s]) => (s?.ports ?? []).map((p) => `${n}:${p}`));
      return cfg('docker-compose', file, { services: Object.keys(d.services), ports });
    }
  }
  if (b === 'cdk.json') {
    result.suggestions.push(`AWS CDK app (${rel(file)}): run extract-entry-points.mjs on the stack files for exact routes and auth`);
    return cfg('aws-cdk', file, {});
  }
};

// ---------- source scan ----------
const hits = new Map();
const bump = (file, n = 1) => hits.set(file, (hits.get(file) ?? 0) + n);
const nextPath = (file) => {
  const f = file.split(path.sep).join('/');
  const app = f.match(/(?:^|\/)app\/(.*)\/route\.(?:ts|js|tsx|jsx)$/);
  if (app) return '/' + app[1].replace(/\([^)]*\)\/?/g, '').replace(/\[\.\.\.(\w+)\]/g, '{$1+}').replace(/\[(\w+)\]/g, '{$1}');
  const pages = f.match(/(?:^|\/)pages\/(api\/.*)\.(?:ts|js)$/);
  if (pages) return '/' + pages[1].replace(/\/index$/, '').replace(/\[(\w+)\]/g, '{$1}');
  return undefined;
};
const joinPath = (a, b) => {
  const p = `${a ?? ''}/${b ?? ''}`.replace(/\/{2,}/g, '/').replace(/\/$/, '');
  return p.startsWith('/') ? p || '/' : `/${p}`;
};

for (const file of files) {
  const b = path.basename(file);
  const ext = path.extname(file).toLowerCase();
  if (MANIFESTS.test(b)) {
    const deps = depsOf(file, readText(file));
    result.stack.manifests.push({ file: rel(file), kind: b, dependencies: deps.length });
    for (const d of deps) for (const [re, cat] of DEPENDENCIES) if (re.test(d)) addFramework(d, cat, rel(file));
    continue;
  }
  if (!SOURCE_EXTS.has(ext)) {
    if (ext === '.tf') result.stats.byLanguage.Terraform = (result.stats.byLanguage.Terraform ?? 0) + 1;
    parseConfigFile(file);
    continue;
  }
  result.stats.sourceFiles++;
  result.stats.byLanguage[LANG[ext]] = (result.stats.byLanguage[LANG[ext]] ?? 0) + 1;
  const content = readText(file);
  if (!content) continue;
  const at = lineIndex(content);
  const applies = (p) => !p.exts || p.exts.includes(ext);
  const R = rel(file);

  if (ext === '.graphql' || ext === '.gql') {
    for (const m of content.matchAll(/^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\s*\{([\s\S]*?)\}/gm))
      for (const f of m[2].matchAll(/^\s*(\w+)\s*[(:]/gm)) result.entryPoints.push({ kind: 'graphql', framework: 'graphql-schema', method: m[1].toUpperCase(), path: f[1], file: R, line: at(m.index + m[0].indexOf(f[0])) });
    bump(file, 2);
    continue;
  }
  if (ext === '.proto') {
    for (const m of content.matchAll(/rpc\s+(\w+)\s*\(/g)) result.entryPoints.push({ kind: 'grpc', framework: 'protobuf', method: 'RPC', path: m[1], file: R, line: at(m.index) });
    continue;
  }

  const prefixes = [];
  for (const p of PREFIXES.filter(applies))
    for (const m of content.matchAll(p.re)) {
      let pre = m.groups.path;
      if (m.groups.cls) pre = pre.replace(/\[controller\]/gi, m.groups.cls.replace(/Controller$/, '').toLowerCase());
      prefixes.push({ scope: p.scope, index: m.index, var: m.groups.var, path: pre });
    }
  const nextjs = nextPath(file);
  const groupAuth = new Map();
  for (const m of content.matchAll(/(\w+)\.Use\(([^)]*)\)/g)) if (/auth|jwt|session|guard|protect|require/i.test(m[2])) groupAuth.set(m[1], m[2].trim());
  const classAuth = [];
  if (ext === '.cs' || ext === '.java' || ext === '.kt' || ext === '.ts')
    for (const m of content.matchAll(/((?:\s*(?:\[[^\]]+\]|@\w+(?:\([^)]*\))?)\s*)+)\s*(?:public\s+|export\s+)?(?:sealed\s+|abstract\s+|partial\s+)*class\s+\w+/g))
      if (/\[Authorize|@PreAuthorize|@Secured|@RolesAllowed|@UseGuards/.test(m[1])) classAuth.push(m.index);
  const routeAuth = (idx, recv) => {
    const line = at(idx);
    const tags = new Set();
    const lines = content.split('\n');
    const above = [];
    for (let i = line - 2; i >= 0 && /^\s*(\[|@)/.test(lines[i]); i--) above.push(lines[i]);
    const own = [lines[line - 1] ?? '', ...above].join('\n');
    for (const a of AUTH.filter((x) => ['anonymous', 'require', 'verify-token', 'signature', 'api-key'].includes(x.tag))) {
      a.re.lastIndex = 0;
      if (a.re.test(own)) tags.add(a.tag === 'anonymous' ? 'anonymous' : `route:${a.tag}`);
    }
    if (recv && groupAuth.has(recv)) tags.add(`group:${groupAuth.get(recv)}`);
    if (classAuth.some((c) => c < idx) && !tags.has('anonymous')) tags.add('class:require');
    return tags.size ? [...tags] : ['none'];
  };
  for (const p of ROUTES.filter(applies)) {
    for (const m of content.matchAll(p.re)) {
      const g = m.groups ?? {};
      if (p.framework === 'js-router' && CLIENT_RECEIVERS.test(g.recv)) {
        result.outbound.push({ kind: 'http', file: R, line: at(m.index), text: snippet(content, m.index), note: `${g.recv}.${g.method} looks like a client call` });
        continue;
      }
      const recv = g.recv ?? content.slice(Math.max(0, m.index - 60), m.index).match(/(\w+)\s*$/)?.[1];
      const varPrefix = prefixes.filter((x) => x.scope === 'var' && x.var === recv && x.index < m.index).at(-1);
      const classPrefix = prefixes.filter((x) => x.scope === 'class' && x.index < m.index).at(-1);
      const pre = varPrefix?.path ?? (['nestjs', 'aspnet-mvc'].includes(p.framework) ? classPrefix?.path : undefined);
      const method = g.method ? String(g.method).toUpperCase().replace(/^(ROUTE|API_ROUTE|REQUEST|ALL|ANY)$/, 'ANY') : 'ANY';
      result.entryPoints.push({ kind: method === 'WEBSOCKET' ? 'websocket' : 'route', framework: p.framework, method: method === 'WEBSOCKET' ? 'WS' : method, path: pre !== undefined ? joinPath(pre, g.path) : g.path ?? '', file: R, line: at(m.index), text: snippet(content, m.index), prefixed: pre !== undefined || undefined, auth: p.framework === 'fetch-handler' ? undefined : routeAuth(m.index, recv) });
      bump(file, 3);
    }
  }
  for (const p of ENTRIES.filter(applies)) {
    for (const m of content.matchAll(p.re)) {
      const e = { kind: p.kind, framework: 'code', file: R, line: at(m.index), text: snippet(content, m.index), note: p.note };
      if (p.kind === 'nextjs-route') {
        if (!nextjs) continue;
        Object.assign(e, { kind: 'route', framework: 'nextjs', method: m.groups.method, path: nextjs });
      }
      result.entryPoints.push(e);
      bump(file, 3);
    }
  }
  for (const a of AUTH)
    for (const m of content.matchAll(a.re)) {
      result.auth.push({ tag: a.tag, file: R, line: at(m.index), text: snippet(content, m.index) });
      bump(file, 2);
    }
  const isDefinition = (idx) => /^(?:async\s+)?\w+\s*\([^)]*\)\s*(?::\s*[^{=]+)?\{\s*$/.test(snippet(content, idx));
  for (const o of OUTBOUND)
    for (const m of content.matchAll(o.re)) {
      if (isDefinition(m.index)) continue;
      result.outbound.push({ kind: o.kind, file: R, line: at(m.index), text: snippet(content, m.index), note: o.note });
      bump(file);
    }
  for (const c of CONFIG)
    for (const m of content.matchAll(c.re)) {
      const g = m.groups ?? {};
      addName(g.name ?? g.name2 ?? g.name3, file, at(m.index), 'code');
    }
  for (const s of SINKS)
    for (const m of content.matchAll(s.re)) {
      if (isDefinition(m.index)) continue;
      const text = snippet(content, m.index);
      let what = s.what;
      if (what === 'SQL built from strings' && !/(?:WHERE|VALUES|SET|IN\s*\(|=|LIKE|LIMIT|OFFSET)[^;]*(?:\$\{|\{\w+\}|%s|%v|['"`]\s*\+)/i.test(text)) what = 'SQL with interpolated identifiers (table or column names)';
      result.sinks.push({ check: s.check, what, file: R, line: at(m.index), text });
      bump(file, 3);
    }
}

// Auth seen anywhere in the same file, for entry points without route-level evidence (fetch handlers, triggers).
for (const e of result.entryPoints) {
  if (e.auth) continue;
  const inFile = result.auth.filter((a) => a.file === e.file && ['require', 'verify-token', 'signature', 'api-key'].includes(a.tag));
  if (inFile.length) e.authInFile = [...new Set(inFile.map((a) => a.tag))];
}
const seen = new Set();
result.outbound = result.outbound.filter((o) => {
  const k = `${o.file}:${o.line}:${o.kind}`;
  return !seen.has(k) && seen.add(k);
});
const seenAuth = new Set();
result.auth = result.auth.filter((a) => {
  const k = `${a.file}:${a.line}:${a.tag}`;
  return !seenAuth.has(k) && seenAuth.add(k);
});
result.stack.frameworks = [...frameworks.values()];
result.configNames = [...configNames.values()].sort((a, b) => a.name.localeCompare(b.name));
result.hotFiles = [...hits.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([f, score]) => ({ file: rel(f), score }));

const fw = result.stack.frameworks.map((f) => f.name.toLowerCase()).join(' ');
if (/aws-cdk-lib/.test(fw)) result.suggestions.push('aws-cdk-lib found: run extract-entry-points.mjs on the stack files for exact routes, auth and IAM');
if (/microsoft\.aspnetcore|microsoft\.net\.sdk\.web/.test(fw)) result.suggestions.push('ASP.NET Core: read Program.cs or Startup.cs for middleware order, the fallback authorization policy, CORS and auth setup before judging any single endpoint');
if (/gin-gonic|go-chi|labstack\/echo|gofiber|gorilla\/mux/.test(fw) || result.stats.byLanguage.Go) result.suggestions.push('Go: check which middleware each router group gets; a route registered on the parent router skips the group middleware');
if (result.stack.config.some((c) => c.kind === 'cloudflare-wrangler')) result.suggestions.push('Cloudflare Worker: routing happens inside the fetch handler; trace every branch of it, including the default case');
if (!result.entryPoints.length) result.suggestions.push('No entry points recognised: read the code by hand, starting from main/Program/index files and the hot files');
result.limits = 'Candidates from pattern matching, not proof. Routes built dynamically, prefixes applied across files, and frameworks not in the catalog are missed. Confirm each item by reading the code.';

let output;
if (asJson) output = JSON.stringify(result, null, 2);
else {
  const cell = (s) => String(s ?? '').replace(/\|/g, '\\|');
  const cap = (list, n) => (list.length > n ? { rows: list.slice(0, n), more: list.length - n } : { rows: list, more: 0 });
  const L = [`# Recon: ${result.scope.join(', ')}`, '', `> ${result.limits}`, ''];
  L.push('## Stack', '', `Files: ${result.stats.files}, source files: ${result.stats.sourceFiles}. Languages: ${Object.entries(result.stats.byLanguage).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}.`, '');
  if (result.stack.frameworks.length) L.push('| Dependency | Category | Found in |', '|---|---|---|', ...result.stack.frameworks.map((f) => `| ${f.name} | ${f.category} | ${f.evidence} |`), '');
  if (result.stack.config.length) {
    L.push('### Config and IaC', '', '| Kind | File | Details | Flags |', '|---|---|---|---|');
    for (const c of result.stack.config) {
      const { kind, file, flags, ...rest } = c;
      L.push(`| ${kind} | ${file} | ${cell(JSON.stringify(rest)).slice(0, 300)} | ${cell((flags ?? []).join('; '))} |`);
    }
    L.push('');
  }
  const ep = cap(result.entryPoints, 300);
  L.push(`## Entry points (${result.entryPoints.length} candidates)`, '', '| Kind | Method | Path | Where | Framework | Auth (route / file) |', '|---|---|---|---|---|---|');
  for (const e of ep.rows) L.push(`| ${e.kind} | ${e.method ?? ''} | \`${cell(e.path ?? e.text ?? '')}\` | ${e.file}:${e.line} | ${e.framework}${e.handler ? ` (${e.handler})` : ''} | ${Array.isArray(e.auth) ? e.auth.join(', ') : e.auth ?? (e.authInFile ? `in file: ${e.authInFile.join(', ')}` : '')} |`);
  if (ep.more) L.push(`| ... | | ${ep.more} more in recon.json | | | |`);
  L.push('');
  const section = (title, list, cols, row, n = 150) => {
    const c = cap(list, n);
    L.push(`## ${title} (${list.length})`, '');
    if (!list.length) return L.push('_None found._', '');
    L.push(`| ${cols.join(' | ')} |`, `|${cols.map(() => '---').join('|')}|`, ...c.rows.map(row));
    if (c.more) L.push(`| ${c.more} more in recon.json |${cols.slice(1).map(() => '').join('|')}|`);
    L.push('');
  };
  section('Auth markers', result.auth, ['Tag', 'Where', 'Code'], (a) => `| ${a.tag} | ${a.file}:${a.line} | \`${cell(a.text)}\` |`);
  section('Outbound connections', result.outbound, ['Kind', 'Where', 'Code'], (o) => `| ${o.kind} | ${o.file}:${o.line} | \`${cell(o.text)}\` |`);
  section('Risky sinks', result.sinks, ['Check', 'What', 'Where', 'Code'], (s) => `| ${s.check} | ${s.what} | ${s.file}:${s.line} | \`${cell(s.text)}\` |`);
  section('Configuration and secret names (values never read)', result.configNames, ['Name', 'Source', 'Uses', 'First seen'], (c) => `| ${c.name} | ${c.source} | ${c.count} | ${c.first} |`, 200);
  L.push('## Hot files (read these first)', '', ...result.hotFiles.map((h) => `- ${h.file} (${h.score})`), '');
  if (result.suggestions.length) L.push('## Next steps', '', ...result.suggestions.map((s) => `- ${s}`), '');
  if (warnings.length) L.push('## Warnings', '', ...warnings.map((w) => `- ${w}`), '');
  output = L.join('\n');
}
if (outFile) {
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, output);
  console.log(`wrote ${outFile}: ${result.entryPoints.length} entry points, ${result.auth.length} auth markers, ${result.outbound.length} outbound, ${result.sinks.length} sinks`);
} else console.log(output);
