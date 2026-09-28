#!/usr/bin/env node
// Builds report.html in a run folder: one page to present a run to the team.
// Reads whatever exists: run-meta.json, findings.json, model.json, CHANGE_IMPACT.md, THREAT_MODEL.md, inventory.md,
// dataflow.md, stride.md, diff.md, entry-points.md, recon.md.
// Usage: node build-report.mjs <runDir>
// Rendering loads marked, DOMPurify and mermaid from a CDN (pinned with SRI). Offline, the page falls back to the raw
// markdown and Mermaid source, so it still works without a network. Nothing in the page calls any other host.
import fs from 'node:fs';
import path from 'node:path';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: build-report.mjs <runDir>');
  process.exit(2);
}
const read = (f) => (fs.existsSync(path.join(dir, f)) ? fs.readFileSync(path.join(dir, f), 'utf8') : '');
const readJson = (f) => {
  try {
    return JSON.parse(read(f) || 'null');
  } catch {
    return null;
  }
};
const meta = readJson('run-meta.json') ?? {};
const findings = readJson('findings.json')?.findings ?? [];
const model = readJson('model.json');

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const open = findings.filter((f) => !['fixed', 'false-positive', 'mitigated'].includes(f.status));
const sev = Object.fromEntries(SEVS.map((s) => [s, open.filter((f) => f.severity === s).length]));
const nodes = (model?.diagrams ?? []).flatMap((d) => d.nodes ?? []);
const counts = {
  diagrams: model?.diagrams?.length ?? 0,
  elements: new Set(nodes.map((n) => n.id)).size,
  flows: (model?.diagrams ?? []).reduce((s, d) => s + (d.flows?.length ?? 0), 0),
  zones: new Set(nodes.map((n) => n.trust)).size,
};

const DOCS = [
  ['change', 'Change impact', 'CHANGE_IMPACT.md'],
  ['report', 'Threat model', 'THREAT_MODEL.md'],
  ['inventory', 'Inventory', 'inventory.md'],
  ['diagrams', 'Data flow diagrams', 'dataflow.md'],
  ['stride', 'STRIDE table', 'stride.md'],
  ['diff', 'Since last run', 'diff.md'],
  ['entry', 'Entry points', 'entry-points.md'],
  ['recon', 'Recon', 'recon.md'],
];
const docs = Object.fromEntries(DOCS.map(([id, , f]) => [id, read(f)]).filter(([, v]) => v));

const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const int = (n) => (typeof n === 'number' ? n.toLocaleString('en-GB') : '-');
const dur = (s) => (s == null ? 'not recorded' : s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`);
const card = (label, value, sub = '') => `<div class="card"><div class="v">${value}</div><div class="l">${esc(label)}</div>${sub ? `<div class="s">${esc(sub)}</div>` : ''}</div>`;
const title = `trust-issues: ${meta.target ?? path.basename(path.dirname(path.resolve(dir)))}`;
const total = open.length || 1;
const gates = (meta.gates ?? []).map((g) => `<tr><td>${esc(g.name)}</td><td>${esc(g.outcome)}</td><td>${esc(g.note)}</td><td>${esc(g.at?.slice(0, 16).replace('T', ' '))}</td></tr>`).join('');
const stages = (meta.stages ?? []).map((s) => `<tr><td>${esc(s.name)}</td><td>${int(s.agents)}</td><td>${int(s.subagentTokens)}</td><td>${dur(Math.round((s.durationMs ?? 0) / 1000))}</td></tr>`).join('');
const nav = [['summary', 'Summary'], ...DOCS.filter(([id]) => docs[id]).map(([id, label]) => [id, label])];
const DATA = JSON.stringify({ docs }).replace(/<\//g, '<\\/');

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<script src="https://cdn.jsdelivr.net/npm/marked@18.0.5/lib/marked.umd.js" integrity="sha384-ZD0fTOwPMHi7zM6WTVIWJR21I07lq0ccnqz3J6WMvQKG9thh4y7TA1QE6PJu0Af8" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.4.11/dist/purify.min.js" integrity="sha384-o44XUELLEnv/iSlA1NWxBweqbD4TSR0qgq2VzVsxtkHS989JJjGKSE9vkfo5MN4K" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.6/dist/mermaid.min.js" integrity="sha384-qX9VvWkP79m/O121ZE6sOYp0nf/pldQgtvWDbkpzi+3mUo4Wn4Ix4cFzNPay3VaB" crossorigin="anonymous"></script>
<style>
:root{--bg:#0e1116;--panel:#161b22;--ink:#e6edf3;--mut:#9aa7b4;--line:#2a313c;--accent:#3b82f6;--crit:#b91c1c;--hi:#ef4444;--med:#f59e0b;--lo:#22c55e;--info:#64748b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;display:flex}
aside{position:sticky;top:0;align-self:flex-start;height:100vh;width:230px;flex:none;background:var(--panel);border-right:1px solid var(--line);padding:20px 16px;overflow:auto}
aside h1{font-size:15px;margin:0 0 4px}aside .scope{color:var(--mut);font-size:12px;margin-bottom:16px}
aside a{display:block;color:var(--ink);text-decoration:none;padding:8px 10px;border-radius:7px;font-size:14px}aside a:hover{background:#1f2733}
main{flex:1;min-width:0;max-width:1150px;margin:0 auto;padding:28px 36px 80px}
header.top{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px}header.top h2{margin:0 0 4px;font-size:24px}
.muted{color:var(--mut)}
section{scroll-margin-top:20px;margin-bottom:40px}
section>h3{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);border-bottom:1px solid var(--line);padding-bottom:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.v{font-size:24px;font-weight:650}.l{color:var(--mut);font-size:12px;margin-top:2px}.s{color:var(--mut);font-size:11px;margin-top:6px}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;border:1px solid var(--line);margin:8px 0}.sevbar i{display:block}
.legend{display:flex;gap:16px;font-size:13px;color:var(--mut);flex-wrap:wrap}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
table.t,.md table{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0;display:block;overflow:auto}
table.t th,table.t td,.md th,.md td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
table.t th,.md th{background:#1f2733}
.md h1{font-size:22px;border-bottom:1px solid var(--line);padding-bottom:6px}.md h2{font-size:19px;margin-top:28px;border-bottom:1px solid var(--line);padding-bottom:6px}.md h3{font-size:16px}
.md code{background:#1f2733;padding:1px 5px;border-radius:5px;font-size:12px}
.md pre,pre.raw{background:#0b0e13;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap}
.md blockquote{border-left:3px solid var(--accent);margin:12px 0;padding:6px 14px;color:var(--mut);background:#141a22}
.md a{color:#79b8ff}
.mermaid{background:#fafafa;border:1px solid var(--line);border-radius:10px;padding:14px;margin:14px 0;text-align:center;overflow:auto}
tr.sev-critical td:nth-child(3){background:var(--crit);color:#fff}tr.sev-high td:nth-child(3){background:var(--hi);color:#fff}
tr.sev-medium td:nth-child(3){background:var(--med);color:#111}tr.sev-low td:nth-child(3){background:var(--lo);color:#111}
.offline{display:none;background:#3b2f14;border:1px solid var(--med);border-radius:8px;padding:8px 12px;margin-bottom:16px;font-size:13px}
footer{color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:14px;margin-top:40px}
@media (max-width:760px){body{display:block}aside{position:static;width:auto;height:auto}main{padding:20px 16px}}
</style></head>
<body>
<aside>
  <h1>${esc(meta.target ?? 'trust-issues')}</h1>
  <div class="scope">${esc(meta.mode ?? '')}${meta.commit ? ` &middot; ${esc(meta.commit)}` : ''}${meta.date ? ` &middot; ${esc(meta.date)}` : ''}</div>
  ${nav.map(([id, label]) => `<a href="#${id}">${esc(label)}</a>`).join('')}
</aside>
<main>
  <header class="top"><h2>${esc(title)}</h2>
    <div class="muted">Decision-support, not sign-off. The owner validates every finding. Internal: describes weaknesses in our own code.</div></header>
  <div class="offline" id="offline">Offline: showing raw markdown and diagram source. Connect to render tables and diagrams.</div>
  <section id="summary"><h3>Summary</h3>
    <div class="cards">
      ${card('Open findings', int(open.length), `${findings.length} in total`)}
      ${card('Critical', int(sev.critical))}${card('High', int(sev.high))}${card('Medium', int(sev.medium))}${card('Low', int(sev.low + sev.info))}
    </div>
    <div class="card"><div class="l">Open findings by severity</div>
      <div class="sevbar">${[['critical', 'crit'], ['high', 'hi'], ['medium', 'med'], ['low', 'lo'], ['info', 'info']].map(([s, c]) => `<i style="width:${(100 * sev[s]) / total}%;background:var(--${c})"></i>`).join('')}</div>
      <div class="legend">${[['critical', 'crit'], ['high', 'hi'], ['medium', 'med'], ['low', 'lo'], ['info', 'info']].map(([s, c]) => `<span><i class="dot" style="background:var(--${c})"></i>${s} ${sev[s]}</span>`).join('')}</div>
    </div>
    <div class="cards">
      ${card('Diagrams', int(counts.diagrams))}${card('Elements', int(counts.elements))}${card('Data flows', int(counts.flows))}${card('Trust zones', int(counts.zones))}
      ${card('Wall-clock', dur(meta.wallClockSeconds))}${card('Subagent tokens', int(meta.tokens?.subagentTotal ?? 0), 'measured subagents only')}
    </div>
    ${gates ? `<table class="t"><thead><tr><th>Owner gate</th><th>Outcome</th><th>Note</th><th>At (UTC)</th></tr></thead><tbody>${gates}</tbody></table>` : ''}
    ${stages ? `<table class="t"><thead><tr><th>Stage</th><th>Agents</th><th>Subagent tokens</th><th>Duration</th></tr></thead><tbody>${stages}</tbody></table>` : ''}
  </section>
  ${DOCS.filter(([id]) => docs[id]).map(([id, label]) => `<section id="${id}"><h3>${esc(label)}</h3><div class="md" data-doc="${id}"></div></section>`).join('\n  ')}
  <footer>Generated by the trust-issues skill from local files only. Keep this report internal.</footer>
</main>
<script>
const DATA = ${DATA};
function raw(){
  document.getElementById("offline").style.display = "block";
  document.querySelectorAll(".md[data-doc]").forEach(function(el){ var p = document.createElement("pre"); p.className = "raw"; p.textContent = DATA.docs[el.dataset.doc] || ""; el.replaceChildren(p); });
}
function render(){
  document.querySelectorAll(".md[data-doc]").forEach(function(el){ el.innerHTML = window.DOMPurify.sanitize(window.marked.parse(DATA.docs[el.dataset.doc] || "")); });
  document.querySelectorAll("code.language-mermaid").forEach(function(code){ var d = document.createElement("div"); d.className = "mermaid"; d.textContent = code.textContent; (code.closest("pre") || code).replaceWith(d); });
  document.querySelectorAll(".md table tr").forEach(function(tr){ var m = tr.textContent.match(/\\((Critical|High|Medium|Low)\\)/); if (m) tr.classList.add("sev-" + m[1].toLowerCase()); });
  window.mermaid.initialize({ startOnLoad: false, theme: "default", securityLevel: "strict" });
  window.mermaid.run({ querySelector: ".mermaid" });
}
var tries = 0;
(function boot(){ if (window.marked && window.DOMPurify && window.mermaid) render(); else if (++tries > 40) raw(); else setTimeout(boot, 75); })();
</script>
</body></html>
`;
fs.writeFileSync(path.join(dir, 'report.html'), html);
console.log(`wrote ${path.join(dir, 'report.html')}: ${open.length} open findings (critical ${sev.critical}, high ${sev.high}, medium ${sev.medium}, low ${sev.low}, info ${sev.info})`);
