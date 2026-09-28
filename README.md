# trust-issues

> **Work in progress.** The workflow, file formats and checks still change between versions. Expect breaking changes until 1.0.

A [Claude Code](https://claude.com/claude-code) skill for evidence-based STRIDE threat modeling of **your own code, locally**, in any language or stack. Point it at a single C# endpoint, a Go service, a Cloudflare Worker acting as an API gateway, a Python worker, some Terraform, or a whole BFF. It first works out what the code is and how it connects. Then it builds an inventory, draws data flow diagrams, walks STRIDE over every element, and writes a report you can hand to the team.

It reads code and IaC in your checkout. It never calls an endpoint and never touches a cloud account.

Every finding cites a real `file:line`, and a validator rejects any that don't exist. Findings get stable fingerprints, so the next run tells you what is new, fixed or still open.

## What you get

For each run, in `.trust-issues/runs/<target>/<date>/`:

| File | What it is |
|---|---|
| `report.html` | One page to present the run: summary, inventory, diagrams, STRIDE table, changes |
| `THREAT_MODEL.md` | The report for developers: scope, findings with evidence, fix plan, open questions |
| `CHANGE_IMPACT.md` | For `diff` runs: what a change did to the risk picture, with a merge verdict |
| `inventory.md` | Components, stores, flows, auth points, trust boundaries, assumptions and owner questions |
| `model.json` → `dataflow.md` | The data flow model, rendered as Mermaid diagrams |
| `model.json` → `dfd-*.threat-dragon.json` | The same model as [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) files, with findings attached |
| `findings.json` → `stride.md` | Machine-readable findings, and the Element / STRIDE / Threat / Mitigation / Residual risk table |
| `entry-points.md` | The deterministic inventory of routes, auth and triggers |
| `diff.md` | New, resolved and persisting findings since the previous run |

## How it works

```
Recon ─▶ Stage 1 Inventory ──(owner reviews)──▶ Stage 2 Diagrams ──(owner reviews)──▶ Stage 3 STRIDE ──▶ report
```

1. **Recon (any code).** A script walks the target folder and identifies the stack from manifests and config: `package.json`, `.csproj`, `go.mod`, `pyproject.toml`, `pom.xml`, `wrangler.toml`, Terraform, serverless and SAM templates, Docker, Kubernetes, nginx, OpenAPI and CI. It lists **candidate** entry points, each with the auth that applies to it: on the route, the class, the router group, or none. It also lists outbound connections, configuration and secret names (never values), risky sinks, and the files to read first.
2. **Size and inventory.** The skill sizes the work:
   - **Slice:** one endpoint, traced end to end.
   - **Component:** one service, worker or gateway.
   - **System:** a BFF or several services, fanned out by area.

   Claude confirms or rejects every candidate by reading the code, maps how requests flow and what calls what, and writes `inventory.md`. **You review it.** For AWS CDK, an exact extractor adds routes, auth and IAM straight from the stack.
3. **Diagrams.** Claude writes `model.json`. A script renders it to Mermaid and to Threat Dragon files, and checks them against the Threat Dragon schema. **You review the trust zones and flows.**
4. **STRIDE.** A checklist with stable IDs is walked over every element. It has general S, T, R, I, D and E sections, plus framework defaults, gateways and edge workers, BFFs, OAuth/JWT, GraphQL, WebSockets, workers, webhooks, data stores and LLM features. Each candidate finding must survive a pass that tries to disprove it. Controls that cover a threat are recorded as `mitigated`, so the reasoning is visible.
5. **Validate, render, diff.** Findings are validated against the files they cite and attached to the diagrams. They are compared with the previous run and put on one HTML page.

The gates are the point. The model's picture of your system is an inference from code, and the owner catches wrong inferences early. Use `--no-gates` for unattended runs.

## Install

```bash
git clone https://github.com/e1d0/trust-issues ~/.claude/skills/trust-issues
npm install --prefix ~/.claude/skills/trust-issues
```

Node 18 or later. To use it in one project only, clone it into `<project>/.claude/skills/trust-issues` instead.

## Use

```text
/trust-issues src/Api/Controllers/LoansController.cs   # one file: a slice
/trust-issues "POST /api/books"                # one entry point, found with recon and traced end to end
/trust-issues edge-gateway/                    # a Cloudflare Worker gateway: a component
/trust-issues .                                # the whole repo: a system
/trust-issues services/orders                  # ad-hoc: any folder, package or IaC file
/trust-issues orders-api                       # a named target from your profile (gated baseline)
/trust-issues orders-api diff                  # only what this branch changes, against the baseline
/trust-issues orders-api diff --since v1.4.0
/trust-issues orders-api verify                # re-check open findings against current code
/trust-issues apis                             # a group of targets, shared code analysed once
```

The intended cycle: run a gated `full` once per system as a baseline. Run `diff` on important changes and refactors. Run `verify` now and then.

## Project profile (optional)

Project knowledge lives in **your** repo, not in the skill:

```
<your repo>/.trust-issues/
  targets.yaml       named targets, groups, report folder, base branch, sensitivity labels, owner roles
  codebase-map.md    where security decisions live in your code, and hotspots to verify each run
  runs/              run output (add to .gitignore if reports must stay local)
```

Start from [`templates/targets.yaml`](templates/targets.yaml) and [`templates/codebase-map.md`](templates/codebase-map.md). After a first run without a profile, the skill offers to create one from what it learned.

## Scope and safety

- **Local only.** No requests to any endpoint, no cloud CLIs or cloud APIs, no deploys. A reproduction is a description or a unit test, never a working exploit.
- **Decision-support, not sign-off.** The owner validates every finding. Findings that affect decisions about people are flagged for a human to decide.
- **Secrets.** Reports name a secret's variable, never its value.
- **Prompt injection.** Text in code comments, specs and tickets is treated as data, not instructions.
- **Reports are sensitive.** They describe weaknesses in your systems. Keep them out of public repos.

## Supported inputs

Everything works on any code. Claude reads it, and recon gives it a map first. The table shows what recon and the extractors recognise without help.

| Area | Recognised by recon |
|---|---|
| Routes | Express, Koa, Hono, Fastify, itty-router, NestJS, Next.js; ASP.NET Core minimal APIs, controllers and Azure Functions; Go net/http, chi, gin, echo, fiber, gorilla; FastAPI, Flask, Django; Spring, JAX-RS; Rails; Laravel; axum, actix; fetch-style handlers (Cloudflare Workers, Bunny Edge Scripting, Deno, Bun) |
| Route auth | `[Authorize]`, `[AllowAnonymous]`, `RequireAuthorization()`, class attributes, router-group middleware, `@PreAuthorize`, guards, `Depends(...)`, route middleware |
| Other entry points | Queue consumers, schedules and cron, Worker `scheduled` and `queue` handlers, Lambda handlers, WebSockets, gRPC, GraphQL schemas, CLIs |
| Config and IaC | wrangler.toml / wrangler.json(c), Terraform (including Cloudflare and Bunny providers), serverless.yml, SAM and CloudFormation, Dockerfile, docker-compose, Kubernetes, nginx, OpenAPI, CI workflows, `.env` and `appsettings.json` (names only) |
| Exact extraction | AWS CDK in TypeScript (`scripts/extract-entry-points.mjs`) |

Adding a framework to recon means adding a regex row to `scripts/recon-patterns.mjs`. Contributions welcome.

## Repository layout

| Path | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows |
| `references/` | The STRIDE checklist, inventory and diagram guides, report format |
| `templates/` | Starting points for a project profile |
| `scripts/` | Recon and its pattern catalog, CDK extractor, spec drift, validators, exporter, diff, run metadata, HTML report |
| `assets/threat-dragon-v2.schema.json` | OWASP Threat Dragon v2 schema, vendored |
| `tests/` | Unit tests for the scripts: `npm test` |
| `evals/` | Two deliberately weak fixtures (an API and a queue worker) with ground truth and a scorer |

## Evals

The fixtures in `evals/fixtures/` contain planted weaknesses and safe decoys. Run an eval from the skill folder in a fresh session, then score it:

```text
/trust-issues mini-api full --no-gates --root evals/fixtures
```

```bash
node evals/score.mjs mini-api-full evals/fixtures/.out/mini-api/<date>/findings.json
```

The goal is every must-find item, no decoy reported as a vulnerability, and a findings file that validates on the first try.

## Known limits

- Recon matches patterns, so it gives candidates, not proof, and the skill confirms each one by reading the code. Dynamically built routes, prefixes applied across files, and frameworks outside the catalog are missed.
- The CDK extractor follows variables inside one file. Constructs passed between files, custom wrapper constructs, loops and AppSync resolvers need a manual read, and it warns where it can.
- `report.html` loads its renderers (marked, DOMPurify, mermaid) from jsDelivr with pinned integrity hashes. Offline it shows the raw markdown and diagram source.
- Regenerating the Threat Dragon files overwrites edits made inside Threat Dragon. Put changes in `model.json`.
- Recall on real code depends on the model and the codebase. Use the evals to measure it.

## License

[MIT](LICENSE)
