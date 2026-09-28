# Report format

Each run writes one folder: `<reportDir>/<target-id>/<YYYY-MM-DD>/`. `reportDir` comes from the profile and defaults to `.trust-issues/runs`.

| File | Produced by | Stage | Purpose |
|---|---|---|---|
| `run-meta.json` | `scripts/run-meta.mjs` | all | Timing, owner gates, measured subagent usage, counts |
| `recon.md`, `recon.json` | `scripts/recon.mjs` | 1 | Stack, candidate entry points with route-level auth, connections, config names, sinks, hot files |
| `entry-points.md`, `entry-points.json` | `scripts/extract-entry-points.mjs` or the model | 1 | Confirmed entry points: extracted for CDK, written from recon plus reading otherwise |
| `spec-drift.md` | `scripts/spec-drift.mjs` | 1 | Stack vs OpenAPI differences (only if the target has a spec) |
| `inventory.md` | the model | 1 | Components, stores, flows, auth, trust boundaries, assumptions, owner questions. See `references/inventory-guide.md` |
| `model.json` | the model | 2 | The data flow model. See `references/diagram-guide.md` |
| `dataflow.md`, `dfd-<key>.threat-dragon.json` | `scripts/export-model.mjs` | 2, 3 | Mermaid DFDs and Threat Dragon models, threats attached from findings.json |
| `findings.json` | the model | 3 | Machine-readable findings, validated by `scripts/validate-findings.mjs`. The single source of truth for threats |
| `stride.md` | `scripts/export-model.mjs` | 3 | Element / STRIDE / Threat / Mitigation / Residual risk |
| `THREAT_MODEL.md` | the model | 3 | The report for developers, sections below |
| `CHANGE_IMPACT.md` | the model | diff | What a change did to the risk picture, template below |
| `diff.md` | `scripts/diff-findings.mjs` | 3 | New, resolved and persisting findings since the previous run |
| `report.html` | `scripts/build-report.mjs` | end | One page that shows all of the above, for presenting to the team |

## findings.json

```json
{
  "target": "session-auth",
  "generatedAt": "2026-09-25",
  "commit": "85d578a535",
  "mode": "full",
  "model": "claude-fable-5-1",
  "scope": { "stacks": ["infra/lib/shop-api-stack.ts"], "match": ["auth-api", "session-authorizer"], "paths": ["services/shop-api/session-authorizer"], "excluded": [] },
  "findings": [
    {
      "id": "SESSION-AUTH-001",
      "fingerprint": "S-AUTHZ-CACHE:authorizer:session",
      "title": "Authorizer cache keyed on Authorization header while identity comes from Cookie",
      "stride": ["S", "I"],
      "element": "authorizer:session",
      "owasp": "API2:2023",
      "cwe": "CWE-524",
      "severity": "high",
      "likelihood": "medium",
      "impact": "high",
      "confidence": "likely",
      "status": "open",
      "evidence": [
        { "file": "infra/lib/shop-api-stack.ts", "line": 93, "note": "identity source Authorization, TTL 5 min" },
        { "file": "services/shop-api/session-authorizer/index.ts", "line": 28, "note": "session read from Cookie" }
      ],
      "scenario": "Step-by-step: who the attacker is, what they send, what they get.",
      "recommendation": "Concrete fix in this codebase's terms (construct option, handler change).",
      "effort": "S",
      "verification": "How to prove the fix: a test, a curl sequence against dev, a config check.",
      "residual": "Optional. Risk left given current controls, e.g. 'High until the cache key includes Cookie'.",
      "ownerRole": "Optional. Who decides, from the inventory's ownerRoles, e.g. 'backend' or 'platform'.",
      "statusReason": "Required when status is accepted-risk, mitigated or false-positive."
    }
  ]
}
```

- `id` is `<TARGET-ID uppercase>-<3 digits>`, unique inside the run. `fingerprint` is stable across runs (see the checklist).
- Every finding needs at least one evidence entry with a real file and line. The validator rejects the file otherwise.
- Do not report a finding you could not ground in code. Put it under open questions instead.
- `status` is one of `open`, `accepted-risk`, `mitigated`, `false-positive`, `fixed`. Use `mitigated` for a threat you considered where a control you read covers it, for example a parameterised query or an ownership check. Cite the control as evidence and name it in `statusReason`. Record notable mitigated cases, so a reviewer can see the reasoning was done. Do not pad the file with them.
- `element` must be a node id (or alias) in `model.json`, or a `shared:` id. The exporter warns about findings it cannot place.

## THREAT_MODEL.md sections

1. **Summary**: three to five sentences. Overall risk, the top three fixes, what was out of scope.
2. **Scope and method**: target, commit, mode, model, files read, what was not covered.
3. **System context**: who or what calls the target, users and roles, assets.
4. **Data flow diagram**: copy the overview Mermaid block from `dataflow.md` and link to `dataflow.md` for the detail diagrams and to the `dfd-*.threat-dragon.json` files.
5. **Entry points**: summary from `entry-points.md`, meaning route counts by auth type plus queues, schedules and rules. List every entry point reachable without a user credential that touches user data.
6. **Findings**: a summary table (id, title, STRIDE, severity, confidence, effort, owner role), then one subsection per open or accepted-risk finding: scenario, evidence as links, recommendation, verification, residual risk. Link to `stride.md` for the full table, mitigated cases included.
7. **STRIDE coverage**: one row per STRIDE category saying which checks were applied and to which elements, and which checks were not applicable. This shows the gaps.
8. **Fix plan**: findings grouped as fix now (critical and high), next sprint (medium), backlog (low and hardening). Group fixes that share a root cause in shared code, for example a shared construct library or a shared Lambda role.
9. **Open questions**: things only an owner can answer (intended public routes, key distribution, accepted risks), plus any inventory question still OPEN after the gates.
10. **Changes since last run**: from `diff.md`, if present.

Start the report with one line: "Decision-support, not sign-off. The owner validates every finding." If a finding supports a decision about people (eligibility, fraud flags, profiling, PII retention), say that a human owner must decide and document it, and flag the regulatory question rather than answering it.

## CHANGE_IMPACT.md (diff mode)

Written for the reviewer of the change. One page.

```markdown
# Change impact: <target>, <since>..<commit>

> Decision-support, not sign-off.

**Verdict:** one of: no security-relevant change | review before merge | block until fixed. One sentence why.

## What changed
| Element | Change | Files |
|---|---|---|
| route:POST /x | new, no authorizer | infra/lib/shop-api-stack.ts:120 |

## Effect on the model
New or changed trust zones, flows, credentials and entry points. Name the diagram(s) that changed.

## Findings
| | Id | Title | Severity | Note |
|---|---|---|---|---|
| new | ... | | | |
| worse | ... | | | severity or reach went up |
| fixed by this change | ... | | | |
| still open, touched | ... | | | the change touched code with an open finding |

## Before merge
Numbered, concrete asks. Empty when the verdict is "no security-relevant change".
```

## Writing rules

- Keep it factual. No fear language. Every claim cites evidence.
- Write for the target's developers: name the file and the fix.
- Mark shared-code findings clearly, because one fix closes them for every target.
