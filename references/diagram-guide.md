# Stage 2: diagrams

The data flow model lives in one file, `model.json`. `scripts/export-model.mjs` renders it, together with `findings.json`, into `dataflow.md` (Mermaid), one `dfd-<key>.threat-dragon.json` per diagram, and `stride.md`. Never edit the rendered files by hand. Edit `model.json` or `findings.json` and export again.

## model.json

```json
{
  "target": "pilot-order-api",
  "owner": "team or person",
  "diagrams": [
    {
      "key": "0-overview",
      "title": "0 - Overview",
      "description": "optional one line shown above the diagram",
      "nodes": [
        { "id": "actor:customer-browser", "kind": "actor", "tier": 0, "name": "Customer browser", "trust": "1 - Internet" },
        { "id": "authorizer:session", "kind": "process", "tier": 1, "name": "Session authorizer", "trust": "2 - API Gateway" },
        { "id": "lambda:order-api", "kind": "process", "tier": 2, "name": "order-api", "trust": "3 - Lambda", "elements": ["route:*"] },
        { "id": "ext:commerce-platform", "kind": "store", "tier": 4, "name": "Commerce platform", "trust": "5 - SaaS" }
      ],
      "flows": [
        { "from": "actor:customer-browser", "to": "authorizer:session", "data": "order id", "sensitivity": "PII", "credential": "session cookie", "protocol": "HTTPS", "publicNetwork": true, "encrypted": true },
        { "from": "lambda:order-api", "to": "ext:commerce-platform", "data": "order query", "sensitivity": "PII", "credential": "platform client secret", "assumed": true }
      ]
    }
  ]
}
```

| Field | Rule |
|---|---|
| `key` | `[a-z0-9-]+`, stable across runs. It names the Threat Dragon file. |
| `nodes[].id` | An element id from `references/stride-checklist.md`, the same id findings use. Stable across runs. |
| `nodes[].kind` | `actor` (people, browsers, partners, callers), `process` (routes, authorizers, lambdas, workers), `store` (tables, buckets, queues as stores, SaaS systems of record). |
| `nodes[].trust` | The trust zone. Prefix a number to fix the order, for example `1 - Internet`. One dotted box per zone. |
| `nodes[].tier` | Orders zones left to right (the lowest tier in a zone wins). |
| `nodes[].elements` | Optional. More element ids this node stands for, so findings attach to a collapsed overview node. A trailing `*` is a prefix match, for example `route:*`. |
| `nodes[].outOfScope` | Optional, with `reasonOutOfScope`. |
| `flows[]` | `from`, `to`, `data`, `sensitivity` are required. `credential` is what crosses the boundary. `assumed: true` draws a dashed edge until the owner confirms it. |

Flows are labelled `data : sensitivity [credential]`.

## How findings attach

A finding appears on every node whose `id` equals its `element` or whose `elements` covers it, in every Threat Dragon file. In `stride.md` each finding is listed once: under the first diagram with an exact node id match, otherwise the first with an alias match. `shared:*` findings go in a "Shared code" section. Anything else that matches no node goes under "Not on a diagram", and the exporter warns. Fix those warnings by adding the node or an alias, unless the element really does not belong on a diagram.

Severity maps to Threat Dragon's three levels: critical and high to High, medium to Medium, low and info to Low. The original severity stays in the threat's `score` and description. Status maps open and accepted-risk to Open, mitigated to Mitigated. Fixed and false-positive findings are left out of every view.

## Layout rules

- Component level, not every function. A route group served by one lambda is one node unless its routes differ in auth.
- If the target fits one readable diagram (about 15 nodes), draw one. If not, draw `0-overview` with each area collapsed to one node (use `elements` aliases), plus one detail diagram per trust boundary or domain.
- Keep node ids the same across diagrams, so the same element is the same thing everywhere.
- Label every flow that crosses a trust zone with its credential. A crossing with no credential is itself worth a look at Stage 3.
- Mark anything inferred but not confirmed as `assumed`.

## Commands

```bash
node $SKILL_DIR/scripts/export-model.mjs <run> --check   # validate model.json only
node $SKILL_DIR/scripts/export-model.mjs <run>           # write dataflow.md, stride.md, dfd-*.threat-dragon.json
node $SKILL_DIR/scripts/validate-threat-dragon.mjs <run> # schema check, run from the repo root (needs ajv)
```

The exporter derives every UUID from the target, diagram key and element id, so re-running on unchanged input gives identical files, and a Threat Dragon file diffs cleanly between runs. Regenerating overwrites edits made inside Threat Dragon. If the owner starts editing in Threat Dragon, say that the next export will overwrite them and ask them to put the changes in `model.json` instead.

## Threat Dragon gotchas

- Edges carry no `size` and no `position`. The v2 schema requires any `size` to be at least 10.
- `strokeDasharray`, where present, must be a string such as `"4 4"`.
- One diagram per file, so each opens fast.
- The schema is vendored at `assets/threat-dragon-v2.schema.json` (from OWASP Threat Dragon `td.vue/src/assets/schema`). Refresh it when Threat Dragon ships a new schema version.

## Gate 2

Present the overview Mermaid diagram and the list of assumed flows in the reply, and ask the owner to check the trust zones, the credentials on crossing flows, and the flows you are least sure about. Stop. Apply their corrections to `model.json`, export again, and record the gate:

```bash
node $SKILL_DIR/scripts/run-meta.mjs gate <run> --name diagrams --outcome approved|corrected --note "<one line>"
```
