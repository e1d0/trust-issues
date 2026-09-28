# Stage 1: inventory

How to build `inventory.md`, the reviewable picture of the target before any diagram or threat. Everything in it is inferred from code, so it is a draft until the owner confirms it at gate 1.

## Sources, in this order

1. `recon.md`: the stack, candidate entry points with route-level auth, outbound connections, config names, sinks and hot files. A map of where to read, not ground truth.
2. `entry-points.md`: from an exact extractor where one exists (CDK), otherwise written by you from recon plus reading.
3. The entry files and every handler in scope, read in full. They confirm or reject each candidate.
4. Shared code the entry points depend on, from the profile's `codebase-map.md` when there is one, otherwise from the hot files and the handlers' imports.
5. Manifests and config: dependencies reveal external systems (payment SDKs, CRM clients, DB drivers, monitoring, LLM APIs); config names reveal upstream URLs, bindings and credentials.

Never read out, echo or copy a secret value or real personal data from `.env*` files, fixtures or logs. Record that the secret exists and what it is for.

## Fan-out for large targets

A slice or a component needs no subagents. For a system with more than about 30 entry points or several services, split the sweep by domain (auth and session, checkout and payment, account data, public marketing routes, workers) and give every reader the same prompt and output shape, so the parts merge cleanly:

```
You are building ONE PART of a trust-issues inventory for <TARGET>.
Area: <NAME>. Read: <paths>. Entry points for this area: <rows from recon.md or entry-points.md>.
Rules:
- Read-only. Local files only. Never echo secret values or real personal data.
- This is inference from code. Anything you are not sure about goes in assumptions or openQuestions, with the reason.
- Cite file:line for every component, flow and auth point.
- For each data flow: from, to, protocol (HTTPS REST, GraphQL, SDK, SQS, DB wire, ...), sync or async, data, sensitivity, credential.
- For auth: where it happens, mechanism (session cookie, JWT, API key, IAM/SigV4, Basic, HMAC, none), authN or authZ.
Return JSON:
{ "area", "components": [{ "name", "type", "responsibility", "location" }],
  "dataStores": [{ "name", "type", "dataHeld", "sensitivity", "location" }],
  "externalEntities": [{ "name", "purpose", "dataExchanged", "evidence" }],
  "dataFlows": [{ "from", "to", "protocol", "syncAsync", "data", "sensitivity", "credential", "evidence" }],
  "authPoints": [{ "location", "mechanism", "authNorAuthZ", "notes" }],
  "trustBoundaries": [{ "name", "rationale" }],
  "assumptions": [], "openQuestions": [] }
```

Then run one reconciliation pass over all parts. It cross-checks, it does not re-read everything, and returns `conflicts`, `duplicates` (same thing, different names), `gaps` (nothing covered it), `consolidatedTrustBoundaries` (outer to inner) and `topOpenQuestions`. Gaps worth asking about: logs and APM tools as a data store (PII in logs), the CDN cache as a store, the admin or CMS access path, out-of-repo systems of record, secret distribution, rate limiting.

Record each fan-out with `run-meta.mjs stage` using the numbers from its notification.

## Sensitivity labels

Use the `sensitivity` list from the profile's `defaults`. Without one, use `public | internal | PII | payment | credential`. Every data store and every flow gets one.

## inventory.md template

```markdown
# Inventory: <target>

> DRAFT for review. Inferred from code at <commit> on <date>. Decision-support, not ground truth: every row is a draft until the owner confirms it. Scope: <in scope>. Out of scope: <out of scope>.

## A. Architecture in brief
Size: slice | component | system. In scope: <paths>. Out of scope, treated as external: <what>.
3 to 6 lines. Name the one or two things that dominate the risk picture.

## B. Components
| Element id | Component | Type | Trust zone | Responsibility | Location |

## C. Data stores
| Element id | Store | Type | Data held | Sensitivity | Notes |

## D. External entities
| Element id | Entity | Relationship | Data exchanged | Sensitivity | Who controls it |

## E. Data flows and connections
| # | From -> To | Protocol | Sync | Data | Sensitivity | Credential | Evidence |

### Entry points
| Element id | Trigger | Auth as enforced (route, group, class, global, none) | Validation | Handler | Evidence |

Every recon candidate in scope is either a row here or listed under "Rejected candidates" with the reason (not reachable, dead code, test only, a client call).

## F. Authentication and authorization
| Location | Mechanism | AuthN / AuthZ | Evidence | Notes |

## G. Trust boundaries (outer to inner)
1. <name>: <one-line rationale>

## H. Conflicts reconciled
- <call you made where sources disagreed>. Ask the owner to sanity-check.

## I. Assumptions
1. <assumption> [OPEN | CONFIRMED | CORRECTED]

## J. Must confirm before diagrams
### Q1. <short title>
- In plain terms: <the question, no jargon>
- Why it matters: <what changes in the model>
- Current read: <what the code suggests, with file:line>
- Who to ask: <owner role>
- Answer: <owner fills in: CONFIRMED | CORRECTED | DELEGATED | OPEN | N/A>

## K. Resolution
| Q | Owner answer | Status | Effect on the model |
```

Use the element id formats from `references/stride-checklist.md` in sections B to D. The same ids become the nodes in `model.json`, and findings attach to them.

## Gate 1

Present sections A, G, H, I and J in the reply, not the whole file, and ask the owner to review and correct. Stop. When they answer, fold the answers into I, J and K, fix any table the answers correct, and record the gate:

```bash
node $SKILL_DIR/scripts/run-meta.mjs gate <run> --name inventory --outcome approved|corrected --note "<one line>"
```
