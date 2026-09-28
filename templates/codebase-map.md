# Codebase map: where security decisions live

Copy to `<your repo>/.trust-issues/codebase-map.md`. trust-issues reads it at the start of every run, so a run starts from what you already know instead of rediscovering it. Keep it short and factual. It is project knowledge, so it lives in your repo, never in the skill.

## Shared infrastructure (read first, applies to every target)

| Concern | Where | What to look for |
|---|---|---|
| API creation | `infra/lib/constructs/api.ts` | CORS defaults, resource policy, logging, default authorizer, request validation |
| Function defaults | `infra/lib/constructs/function.ts` | Default role and its permissions, environment variables, timeouts |
| Secrets | `infra/lib/config.ts` | Where secrets come from and how they reach the runtime |
| Edge | `infra/lib/edge-stack.ts` | WAF rules, rate limits, rules that skip other rules |
| Observability | | Whether request or response bodies are shipped to logs or APM |

## Code conventions

- How handlers read identity (for example `event.requestContext.authorizer.*`), and which fields are trusted.
- Where request validation happens (API schema, a validation library, by hand).
- How errors are mapped to responses, and whether upstream error bodies can leak.
- Which clients wrap outbound calls, with their timeouts and credentials.

## Non-API entry points

| Trigger | Where | What to look for |
|---|---|---|
| Queues | | Who can send, DLQ, batch failure handling |
| Schedules | | What the job deletes or exports |
| Events | | Patterns loose enough to match other sources |

## Hotspots to verify on every run

Hypotheses worth checking with evidence each time, not findings. Remove one when a run confirms it is fixed.

1.
