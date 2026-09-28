# STRIDE checklist

Written for API backends, BFFs and serverless workloads, with AWS terms where a check is AWS-specific. The ideas carry to any stack.

Each check has a stable ID. A finding's fingerprint is `<checkId>:<element>`. Stable fingerprints let later runs report new, fixed and persisting findings. Use `X-OTHER` for a threat no check covers, and propose a new check in the report.

## Element ids

| Element | Id format | Example |
|---|---|---|
| Caller or person | `actor:<name>` | `actor:customer-browser`, `actor:payment-provider` |
| HTTP route or operation | `route:<METHOD> <path>` | `route:GET /api/books/{id}` |
| Service, app or container | `service:<name>` | `service:library-api` |
| Function or handler | `fn:<name>` (AWS Lambda: `lambda:<name>`) | `fn:BuyTicket`, `lambda:order-api` |
| Gateway, edge worker or reverse proxy | `gateway:<name>` | `gateway:edge-worker`, `gateway:nginx` |
| Middleware or authorizer | `middleware:<name>` or `authorizer:<name>` | `middleware:requireAuth`, `authorizer:session` |
| WebSocket route | `ws:<route>` | `ws:$connect` |
| gRPC method | `grpc:<Service>/<Method>` | `grpc:Tickets/Reserve` |
| GraphQL operation | `gql:<Query or Mutation>.<field>` | `gql:Mutation.cancelLoan` |
| Queue or topic | `queue:<name>` | `queue:loyalty-change-events` |
| Schedule or background job | `schedule:<name>` or `job:<name>` | `schedule:delete-expired-accounts` |
| Event rule, pipe or bus | `rule:<name>` | `rule:order-created` |
| Webhook or callback | `webhook:<partner>:<path>` | `webhook:payments:/payments/notifications` |
| Data store | `store:<kind>:<name>` | `store:postgres:library`, `store:kv:SESSIONS` |
| External system | `ext:<name>` | `ext:commerce-platform` |
| Edge or config setting | `edge:<name>` or `stack:<name>` | `edge:waf`, `stack:shop-api` |
| Shared code | `shared:<file or package>` | `shared:lib/auth-middleware.ts` |

These ids are also the node ids in `model.json`, so every finding lands on the right diagram element.

The general sections (S, T, R, I, D, E) apply to every target. The entry-point sections at the end add checks for specific kinds. OWASP API Security Top 10 2023 tags are in brackets.

## S: Spoofing (authentication)

| ID | Check |
|---|---|
| S-ROUTE-PUBLIC | Every route with no authorizer and no API key: is public access intended, and does it read or change user-specific data? [API2] |
| S-AUTHZ-CACHE | Authorizer identity source (cache key) equals the credential the authorizer actually validates. If not, cached results can leak across callers for the TTL. [API2] |
| S-AUTHZ-POLICY | Authorizer policy resource is scoped to the method ARN, or cached policies are safe to reuse across routes. [API5] |
| S-TOKEN | Session and refresh tokens: generation entropy, storage, cookie flags (HttpOnly, Secure, SameSite, Domain), rotation, revocation, expiry checks. [API2] |
| S-APIKEY | API-key-only routes: is the key embedded in a public web or app bundle? API keys identify clients, not users. [API2] |
| S-WEBHOOK | Inbound webhooks and callbacks (payment providers, wallet passes, partner callbacks): signature or HMAC verified, replay protection, constant-time compare. [API2] |
| S-WAF-BYPASS | WAF allow rules on spoofable inputs (User-Agent, headers, path prefixes) that skip rate limits or managed rules. |
| S-IDP | Identity provider (Cognito, Auth0, Entra ID, Keycloak, ...): which pool, group, role or claim checks happen in handlers, and whether any authenticated staff member can call every admin route. [API5] |

## T: Tampering (integrity)

| ID | Check |
|---|---|
| T-VALIDATION | POST/PUT/PATCH without a request model, or models without `required`, `additionalProperties: false`, length and format limits. [API3, API8] |
| T-MASS-ASSIGN | Handler spreads the request body into database, commerce-platform or partner updates, so a caller can set fields they should not (price, customer id, status). [API3] |
| T-INJECTION | User input reaching queries (SQL, DynamoDB expressions, NoSQL filters, search or commerce-platform query predicates), shell, templates, or URLs (SSRF). [API7, API10] |
| T-BUSINESS | Business-flow integrity: cart and price recalculation server-side, voucher and loyalty point double-spend, idempotency on order and payment actions. [API6] |
| T-QUEUE | Messages from SQS, EventBridge or streams are trusted without validation, or can be injected by a public route. |
| T-SUPPLY | Third-party code pulled at build time (Docker images, git clones, unpinned deps), lockfile integrity. |

## R: Repudiation (auditability)

| ID | Check |
|---|---|
| R-AUDIT | Security-relevant actions (login, account change, deletion, on-behalf actions, admin actions, point bookings) produce a log line with actor, target and outcome. |
| R-ACCESS-LOG | API Gateway access logging enabled and retained. Execution logging at ERROR or OFF alone is not an audit trail. |
| R-ONBEHALF | Actions taken by employees on behalf of customers record the employee identity, not only the customer. |

## I: Information disclosure

| ID | Check |
|---|---|
| I-BOLA | Object-level authorization: every handler that takes an id (order, address, cart, wishlist, contact) checks ownership against the authorizer context. [API1] |
| I-EXPOSURE | Responses return whole upstream objects (customer, order, user record) instead of a projection. [API3] |
| I-LOGGING | Tokens, cookies, PII or payment data in logs, error messages, or APM payload capture (for example Datadog `captureLambdaPayload`). |
| I-SECRETS | Secrets in plaintext Lambda env vars, CloudFormation, repo `.env` files, or frontend bundles. |
| I-ERRORS | Upstream error bodies or stack traces returned to the client. |
| I-CORS | CORS: wildcard or reflected origins combined with `allowCredentials: true`. |
| I-ENUM | User or resource enumeration through differing responses (register, login, newsletter, back-in-stock). |

## D: Denial of service and cost

| ID | Check |
|---|---|
| D-RATE | Per-IP and per-user rate limits on expensive or abusable routes (auth, voucher, support mail, AI/Bedrock, recommendation). [API4] |
| D-RESOURCE | Unbounded page sizes, payload sizes, fan-out calls to partners, missing timeouts, Lambda concurrency limits. [API4] |
| D-COST | Routes that trigger paid services (Bedrock, translate, SES, SMS) callable anonymously. [API4, API6] |
| D-AMPLIFY | Public routes that trigger emails or messages to arbitrary recipients (mail bombing, spam relay). [API6] |

## E: Elevation of privilege

| ID | Check |
|---|---|
| E-BFLA | Function-level authorization: routes for employees, on-behalf flows or admin actions reachable with a customer session. [API5] |
| E-IAM | Lambda role permissions far beyond what the handler needs (shared role, managed FullAccess policies, wildcard resources). |
| E-ONBEHALF | How employee or on-behalf context is established, and whether a customer can set it. |
| E-RESOURCE-POLICY | API resource policy and authorizer policies that allow broader invoke than intended. |
| E-SSRF-META | Any path from user input to outbound requests that could reach internal endpoints or cloud metadata. [API7] |

## Entry-point specific checks

### Framework defaults (any language)

| ID | Check |
|---|---|
| FW-DEFAULT-DENY | Is auth deny-by-default? A fallback policy (ASP.NET `FallbackPolicy`), global middleware, or a guard on the router root, so a new route is protected without anyone remembering to add it. Otherwise list every route that relies on a per-route marker. |
| FW-OVERRIDE | Anonymous overrides (`[AllowAnonymous]`, `permitAll()`, `@Public()`, `.AllowAnonymous()`) on routes that touch user data, or placed on a whole class. |
| FW-ORDER | Middleware order: authentication before authorization before the handler; CORS, rate limiting and body limits before expensive work; error handling that does not skip auth. |
| FW-GROUPS | Routes registered on the parent router or app miss the middleware of a group or sub-router (Go chi, gin, echo; Express routers; ASP.NET `MapGroup`). |
| FW-BINDING | Model binding or body parsing maps every field onto domain objects (over-posting, mass assignment). |
| FW-DEBUG | Debug and admin surfaces reachable in production: Swagger UI, GraphiQL, pprof, actuator, developer exception pages, verbose errors. |
| FW-LIMITS | Server timeouts, body size limits and concurrency limits are set (Go `http.Server` timeouts, Kestrel limits, Node body parser limits). |

### Gateways, edge workers and reverse proxies

| ID | Check |
|---|---|
| GW-AUTH | Auth is enforced at the gateway for every route, including the default or fallback branch of the router, and the upstream re-checks what it must not delegate. |
| GW-NORMALIZE | Paths are normalised the same way before the auth decision and before forwarding (encoded slashes, `..`, double slashes, case, trailing dots), so a path cannot pass auth as one route and reach the upstream as another. |
| GW-HEADERS | Client-supplied identity headers (`X-User-Id`, `X-Forwarded-*`, `X-Original-URL`, `Cf-*`) are stripped before the gateway sets its own, and the upstream trusts them only from the gateway. |
| GW-UPSTREAM | Upstream targets come from config or an allowlist, never from the request (host, path prefix or URL parameters), so the gateway cannot be turned into an open proxy or SSRF. |
| GW-ORIGIN | The origin is reachable only through the gateway: mTLS, a secret header, IP allowlist, or a private network. Check alternative public entry points too (a `workers.dev` URL, direct DNS records, default cloud endpoints). |
| GW-CACHE | Authenticated or personalised responses are not cached at the edge, or the cache key includes the identity. |
| GW-BINDINGS | Internal bindings or service-to-service calls (Cloudflare service bindings, internal DNS) skip public auth; check the callee still validates who is calling and for which user. |
| GW-SECRETS | Secrets live in the platform's secret store, not in plain config vars or the bundle. |

### Workers: queues, streams, event rules, schedules

| ID | Check |
|---|---|
| W-TRUST-INPUT | Message or event fields are used without validation. Who can write to the queue, bus or table stream, including public routes that enqueue directly? |
| W-POISON | Poison messages: retries, DLQ configured and monitored, partial batch failure handling, no infinite retry loops that duplicate side effects. |
| W-IDEMPOTENCY | Duplicate delivery (at-least-once) cannot double-apply payments, points, emails or partner updates. |
| W-ORDERING | Out-of-order events cannot overwrite newer data with older data. |
| W-SCHEDULE-SCOPE | Scheduled jobs that delete, export or bulk-update data: bounded scope, dry-run or safety limits, and who can change the schedule input. |
| W-FANOUT | One event triggering unbounded partner calls or emails. |

### Webhooks and callbacks

| ID | Check |
|---|---|
| H-AUTH | Caller authentication: signature or HMAC over the raw body, Basic auth, or mTLS, with constant-time compare and per-environment secrets. |
| H-REPLAY | Timestamp or nonce checks, and duplicate event ids rejected. |
| H-SOURCE | Trusting the payload vs re-fetching state from the partner API before acting on it. |
| H-WAF | Webhook paths exempted from WAF or rate limits, and whether that exemption is narrower than needed. |

### Data stores

| ID | Check |
|---|---|
| DS-ACCESS | Which roles can read or write the store. With a shared Lambda role, every lambda can. |
| DS-PII | PII or secrets stored, retention and TTL, encryption, and backups or point-in-time recovery for data that matters. |
| DS-PUBLIC | S3 buckets or objects reachable publicly or through presigned URLs with long expiry. |

### Edge: CloudFront and Lambda@Edge

| ID | Check |
|---|---|
| EDGE-ORIGIN | Origins reachable directly, bypassing CloudFront and WAF. |
| EDGE-HEADERS | Security headers, cache keys that include auth headers or cookies, and cache poisoning through unkeyed headers. |

### BFFs (backends for frontends)

| ID | Check |
|---|---|
| BFF-TOKENS | Upstream access and refresh tokens stay on the server. The browser holds only an HttpOnly session cookie, never a bearer token it could leak through XSS. |
| BFF-CSRF | Cookie-authenticated state-changing routes have CSRF protection: SameSite plus an origin or custom-header check, or a token. |
| BFF-DEPUTY | Confused deputy: the BFF calls backends with its own service credential. Every call must carry or enforce the end user's identity and scope, so a user cannot reach another user's data through the BFF. |
| BFF-PASSTHROUGH | Proxy or pass-through routes forward to an allowlist of upstream paths and methods, not to any path the client names. |
| BFF-HEADERS | Host, X-Forwarded-*, X-Original-URL and similar headers are not trusted for routing, redirects, links in emails, or auth decisions. |
| BFF-REDIRECT | Redirect and return-URL parameters are checked against an allowlist (open redirect, token leakage through Referer). |
| BFF-CACHE | CDN and server caches never serve one user's personalised response to another: cache keys include the session, or personalised routes are not cached. |
| BFF-SSR | Server-side rendering does not embed secrets, other users' data or internal errors in the page or its hydration state. |
| BFF-AGGREGATE | Aggregated responses from several upstreams are filtered to what the caller may see, and upstream errors are not passed through verbatim. |

### OAuth, OIDC and JWT

| ID | Check |
|---|---|
| OA-REDIRECT | `redirect_uri` is matched exactly against a registered list; `state` and PKCE are used and verified. |
| OA-JWT | JWT verification pins the algorithm (no `none`, no HS/RS confusion), validates `iss`, `aud`, `exp` and `nbf`, and resolves `kid` only from the trusted JWKS. |
| OA-SCOPE | Scopes and roles in the token are enforced per route, not only "token is valid". |
| OA-REVOKE | Logout and password change revoke refresh tokens and sessions; long-lived tokens have a revocation path. |
| OA-CLIENT | Client secrets never ship in public clients (SPA, mobile); public clients use PKCE. |

### GraphQL and AppSync

| ID | Check |
|---|---|
| GQL-AUTHZ | Auth mode per type and field, and resolver-level ownership checks. Field-level auth on sensitive fields. |
| GQL-DEPTH | Query depth, complexity, alias and batching limits; introspection and field suggestions off in production. |
| GQL-BATCH | Batched queries or aliases cannot bypass rate limits on login, OTP or voucher mutations. |

### WebSockets and streaming

| ID | Check |
|---|---|
| WS-AUTH | The connection is authenticated at `$connect`, and every message route re-checks that the connection may act on the target resource. |
| WS-ORIGIN | Origin is checked on the upgrade (cross-site WebSocket hijacking with cookie auth). |
| WS-FANOUT | Broadcast and subscription filters cannot deliver one user's events to another. |

### LLM and AI features

| ID | Check |
|---|---|
| AI-INJECTION | User or third-party content in prompts (direct and indirect prompt injection) cannot change instructions, reveal system prompts, or trigger tools. [OWASP LLM01] |
| AI-OUTPUT | Model output is treated as untrusted: escaped before rendering, never executed, never used unchecked in queries, URLs or tool arguments. [OWASP LLM05] |
| AI-TOOLS | Tools and agents the model can call run with the end user's permissions, not a service's, with allowlisted actions. [OWASP LLM06] |
| AI-DATA | Retrieval (RAG) returns only documents the caller may read; no PII or secrets in prompts sent to third-party models without a basis. [OWASP LLM02] |
| AI-COST | Per-user limits on tokens and requests. [OWASP LLM10] |

## Scoring

- **Likelihood**: high = exploitable anonymously or with a normal customer account using only a browser. medium = needs a specific precondition (leaked id, timing, insider). low = needs privileged access or an unlikely chain.
- **Impact**: high = other customers' PII, payment or order integrity, account takeover, admin control, significant cost. medium = limited data or single-user impact. low = hardening or defense in depth.
- **Severity** from likelihood x impact: high x high = critical. high x medium or medium x high = high. medium x medium, high x low or low x high = medium. Everything else = low. Use `info` for observations with no direct risk.
- **Considered and mitigated**: when a check applies and a control you read covers it (parameterised query, ownership check, signature verification), record it as `status: mitigated` with the control as evidence. Keep this to cases a reviewer would otherwise ask about.
- **Residual risk**: for every open finding, say what risk remains with the controls in place today, for example "High until the cache key includes Cookie", or "Owner decision" when only a human can rule.
- **Confidence**: confirmed = you traced the full path in code, or a test proves it. likely = the code strongly suggests it but a runtime detail (AWS behavior, config value) is unverified. needs-verification = plausible, must be checked by a human.
