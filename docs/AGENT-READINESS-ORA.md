# Agent readiness (ora.ai audit) — two hosts, one entity

**Baseline, scanned 2026-08-29:** `irc.freeq.at` **33/100 (D)** ·
`freeq.at` **30/100 (D)**. Re-check at `https://ora.ai/score/<domain>`.

## The question this document answers first

**Does this need to work on both `freeq.at` and `irc.freeq.at`? Yes — but they
are not the same job.** ora scores them as two separate domains, and an agent
that lands on one has no way to know the other exists unless we say so.

| | `freeq.at` (Flask, `freeq-site/`, Miren) | `irc.freeq.at` (Rust `freeq-server` + React SPA) |
|---|---|---|
| role | the **entity**: what freeq is, who it's for, docs, blog | the **product**: live API, IRC/WS transport, app UI |
| agents arrive asking | "what is freeq, should I use it" | "how do I call it, how do I authenticate" |
| owns | llms.txt index, JSON-LD identity, docs as markdown, trust anchors | OpenAPI, MCP, auth metadata, agent.json, live endpoints |
| both must serve | robots.txt, sitemap.xml, real 404s, `.md` negotiation, `Link` headers, `/.well-known/{ard,agent-card,api-catalog}` | same, with values pointing at the *right* host |

Rules that follow from that split:

1. **One source of truth, two renderings.** Identity facts (name, description,
   repo, surfaces) live in one place per codebase and are rendered into every
   `.well-known` document, not retyped. The two hosts already drifted once —
   `freeq.at` is running an Aug-18 deploy and 404s the `/llms.txt` that has
   been in `main` since Aug 29.
2. **Cross-link, don't duplicate.** Each host's JSON-LD `sameAs` names the
   other host, the GitHub org, and the npm scope, so agents resolve one entity
   instead of two D-grade strangers. Only `irc.freeq.at` claims the API;
   `freeq.at` *points at it* (RFC 9727 api-catalog, `Link: rel=service-desc`).
3. **Never advertise what isn't there.** Same rule that kept `@freeq/mcp`
   marked `mcp_published: false`. A dead `.well-known` URL scores worse than
   an absent one: ora graded four of ours "exists but is not valid JSON"
   because the SPA answered `200 text/html` for paths that don't exist.

## Root cause of the `irc.freeq.at` score: soft-404s

Every unknown path returns the 983-byte SPA shell with `200 text/html`:

```
/robots.txt   200 text/html    /.well-known/ard.json  200 text/html
/sitemap.xml  200 text/html    /.well-known/mcp       200 text/html
/openapi.json 200 text/html    /nonexistent-xyz       200 text/html
```

So the audit scored `ard.json`, `ai-catalog.json`, `api-catalog` and the Web
Bot Auth directory as **malformed** rather than absent, and missed an OpenAPI
spec that is live one path over at `/api/v1/openapi.json`. Fixing the fallback
is worth more than any single feature below.

## Gap list

Points are ora's own maxima. `[S]` = freeq.at (site), `[R]` = irc.freeq.at
(rust server / SPA), `[H]` = needs a human (account, publish, deploy).

### Tier 1 — structural, cheap, no new subsystems (~+40 across both hosts)

| # | Gap | Where | Pts |
|---|---|---|---|
| T1.1 | Unknown paths return a real `404` with a short markdown body (sitemap/llms.txt/docs pointers), not the SPA shell | R (+ S body) | 2+2 |
| T1.2 | `robots.txt` with explicit AI-crawler directives and a `Sitemap:` line | S, R | 2+2 |
| T1.3 | `sitemap.xml` with `lastmod` | S, R | 3+3 |
| T1.4 | JSON-LD on the homepage: `Organization` + `SoftwareApplication` + `WebSite`, with `sameAs` cross-links | S, R | 10+10 |
| T1.5 | `canonical`, `og:type`, `og:image` on every page | S, R | 1+1 |
| T1.6 | Trust anchors: `/contact/`, `/privacy/` (About exists) | S | 2 |
| T1.7 | `/.well-known/ard.json` + `/.well-known/ai-catalog.json`, valid JSON, with a trust manifest block | S, R | 4+4 |
| T1.8 | `/.well-known/agent-card.json` (A2A) | S, R | 2+2 |
| T1.9 | `/.well-known/api-catalog` (RFC 9727) → the OpenAPI spec on `irc.freeq.at` | S, R | 2+2 |
| T1.10 | `/agents.md` + `/AGENTS.md` served: when-to-use guidance for agents | S, R | 3+2 |
| T1.11 | `/auth.md` (WorkOS draft): guest `did:key`, ATPROTO-CHALLENGE SASL, API-BEARER | S, R | 4+4 |
| T1.12 | `/.well-known/oauth-protected-resource` (RFC 9728) + `WWW-Authenticate: Bearer resource_metadata=…` on 401 | R | 6 |
| T1.13 | `HTTP Link` headers (RFC 8288): `canonical`, `alternate` (markdown), `service-desc`, `describedby` | S, R | 1+1 |
| T1.14 | Markdown surface: `/index.md`, `.md` suffix on pages, `Accept: text/markdown` + `Vary: Accept`, `<link rel=alternate type=text/markdown>`, markdown to bot UAs | S, R | 6+6 |
| T1.15 | `/.well-known/http-message-signatures-directory` as valid JSON (Web Bot Auth) | R | 1 |
| T1.16 | `/openapi.json` alias at site root (the spec lives at `/api/v1/openapi.json`) | R | 7 |
| T1.17 | Homepage text visible without JS (SPA ships 5 chars of crawlable text) | R | 3 |
| T1.18 | `?mode=agent` view; per-area `llms.txt` (`/docs/llms.txt`, `/sdk/llms.txt`) | S | 3 |

### Tier 2 — real subsystems (~+25)

| # | Gap | Where | Pts |
|---|---|---|---|
| T2.1 | **Remote MCP at `https://irc.freeq.at/mcp`** (Streamable HTTP) — Phase 3b of `AGENT-DISCOVERY-PLAN.md`. Unlocks 9 dead MCP checks: manifest, tool listing/naming/descriptions, schemas, auth, transport, resources | R | ~15 |
| T2.2 | `/.well-known/mcp` + `/.well-known/mcp/server-card.json` | S, R | 2 |
| T2.3 | **WebMCP** (`navigator.modelContext`) in `freeq-app` so an agent can drive the web client | R | 5 |
| T2.4 | Developer portal page (rendered API reference at `/api/docs`, linked from both homepages) | S, R | 6 |
| T2.5 | Sandbox / test environment documented and reachable | S | 2 |

### Tier 3 — human, external, or deliberately skipped

| # | Item | Note |
|---|---|---|
| T3.1 | **Deploy both hosts.** `freeq.at` is 12 days stale (`664acfd`); nothing below scores until `./deploy/deploy.sh` and `freeq-site/deploy.sh` run | [H] |
| T3.2 | Publish `@freeq/sdk`, `@freeq/bot-kit`, `@freeq/mcp` to npm; then flip `mcp_published` | [H] +4 |
| T3.3 | Wikipedia article + Wikidata item (`P856` = freeq.at) | [H] +4 |
| T3.4 | Self-publish `skills/` on skills.sh; list MCP server in registries | [H] +3 |
| T3.5 | ChatGPT app directory listing | [H] +2 |
| T3.6 | Payments (MPP/x402/UCP/ACP/AP2) | skip — not commerce |
| T3.7 | MCP Apps UI / A2UI generative UI | skip for now — 12 pts, large surface, low return until T2.1 exists |

## The welcome mat (adjacent, not from the audit)

`https://welcome-mat.info` specifies agent self-signup: a service publishes
`/.well-known/welcome.md`, an agent generates a keypair, signs the terms, and
enrols with no human in the loop. Adoption is near zero — 6 stars, one demo
deployment, and none of the eight agent-forward domains probed serve the file
— but the *shape* is what freeq already does, and the spec explicitly permits
services whose ongoing protocol is not HTTP to enrol over HTTP and issue
protocol-native credentials.

Shipped: `agent-docs/welcome.md` and `agent-docs/tos.txt`, served from both
hosts. The document is welcome-mat **shaped**, not conformant, and says so in
its own `deviations` section — freeq proves possession with a SASL challenge
per connection, not a DPoP proof per request, and has no `POST /api/signup`.
Publishing a conformant-looking file that 404s on signup would be the exact
failure this plan exists to avoid.

**Worth adopting later, independent of the protocol's fate:** signed ToS
consent bound into the credential (`tos_hash`), with a change of terms
invalidating existing consent. freeq currently mints tokens with no record
that anyone agreed to anything, which is a strange gap for a project whose
thesis is non-repudiable speech. Consent as a signature, not a checkbox.

## Verification

Both hosts, after deploy:

```
./scripts/agent-readiness.sh https://freeq.at
./scripts/agent-readiness.sh https://irc.freeq.at
```

The script asserts status code, content type and JSON validity for every path
this document promises — the check ora actually performs. A path that returns
`200 text/html` when JSON was promised is a failure, not a pass.
