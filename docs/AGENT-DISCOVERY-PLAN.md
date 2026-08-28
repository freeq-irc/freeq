# Agent Discovery Plan — OpenAPI, MCP, Skills, llms.txt

**Branch:** `agent-discovery` · **Status:** planning · **Updated:** 2026-05-24

## Goal

Make freeq maximally discoverable and usable by AI agents through the four
surfaces agents actually look for in 2026:

1. **OpenAPI** — machine-readable REST contract at a well-known URL
2. **MCP** — a Model Context Protocol server (local stdio + remote HTTP)
3. **Agent skills** — SKILL.md packages for Claude Code / pi / codex ecosystems
4. **llms.txt** — curated markdown index at `freeq.at/llms.txt` and `irc.freeq.at/llms.txt`

All four cross-link each other so any single entry point leads to the rest.

## What already exists (leverage, don't rebuild)

| Asset | Where | Status |
|---|---|---|
| REST API (~42 endpoints) | `freeq-server/src/web.rs` `/api/v1/*` | live, documented only in `docs/api-reference.md` prose |
| Agent Assistance Interface | `/.well-known/agent.json` + `/agent/tools/*` | live discovery surface, custom format |
| MCP example (voice/AV bot) | `freeq-agent-kit/examples/claude-mcp/` | working but specialized, not a general freeq MCP |
| pi extension + skill | `freeq-pi/` (`@freeq/pi`), `freeq-pi/skills/freeq/SKILL.md` | published pattern to copy |
| TS SDK | `freeq-sdk-js/` (`@freeq/sdk`) | the natural base for the MCP server |
| Docs site | `freeq-site/` (Flask, freeq.at, renders repo `docs/*.md`) | natural home for llms.txt |
| API bearer bridge | `API-BEARER` NOTICE after SASL 903 | auth story for remote MCP / authed REST |

---

## Phase 1 — OpenAPI 3.1 spec (foundation; everything else references it)

**Deliverable:** `spec/openapi.yaml`, served at `https://irc.freeq.at/api/v1/openapi.json`
(and `.yaml`), linked from `agent.json` and llms.txt.

**Approach: hand-authored spec + CI drift test** (not utoipa codegen).
Rationale: `web.rs` is gamma-275 hotspot, 6k lines, handlers mostly return
`serde_json::json!` blobs — annotating for utoipa means typing ~42 handlers'
responses, a huge invasive diff. Instead:

1. Write `spec/openapi.yaml` covering all public `/api/v1/*` GET/POST routes
   (health, channels, history, search, messages, pins, topic, export, users,
   whois, upload, blob, media, og, keys, signing-keys, verify, actors,
   actions, tasks, agents/manifests, sessions, favorites, av token, model
   proxy). Include auth scheme (`bearer` — API-BEARER token or broker token),
   error envelope, and rate-limit notes.
2. Also describe `/agent/tools/*` + `/.well-known/agent.json` in the same spec
   (tagged `agent-assistance`) — one contract for everything HTTP.
3. Serve it: embed the YAML via `include_str!`, add routes
   `/api/v1/openapi.json` (transcode at startup) and `/api/v1/openapi.yaml`.
4. **Drift test** (the important part): a `#[test]` in `web.rs` tests module
   that walks the axum router's registered paths and asserts every
   `/api/v1/*` route appears in the spec and vice-versa (path-level, not
   schema-level). Spec can't silently rot.
5. Add `"openapi": "/api/v1/openapi.json"` to the `agent.json` discovery doc.
6. Optional nicety: serve Scalar/Swagger UI at `/api/docs` (single static
   HTML pointing at the spec).

Future (P3): migrate to utoipa if/when web.rs handlers get typed responses.

## Phase 2 — llms.txt (cheapest, highest visibility)

**Deliverables:**

1. **`freeq.at/llms.txt`** — Flask route in `freeq-site/app.py`. Generated
   from the same doc registry the site already uses: H1 = "freeq", blurb,
   then curated sections (Getting started, Protocol / ATPROTO-CHALLENGE,
   REST API, Agent surfaces: MCP + skills + agent.json + OpenAPI, SDKs,
   Bots). Each entry links to the **raw markdown** — add a `/docs/<slug>.md`
   route that serves the markdown source (llms.txt convention: agents want
   .md, not rendered HTML).
2. **`freeq.at/llms-full.txt`** — concatenated markdown of the curated set
   (bounded — curated docs only, not all 100+ files in docs/).
3. **`irc.freeq.at/llms.txt`** — small static route in `web.rs`: what this
   server is, links to `/api/v1/openapi.json`, `/.well-known/agent.json`,
   MCP endpoint, and freeq.at docs.
4. Repo-root `llms.txt` checked in (GitHub is itself an agent discovery
   surface) pointing at the hosted versions.

## Phase 3 — General-purpose MCP server

**Deliverable A: `@freeq/mcp` npm package** (new dir `freeq-mcp/`, TypeScript,
wraps `@freeq/sdk`, official `@modelcontextprotocol/sdk`, stdio transport).

One-line install for Claude Desktop / Claude Code / Cursor / etc:

```json
{ "mcpServers": { "freeq": { "command": "npx", "args": ["-y", "@freeq/mcp"] } } }
```

Tools (initial set, mirroring the pi extension's verbs + read surfaces):

| Tool | Backing |
|---|---|
| `freeq_connect` / `freeq_whoami` | SDK connect + SASL (did:key identity like freeq-pi, or guest) |
| `freeq_channels` | GET /api/v1/channels |
| `freeq_join`, `freeq_say`, `freeq_send` (DM) | SDK |
| `freeq_history`, `freeq_search` | CHATHISTORY / SEARCH via SDK, REST fallback |
| `freeq_ask` (ask a peer, wait for reply) | pattern from freeq-pi |
| `freeq_peers`, `freeq_whois` | NAMES/WHOIS + /api/v1/users |
| `freeq_pins`, `freeq_verify` | REST |
| `freeq_diagnose` | `/agent/tools/*` agent-assistance passthrough — differentiator |

Resources: `freeq://channel/<name>/history`, `freeq://server/health`.
Reuse identity/keystore code from `freeq-pi` (extract shared bits into
`@freeq/sdk` if needed rather than copy-paste).

**Deliverable B: remote MCP (Streamable HTTP) at `https://irc.freeq.at/mcp`**
— zero-install: agents add the URL directly. Implement in `web.rs` (or a new
`mcp.rs` module) speaking MCP Streamable HTTP, exposing the *read-only* subset
(channels, history, search, verify, diagnose) unauthenticated, and write tools
gated on bearer auth (API-BEARER or broker session). Ship after A; A validates
the tool surface. Advertise in `agent.json`, llms.txt, and the OpenAPI spec.

## Phase 4 — Agent skills (formalize + publish)

**Deliverable:** top-level `skills/` directory, each skill a folder with
`SKILL.md` (standard frontmatter: name, description) so it works in Claude
Code, pi, and anything else that consumes the emerging SKILL.md convention.

| Skill | Content | Source |
|---|---|---|
| `skills/freeq/` | talk to peers/humans over freeq — adapt from `freeq-pi/skills/freeq/SKILL.md`, but tool-agnostic (works via MCP tools or CLI) | exists, generalize |
| `skills/freeq-bots/` | build a freeq bot with `@freeq/bot-kit` / freeq-sdk: identity, SASL, signing, agent-assist loop | new, distill from `docs/BOT-QUICKSTART.md` + `docs/agent-assistance.md` |
| `skills/freeq-api/` | use the REST API + OpenAPI spec; auth bridging; search/history/verify recipes | new, distill from `docs/api-reference.md` |

Distribution: checked into repo (agents find via GitHub + llms.txt), bundled
in `@freeq/mcp` package, `freeq-pi` keeps its own copy (symlink/build step to
avoid divergence). Mention install paths in each README.

## Phase 5 — Tie-together + announce

- `agent.json` gains: `openapi`, `mcp` (remote URL + npm package), `skills`,
  `llms_txt` fields.
- README.md "For agents" section (top, short): llms.txt, OpenAPI, MCP
  one-liner, skills.
- `docs/api-reference.md` gets a banner pointing at the OpenAPI spec.
- freeq-site: add an `/agents` page section covering all four surfaces
  (template `agents.html` already exists).
- Deploy: server changes via `./deploy/deploy.sh`, site via freeq-site deploy.

## Order & effort

| Phase | Effort | Depends on |
|---|---|---|
| 1. OpenAPI + drift test | ~1 day (spec writing is the bulk) | — |
| 2. llms.txt (site + server + repo) | ~half day | 1 (links to spec) |
| 3a. `@freeq/mcp` stdio | ~1–2 days | — (parallel with 1–2) |
| 3b. remote MCP `/mcp` | ~1–2 days | 3a |
| 4. skills/ | ~half day | 3a (skills reference MCP tools) |
| 5. tie-together + deploy | ~half day | all |

## Testing

- OpenAPI: route-coverage drift test (Phase 1.4) + `openapi lint` (redocly or
  spectral) in CI.
- llms.txt: freeq-site pytest — routes exist, .md routes serve raw markdown,
  all llms.txt links resolve 200.
- MCP: vitest against a local server (same harness as sdk-js tests); MCP
  inspector smoke test documented.
- Remote MCP: acceptance tests alongside existing web.rs tests.

## Open questions (decide before Phase 3)

1. Remote MCP auth: reuse API-BEARER, or wire MCP's OAuth flow to the
   existing broker? (Start with bearer; OAuth later.)
2. Should `@freeq/mcp` default to guest auth (zero-config first run) with
   did:key upgrade prompt? (Proposed: yes.)
3. llms-full.txt curation list — which ~10 docs make the cut?
