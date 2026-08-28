# Agent Discovery Plan — OpenAPI, MCP, Skills, llms.txt

**Branch:** `agent-discovery` · **Status:** in progress · **Updated:** 2026-05-25

## Progress log

| Phase | Status | Notes |
|---|---|---|
| 1. OpenAPI spec + drift test | **done** | `spec/openapi.yaml` (82 paths, 3.1.0) served at `/api/v1/openapi.{json,yaml}`; 7 unit + 4 acceptance tests |
| 2. llms.txt | **done** | `/llms.txt` on server + freeq.at, `/llms-full.txt`, `/docs/<slug>.md` raw markdown, repo-root `llms.txt`; 11 pytest |
| 3a. `@freeq/mcp` stdio | **done** | `freeq-mcp/` — 17 tools, 3 resources, 87 vitest; verified against production over stdio |
| 3b. remote MCP `/mcp` | todo | the one phase left |
| 4. `skills/` | **done** | `skills/{freeq,freeq-api,freeq-bots}`; 6 pytest keep them valid |
| 5. tie-together | **done** | `agent.json` surfaces, README "For agents", `/agents` page, llms.txt entries. Deploy not run — needs a human. |

### Deviations from the original plan

- **YAML is canonical, JSON is derived at startup.** `serde_yaml_ng` added to
  `freeq-server` (no yaml crate existed in the tree) so the hand-authored
  `spec/openapi.yaml` can be `include_str!`'d and transcoded once into JSON
  behind a `OnceLock`. Authoring in JSON was rejected as unmaintainable by hand.
- **Drift test reads router *source*, not the live `Router`.** axum 0.8 exposes
  no route introspection, so the test `include_str!`s `web.rs`,
  `agent_assist/api.rs` and `policy/api.rs` and regex-extracts `.route("…")`
  literals. Same guarantee (paths can't silently rot), no reflection needed.
- **Scalar/Swagger UI at `/api/docs` not built.** The spec is for agents; a
  human-facing renderer is cosmetic and adds a vendored JS bundle. Revisit if
  asked.

### Phase 1 as built

- `spec/openapi.yaml` — hand-authored 3.1.0 contract covering all 82 router
  paths: `/api/v1/*`, `/agent*`, `/.well-known/agent.json`, policy endpoints
  (flagged as conditionally mounted), OAuth/broker, and the transport routes
  (`/irc`, `/av/*`). Shared `components` for the error envelope, bearer +
  broker-signature schemes, and the `limit`/`before`/`since` parameters.
- `freeq-server/src/openapi.rs` — `include_str!` the YAML, serve it verbatim,
  transcode to JSON once behind a `OnceLock`, and serve `/llms.txt`.
- `freeq-server/src/llms.txt` — the server-side index (what this host is,
  where the machine-readable surfaces are, how to read/verify conversations).
- `/.well-known/agent.json` gained a `surfaces` block cross-linking OpenAPI,
  llms.txt, `/irc`, and `@freeq/mcp` (`AgentSurfaces` in `agent_assist/types.rs`).
- Tests: 7 unit tests in `openapi.rs` (YAML/JSON validity, both drift
  directions, capability↔spec agreement, unique `operationId`s, a guard
  against the path extractor matching nothing) and 4 acceptance tests in
  `freeq-server/tests/agent_discovery.rs` (spec fetchable as JSON + YAML,
  llms.txt markdown, `agent.json` cross-links resolve, and every documented
  parameterless GET endpoint answers something other than 404).
- Drift test verified to fail on a deliberately unregistered probe route, so
  it is not vacuous. `cargo test --workspace` in CI covers it; no CI change
  needed.

### Phase 2 as built

- `freeq-site/app.py` gained a curated registry (`LLMS_SECTIONS`,
  `LLMS_SERVER_SURFACES`) and three routes: `/llms.txt` (generated index),
  `/llms-full.txt` (curated docs concatenated), and `/docs/<slug>.md` (raw
  markdown source — llms.txt links here, not at the rendered page).
- Section titles come from each doc's own H1, so the index can't drift from
  the docs' own naming.
- `_doc_path()` now falls back between the site's `docs/` copy and the repo's
  `docs/`. The copy is only refreshed by `deploy.sh`, so without the fallback
  a newly added doc looked broken locally and worked in production.
- Repo-root `llms.txt`: hand-written, points at the hosted indexes and the
  in-repo docs (GitHub is itself a discovery surface).
- Tests: 11 new pytest in `freeq-site/tests/test_llms_txt.py` — every curated
  slug resolves to a real doc, every on-site link in the generated index
  returns 200, the `.md` route serves source rather than HTML and doesn't
  shadow the rendered page, `llms-full.txt` stays bounded to the curated set,
  and the repo-root file's in-repo links exist.
- CI gained a `site` job running the freeq-site pytest suite; it had no CI
  coverage at all, which is how a curated index would have rotted silently.

### Phase 3a as built

`freeq-mcp/` (`@freeq/mcp`), stdio MCP server on `@modelcontextprotocol/sdk`,
wrapping `@freeq/sdk` for IRC and the REST API for reads.

- **17 tools.** Reads (`channels`, `history`, `search`, `message`, `verify`,
  `pins`, `topic`, `whois`, `diagnose`, `whoami`) need no connection — making
  an agent open a WebSocket to read a public channel is a tax. Writes
  (`connect`, `disconnect`, `join`, `say`, `ask`, `inbox`, `answer`) connect on
  demand.
- **Three resources**: `freeq://server/openapi.json`, `freeq://server/llms.txt`,
  `freeq://server/health` — the Phase 1/2 surfaces, reachable as context
  rather than as a decision to call something.
- **`freeq_verify` explains itself.** It distinguishes an author-signed message
  (non-repudiable) from a server-relayed one (proof of relay only). Returning
  `verified: true` alone invites exactly the over-claim freeq exists to prevent.
- **Two identity modes** (open question 2, resolved as proposed): with
  `FREEQ_OWNER_DID` set, a persistent bot-kit `did:key` identity plus a
  delegation certificate naming the owner; without it, a guest connection, and
  every write result says plainly that nothing is attributable.
- **`freeq_ask` is wire-compatible with `@freeq/pi`'s `ask`** — caller-minted
  request id on the `+freeq.at/event` channel, exactly one reply, replies from
  anyone but the peer asked are rejected. Answers carry an explicit
  untrusted-input caveat.
- **`freeq_inbox` exists because MCP calls are stateless and IRC is not.** A
  bounded per-target buffer (200 messages) holds what arrived between calls;
  without it "what did people say to me" could only ever return messages that
  landed during the call.
- **Errors are actionable.** REST failures are translated: 403 says invite-only
  or key-protected and to join over IRC, 503 says the server may run without
  persistence, 401 says where a bearer comes from.
- Tests: 87 vitest — config/env parsing, REST URL construction and error
  translation, the session state machine (ask contract, buffer bounds,
  reconnect/teardown), and the MCP surface itself driven by a real MCP client
  over an in-memory transport (tool list, schemas, required args, read-only
  refusals, resources).
- CI gained an `mcp` job: install, build, test, plus a smoke step that imports
  the built entry point as plain ESM.

### Phases 4 & 5 as built

- `skills/freeq` — the pi skill generalized: a capability table mapping each
  action to MCP tools, the pi extension, or raw HTTP, so it is useful whatever
  the host provides. Keeps the untrusted-input and never-send rules verbatim,
  and adds the attribution section (verify before you quote; guest mode means
  nothing you send is attributable).
- `skills/freeq-api` — REST recipes, the `%23` gotcha, what 403/503 actually
  mean, how to read a verify result, and where a bearer token comes from.
- `skills/freeq-bots` — shortest working bot, the two-DIDs distinction
  (agent key vs owner) that causes most bad bot designs, channel etiquette,
  and "ask the server" rather than guessing.
- Kept in the repo rather than copied into `@freeq/mcp`. The plan floated
  bundling them in the npm package; a physical copy is exactly the divergence
  the plan itself warned about, and MCP clients read SKILL.md from a checkout,
  not from `node_modules`. `freeq-pi` keeps its own pi-specific copy, which is
  a different document (it speaks in `freeq({action:…})` calls), not a stale
  duplicate.
- 6 pytest in `freeq-site/tests/test_skills.py`: frontmatter parses, `name`
  matches the directory, the description is long enough to route on and says
  when to use the skill, cross-references resolve, and every
  `freeq.at/docs/<slug>.md` link names a mapped doc. They live in the site
  suite because it is the only CI pytest that sees the repo root — and a
  malformed SKILL.md fails *silently* in every consumer, which is the worst
  kind of broken.
- Tie-together: `/.well-known/agent.json` `surfaces` now includes `skills`;
  README gained a "For agents" section; the site's `/agents` page gained a
  "Four ways in" table; both llms.txt files list the skills.
- **Not done: deploy.** `./deploy/deploy.sh` (server) and `freeq-site/deploy.sh`
  (site, needs `MIREN_CLUSTER`) are human-run. `@freeq/mcp` is unpublished —
  `npm publish` needs credentials.

**Bug found and fixed along the way:** `@freeq/sdk`'s
`import spec from './identity-claims.json'` had no `with { type: 'json' }`.
Bundlers tolerate that; Node's ESM loader has required the attribute since v22,
so *any* consumer running the SDK as plain ESM died at import time with
`ERR_IMPORT_ATTRIBUTE_MISSING`. Fixed in the SDK (and its `module` set to
`esnext` so TypeScript will emit the attribute); all 465 SDK and 366 bot-kit
tests still pass.

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
