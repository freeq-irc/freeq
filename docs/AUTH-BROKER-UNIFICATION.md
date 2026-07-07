# Auth Broker Unification

The AT Protocol OAuth flow lives in one place and is shared by everything that
needs it, and a single broker implementation runs either as a standalone
service or mounted in-process inside `freeq-server`.

## Why

The OAuth protocol machinery (handle→DID→PDS resolution, auth-server discovery,
PAR with the DPoP-nonce dance, code exchange, refresh) was implemented three
times — in the standalone broker, in the server's own auth endpoints, and in
the SDK's CLI login. The standalone broker and the server's embedded auth had
also diverged in behavior. This unifies the protocol into one engine and lets
the broker run in both deployment shapes from one codebase. The survey below
records the divergent state this replaces.

---

## Survey: the state before unification

### Three copies of the AT Proto OAuth engine

Three independent implementations of the same protocol machinery (handle→DID→PDS
resolution, auth-server discovery, PAR with the DPoP-nonce retry dance, code
exchange, PKCE, client_id/metadata construction):

| # | Location | DPoP key | DID resolution | SSRF guard | Refresh tokens |
|---|----------|----------|----------------|------------|----------------|
| 1 | `freeq-auth-broker` | own p256 impl | own (well-known + bsky API) | **weak** — private-IP check on `did:web` only; PDS/auth-server/token/PAR URLs unguarded | **yes** — SQLite, AES-GCM-encrypted at rest, per-token refresh locks, `invalid_grant` classification |
| 2 | `freeq-server/src/web.rs` | `freeq_sdk::oauth::DpopKey` | configured `state.did_resolver` | **strong** — DNS-pinned clients, generic errors, CTF regression tests | **none** — in-memory sessions only, die on restart |
| 3 | `freeq-sdk/src/oauth.rs` (loopback CLI) | canonical `DpopKey` | `DidResolver` | n/a (client-side) | none |

### Endpoint namespaces (not the same surface)

- **Standalone broker:** `/health`, `/client-metadata.json`, `/auth/login`,
  `/auth/callback`, `POST /session`, `POST /api/graph/{follow,unfollow}`. Pushes
  results into the server via HMAC-signed `POST /auth/broker/{web-token,session}`.
- **Embedded server:** `/auth/login`, `/auth/callback`, `/auth/step-up`,
  `/auth/mobile`, `/client-metadata.json`, plus the broker-push receivers
  (`403` unless `BROKER_SHARED_SECRET` set). **No `/session`, no `/health`, no
  `/api/graph/*`.**

### Feature matrix — each side had things the other lacked

| Capability | Standalone | Embedded |
|---|---|---|
| `/session` refresh (broker_token → fresh web-token) | ✅ | ❌ (web-token expiry ⇒ full re-OAuth) |
| `invalid_grant` vs transient classification (401 vs 502) | ✅ | n/a |
| Single-use refresh-token rotation, serialized | ✅ | n/a |
| Encrypted-at-rest refresh tokens + DPoP keys | ✅ | n/a |
| Graph delegation (`/api/graph/*`, used by iOS) | ✅ | ❌ |
| Step-up OAuth purposes (BlobUpload, BlueskyPost) | ❌ | ✅ |
| IRC `/login` completion (`irc_state`) | ❌ | ✅ |
| SSRF-hardened OAuth chain (DNS pinning) | ❌ | ✅ |
| `return_to` allowlist + popup handling | ✅ | ❌ (`return_to` not a parameter) |
| `broker_token` issued to clients | ✅ | ❌ (mobile redirect omitted it) |

### Deployment topologies

- **irc.freeq.at:** standalone broker at `auth.freeq.at` does login + refresh —
  but the embedded code was still live there too (`/auth/step-up`, `/auth/mobile`,
  the broker-push receivers), so the two implementations were entangled in prod,
  not alternatives.
- **irc.zerosum.org:** no broker process; clients drive the server's `/auth/login`
  directly, `BROKER_SHARED_SECRET` unset.
- **No mode discovery:** nothing advertises which mode a server runs; clients
  hardcode it per build, except the web client, which uses a host heuristic.

### Embedded-mode gaps clients papered over

- The web client skipped `/session` and deleted any stored broker token whenever
  broker origin == web origin, so embedded users had no durable re-auth.
- Native clients called `/session` unconditionally but never received a
  `broker_token` in embedded deployments (the mobile redirect omitted it), so
  refresh silently never happened.
- iOS Bluesky follow/unfollow targets `/api/graph/*`, which only the standalone
  broker served — dead against embedded deployments.

### Known divergence bugs

- `return_to` validation existed only on the broker; a stale client `brokerBase`
  hitting the wrong implementation caused the zerosum "invalid return_to url"
  incident.
- The broker's OAuth result HTML had broken JS, which spawned the server's
  `/auth/mobile` workaround page — a divergence creating a workaround for a
  divergence.
- Security posture was asymmetric: the broker missed the server's SSRF hardening,
  and the server missed the broker's refresh-token hygiene.
- Broker allowlists (CORS origins, `return_to`) were hardcoded — self-hosters
  had to edit source and rebuild.
- Open redirect: `is_valid_return_to` prefix-matched, so
  `https://irc.freeq.at.evil.example` passed the allowlist and the token-bearing
  `#oauth=` fragment could be redirected to an attacker origin (residual
  SECURITY-AUDIT C-6).

### Wire contracts that must not break

Both deployments are live, so anything shipped must be additive against:

1. `#oauth={base64url json}` fragment: `token`, `broker_token`, `nick`, `did`,
   `handle`, `pds_url`.
2. `freeq://auth?token&broker_token&nick&did&handle` as an HTTP **302**
   (ASWebAuthenticationSession requirement).
3. `POST /session` `{broker_token}` → `{token, nick, did, handle}`; 401 = dead
   session (client drops token), 502 = transient (client retries).
4. Broker-push HMAC: `X-Broker-Signature` = HMAC-SHA256 over
   `ts={X-Broker-Timestamp}\n || body`, 60s window; `BrokerSessionRequest`
   evolves additively.
5. `client-metadata.json` scope union incl. `transition:generic` grace period.
6. `GET /health` (web client preflight).

---

## Crates

- **`freeq-oauth`** — the OAuth engine. Pure protocol, no HTTP server, no
  state: `DpopKey` + proofs, auth-server discovery, PAR, code exchange, token
  refresh (with dead-vs-transient classification), PKCE, `client_id` /
  `client-metadata` construction. Network calls take an injected client via the
  `ClientProvider` seam, so the caller owns SSRF/timeout policy. Consumed by the
  broker, the server, and the SDK. Never depends on `freeq-sdk`.

- **`freeq-ssrf`** — SSRF-safe outbound HTTP: reject private/reserved IPs,
  DNS-pin a client against rebinding. A primitive below OAuth (also used by
  media fetch, `did:web` resolution, blob proxying). Charter is outbound-request
  safety only.

- **`freeq-auth-broker`** — the auth *service*. Owns the HTTP endpoints and the
  stateful pieces the engine deliberately doesn't: session storage, the writer
  abstraction, DID/handle resolution, the SSRF client provider, HMAC push, and
  the CSRF/result-page handling. Runs standalone (its binary) or embedded (the
  server mounts its `session_router`).

`freeq-server` consumes `freeq-oauth` for its own `auth_login`/`auth_callback`/
`auth_step_up`, and depends on `freeq-auth-broker` to mount `session_router`
when running embedded. `freeq-sdk` consumes `freeq-oauth` for CLI login.

```
        freeq-auth-broker   freeq-server   freeq-sdk
                 └──────────────┼──────────────┘
              freeq-oauth ── freeq-ssrf
```

## Deployment modes

Selected by `BROKER_SHARED_SECRET` on the server:

| | Standalone | Embedded |
|---|---|---|
| Gate | secret **set** (server is a push receiver) | secret **unset** |
| Process | `freeq-auth-broker` binary, separate host | `freeq-server` mounts `session_router` |
| Writer | `RemoteWriter` — HMAC-signed push to the server | `LocalWriter` — writes into `SharedState` in-process |
| Store | `SqliteStore` — durable, encrypted at rest | `InMemoryStore` — ephemeral |
| `/session` durability | across restarts | within the server's uptime (resets on restart) |

A given deployment is one or the other; they never run at the same time.

## Key abstractions (`freeq-auth-broker`)

- **`SessionWriter`** — how a freshly minted session reaches the server.
  `mint_web_token(did, handle) -> (token, nick)` and `push_session(SessionPush)`.
  `RemoteWriter` does the HMAC-signed HTTP POST; `LocalWriter` (defined in
  `freeq-server`) writes straight into `SharedState`.

- **`SessionStore`** — where broker sessions live (`broker_token → refresh
  token / DPoP key`). `SqliteStore` is durable and encrypts sensitive fields at
  rest; `InMemoryStore` is a `HashMap` in RAM.

- **`session_router(state)`** — the `/session` + `/api/graph/*` routes, mountable
  by an embedding server. The standalone `router()` serves these plus the login
  endpoints.

## Login → session lifecycle

1. `/auth/login` resolves the handle, discovers the auth server, and PARs — each
   attacker-influenced hop fetched through an SSRF-validated, DNS-pinned client.
2. `/auth/callback` exchanges the code, persists the session via the store, and
   publishes it via the writer. It issues a `broker_token` (in the `#oauth=`
   result and the `freeq://auth` mobile redirect).
3. `/session` takes a `broker_token`, refreshes the PDS access token (single-use
   refresh-token rotation, serialized per token), mints a fresh web-token, and
   republishes the session. A dead grant returns 401 (client re-authenticates);
   a transient failure returns 502 (client retries).
4. `/api/graph/{follow,unfollow}` delegate Bluesky graph writes to the user's
   PDS on their behalf, authenticated by the same `broker_token`.

## Security properties

- **SSRF:** every outbound hop to a user-controlled host (PDS discovery, PAR,
  graph writes) uses a DNS-pinned client that rejects private/reserved targets.
- **`return_to`:** validated by exact scheme+host match; protocol-relative and
  backslash forms are rejected.
- **`/session` CSRF:** requests are allowed when they carry no `Origin`
  (non-browser clients), are same-origin (`Origin` == `Host` — an embedded
  server's own web client), or match the cross-origin allowlist (a standalone
  broker serving a web client on a different host).
- **At rest:** `SqliteStore` encrypts refresh tokens and DPoP keys with
  AES-GCM, keyed by HKDF over the broker's shared secret.
- **Broker↔server push:** every `RemoteWriter` request body is HMAC-SHA256
  signed with a 60-second replay window; the server verifies before acting.

## Testing

- `freeq-oauth`, `freeq-ssrf` — unit tests for the engine primitives (DPoP
  proofs, PKCE, discovery/PAR against mock well-knowns, SSRF policy).
- `freeq-auth-broker/tests/characterization.rs` — the broker's request paths end
  to end against mock upstreams: callback exchange, `/session` refresh with
  rotation and 401/502 classification, graph authorization, and the HMAC push
  cross-checked against the server's own verifier.
- `freeq-server/tests/embedded_session.rs` — the embedded loop: login callback →
  persist → `/session` refresh → fresh web-token, and `/session` absent in
  standalone (receiver) mode.
- The mocked suites can't exercise the real-PDS OAuth leg; that is covered by
  live smoke tests (embedded on a running server, standalone via the two-binary
  runbook in `scripts/`).

## Future option: durable embedded sessions

Embedded sessions are in-memory today. Making them survive restarts is a
matter of pointing the embedded mount at a `SqliteStore` instead of
`InMemoryStore` (the trait already supports it) and supplying an encryption key
— a deliberate opt-in for a self-hoster who wants restart-durable sessions
without running a separate broker process. Not implemented.
