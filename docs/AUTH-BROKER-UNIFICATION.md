# Auth Broker Unification — Survey & Design

**Status:** proposal (2026-07-06). No code changed yet.

**Goal:** DRY up the two divergent auth implementations — the standalone
`freeq-auth-broker` service and the embedded auth inside `freeq-server` —
into one codebase that supports both deployment shapes: a separate broker
process on its own origin (freeq.at topology) and "local mounting" inside
the server (zerosum topology).

**Design authority:** the standalone broker is the *reference
implementation*. Where the two implementations disagree on semantics or
architecture (session model, `/session` contract and its 401/502
classification, refresh-lock discipline, encrypted-at-rest storage, the
sink/push shape, `return_to`/CORS policy), the standalone broker's behavior
wins. The only things adopted *from* the embedded side are security
hardening and bug fixes the broker never received — the DNS-pinned SSRF
guards, generic (non-reflective) error bodies, and the working OAuth result
page — plus the embedded-only features (step-up purposes, `irc_state`)
which have no standalone counterpart to defer to.

**Process rule:** no extraction or deletion begins until the Phase 0
characterization suite passes against the *unmodified* code. Refactor
phases must keep that suite green throughout.

---

## 1. Survey: what exists today

### 1.1 Three copies of the AT Proto OAuth engine

The workspace contains **three independent implementations** of the same
protocol machinery (handle→DID→PDS resolution, auth-server discovery, PAR
with the DPoP-nonce retry dance, code exchange, PKCE, client_id/metadata
construction):

| # | Location | Lines | DPoP key | DID resolution | SSRF guard | Refresh tokens |
|---|----------|-------|----------|----------------|------------|----------------|
| 1 | `freeq-auth-broker/src/main.rs` | ~1,780 | own p256 impl | own (well-known + bsky API) | **weak** — private-IP check on `did:web` only; PDS/auth-server/token/PAR URLs unguarded | **yes** — SQLite, AES-GCM-encrypted at rest, per-token refresh locks, `invalid_grant` classification |
| 2 | `freeq-server/src/web.rs` (~1,300 auth lines of 4,615) | | `freeq_sdk::oauth::DpopKey` | configured `state.did_resolver` | **strong** — `safe_outbound_client`: DNS-pinned clients, generic errors, CTF-07/08/09/11 regression tests | **none** — in-memory sessions only, die on restart |
| 3 | `freeq-sdk/src/oauth.rs` (`login()`, loopback CLI flow) | ~1,660 | canonical `DpopKey` | `DidResolver` | n/a (client-side) | none |

The SDK already owns the right primitives (`oauth::DpopKey`, `ssrf`,
`pds::pds_endpoint`, `did::DidResolver`) — the embedded path consumes them;
the standalone broker duplicates them.

### 1.2 Endpoint namespaces (they are NOT the same surface)

**Standalone broker** (`main.rs:422-430`):
`GET /health`, `/health-v3`, `/client-metadata.json`, `GET /auth/login`,
`GET /auth/callback`, `POST /session`, `POST /api/graph/follow`,
`POST /api/graph/unfollow`. Pushes results into the server via HMAC-signed
`POST {server}/auth/broker/web-token` and `POST {server}/auth/broker/session`.

**Embedded server** (`web.rs:171-247`):
`GET /auth/login`, `GET /auth/callback`, `GET /auth/step-up`,
`GET /auth/mobile`, `/client-metadata.json`, plus the broker-push receivers
`POST /auth/broker/web-token|session` (403 unless `BROKER_SHARED_SECRET` set).
**No `POST /session`, no `/health`, no `/api/graph/*`.**

### 1.3 Feature matrix — each side has things the other lacks

| Capability | Standalone broker | Embedded |
|---|---|---|
| Durable sessions / `POST /session` refresh (broker_token → fresh web-token) | ✅ | ❌ (in-memory only; web-token expiry ⇒ full re-OAuth) |
| `invalid_grant` vs transient classification (401 vs 502) | ✅ | n/a |
| Per-token refresh serialization (single-use rotating refresh tokens) | ✅ | n/a |
| Encrypted-at-rest refresh tokens + DPoP keys | ✅ | n/a |
| Graph delegation (`/api/graph/follow`, `/unfollow` — used by iOS) | ✅ | ❌ |
| Step-up OAuth purposes (BlobUpload, BlueskyPost) keyed `(did, purpose)` | ❌ (comment in `main.rs:621` explicitly punts to server) | ✅ |
| IRC `/login` completion (`irc_state`) | ❌ | ✅ |
| SSRF-hardened OAuth chain (DNS pinning, CTF tests) | ❌ | ✅ |
| `return_to` allowlist + popup handling | ✅ | ❌ (`return_to` not a parameter at all) |
| Upload-token minting on session push | (receiver side) | ✅ |
| freeq:// mobile redirect | ✅ (302 — required by ASWebAuthenticationSession) | ✅ (meta-refresh HTML + separate `/auth/mobile` bridge page) |
| broker_token issued to clients | ✅ | ❌ (mobile redirect at `web.rs:3033` omits it) |

### 1.4 Deployment topologies

- **irc.freeq.at (chad's):** standalone broker at `auth.freeq.at` (Docker on
  Hetzner, :8081) does login + refresh. **The embedded code is still live
  there too** — `/auth/step-up`, `/auth/mobile`, `client-metadata.json`, and
  the broker-push receivers. The two implementations are entangled in prod,
  not alternatives.
- **irc.zerosum.org (ours):** no broker process. `authBrokerBase = apiBaseUrl`;
  clients drive the server's `/auth/login` directly. `BROKER_SHARED_SECRET`
  unset.
- There is **no mode discovery**: nothing in `/api/v1/health` or ISUPPORT
  advertises which mode a server runs. Clients hardcode it per build
  (iOS/macOS plist `AUTH_BROKER_BASE`, Android build flavor, Windows setting,
  WinUI a `const`), except the web client which uses a host heuristic
  (`ConnectScreen.tsx:139-146`: `irc.freeq.at` ⇒ `auth.freeq.at`, else
  same-origin).

### 1.5 Embedded-mode gaps clients currently paper over

- Web client (`ConnectScreen.tsx:230-233`): if `brokerOrigin === webOrigin`
  it **skips `/session` and deletes any stored broker token** — embedded
  users lose durable re-auth entirely.
- Web client preflights `GET {brokerOrigin}/health` before login
  (`ConnectScreen.tsx:327`) — on embedded servers this only passes because
  the SPA fallback serves `index.html` with a 200.
- Native clients call `POST {authBrokerBase}/session` unconditionally, but
  in embedded deployments they never receive a `broker_token` (the mobile
  redirect omits it), so refresh silently never happens; iOS's old
  `hasSavedSession` gate broke on exactly this (see
  `project_native_embedded_auth_gate`).
- iOS's Bluesky follow/unfollow (`BlueskyGraph.swift:125`) targets
  `/api/graph/*`, which only the standalone broker serves ⇒ feature is dead
  against embedded deployments.

### 1.6 Known divergence bugs (from docs + code)

- `return_to` validation exists only on the broker — the zerosum
  "invalid return_to url" incident (`IOS-PROVENANCE-HANDOFF.md`,
  `MODAL-IDENTITY-HANDOFF.md`) was caused by a stale client `brokerBase`
  hitting the *wrong implementation*.
- The broker's OAuth result HTML had broken JS, which spawned the server's
  `/auth/mobile` workaround page (`web.rs:2158-2162`) — divergence creating
  workarounds for divergence.
- Security posture is asymmetric: the broker misses the SSRF hardening the
  server got (CTF-07/08/09), and the server misses the broker's refresh-token
  hygiene. Some audit items (M-10 permissive CORS, C-6 open redirect) are
  already fixed in broker code but stale in docs.
- Allowlists (CORS origins, `return_to`) are **hardcoded** in the broker
  (`main.rs:432-439`, `1010-1016`, `1650-1659`) — self-hosters must edit
  source and rebuild.
- **Open redirect still live in the reference (found during Phase 0b).**
  `is_valid_return_to` prefix-matches (`url.starts_with(prefix)`), so
  `https://irc.freeq.at.evil.example` passes the allowlist and the
  token-bearing `#oauth=` fragment is redirected to an attacker origin.
  This is residual SECURITY-AUDIT C-6. Pinned (as a documented bug) by
  `characterization::return_to_allowlist`. Fix belongs in the shared
  engine: parse the URL and exact-match the host/origin; flip the test
  assertion when it lands. Deliberately NOT fixed mid-characterization —
  Phase 0 only pins behavior.

### 1.7 The wire contracts that must not break

Both deployments are live (freeq.at is upstream's; we control zerosum only).
Anything shipped must be additive against:

1. `#oauth={base64url json}` fragment payload: `token`, `broker_token`,
   `nick`, `did`, `handle`, `pds_url`.
2. `freeq://auth?token&broker_token&nick&did&handle` as an HTTP **302**
   (ASWebAuthenticationSession requirement).
3. `POST /session` `{broker_token}` → `{token, nick, did, handle}`;
   401 = dead session (client drops token), 502 = transient (client retries).
4. Broker-push HMAC contract: `X-Broker-Signature` = HMAC-SHA256 over
   `ts={X-Broker-Timestamp}\n || body`, 60s window; `BrokerSessionRequest`
   evolves additively (`granted_scope` has `serde(default)` — see
   `oauth-scope-edge-cases.md`).
5. `client-metadata.json` scope union incl. `transition:generic` grace period.
6. `GET /health` (web client preflight; WinUI + windows-app check it too).

---

## 2. Design

### 2.0 Engine home: a dedicated `freeq-oauth` crate (decided 2026-07-06)

The original plan put the engine in `freeq_sdk::oauth`. On inspection that
fails a hard requirement: only `p2p` is feature-gated in `freeq-sdk`;
`e2ee`, `ratchet`, `x3dh`, `av`, `client`, `streaming` all compile
unconditionally. Depending on `freeq-sdk` just to reach `oauth` would drag
that entire surface (and its crypto deps) into the slim broker binary —
defeating the broker's reason to exist as a small standalone service.

Decision: a new **`freeq-oauth`** workspace crate holding the pure protocol
engine. `freeq-sdk`, `freeq-server`, and `freeq-auth-broker` all depend on
it. `freeq_sdk::oauth::DpopKey` becomes `pub use freeq_oauth::DpopKey`, so
downstream import paths (freeq-server, freeq-sdk-ffi) don't change.

Hard rule: **`freeq-oauth` must never depend on `freeq-sdk`** (that would
re-introduce the bloat transitively). Consequence — the engine takes an
**injected `reqwest::Client`** rather than building its own, so the SSRF /
timeout / DNS-pinning policy stays the caller's: the server injects its
DNS-pinned SSRF-guarded client, the broker its bounded client, the SDK a
plain one. This is strictly better than today (network policy is explicit
at every hop) and keeps DID resolution (which lives in `freeq_sdk::did`) on
the caller side — the engine starts from a resolved `pds_url`.

### 2.1 Shape: engine in the SDK, service as a library crate, two mounts

```
freeq-sdk::oauth (engine — pure protocol, no HTTP server)
    │  discovery, PAR+nonce dance, code exchange, refresh+invalid_grant,
    │  PKCE, client_id/client-metadata builders, DpopKey (already there),
    │  SSRF-guarded outbound clients (move safe_outbound_client here)
    ▼
freeq-auth-service (NEW lib crate — axum Router + session logic)
    │  routes: /auth/login /auth/callback /session /client-metadata.json
    │          /api/graph/follow /api/graph/unfollow /health /health-v3
    │  SessionStore trait  ── SqliteStore (encrypted, per-token locks)
    │  SessionSink trait   ── how minted tokens reach the IRC server
    │  AuthConfig          ── public_url, allowed origins/return_to (CONFIG,
    │                         not hardcoded), encryption key, flow hooks
    ├──────────────────────────────┬─────────────────────────────────┐
    ▼                              ▼                                 │
freeq-auth-broker (bin)        freeq-server (embedded mount)         │
  thin main.rs:                  .merge(auth_service::router(...))   │
  env config +                   LocalSink: writes web_auth_tokens / │
  RemoteSink (HTTP+HMAC          web_sessions / upload_tokens        │
  to FREEQ_SERVER_URL)           directly into SharedState;          │
                                 completes irc_state logins in-proc  │
```

**`SessionSink`** is the pivot abstraction. It carries exactly what the
broker→server push carries today:

```rust
#[async_trait]
trait SessionSink: Send + Sync {
    /// Mint a one-time SASL web-token for this identity.
    async fn mint_web_token(&self, did: &str, handle: &str) -> Result<(String, String)>; // (token, nick)
    /// Install/refresh a web session (access token + DPoP key) for
    /// server-proxied PDS operations. Returns optional upload_token.
    async fn push_session(&self, s: &SessionPush) -> Result<Option<String>>;
    /// Hook: a login flow carrying `irc_state` completed (embedded only;
    /// RemoteSink returns Unsupported and the flow falls back to web).
    async fn complete_irc_login(&self, irc_state: &str, did: &str, handle: &str) -> Result<bool>;
}
```

- `RemoteSink` = today's `mint_web_token` / `push_web_session` HTTP+HMAC
  calls, verbatim. The server keeps its `/auth/broker/*` receivers unchanged
  — old broker binaries keep working against new servers and vice versa.
- `LocalSink` = direct insertion into `SharedState` (no HMAC, no HTTP hop),
  plus `complete_irc_login` wired to `connection::login::complete_irc_login`.

**`SessionStore`** starts with one impl (SQLite, current broker schema +
encryption). Embedded mounts point it at a `broker.db` next to the server's
existing DBs. An in-memory impl is trivial for tests.

### 2.2 What each side inherits (the payoff)

Embedded deployments (zerosum, self-hosters) gain, with zero new code of
their own:
- `POST /session` → durable login (broker_token survives web-token expiry
  and server restarts). The mobile redirect starts including `broker_token`,
  which un-breaks the native refresh path against embedded servers.
- `/api/graph/*` → iOS follow/unfollow works.
- Real `/health` (no more SPA-fallback accident), `return_to` validation,
  popup handling.

The standalone broker gains:
- The server's SSRF hardening (DNS-pinned clients, generic errors) and its
  CTF regression tests, which move into the shared engine.
- Configurable CORS/`return_to` allowlists (env: `AUTH_ALLOWED_ORIGINS`,
  defaulting to the current hardcoded list so freeq.at redeploys unchanged).
- One HTML result page implementation (the server's working one; the broker's
  broken-JS page dies; `/auth/mobile` stays as the iOS bridge).

Step-up (`/auth/step-up`) and its `OauthPurpose` model move into the shared
service too — flows are parameterized by purpose; the pending-state map is
owned by the service so login and step-up share it. The standalone broker
simply doesn't enable step-up purposes in its config (preserving today's
"step-up is served by the server" split on freeq.at), while embedded mounts
enable everything.

### 2.3 Design choices flagged (and the alternatives)

1. **Engine into `freeq-sdk` vs a fourth standalone crate.** Chosen: SDK.
   It already owns `DpopKey`, `ssrf`, `pds`, `did`, and its own `login()`
   flow gets rewritten onto the same engine (killing copy #3). The broker
   consumes it with `default-features = false, features = ["rustls-tls"]`
   so it doesn't drag iroh/e2ee into the small Docker image (those are
   already optional/feature-gated). Rejected: putting axum handlers in the
   SDK — it's a client SDK; the HTTP surface belongs in the service crate.
2. **New `freeq-auth-service` crate vs making `freeq-auth-broker` a lib+bin.**
   Either works; chosen: reuse `freeq-auth-broker` as `lib.rs` (service) +
   `main.rs` (thin standalone bin). One less crate, the git history stays
   attached to the code, and the crate name keeps meaning what upstream
   expects. If the server-side dep feels wrong later, splitting the lib out
   is mechanical.
3. **Trust boundary erosion (the real tradeoff).** The broker's stated
   rationale (ENCRYPTION.md) is that PDS credentials never live on the IRC
   server. Embedded mode already violates this for *access* tokens
   (in-memory `web_sessions`); mounting the session store adds *refresh*
   tokens (encrypted, SQLite) to the combined host. That is a deliberate
   deepening of an existing property of embedded mode, not a new class of
   exposure — single-host self-hosters have one trust domain anyway. The
   standalone topology remains available precisely for deployments that
   want the boundary. Broker rationale is upstream's design; this refactor
   is additive and keeps the standalone service first-class (per
   `project_auth_broker_origin`).
4. **No mode-discovery endpoint (yet).** Clients keep their per-build
   `authBrokerBase`. Once embedded serves the full broker namespace, the
   *distinction stops mattering to clients* — `{authBrokerBase}/session`
   works either way, which is a better fix than discovery. The web client's
   `brokerOrigin === webOrigin` skip-and-delete branch should be removed in
   the same release the server ships the mounted `/session`. A
   `auth_mode`/`session_endpoint` field in `/api/v1/health` remains an easy
   additive follow-up if needed.
5. **`/session` on the server origin is new attack surface.** It inherits
   the broker's CSRF origin checks + per-token locks; rate-limiting rides
   the server's existing per-IP connection limits. Worth a focused pass in
   review since it newly holds refresh tokens (see audit items C-5/L-4 —
   the encrypted-at-rest handling already addresses C-5).

### 2.4 Phasing (each phase independently shippable, wire-compatible)

- **Phase 0 — characterization tests (before anything moves).**
  - *0a. Mechanical lib split.* `freeq-auth-broker/src/main.rs` →
    `lib.rs` + thin `main.rs`. Move-only: no logic changes, no renames
    beyond visibility. This exists solely to make handlers testable —
    the broker currently has 3 unit tests and its router is unreachable
    from tests.
  - *0b. Pin the broker (the reference).* Axum integration tests against
    the broker router with a mock PDS/auth-server (lift the
    `mock_pds_router` pattern from `freeq-sdk/src/oauth.rs` tests):
    - `/auth/login`: PAR request shape, DPoP-nonce retry (only on
      `use_dpop_nonce`), `return_to` allowlist accept/reject, referer
      fallback, popup/mobile flags, redirect URL construction.
    - `/auth/callback`: `#oauth=` fragment payload keys, mobile
      `freeq://` **302** (not HTML), token exchange nonce-retry with the
      code-consumption caveat (known nonce sent on first attempt),
      encrypted-at-rest storage round-trip, graceful degrade when the
      server push fails (identity-only login still succeeds).
    - `/session`: `{broker_token}` → `{token,nick,did,handle}`;
      `invalid_grant` → **401** and `use_dpop_nonce`/5xx/non-JSON →
      **502**; rotated refresh token persisted; **concurrent calls for
      one token serialize on the refresh lock and reuse the rotated
      token** (the 2026-07-03 regression); CSRF origin rejection.
    - `/api/graph/follow|unfollow`: broker-token auth, self-follow
      rejection, own-repo check on the at:// URI, DPoP nonce dance
      against the PDS.
    - Broker→server push: `sign_body` output verifies against the
      server's `verify_broker_signature_raw` (cross-crate round-trip,
      including the 60s replay window and `ts=\n` binding).
    - `/client-metadata.json` + `build_client_id`: scope union string,
      loopback vs production client_id forms.
  - *0c. Pin the embedded side that must survive.* Audit existing
    `freeq-server` web tests against §1.7; add coverage where thin —
    notably step-up purpose keying `(did, purpose)`, `irc_state`
    completion, and the mobile redirect shape.
  - *Gate:* full workspace baseline recorded at HEAD; 0b/0c green against
    unmodified code before Phase 1 starts.
- **Phase 1 — engine extraction (pure refactor).** Move discovery / PAR /
  exchange / refresh / PKCE / client_id / metadata / `safe_outbound_client`
  into `freeq_sdk::oauth`. Rewrite the three call sites onto it. Port
  CTF-07/08/09/11 SSRF tests to the engine (tests-first for the new public
  primitives). Behavior identical; the broker binary silently gains SSRF
  hardening. No wire changes.
- **Phase 2 — service crate.** `freeq-auth-broker` becomes lib+bin;
  `SessionStore`/`SessionSink`/`AuthConfig` introduced; standalone bin is a
  thin wrapper with `RemoteSink`. Allowlists become env-configurable with
  current values as defaults. freeq.at redeploy is a no-op behaviorally.
- **Phase 3 — embedded mount.** `freeq-server` merges the service router
  with `LocalSink` + SQLite store; deletes its hand-rolled
  `auth_login`/`auth_callback`/`auth_step_up` bodies (handlers become the
  shared ones); mobile redirect gains `broker_token`. Zerosum gets durable
  sessions. `/auth/broker/*` receivers unchanged.
- **Phase 4 — client cleanup.** Web: drop the skip-`/session` branch and the
  accidental-`/health` reliance. iOS/Android: nothing required (their
  unconditional `/session` calls simply start working); optionally unify
  Android flavors' `AUTH_BROKER_BASE` to server origin everywhere except
  freeq.at builds.

Rollout order is safe in any sequence (all changes additive). Phases 1–2
touch code upstream runs — coordinate with chad before pushing; zerosum is
the live-test target per usual.

### 2.4a Phase 0 status (2026-07-06)

Done and green:
- **0a** — `freeq-auth-broker` split into `lib.rs` (`pub fn router()` + `pub`
  config/state/helpers) + a thin `main.rs`. 3 pre-existing unit tests
  unchanged and passing across the move.
- **0b** — `freeq-auth-broker/tests/characterization.rs`: 23 tests pinning
  the reference. Covers `/health`, `/client-metadata.json`, `/auth/callback`
  (fragment payload, known-nonce-first regression, nonce retry dance, mobile
  `freeq://` 302, encrypted-at-rest storage round-trip, identity-only
  degrade, one-time state, error paths), `/session` (401 invalid_grant vs
  502 transient, single-use rotation persistence, **concurrent-refresh
  serialization** = the 2026-07-03 regression, CSRF origin, scope
  defaulting), `/api/graph/{follow,unfollow}` authorization, the HMAC push
  wire-format cross-checked against the server's verifier, and the pure
  helpers (return_to allowlist, client_id, field crypto, DPoP proof).
- **0c** — `freeq-server/tests/embedded_auth_callback.rs`: 4 tests for the
  embedded-only callback paths that were uncovered (mobile custom-scheme
  redirect + nick derivation, `irc_state` `/login` completion, web session +
  one-time-token minting, one-time state). Existing `broker_auth.rs` (20),
  `oauth_scope.rs` (21), `oauth_ssrf.rs` (7, CTF-07/08/09/10), `protocol_ctf`
  (CTF-11 XSS) already pin the push contract, step-up keying, and SSRF/XSS.

Findings to carry forward:
- Open-redirect in `is_valid_return_to` (documented above).
- **Pre-existing broken test target (not ours):** `freeq-server/tests/
  evidence_verify.rs` references `CARGO_BIN_EXE_freeq-verify`, a binary that
  exists nowhere in the workspace, so a blanket `cargo test -p freeq-server`
  fails to compile that target. Unrelated to auth. Baseline was taken by
  running the auth-relevant targets explicitly. Worth filing separately.

### 2.5 Testing

- **Phase 0 characterization suite is the safety net** — it pins the
  reference (standalone broker) behavior and must stay green through every
  later phase. It is written against the *current* code first.
- Engine: unit tests in `freeq-sdk` (mock PDS router pattern already exists
  in `oauth.rs` tests) + ported CTF regression tests.
- Service: the Phase 0 suite re-targets the shared router unchanged; both
  sinks (`RemoteSink` with a mock server, `LocalSink` with real
  `SharedState`) run against the same suite.
- Server: existing web.rs broker/auth acceptance tests must pass unchanged —
  they pin the wire contracts in §1.7.
- Full suites at HEAD before starting (baseline), and per-package before any
  commit.
