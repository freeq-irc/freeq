# The AV Map — every component, every clock, every way it breaks

**Audience:** anyone debugging "X can't hear Y" or building AV features.
**Companions:** `AV-ARCHITECTURE.md` (data path), `AV-SESSION-AUDIT.md`
(F1–F9 root causes), `AV-TEST-PLAN.md` (invariants I1–I6 + scenario matrix).
This document is the consolidated operational map: who does what, on which
clock, and which timers can disagree.

---

## 1. The surfaces

One server binary, five client families, two subscription models.

```
                       ┌──────────────────────────────────────────────┐
                       │  freeq-server  (--features av-native)        │
                       │                                              │
  IRC (TCP/WS) ──────► │  session state machine        av.rs          │
  TAGMSG av-*          │   · av_sessions / av_participants (SQLite)   │
                       │   · joins, leaves, grace, sweeps, tokens     │
                       │                                              │
  REST ──────────────► │  /api/v1/sessions[/{id}]      web.rs         │
                       │  /api/v1/av/sessions/{id}/token              │
                       │                                              │
  media WS /av/moq ──► │  SFU: moq_relay::Cluster      av_sfu.rs      │
  media QUIC :8080 ──► │   · one namespace for both transports        │
                       │   · media_conns registry (?inst=) →          │
                       │     revocation on roster teardown            │
                       │                                              │
  iroh QUIC ─────────► │  S2S: AvSessionCreated/Joined/Left/Ended     │
                       └──────────────────────────────────────────────┘

  CLIENT FAMILY         SUBSCRIBES BY      JOIN→MEDIA ORDER
  web (freeq-app)       ROSTER (poll)      join → publish tokenless → re-dial on token
  macOS  (FFI→freeq-av) ANNOUNCEMENTS      join → wait token (2 s cap) → dial ?jwt&inst
  iOS    (FFI→freeq-av) ANNOUNCEMENTS      same as macOS (AvStartRace parity)
  Windows (windows-core) ANNOUNCEMENTS     same FFI path
  bots (freeq-av-client, eliza, claude-mcp) ANNOUNCEMENTS  varies by author
```

**The single most important fact** (from the July audit): web computes whom to
subscribe to from the **roster** (`{sid}/{nick}~{inst}` via 1.2 s poll +
av-state pushes); every native/agent subscribes to whatever the SFU
**announces**. Any divergence between roster and announcements splits a call
*asymmetrically* — natives keep hearing everyone, web silently loses whoever
the roster misdescribes. Class A. Both models are legitimate; the divergence
is the bug surface.

## 2. The clocks (every timer that can disagree)

| Clock | Value | Owner | What happens at the boundary |
|---|---|---|---|
| web roster poll | **1.2 s** | web | subscriptions recomputed; stale roster = wrong mesh until next tick |
| native roster reconcile | **5 s** | macOS/iOS | display-only strip; media unaffected |
| native token wait → tokenless dial | **2 s** | FFI callers | dial without `?jwt` against token-less servers; if token arrives late, dial already happened |
| IRC disconnect grace | **30 s** | server | AV slot survives a blip (`av_grace_pending`); at expiry: roster leave + **media revoked** |
| cleanup sweep | **5 min tick** | server | `should_auto_end`: reaps only sessions with no live-claimed instances |
| session age arm | **2 h** | server | only for resurrected ghost sessions (F1 fix) — never a live call |
| AV token expiry | **24 h** | server (JWT) | a day-long call's re-dial after that fails; nobody refreshes tokens |
| start-collision window | **< ~1 s** | humans | two av-starts race; loser must converge via `av-error=start-collision` |
| media reconnect backoff | AvSession internal | freeq-av | drop ends every PCM stream; participants re-announced fresh |
| autoplay/AudioContext | user gesture | browsers | joined-but-silent until the page has a gesture; Safari stricter |
| WASM worklet load | ~100s of ms | web | first audio frames can predate a ready decoder |

Flakiness is almost always two of these clocks disagreeing about the world at
the same instant. The July production incident was three: 2 h age arm ×
5-minute sweep × a client that missed one TAGMSG.

## 3. The identity tuple

A participant in a call is `(session_id, did-or-nick, instance)`.

- `session_id` — ULID, minted by av-start. **Class B** = two participants who
  think they're in "the channel's call" holding different ids (start races,
  joins into dead sessions, restarts).
- `instance` — per-call random id, self-declared on the media dial (`?inst=`).
  Keys: self-recognition (no self-echo), multi-device (one DID, two tiles),
  media revocation, rejoin-in-place. A client that re-joins with a **new**
  instance is a *different participant* to everyone else — the July logs'
  join/leave/retry churn was exactly this, visible as ghosts.
- nick — display + the roster path component for web (`{sid}/{nick}~{inst}`),
  which is why a mid-call **rename** must re-send av-join with the same
  instance (F5) or the roster points at a dead path.

## 4. Lifecycle, temporally honest

```
START (native)                         START (web)
──────────────                         ───────────
send av-start ─┐                       send av-start ─┐
               ├─ server: create sid,  │               ├─ same
               │  join creator, mint   │               │
               │  token, broadcast     │               │
av-token TAGMSG◄┘                      av-state started◄┘
hold dial ≤2 s                          publish tokenless (moq-publish)
dial ?jwt&inst → publish               token TAGMSG → re-dial with ?jwt
subscribe: SFU announces               subscribe: roster poll paths
                                        (1.2 s later than natives, always)

BLIP (IRC drops, media alive)
────────────────────────────
t+0     conn dies → av_grace_pending registers instance
t+0..30 roster KEEPS slot (F2 fix); joiners' reap skips grace-pending
t+30    grace expiry → roster leave + av-state=left + MEDIA REVOKED (F6 fix)
        (web loses tile ≤1.2 s later; natives lose audio at revocation)

END
───
last leave → session ends → av-state=ended
client that missed the TAGMSG → next join answers av-error=join-failed (F3)
→ client MUST tear down + rediscover (unit-tested on all three UIs)
```

## 5. Failure-class catalog (what "flaky" decomposes into)

Class A — roster ≠ announcements (web-only, one-way loss)
  A1 stale roster slot (blip reap — F2, fixed)   A2 rename orphan (F5, fixed)
  A3 roster poll lag (1.2 s, inherent)           A4 self-echo edge (F8, fixed)

Class B — session identity split (mutual pairwise silence)
  B1 force-ended live call (F1, fixed)           B2 join into dead session (F3, fixed)
  B3 start collision loser (F4, fixed)           B4 server restart re-join divergence (§5.6, scenario-only)

Class C — media lifecycle ≠ IRC lifecycle
  C1 IRC-dead/media-alive ghost (F6, fixed)      C2 media-dead/IRC-alive (reconnect backoff; UI shows tile, no audio — UNAUDITED)
  C3 token-required rejection ghost (F7, fixed)  C4 token expiry mid-call re-dial (24 h — UNAUDITED)

Class D — environmental (client-local, no protocol bug)
  D1 mic permission denied     D2 AudioContext suspended (no gesture)
  D3 WASM decoder not ready    D4 Safari/codec matrix (AV1 screen-share)
  D5 output-device switch (AirPods arrive mid-call)

Class E — deployment/config
  E1 binary without av-native (deploy.sh now hard-fails on `"av":true`)
  E2 FREEQ_AV_REQUIRE_TOKEN flip vs stale clients (rehearsal §5.11, not yet run)
  E3 federated session events vs local SFU (S2S carries state, media doesn't federate)

## 6. Harness inventory — what exists, what it can't see

| Layer | What it proves | Runs in CI? |
|---|---|---|
| `av.rs` unit tests (policy: auto-end, reaper, grace) | decisions, not behavior | ✅ yes |
| `tests/av_error_signal.rs` (real server+SDK) | av-error semantics | ✅ yes |
| client unit tests (AvStartRace, av-mesh, resolvers) | per-client decisions | ✅ mac/web; iOS in xcode job |
| `av_cross_transport_e2e` (tone matrix, QUIC×WS) | SFU namespace unification | ❌ manual; **bypasses IRC entirely** — blind to classes A and B |
| Playwright `audio-flow`/`audio-publish`/`av-sessions` | web joins, WS frames flow | ❌ manual; needs local av-native server; asserts flow, not audibility |
| `av_live_probe` | prod signaling sanity post-deploy | ❌ manual |
| **CI reality** | — | **every AV crate is `--exclude`d from the workspace test run: zero AV code executes on push** |

The gap in one sentence: nothing anywhere automatically proves **I1 (X hears
Y)** through the **full stack** (IRC join → token → dial → publish →
announce/roster → subscribe → decode), and nothing exercises the two
subscription models **against each other** under churn — which is precisely
where every production incident has lived.

## 7. The harness (see `scripts/avharness/` once built)

Design, layered like the macOS rendering harness (numbers gate CI; states are
summonable; eyes stay for pixels):

- **L1 — session-layer chaos (CI, headless, no audio).** Real server + N real
  SDK clients. Drives: start, join, leave, blip-with-joiner, dead-session
  join, concurrent start, restart mid-call, rename mid-call. Asserts, with
  timing budgets: I2 (roster exact), I4 (teardown ≤ grace+5 s), I5 (one
  session id everywhere), av-error delivery, token issuance, media revocation
  ordering. This automates §5.1–5.7 minus the hearing.
- **L2 — tone-mesh through the full stack (the one that matters).** Local
  av-native server; N agents each publish a distinct sine (440·k Hz) **via
  the real lifecycle** (IRC av-join → token → dial `?jwt&inst`). Every agent
  Goertzel-detects every other agent's tone: the full I1 matrix as numbers.
  Then chaos, re-asserting the matrix after each event: kill an agent's IRC
  (grace), kill its media socket, restart the server, collide two starts,
  rename mid-call. Exit non-zero names the failing invariant and pair.
- **L3 — the cross-model probe (web in the loop).** Playwright drives a real
  web client (fake 440 Hz mic) against the same server with two tone agents;
  the page asserts *received energy per peer* via an injected AnalyserNode,
  and the harness blips one agent to prove the roster path converges the way
  the announcement path does. This is the only layer that can catch class A
  regressions before users do.
- **L4 — live probes (post-deploy).** `av_live_probe` (exists) + an
  `--assert-hears` bot mode for spot-checking production pairs.

Diagnostics to build alongside: `GET /api/v1/sessions/{id}?debug=1` returning
the SFU's announced paths beside the roster — class A divergence visible in
one request, in production, during an incident.

## 8. Standing rules

1. Any new AV bug: root-cause entry in `AV-SESSION-AUDIT.md`, a test at the
   layer that owns the decision, a scenario row in `AV-TEST-PLAN.md`, **and a
   chaos step in the harness if it's temporal**.
2. Any new clock (timer, poll, grace, expiry) gets a row in §2 of this file
   the day it ships.
3. `deploy.sh` already refuses a binary without `"av":true`; the token flip
   (E2) must not happen before §5.11's rehearsal runs green on staging.
