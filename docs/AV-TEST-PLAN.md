# AV Multi-User Test Plan — the launch gate

**Companion to `docs/AV-SESSION-AUDIT.md`** (read it first: it explains the two
subscription models — roster-driven web vs. announcement-driven native — and
the confirmed failure classes A/B/C every test below targets).

**Definition of done:** every cell in §2 passes, every scenario in §5 passes,
and the automated layers in §3–4 are green in CI. Until then, no launch.

**Where the automation is now:** L1 (`tests/av_lifecycle.rs`) runs on every
push and automates §5.1–5.7 minus the hearing; L2 (`scripts/avharness.sh`)
measures the hearing and is the launch gate. Rows below say "Automated:" where
that is true. Three findings the harness turned up while being built — F10,
F11, F12 — are open and tracked in `AV-SESSION-AUDIT.md` §6.

---

## 1. Invariants under test

For every pair of participants (X, Y) in a call, after ≤ 5 s of settling:

- **I1 — hear:** X hears Y when Y speaks unmuted, and vice versa (no one-way pairs).
- **I2 — see-roster:** X's participant UI lists exactly the live participants.
- **I3 — see-video:** if Y's camera is on, X renders Y's tile (and screen share likewise).
- **I4 — leave:** when Y leaves/crashes, X stops hearing Y and Y's tile drops within grace+5 s.
- **I5 — one-session:** all participants who believe they're "in the channel's call" are in the **same** session id.
- **I6 — self:** X never subscribes to its own broadcast (no self-echo).

A failure of I1/I3 in exactly one direction is class A (roster/announce
divergence); a failure of I5 is class B; a failure of I4 is class C.

## 2. Client-pair matrix

Clients: **web** (Chrome + Safari), **macOS**, **iOS**, **Windows**, **bot**
(freeq-av agent). For each unordered pair (including same-type pairs), verify
I1–I6 in a 2-party call, then in a 3-party call with a third client of a
*different* type:

| | web | macOS | iOS | Windows | bot |
|---|---|---|---|---|---|
| **web** | ☐ | ☐ | ☐ | ☐ | ☐ |
| **macOS** | | ☐ | ☐ | ☐ | ☐ |
| **iOS** | | | ☐ | ☐ | ☐ |
| **Windows** | | | | ☐ | ☐ |
| **bot** | | | | | ☐ |

Pay special attention to mixed pairs: the two subscription models only
disagree when a roster entry goes stale, so every §5 scenario must be run at
least once with a web client AND a native client observing the same event.

Codec sub-matrix (I3): web publishes H.264 (`avc1`); native publishes H.264;
browser screen-share may negotiate AV1 → verify Windows (no HW AV1 decode
path; software rav1d) and iOS (AV1 feature just enabled) both render it.

## 3. Automated: server layer (exists — extend)

Unit tests in `freeq-server/src/av.rs` + `connection/messaging.rs` (run in CI
via `cargo test -p freeq-server`):

- ✅ `should_auto_end_policy` — live calls never age-ended (F1).
- ✅ `reap_orphan_slots_spares_grace_pending_instances` (F2).
- ✅ reaper live-set / multi-device / rejoin-in-place suite (pre-existing).
- ✅ e2e: join rejection emits `+freeq.at/av-error=join-failed` + av-id
  (`tests/av_error_signal.rs`, real server + real SDK client).
- ✅ e2e: start collision emits `start-collision` naming the winning session
  (`tests/av_error_signal.rs`).
- ✅ sweeper policy is the pure `should_auto_end` (unit-tested); the
  grace-pending path is pinned by the reaper test above.
- ✅ **L1 lifecycle suite (`tests/av_lifecycle.rs`, 8 scenarios)** — the
  session state machine's temporal behavior against real SDK clients: blip
  with a joiner, dead-session join, concurrent start, SIGKILL + restart,
  mid-call rename, token issuance, revocation ordering. Runs on every push
  (two scenarios need `--features av-native` and skip cleanly without it).

## 4. Automated: client layers (exists — extend)

- **JS SDK** (`freeq-sdk-js`, vitest): ✅ `avError` parse (3 tests).
- **web** (`freeq-app`, vitest): ✅ `av-mesh.test.ts` mesh reachability +
  self-echo edge (F8, 3 cases); ✅ `client-av.test.ts` avError dispatch
  (join-failed teardown, start-collision convergence, wrong-session no-op)
  + the 4 rotted `startAvSession` tests resurrected (injectable poll pacing).
- **macOS** (`swift test`): ✅ `AvStartRaceTests` (4) + `AvErrorResolutionTests` (6).
- **iOS** (`xcodebuild test`, scheme now includes freeqTests): ✅
  `AvStartRaceTests` (10) incl. concurrent-start convergence; 100 tests green.
  **iOS tests must stay in CI — this bundle had rotted unrunnable, which is
  how the start-race divergence survived.**
- **bot/e2e** (`freeq-av-client/examples/*_e2e.rs`): audio flow e2e exists;
  ☐ TODO wire into CI against a local server (`sfu_only_test`, `audio_e2e`).
- ✅ **L2 tone mesh** (`freeq-av-client/src/bin/avharness.rs`,
  `scripts/avharness.sh`): I1 measured as a matrix through the full lifecycle,
  plus five chaos steps. Weekly + `workflow_dispatch` (`av-harness` job on
  macos-26) — too heavy for the per-push path. **This is the launch gate.**

## 5. Scenario suite (manual until scripted; each maps to a finding)

Run each with: 1 web + 1 macOS + 1 iOS in #test unless stated. "✓" = all
invariants I1–I6 hold afterward.

### 5.1 Long call (F1) — REGRESSION GATE
**Automated (partly): `av_lifecycle.rs::start_join_leave_converges`** covers
start/join/leave convergence and the `ended` broadcast; the >2 h age arm stays
manual (`av::should_auto_end` unit-tests the policy).

Start a call; keep 2+ participants in it **> 2 h 10 m** (or temporarily lower
the threshold in a test build). ✓ the session survives; nobody is ejected; no
`ended` broadcast. Then all leave → session ends within one cleanup tick.

### 5.2 Blip + joiner (F2)
**Automated: `av_lifecycle.rs::blip_with_joiner_keeps_slot`** (L1) and the
`blip` chaos step of `scripts/avharness.sh` (L2, with audio).

A (native) in call. Kill A's IRC connection only (e.g. `pfctl` block port 6667
/ toggle Wi-Fi briefly) while its media WS lives. Within the 30 s grace, B
(web) **joins** the call. ✓ A keeps its roster slot (web still hears A);
A rejoins IRC and the call continues. Repeat with A = web (tab network
throttle) and observer = macOS.

### 5.3 Join a dead session (F3)
**Automated: `av_lifecycle.rs::dead_session_join_answers_error`** (session that
ended) + `av_error_signal.rs::rejected_join_emits_machine_readable_av_error`
(id that never existed). The three client-side teardowns stay manual.

A starts a call solo, waits for the session to end (leave from a second
device or `/av end`), then — with the stale session id cached — av-joins it
(easiest: two devices, end from one while the other backgrounds, then
foreground the other and hit join). ✓ the joining client receives
`av-error=join-failed`, tears down, re-discovers, and lands in a *new/real*
session — never a silent ghost. Verify on macOS, iOS, web.

### 5.4 Mid-call rename (F5)
**Automated: `av_lifecycle.rs::rename_mid_call_updates_roster`** — for
*authenticated* users. Guests are **F11 (open)**: their participant key embeds
`guest:{nick}`, so a rename mints a second slot instead of rejoining in place.

A (web) + B (web) + C (macOS) in call. Rename A mid-call (`/nick`), or force
the dot-strip path by reconnecting a custom-domain identity. ✓ within ~2 s B
still hears/sees A (roster followed the republish); C unaffected throughout.

### 5.5 Concurrent start (F4)
**Automated: `av_lifecycle.rs::concurrent_start_converges`** (L1) and the
`collide` chaos step (L2 — which additionally proves the two racers can hear
each other afterwards).

A (macOS) and B (iOS) hit "join" within < 1 s of each other in a channel with
no call. ✓ exactly one session exists; both are in it (loser converged via
`av-error=start-collision` or `started` convergence); a web observer joining
third sees both.

### 5.6 Server restart mid-call (F1×F3 chain from production)
**Automated: `av_lifecycle.rs::restart_mid_call_one_session`** (a real binary,
SIGKILLed and restarted on the same data) and the `restart` chaos step (L2 —
the mesh must re-form within `--recover-secs`).

3-party call; `systemctl restart freeq-server`. All clients auto-reconnect.
✓ within grace+rejoin, everyone is back in ONE session hearing each other
(rejoin-in-place), or — if the session was lost — every client lands in the
same new session. No client left ghost-publishing into the old id.

### 5.7 IRC-dead / media-alive (F6 — HARD requirement, revocation shipped)
**Automated: `av_lifecycle.rs::media_revocation_ordering`** (signaling side,
needs av-native) and the `blip` chaos step (L2, with audio). ⚠️ The L2 step
found **F10 (open)**: revocation only reaches WebSocket connections, so a
QUIC-dialed native client's media *does* outlive its roster slot. Run
`avharness --transport quic --strict-quic-revocation` to gate the fix.

A (native) in call; block A's IRC for > 35 s (grace expiry) with media alive.
✓ at grace expiry the server closes A's media connection (`SFU: session
revoked` in the log): native peers stop hearing A within seconds of the
roster drop — web and native now converge. A's own client tears down and can
rejoin fresh.

### 5.8 Same account, two devices
One DID joins from macOS and iOS (different instances). ✓ each device is a
separate tile for others; the two devices hear each other; leaving on one
doesn't tear down the other.

### 5.9 Same nick, two people (guest collision)
Guest "chad" (web) + authed "chad" (macOS). ✓ neither client disowns the
other (instance/DID-based self-check); both are heard by a third.

### 5.10 Mute/camera/screen churn
Rapidly toggle mute ×5, camera ×5, screen share on/off ×3 on each client in a
3-party call. ✓ final state correct everywhere; no stuck "muted-but-heard" or
black tiles; peers' track events converge.

### 5.11 Token flip rehearsal (F7 — ordering shipped; rehearse before the flag)
**Mechanism automated: `avharness --require-token`** runs the whole mesh
against a server with `FREEQ_AV_REQUIRE_TOKEN=1` and passes, on both
transports. That proves the join→token→dial ordering works under enforcement;
it does not replace the staging rehearsal with real clients below.

On a staging server set `FREEQ_AV_REQUIRE_TOKEN=1`. Natives now dial
join → token → dial with `?jwt=…&inst=…` (2 s tokenless fallback for
token-less servers); web re-dials on token arrival. ✓ all clients complete
calls with enforcement ON. Run this rehearsal once on staging before setting
the flag in production — it is expected to pass now.

### 5.12 Scale/layout
**Partly automated: `avharness --agents N`** holds the audio mesh and the
roster at N (the I1 matrix is every ordered pair, not a spot-check). Layout
remains manual.

1 → 5 → 10 → 30 participants (script bots via `freeq-av-client`). ✓ audio
mesh holds (spot-check pairs), roster correct, and layout remains usable
(backlog: web auto-layout, click-to-focus).

## 6. Diagnostic tooling (build as needed)

- ✅ `cargo run -p freeq-sdk --example av_live_probe` — one-shot LIVE probe
  against production (guest connect → dead-session join → asserts
  `av-error=join-failed` → real av-start → asserts `started` + `av-token` →
  clean `av-end`). Run after every server deploy; exits non-zero on failure.
- `freeq-av-client` bot flag `--assert-hears=<nick>`: subscribe, verify
  non-silent audio frames from a named peer within N s, exit non-zero
  otherwise — turns any §5 scenario into a scriptable check.
- ✅ Server: `GET /api/v1/sessions/{id}?debug=1` includes `announced` — the
  SFU's current broadcast paths under the session prefix — beside the roster,
  so class-A divergence is visible in one request during an incident. Null
  with an `announced_note` on a binary without `av-native`.
- Client logging: all clients log their computed subscribe set on every
  roster/announce change (`[call] poll:` on web; `AV: participant broadcast`
  in FFI) — capture these in every manual run.

## 7. Standing rule

Any new AV bug gets: (1) a root-cause entry in `AV-SESSION-AUDIT.md`, (2) a
unit test at the layer that owns the decision, (3) a scenario row here if it
implicates cross-client behavior.
