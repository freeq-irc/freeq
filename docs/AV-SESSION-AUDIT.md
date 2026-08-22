# AV Session Deep-Dive Audit — "some can hear each other and some can't"

**Date:** 2026-07-22 (F1–F9) · 2026-08-22 (F10–F12, found by the harness)
**Status:** F1–F9 fixed + tested. **F10–F12 OPEN** — see §6.
**Symptom under investigation:** multiple people join a call; hearing/seeing is
split in *random directions*, and which client you're on seems to matter.

---

## 1. Why splits are even possible: two sources of truth

The single most important architectural fact found by this audit:

| Client | How it decides whom to subscribe to |
|---|---|
| **web** | **Roster-driven.** Polls `GET /api/v1/sessions/{id}` (1.2 s + on av-state change) and computes each peer's MoQ path `{session}/{nick}~{instance}` from the roster (`av-mesh.ts`). |
| **macOS / iOS / bots** | **Announcement-driven.** Subscribes to whatever broadcasts the SFU *announces*, filtered by `{session}/` prefix (`freeq-sdk-ffi/src/lib.rs: watch_announcements`). Never reads the roster. |

Any disagreement between *the roster* and *what is actually announced on the
SFU* therefore splits the call **asymmetrically**: native clients keep hearing
everyone (they follow the wire), web clients silently lose whoever the roster
misdescribes. That is precisely the reported symptom, including its apparent
randomness (it depends on *whose* roster entry went stale) and its client
dependence.

Every finding below is an instance of one of these three classes:

- **(A)** roster diverges from announcements → web-side one-way loss
- **(B)** session-identity diverges (participants end up in *different sessions*
  while one UI shows one call) → mutual pairwise silence
- **(C)** media lifecycle diverges from IRC lifecycle (media lives while IRC
  state dies, or vice versa)

---

## 1.5 Production evidence (Jul 21, #test) — diagnosis confirmed

From `journalctl -u freeq-server` on irc.freeq.at:

```
19:00:46  AV session created 01KY30TK… channel=#test (eve)
19:56:10  nandi.uk joined (inst 09ed413c)
20:03:58  eve joined (inst 2d3a7b14)
20:22:17  chadfowler.com joined (inst c0696925)
20:29:10  chadfowler.com re-joined (NEW inst a15ec406) … left 3 s later
20:38:28  chadfowler.com re-joined (NEW inst 59d3ae5d) … left 5 s later
20:57:16  Guest54100 joined
20:57:31  chadfowler.com re-joined (NEW inst 2f4caaad) … left 5 s later
21:04:25  "Auto-ended 1 stale AV sessions"        ← F1: 2h03m force-end,
          nandi.uk + eve + Guest54100 STILL ACTIVE (no left events before this)
22:15:33  av-join rejected … "Session 01KY30TK… not found"  ← F3: nandi.uk's
          client joins the dead session, gets only a NOTICE, ghosts
```

The 5-second join→leave→retry cycles from chadfowler.com are the human
signature of the split ("joined, heard nothing, left, tried again"). The
force-end of a live call (F1) plus the invisible join failure (F3) reproduce
the reported symptom exactly, and "Auto-ended stale AV sessions" fired 3×
in the last 14 days.

---

## 2. Findings

### F1 — CRITICAL (fixed): live calls force-ended at 2 h ⇒ class B
`server.rs` cleanup task (5-minute tick) auto-ended **any session older than
2 hours, even with active participants**. Everyone in a long-running call gets
`av-state=ended`; clients that see it tear down and later restart a **new**
session; any client that misses the TAGMSG (mid-blip, backgrounded) keeps
publishing into the **dead** session. Unscoped SFU + client-side
`belongs_to_session` prefix filtering means the ghosts and the new session's
members silently exclude each other → random pairwise deafness, biased by
client type and who rejoined first.

**Fix:** `av::should_auto_end` (unit-tested). A session with active
participants is *never* age-ended while any participant's instance is claimed
by a live IRC connection; the age arm only reaps resurrected ghost sessions
(e.g. reloaded after a server restart whose owners never returned).

### F2 — CRITICAL (fixed): join-time roster reaper bypassed the grace window ⇒ class A
`reap_orphan_slots` runs on **every av-join** and marked "left" any roster slot
whose instance wasn't claimed by a live IRC connection **right now** — including
participants inside the 30 s disconnect grace (IRC blipped; their MoQ media —
a *separate* connection — still flowing; rejoin imminent). The moment anyone
joined the call, a blipped participant vanished from the roster: web clients
dropped their tiles/audio, natives kept hearing them.

**Fix:** new `av_grace_pending` set in `SharedState`; disconnects register
their AV instances before the grace timer, the timer clears them, and the
reaper skips any slot whose instance is grace-pending (unit-tested:
`reap_orphan_slots_spares_grace_pending_instances`).

### F3 — CRITICAL (fixed): AV failures were invisible to code ⇒ class B, C
A rejected `av-join` (session ended / full) or a lost `av-start` race came back
only as a **human NOTICE**. But every client sets up its call state (and macOS
dials the SFU and starts publishing) *before* the join round-trips. Result: a
client whose join failed kept its in-call UI and its media, but was never in
the roster — in the call per its own screen, silent/invisible to web peers,
possibly parked in a dead session entirely.

**Fix:**
- Server now also sends a **machine-readable TAGMSG**:
  `@+freeq.at/av-error=<code>;+freeq.at/av-id=<sid>;+freeq.at/av-reason=<text>`
  with codes `join-failed` and `start-collision` (the latter names the
  **winning** session).
- JS SDK emits `avError`; web tears down ghost call state on `join-failed`
  and converges onto the winner on `start-collision`.
- macOS/iOS: pure `resolveAvError` (unit-tested on both platforms) →
  `teardownAndRediscover` / `joinSession(winner)`.

### F4 — HIGH (fixed): iOS concurrent-start race (loser wedged) ⇒ class B
iOS only auto-joined when `av-state=started` had `actor == self`. The loser of
a simultaneous start (still pending, seeing the *winner's* nick) stayed wedged
outside the call. macOS fixed this earlier via `resolveAvStarted`; iOS now uses
the same unit-tested resolver ("if we were trying to start this channel's call
at all, converge on whatever session won").

### F5 — HIGH (fixed): mid-call rename orphans the web publisher ⇒ class A
The server can force-rename mid-call (custom-domain dot-strip on reconnect) or
the user can `/nick`. Web re-publishes under `{session}/{newNick}~{instance}`
(needed so instance-keyed peers can re-associate) — but **nothing updated the
roster**, so every roster-driven subscriber kept watching the old path forever.

**Fix:** after the rename republish, web re-sends `av-join` with the *same*
instance; `join_session` rejoins the slot in place and updates its nick, so the
roster follows the wire within one poll. (Native publishers never republish on
rename and never need this.)

### F6 — MEDIUM (fixed): IRC-dead / media-alive ghosts ⇒ class C
If a participant's IRC connection died past the grace window but their MoQ
connection survived, the roster dropped them while their media kept flowing:
web lost them, natives kept hearing them, and nothing revoked the media.

**Fix: server-side media revocation.** Every client self-declares its per-call
instance on the SFU dial URL (`?inst=…`); the SFU keeps an instance → conn
registry (`SfuState::media_conns`), and every roster-teardown path now closes
the instance's media connection(s): grace-expiry/immediate disconnect teardown
(`finish_av_slot_teardown`), the join-time orphan reap, explicit `/av end`,
leave-that-ends-the-session, and the cleanup sweeper. Media membership can no
longer outlive roster membership. (Cooperative attribution — hostile clients
are the token flag's concern, which F7 now enables.)

### F7 — MEDIUM (fixed): natives never dialed with the AV token
macOS/iOS dialed the SFU *before* av-join, so they could never carry the
`+freeq.at/av-token` — the day `FREEQ_AV_REQUIRE_TOKEN=1` was set, every
native call would have broken.

**Fix: join → token → dial.** Natives now send av-join first, hold the media
dial (`PendingMediaDial`), dial with `?jwt=…&inst=…` when the av-token TAGMSG
lands, and fall back to a tokenless dial after 2 s for servers that don't mint
tokens. Pure decision helpers (`shouldDialOnToken`/`shouldDialOnFallback`/
`mediaDialUrl`) are unit-tested on both platforms; teardown/av-error clears the
held dial so a rejected join can't dial into a dead session.

### F8 — LOW (fixed): web self-subscription echo edge
`isSelf` (av-mesh.ts) keyed strictly on instance; if *our own* roster row lost
its instance, we subscribed to our own broadcast → self-echo.

**Fix:** an instance-less roster row now falls through to DID (then nick)
identity, so our own stale row is recognised as self. Cost: our own *legacy*
second device wouldn't be subscribed — it already collided at the publish
path, so it was broken regardless; self-echo is strictly worse. Unit-tested
(3 new av-mesh cases incl. the guest/nick fallback).

### F9 — LOW (fixed): `av-state` fan-out requires channel presence
Roster changes reach clients as channel TAGMSGs; a client not joined to the
channel at that moment missed joined/left/ended transitions. Web self-healed
via its 1.2 s poll; macOS/iOS had no poll, so their participant strip could go
stale.

**Fix:** natives now reconcile the strip against `GET /api/v1/sessions/{id}`
every 5 s while in a call (display-only — media stays announcement-driven).
The pure `reconcileCallParticipants` (self-exclusion by instance, legacy nick
fallback, case-insensitive dedupe) is unit-tested on both platforms.

---

## 3. Temporal-coupling map (who assumes what, when)

```
startCall (macOS/iOS):
  FreeqAv(dial SFU, publish)      ← t0   assumes join will succeed (F3: now handled by av-error)
  send av-join                    ← t1
  av-token arrives                ← t2   ignored by natives (F7)
  roster updated                  ← t1'  web sees us only after this

web joinAvSession:
  send av-join → build publisher (tokenless) → token TAGMSG → re-dial
  roster poll (1.2 s) drives subscriptions — correctness depends on roster
  freshness (F1/F2/F5 all broke this)

server:
  av-join → reap_orphan_slots (now grace-aware) → join_session → broadcast
  disconnect → 30 s grace (av_grace_pending) → leave + av-state=left
  cleanup 5-min tick → should_auto_end (now never ends live calls)
```

## 4. What shipped in this pass

| Change | Where | Tests |
|---|---|---|
| `should_auto_end` policy | `freeq-server/src/av.rs`, cleanup in `server.rs` | `should_auto_end_policy` |
| Grace-aware reaper | `av.rs`, `connection/mod.rs`, `server.rs` (`av_grace_pending`) | `reap_orphan_slots_spares_grace_pending_instances` |
| `+freeq.at/av-error` | `connection/messaging.rs` (`send_av_error`) | SDK-js parse tests |
| `avError` event | `freeq-sdk-js` (events + client) | 3 new client tests |
| web av-error handling | `freeq-app/src/irc/client.ts` | — (logic is thin dispatch) |
| web rename → roster re-join | `freeq-app/src/components/CallPanel.tsx` | manual (test plan §5.4) |
| macOS av-error handling | `AvStartRace.swift` + `CallController.swift` + `AppState.swift` | 6 new `AvErrorResolutionTests` |
| iOS av-error + start-race parity | `AvStartRace.swift` (new), `AppState.swift` | new `AvStartRaceTests` (10) |
| iOS test bundle resurrected | `project.yml` test scheme; stale tests fixed | all 100 iOS tests green + runnable |

## 5. Second pass ("do not leave anything open") — F6–F9 closed

| Change | Where | Tests |
|---|---|---|
| SFU media revocation registry + `?inst=` attribution | `av_sfu.rs` (`media_conns`, `revoke_media`, select in `handle_ws_moq`), `web.rs` routes, all roster-teardown call sites | e2e suite + build |
| Join → token → dial on natives | macOS `CallController` + iOS `AppState` (`PendingMediaDial`, `handleAvToken`, `dialMedia`) | 7 macOS + 3 iOS pure-fn tests |
| Web self-echo edge | `av-mesh.ts` `isSelf` fall-through | 3 av-mesh tests |
| Native roster reconciliation | macOS + iOS 5 s poll, `reconcileCallParticipants` | 3 macOS + 2 iOS tests |
| av-error e2e proof | `freeq-server/tests/av_error_signal.rs` (real server + real SDK clients) | 2 e2e tests |
| web avError dispatch | `client-av.test.ts` (join-failed teardown, collision convergence) | 3 tests |
| Resurrected rotted web AV tests | injectable `__setAvStartPollForTests` (in-flight-guard order dependence) | 4 tests un-rotted |

Verification at time of writing: server **1084** tests, macOS **434**, iOS
**105**, sdk-js **219**, web **753** — all green; `--features av-native`
compiles clean.

---

## 6. Third pass (2026-08-22) — what the harness found

F1–F9 were found by reading code and production logs. F10–F12 were found by
`scripts/avharness.sh` the first few times it ran, which is the argument for
having built it: two of the three contradict something this document already
claimed was closed.

### F10 — HIGH (OPEN): media revocation never happens on the QUIC transport ⇒ class C

F6 above says "Media membership can no longer outlive roster membership."
That is true for WebSocket clients and false for everyone else.

`av_sfu.rs::handle_ws_moq` reads `?inst=` off the dial URL and registers the
connection in `SfuState::media_conns`, which is what `revoke_media` closes.
`handle_quic_connection` does neither — it never parses `inst`, so a
QUIC-dialed connection is not in the registry and nothing can revoke it. Every
native client (macOS, iOS, Windows) dials QUIC with `?inst=` (`mediaDialUrl`
builds `{base}?inst=…&jwt=…`), and they are exactly the announcement-driven
clients that keep hearing a roster-ghost.

So the F6 fix closed the asymmetry for the half of the fleet that was already
on the right side of it.

**Reproduced**, not theorised:

    avharness --transport quic --chaos --chaos-steps blip

> C1: a0's media outlived its roster slot — still heard by [1, 2] 11s after
> grace expiry; announced=true.

with `0` occurrences of `SFU: session revoked` in the server log against `4`
QUIC connections. The harness reports this as a finding rather than a failure
today; `--strict-quic-revocation` turns it into a failure, and that flag is
what the fix should be verified with.

### F11 — MEDIUM (OPEN): a guest's mid-call rename leaves a duplicate slot ⇒ class A

F5's fix — re-send `av-join` with the same instance after a rename — works by
rejoining the participant slot *in place*. The slot's key is
`participant_key(did, instance)`, and a guest's DID is `guest:{nick}`. Rename
the guest and the key changes, so the rejoin inserts a second slot instead of
updating the first: two roster rows, same instance, different nicks.

Observed directly (2 real participants, `participant_count: 3`):

    {"nick":"gren_b",         "instance_id":"inst-gren_b"}
    {"nick":"gren_a_renamed", "instance_id":"inst-gren_a"}
    {"nick":"gren_a",         "instance_id":"inst-gren_a"}   ← ghost

Every roster-driven subscriber then computes two paths for one publisher, one
of which nobody publishes to — a permanent black tile plus a wasted
subscription. Authenticated users are unaffected (a DID is stable across a
rename), which is why `rename_mid_call_updates_roster` in
`tests/av_lifecycle.rs` pins the DID case and this one is still open.

The fix is presumably to key the slot on instance alone when one is present,
or to re-key the guest's slot on rename.

### F12 — LOW (OPEN): C2 measured — media-dead / IRC-alive is invisible to everyone

`AV-MAP.md` §5 lists C2 as UNAUDITED. The harness's `media-kill` step now
measures it, and the answer is the bad one:

> a0 lost its media transport while its IRC connection stayed up. Roster still
> lists it: **true**. Relay still announces it: false. Nobody hears it.

A client in this state shows itself in-call, shows a tile to every peer, and
is silent — and nothing in the protocol tells anyone, on either subscription
model. It self-heals only when the media layer's reconnect backoff succeeds.
Closing it needs a liveness signal: either the SFU reporting publisher
presence into the roster (a `publishing` flag on the participant) or the
client noticing its own transport is down and sending `av-leave`.

### Also worth knowing (not a bug)

The SFU is initialized inside the iroh-endpoint branch of `Server::run`, so a
server started **without `--iroh` reports `av:false`** and has no relay at all,
whatever `--features av-native` says. Production always passes `--iroh`, which
is why this has never bitten; `deploy.sh`'s health check would catch it.

---

**See `docs/AV-TEST-PLAN.md` for the full cross-client matrix that keeps this
fixed, and `docs/AV-MAP.md` §7 for the harness that found F10–F12.**
