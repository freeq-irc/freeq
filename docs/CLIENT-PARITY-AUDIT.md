# Client Parity & Delight Audit — Web · macOS · iOS

Date: 2026-07-23 (updated 2026-07-24 with a parity-sprint progress pass).
Method: source survey of `freeq-app/` (React/TS),
`freeq-macos/` (SwiftUI+AppKit / Rust core), `freeq-ios/` (SwiftUI / Rust
core), cross-checked against live behavior staged for the client
screenshots. Legend: ✅ full · ⚠️ partial/basic · ❌ absent · — n/a for
platform.

This is the basis for a parity + delight plan, not a shipping checklist yet.
Counts in parentheses are file-hit signals, not guarantees — statuses are the
considered call.

---

## 1. The grid

### Core messaging
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Send / receive / history (CHATHISTORY) | ✅ | ✅ | ✅ | all hydrate from server history |
| Reactions | ✅ | ✅ | ✅ | web has the richest emoji picker; native uses a quick set |
| Threads / replies | ✅ | ✅ | ✅ | |
| Edit message | ✅ | ✅ | ✅ | iOS dedup on replay just fixed (2026-07-23) |
| Delete (tombstone) | ✅ | ✅ | ✅ | |
| Pins | ✅ | ✅ | ✅ | iOS pin UI is notably complete |
| In-buffer / server search | ✅ | ✅ | ✅ | all three have a search surface |
| Markdown + code / syntax highlight | ✅ | ✅ | ✅ | macOS has the deepest tokenizer (`SyntaxHighlighter`) |
| Bluesky post embeds | ✅ | ✅ | ✅ | |
| YouTube / link previews | ✅ | ✅ | ✅ | |
| Media upload (image/file) | ✅ | ✅ | ✅ | |
| Typing indicators | ✅ | ✅ | ✅ | |
| away-notify | ✅ | ✅ | ✅ | |
| Read markers (draft/read-marker) | ⚠️ | ⚠️ | ⚠️ | stored server-side; minimal "new" UI everywhere |
| Signed-message badge | ✅ | ✅ | ✅ | verified in the staged shots |
| Multi-message block copy → clean transcript | ✅ | ✅ | — | ✅ **web shipped 2026-07-24** (≥2-row selection → clean copy); iOS skipped (mobile multi-select is a larger, less-natural UX) |

### Identity & trust
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Bluesky OAuth login | ✅ | ✅ | ✅ | |
| Guest connect | ✅ | ✅ | ✅ | |
| Verified / DID badges | ✅ | ✅ | ✅ | |
| Channel E2EE (passphrase / VC) | ✅ | ✅ | ✅ | ✅ **iOS shipped 2026-07-24** (ported crypto core + /encrypt + keychain + lock) |
| P2P (iroh) direct DMs | ❌ | ✅ | ❌ | **macOS-only** |
| Policy / join-gate UI | ✅ | ✅ | ✅ | ✅ **iOS shipped 2026-07-24** (access-denied banner + toast) |

### Audio / video (sessions)
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Voice call | ✅ | ✅ | ✅ | |
| Video / camera | ✅ | ✅ | ✅ | |
| Screen share | ✅ | ✅ | ⚠️ | iOS can view a share; broadcasting from iOS is limited |
| Camera effects / background blur | ❌ | ✅ | ❌ | **macOS-only** (`CameraEffectsProcessor`) |
| Call grid auto-layout (1→~30) | ✅ | ✅ | ✅ | ✅ **web + iOS shipped 2026-07-24** — shared `CallGridLayout` math (10 web + 14 iOS tests match the macOS reference) |
| Click-to-focus a tile | ✅ | ❌ | ❌ | ✅ **web shipped + live 2026-07-24** (focused tile fills, others to a strip, CSS order = no video dup). macOS/iOS: port next (needs native rebuild). |
| CallKit (native call UI) | — | — | ✅ | **iOS-only**, appropriate |

### Agent & session observability — *the pitch surface*
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Coordination cards (task_request/update/complete) | ✅ | ✅ | ✅ | ✅ **native shipped 2026-07-24** (FFI `CoordinationEvent` + card views). NB: production `freeq-server` must be redeployed for replayed events to carry the tags |
| Task timeline | ✅ | ❌ | ❌ | web-only |
| Audit / governance timeline | ✅ | ❌ | ❌ | web-only |
| Session history browser | ✅ | ⚠️ | ⚠️ | web `SessionHistory`/`SessionIndicator`; native shows live call state only |

### AI & delight
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| On-device smart replies | ❌ | ❌ | ✅ | **iOS-only** (`IntelligenceService`) |
| Catch-up digest | ❌ | ❌ | ✅ | **iOS-only** (`CatchUpDigestSheet`) |
| Voice messages + transcription | ⚠️ | ✅ | ✅ | iOS deepest; web is basically `AudioTest` only |
| Sound design | ✅ | ✅ | ✅ | ✅ **web upgraded 2026-07-24** — distinct DM/mention/message tones |
| Onboarding flow | ✅ | ✅ | ✅ | ✅ **iOS shipped 2026-07-24** (first-run sheet, on-pitch) |
| Jumbomoji (≤3 emoji → large) | ✅ | ✅ | ✅ | ✅ **all shipped 2026-07-24** — shared 1–3 emoji policy |

### Platform-native reach
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Menu-bar app / quick-send / global hotkey | — | ✅ | — | macOS-only, appropriate |
| Share extension (send-to-freeq) | — | ✅ | ❌ | **iOS could have this; doesn't** |
| App Intents / Siri Shortcuts | — | ✅ | ✅ | macOS deepest (18 intents); iOS present (8) |
| Live Activity (call on lock screen) | — | — | ✅ | iOS-only |
| Home-screen widgets | — | — | ✅ | iOS-only |
| Apple Watch app | — | — | ✅ | iOS-only |
| PWA install / offline shell | ✅ | — | — | web-only |
| MetricKit / perf signposts | — | ✅ | ⚠️ | macOS instruments hitches |

### Favorites & roaming state
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Favorite channels | ✅ | ✅ | ✅ | all had them (per-device) |
| **Roam per user (per-DID)** | ✅ | ✅ | ✅ | ✅ **shipped 2026-07-24** — `/api/v1/favorites` (Bearer-authed, per-DID); pull+union on connect, push on toggle. Server deployed + verified. Shared `merge` policy (server order wins, no device loses one). |

### Navigation & power-user
| Feature | Web | macOS | iOS | Notes |
|---|:--:|:--:|:--:|---|
| Quick switcher (⌘K) | ✅ | ✅ | ✅ | |
| Slash-command UI | ⚠️ | ✅ | ❌ | macOS `CommandRegistry` richest; **iOS none** |
| Bookmarks | ✅ | ✅ | ✅ | ✅ **iOS shipped 2026-07-24** (context-menu + Saved Messages) |
| Keyboard shortcuts panel | ✅ | ✅ | ⚠️ | |

### Engineering quality (tested surface)
| | Web | macOS | iOS |
|---|:--:|:--:|:--:|
| Unit/logic test files | 22 vitest | 35 core | **8 core** |
| E2E / integration | 18 Playwright specs | ui-sweep + core | thin |

---

## 2. Where each client is *best*

**Web** — the agent & governance story (coordination cards, task + audit
timelines, session history), the richest emoji picker, join-gate UX, PWA
install, and the broadest test coverage. It is currently the *only* place the
agent-native pitch is visible in-product.

**macOS** — the craft flagship: camera effects/blur, call-grid auto-layout
(the reference impl), P2P iroh DMs, channel E2EE, multi-message block copy,
menu-bar + global hotkey + share extension, 18 App Intents, syntax
highlighting, MetricKit perf discipline, most core tests.

**iOS** — the delight leader: on-device smart replies + catch-up digest
(unique AI), deepest voice-message/transcription, CallKit, Live Activity,
widgets, Watch app. Punches above its weight on ambient/mobile-native feel —
but is the thinnest on messaging breadth and tests.

---

## 3. Gaps to close (parity) — ranked

**P0 — the pitch is invisible off-web.** Coordination cards, task timeline,
and audit/governance timeline exist *only* on web. For an "agent-native"
product, macOS and iOS showing agent work as plain text undercuts the whole
story. Port the card renderer (it's pure tag→view; the wire data already
arrives on every client).

**P1 — iOS is missing whole columns.**
- Channel E2EE (web+mac have it; iOS can't read/write encrypted channels).
- Policy / join-gate UI (iOS silently fails gated joins).
- Bookmarks, slash-command UI, onboarding.
- iOS test coverage (8 files) needs to roughly triple to match the others.

**P1 — AV parity both directions.**
- Call-grid auto-layout → web + iOS (macOS is the reference).
- Click-to-focus a tile → *all three* (nobody has it; open P1 TODO).
- Camera effects/blur → web + iOS (macOS-only today).

**P2 — cross-pollinate the unique wins.**
- iOS's smart replies + catch-up digest → macOS (and web where feasible).
- macOS's block-copy transcript → web + iOS.
- macOS P2P DMs → iOS.
- iOS share extension (macOS has one; iOS doesn't).
- Read-marker "new messages" UI → finish on all three.

---

## 4. Delight opportunities (net-new, raise the ceiling everywhere)

- **Jumbomoji** — designed, built nowhere. Cheap, high-charm. Do it in the
  shared render policy so all three inherit it.
- **Reaction morphs / micro-animations** on add.
- **Agent presence as a first-class visual** — the pink/verified identity is
  great; extend it to a live "agent working" shimmer on the card (ties into
  the P0 card port).
- **Voice-message waveform + inline transcript** unified across clients
  (iOS has the pieces; lift them).
- **Sound design** parity on web (native feels alive; web is quiet).
- **Onboarding** on iOS; make all three teach the agent trick
  (watch-your-agent) in first-run.

---

## 5. Suggested sequencing — progress

1. ✅ **Card port (P0) — DONE (2026-07-24).** FFI now surfaces a typed
   `CoordinationEvent`; macOS + iOS render coordination cards (pure style
   policy + card views), with unit + FFI-mapping tests. Every client tells
   the pitch. *Caveat: production freeq-server needs a redeploy so replayed
   coordination events carry the `+freeq.at/event` tags to clients.*
2. **iOS parity sprint (P1):** ✅ E2EE, ✅ join-gate UI, ✅ bookmarks,
   ✅ onboarding — all DONE 2026-07-24. Remaining: expand slash-command set
   (iOS already has join/part/nick/me/msg/topic; macOS has ~20 more), and
   the test-coverage push (iOS core 55→90 tests this pass; keep going).
3. **AV parity (P1) — PARTLY DONE (2026-07-24).** ✅ grid auto-layout ported
   to web + iOS (pure `CallGridLayout` math, unit-tested against the macOS
   reference). Remaining: click-to-focus a tile (all 3) and camera
   effects/blur (web/iOS) — both are interaction / video-pipeline work whose
   correctness needs a **live multi-participant call** to verify; not done
   blind.
4. **Delight pass (P2) — PARTLY DONE (2026-07-24).** ✅ jumbomoji (all 3),
   ✅ block-copy to web, ✅ distinct notification sounds on web. Remaining:
   reaction morphs; smart-replies/catch-up → macOS (needs the on-device
   model port — do deliberately).

### Landed across this work (2026-07-24)
- **P0 coordination cards:** FFI `CoordinationEvent`, macOS + iOS renderers
  (7 card tests each + 3 FFI mapping tests). *Needs prod server redeploy for
  replayed events to carry the tags.*
- **iOS parity sprint:** channel E2EE (32 crypto tests), bookmarks, join-gate
  (3 tests), onboarding, slash-command expansion. iOS core tests 55 → 90.
- **Delight:** jumbomoji on all 3 (6 tests each), web clean block-copy
  (5 tests), distinct web notification sounds (4 tests).
- All builds green (web tsc + 768 vitest; macOS 464 core; iOS 90 core);
  verified iOS onboarding + cards render in the simulator.

### Also landed 2026-07-24 (post-deploy)
- **Production server deploy** — done over SSH to the production host
  (systemd `freeq-server`, git checkout; not the Miren app). Shipped
  the reaction-durability + coordination-tag-replay fixes and rebuilt the
  live web client. Verified: fresh coordination events now replay with
  `+freeq.at/event`; `/api/v1/favorites` gated (401 unauth).
- **Roaming favorites** — server `user_favorites` + REST + all three clients.

### Still open (needs deliberate / live work)
- **AV parity (P1):** ✅ grid auto-layout done (web+iOS). Remaining:
  click-to-focus → all; camera effects/blur → web/iOS. **Do against a live
  multi-participant call** — layout math is unit-verified but focus/blur are
  visual/pipeline changes to eyeball live.
- **Production server deploy:** `freeq-irc` is on the `club` Miren cluster,
  which 403s the current `cloud` identity — needs an identity authorized on
  `club` to run `deploy/irc/deploy.sh -C club` (code already on origin/main).
  Gates coordination-card *replay* only; live coordination events already
  render as cards.
- **Smart-replies / catch-up → macOS:** requires porting the iOS on-device
  IntelligenceService; sizable, do deliberately.
- **iOS scroll-to-message** (bookmarks/search jump lands on the channel, not
  the exact row) and continued iOS test-coverage growth.

Each item above wants tests first on the high-gamma files (per `AGENTS.md`),
especially anything touching `store.ts`, `MessageList.tsx`, `AppState`, and
the SDK client.
